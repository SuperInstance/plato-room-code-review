"""
Tests for the GitHub client's simulation mode and the Room lifecycle.

Run: python -m pytest tests/test_room.py -v
"""

import sys
import os
import time
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from github_client import GitHubClient
from room import CodeReviewRoom, BaseRoom, AlarmDef
from reviewer import run_all_checks


class TestGitHubClientSimulation:
    """GitHub client works without a token (simulation mode)."""

    def test_not_configured_without_token(self):
        client = GitHubClient(token="")
        assert not client.configured

    def test_fetch_diff_returns_sample(self):
        client = GitHubClient(token="")
        diff = client.fetch_pr_diff("owner", "repo", 1)
        assert "diff --git" in diff

    def test_fetch_metadata_returns_sample(self):
        client = GitHubClient(token="")
        meta = client.fetch_pr_metadata("owner", "repo", 1)
        assert meta["state"] == "open"
        assert meta["changed_files"] == 2
        assert meta["test_files"] == 0

    def test_fetch_ci_status_returns_sample(self):
        client = GitHubClient(token="")
        status = client.fetch_ci_status("owner", "repo", 1)
        assert status["passed"] == 3
        assert status["failed"] == 0

    def test_post_review_simulated(self):
        client = GitHubClient(token="")
        result = client.post_review("owner", "repo", 1, "LGTM", "COMMENT")
        assert result.get("simulated") is True

    def test_apply_label_simulated(self):
        client = GitHubClient(token="")
        result = client.apply_label("owner", "repo", 1, "needs-tests")
        assert result.get("simulated") is True


class TestRoomBasics:
    """Test the BaseRoom and CodeReviewRoom."""

    def test_base_room_registers_sensors(self):
        room = BaseRoom()
        room.register_sensor("test", lambda r: {"val": 1.0})
        assert "test" in room._sensors

    def test_base_room_registers_alarms(self):
        room = BaseRoom()
        room.register_alarm("overheat", sensor="temp", operator=">", threshold=90.0)
        assert "overheat" in room._alarms
        alarm = room._alarms["overheat"]
        assert alarm.operator == ">"
        assert alarm.threshold == 90.0

    def test_alarm_evaluation(self):
        alarm = AlarmDef("test", "val > 5", "val", ">", 5)
        assert alarm.evaluate({"val": 10.0}) is True
        assert alarm.evaluate({"val": 3.0}) is False
        assert alarm.evaluate({}) is False  # missing sensor

    def test_alarm_operators(self):
        for op, val, threshold, expected in [
            ("<", 3, 5, True), ("<", 7, 5, False),
            (">", 7, 5, True), (">", 3, 5, False),
            ("<=", 5, 5, True), (">=", 5, 5, True),
            ("==", 5, 5, True), ("!=", 5, 5, False),
        ]:
            alarm = AlarmDef("t", f"v {op} {threshold}", "v", op, threshold)
            assert alarm.evaluate({"v": val}) is expected, f"Failed: {op} {val} {threshold}"

    def test_tick_executes_sensors(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"temp": 42.0})
        data = room.tick()
        assert data["temp"] == 42.0
        assert len(room._history) == 1

    def test_tick_evaluates_alarms(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"temp": 100.0})
        room.register_alarm("hot", sensor="temp", operator=">", threshold=90.0)
        room.tick()
        assert room._alarms["hot"].state == "triggered"

    def test_tick_records_history(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": float(r._seq)})
        for _ in range(5):
            room.tick()
        assert len(room._history) == 5
        assert room._history[-1]["seq"] == 5

    def test_handle_tick_command(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": 1.0})
        import json
        resp = json.loads(room.handle_command("tick"))
        assert resp["type"] == "tick"
        assert "x" in resp["data"]

    def test_handle_history_command(self):
        room = BaseRoom()
        room.register_sensor("s1", lambda r: {"x": 1.0})
        room.tick()
        room.tick()
        import json
        resp = json.loads(room.handle_command("history 2"))
        assert resp["type"] == "history"
        assert resp["count"] == 2

    def test_handle_alarm_list_command(self):
        room = BaseRoom()
        room.register_alarm("a1", sensor="s", operator=">", threshold=5)
        import json
        resp = json.loads(room.handle_command("alarm list"))
        assert resp["type"] == "alarm_list"
        assert resp["alarms"][0]["id"] == "a1"

    def test_handle_actuator_command(self):
        room = BaseRoom()
        called = []
        room.register_actuator("do_thing", lambda r, v: called.append(v))
        import json
        resp = json.loads(room.handle_command("actuator do_thing 3"))
        assert resp["type"] == "ack"
        assert called == [3.0]


class TestCodeReviewRoom:
    """Test the CodeReviewRoom specifically."""

    def test_setup_registers_all_sensors(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 1, port=0)
        assert "pr_state" in room._sensors
        assert "ci_status" in room._sensors
        assert "diff_metrics" in room._sensors

    def test_setup_registers_all_actuators(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 1, port=0)
        assert "post_review" in room._actuators
        assert "post_comment" in room._actuators
        assert "apply_label" in room._actuators

    def test_setup_registers_all_alarms(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 1, port=0)
        assert "no_tests" in room._alarms
        assert "secrets_detected" in room._alarms
        assert "ci_failing" in room._alarms
        assert "security_touched" in room._alarms

    def test_tick_with_sample_data(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 42, port=0)
        data = room.tick()
        # Sample data has 0 test files → no_tests alarm should fire
        assert data["test_file_count"] == 0
        assert data["changed_file_count"] == 2
        # Secrets in sample diff → secrets_detected should fire
        assert data["secret_like_count"] > 0
        assert room._alarms["secrets_detected"].state == "triggered"
        assert room._alarms["no_tests"].state == "triggered"

    def test_tick_without_pr_number(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 0, port=0)
        data = room.tick()
        assert data["pr_open"] == 0
        assert data["changed_file_count"] == 0

    def test_room_id(self):
        gh = GitHubClient(token="")
        room = CodeReviewRoom(gh, "owner", "repo", 1, port=0)
        assert room.room_id == "code-review-room"
