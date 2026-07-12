"""
PLATO Code Review Room — an engine block that orchestrates automated code review.

Sensors pull PR state from GitHub.  Alarms fire on policy violations.
Actuators post reviews back.  The tick loop polls on a configurable cadence.

Deploy as a standalone bot or inside a GitHub Action.

Usage:
    python -m plato_room_code_review.room --repo owner/repo --pr 42

    # or run as a long-lived server (polls periodically)
    python -m plato_room_code_review.room --repo owner/repo --watch
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import socketserver
import threading
import time
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Optional

# plato_core is optional at import time — tests and simulation work without it.
try:
    from plato_core.protocol import PROTOCOL_VERSION
except ImportError:
    PROTOCOL_VERSION = "0.1"

# Support both package-relative and standalone imports
try:
    from .reviewer import run_all_checks, CheckResult
    from .github_client import GitHubClient
except ImportError:
    from reviewer import run_all_checks, CheckResult
    from github_client import GitHubClient

logger = logging.getLogger("plato.room.code_review")

# ─── Core room primitives ─────────────────────────────────────

SensorFunc = Callable[["BaseRoom"], dict[str, float]]
ActuatorFunc = Callable[["BaseRoom", float], None]


@dataclass
class AlarmDef:
    """Declarative alarm definition."""
    alarm_id: str
    condition: str          # e.g. "security_file_count < 1"  (reversed: fires when true)
    sensor: str             # which sensor value to watch
    operator: str           # <, >, <=, >=, ==, !=
    threshold: float
    cooldown_sec: int = 300
    last_triggered: float = 0.0
    state: str = "idle"

    def evaluate(self, sensor_values: dict[str, float]) -> bool:
        """Return True if the alarm should fire."""
        val = sensor_values.get(self.sensor)
        if val is None:
            return False
        ops = {
            "<":  lambda a, b: a < b,
            ">":  lambda a, b: a > b,
            "<=": lambda a, b: a <= b,
            ">=": lambda a, b: a >= b,
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
        }
        op = ops.get(self.operator)
        if op is None:
            return False
        return op(val, self.threshold)


class BaseRoom:
    """
    Base PLATO room — a TCP server that implements the wire protocol.

    Subclasses register sensors, actuators, and alarms in setup().
    The tick loop calls each sensor, stores values, evaluates alarms,
    and notifies subscribers.
    """

    tick_hz: float = 0.2   # default 5s interval
    room_id: str = "base-room"

    def __init__(self, host: str = "0.0.0.0", port: int = 1234):
        self.host = host
        self.port = port
        self._sensors: dict[str, SensorFunc] = {}
        self._actuators: dict[str, ActuatorFunc] = {}
        self._alarms: dict[str, AlarmDef] = {}
        self._history: deque[dict] = deque(maxlen=1000)
        self._subscribers: list[socket.socket] = []
        self._lock = threading.Lock()
        self._seq = 0
        self._running = False
        self._latest: dict[str, float] = {}

    # ── Registration ───────────────────────────────────────

    def register_sensor(self, name: str, func: SensorFunc) -> None:
        self._sensors[name] = func

    def register_actuator(self, name: str, func: ActuatorFunc) -> None:
        self._actuators[name] = func

    def register_alarm(
        self,
        alarm_id: str,
        sensor: str,
        operator: str,
        threshold: float,
        cooldown_sec: int = 300,
    ) -> None:
        condition = f"{sensor} {operator} {threshold}"
        self._alarms[alarm_id] = AlarmDef(
            alarm_id=alarm_id,
            condition=condition,
            sensor=sensor,
            operator=operator,
            threshold=threshold,
            cooldown_sec=cooldown_sec,
        )

    # ── Tick loop ──────────────────────────────────────────

    def tick(self) -> dict[str, float]:
        """Execute one tick: read all sensors, evaluate alarms."""
        self._seq += 1
        values: dict[str, float] = {}
        for name, func in self._sensors.items():
            try:
                result = func(self)
                if isinstance(result, dict):
                    values.update(result)
            except Exception as exc:
                logger.warning("sensor %s error: %s", name, exc)
                values[f"{name}_error"] = 1.0

        self._latest = values
        ts = time.time()
        tick_record = {"t": ts, "seq": self._seq, "data": values}
        self._history.append(tick_record)

        # Evaluate alarms
        for alarm in self._alarms.values():
            if alarm.evaluate(values):
                if ts - alarm.last_triggered >= alarm.cooldown_sec:
                    alarm.last_triggered = ts
                    alarm.state = "triggered"
                    self._on_alarm(alarm, values, ts)
                else:
                    alarm.state = "cooling"
            else:
                alarm.state = "idle"

        # Notify subscribers
        self._notify_subscribers(tick_record)
        return values

    def _on_alarm(self, alarm: AlarmDef, data: dict[str, float], ts: float) -> None:
        """Override in subclass for custom alarm handling."""
        logger.info("ALARM %s fired: %s", alarm.alarm_id, alarm.condition)

    def _notify_subscribers(self, tick_record: dict) -> None:
        msg = json.dumps({"type": "tick", **tick_record}) + "\n"
        dead: list[socket.socket] = []
        with self._lock:
            for sub in self._subscribers:
                try:
                    sub.sendall(msg.encode())
                except Exception:
                    dead.append(sub)
            for d in dead:
                self._subscribers.remove(d)

    # ── Actuation ─────────────────────────────────────────

    def actuate(self, name: str, value: float = 1.0) -> None:
        func = self._actuators.get(name)
        if func:
            func(self, value)
        else:
            logger.warning("unknown actuator: %s", name)

    # ── Protocol command handlers ─────────────────────────

    def handle_command(self, line: str) -> str:
        """Handle one protocol command line, return response JSON."""
        parts = line.strip().split()
        if not parts:
            return json.dumps(asdict(ErrorResponse(message="empty command")))

        cmd = parts[0]

        if cmd == "tick":
            data = self.tick()
            return json.dumps({"type": "tick", "t": time.time(),
                               "seq": self._seq, "data": data})

        if cmd == "history":
            n = int(parts[1]) if len(parts) > 1 else 10
            ticks = list(self._history)[-n:]
            return json.dumps({"type": "history", "count": len(ticks),
                               "ticks": ticks})

        if cmd == "actuator" and len(parts) >= 2:
            name = parts[1]
            value = float(parts[2]) if len(parts) > 2 else 1.0
            self.actuate(name, value)
            return json.dumps({"type": "ack", "command": "actuator",
                               "name": name, "value": value})

        if cmd == "alarm" and len(parts) >= 2:
            sub = parts[1]
            if sub == "list":
                alarms = [
                    {"id": a.alarm_id, "condition": a.condition,
                     "cooldown_sec": a.cooldown_sec,
                     "last_triggered": a.last_triggered,
                     "state": a.state}
                    for a in self._alarms.values()
                ]
                return json.dumps({"type": "alarm_list", "alarms": alarms})
            if sub == "set" and len(parts) >= 5:
                aid = parts[2]
                condition = parts[3]
                cooldown = int(parts[4])
                # Parse "sensor op threshold"
                tokens = condition.split()
                if len(tokens) == 3:
                    self.register_alarm(aid, tokens[0], tokens[1],
                                        float(tokens[2]), cooldown)
                return json.dumps({"type": "ack", "command": "alarm set",
                                   "id": aid})

        if cmd == "subscribe":
            return json.dumps({"type": "subscribed", "tick_hz": self.tick_hz})

        if cmd == "unsubscribe":
            return json.dumps({"type": "unsubscribed"})

        if cmd == "help":
            return json.dumps({"type": "help", "commands": [
                "tick", "history N", "actuator NAME [VALUE]",
                "alarm list", "alarm set ID CONDITION COOLDOWN",
                "subscribe", "unsubscribe", "help", "quit",
            ]})

        if cmd == "quit":
            return json.dumps({"type": "bye"})

        return json.dumps(asdict(ErrorResponse(
            message=f"unknown command: {cmd}")))

    # ── TCP server ────────────────────────────────────────

    def serve(self) -> None:
        """Run the TCP server + tick loop."""
        self._running = True

        # Start tick thread
        tick_thread = threading.Thread(target=self._tick_loop, daemon=True)
        tick_thread.start()

        # Start TCP server
        server = socketserver.ThreadingTCPServer(
            (self.host, self.port), _RoomHandlerFactory(self))
        server.daemon_threads = True
        logger.info("Room %s listening on %s:%d", self.room_id, self.host, self.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            self._running = False
            server.shutdown()

    def _tick_loop(self) -> None:
        interval = 1.0 / self.tick_hz if self.tick_hz > 0 else 5.0
        while self._running:
            try:
                self.tick()
            except Exception as exc:
                logger.error("tick error: %s", exc)
            time.sleep(interval)


def _RoomHandlerFactory(room: BaseRoom):
    """Create a RequestHandler class bound to a specific room."""

    class _RoomHandler(socketserver.StreamRequestHandler):
        def handle(self):
            # Send welcome
            welcome = json.dumps({
                "type": "welcome",
                "room_id": room.room_id,
                "tick_hz": room.tick_hz,
                "sensors": list(room._sensors.keys()),
                "format": "json",
                "protocol_version": PROTOCOL_VERSION,
            }) + "\n"
            self.wfile.write(welcome.encode())

            for line in self.rfile:
                line_str = line.decode().strip()
                if not line_str:
                    continue
                response = room.handle_command(line_str)
                self.wfile.write((response + "\n").encode())

                # Track subscription
                if line_str.startswith("subscribe"):
                    with room._lock:
                        room._subscribers.append(self.request)
                elif line_str.startswith("unsubscribe"):
                    with room._lock:
                        if self.request in room._subscribers:
                            room._subscribers.remove(self.request)
                elif line_str.strip() == "quit":
                    break

    return _RoomHandler


# ─── Code Review Room ────────────────────────────────────────

class CodeReviewRoom(BaseRoom):
    """
    A PLATO room that reviews GitHub PRs.

    Sensors:
        pr_state      — PR open/closed/merged, changed file count, test file count
        ci_status     — CI passing/failing/pending counts
        diff_metrics  — Lines added/removed, security file touches, secret-like strings

    Actuators:
        post_review     — Post a GitHub review (APPROVE / REQUEST_CHANGES / COMMENT)
        post_comment    — Post a single inline comment
        apply_label     — Apply a label to the PR

    Alarms:
        no_tests         — fires when test_file_count == 0 on a non-trivial PR
        secrets_detected — fires when secret_like_count > 0
        ci_failing       — fires when ci_failed > 0
        security_touched — fires when security_file_count > 0
    """

    room_id = "code-review-room"
    tick_hz = 0.1  # every 10 seconds — gentle on the API

    def __init__(
        self,
        github_client: GitHubClient,
        owner: str,
        repo: str,
        pr_number: int = 0,
        host: str = "0.0.0.0",
        port: int = 1234,
    ):
        super().__init__(host=host, port=port)
        self.gh = github_client
        self.owner = owner
        self.repo = repo
        self.pr_number = pr_number
        self._last_review: Optional[dict] = None
        self.setup()

    def setup(self) -> None:
        """Register sensors, actuators, and alarms."""
        # ── Sensors ─────────────────────────────────────────
        self.register_sensor("pr_state", _sensor_pr_state)
        self.register_sensor("ci_status", _sensor_ci_status)
        self.register_sensor("diff_metrics", _sensor_diff_metrics)

        # ── Actuators ───────────────────────────────────────
        self.register_actuator("post_review", _actuator_post_review)
        self.register_actuator("post_comment", _actuator_post_comment)
        self.register_actuator("apply_label", _actuator_apply_label)

        # ── Alarms ──────────────────────────────────────────
        self.register_alarm("no_tests", sensor="test_file_count",
                            operator="<", threshold=1, cooldown_sec=600)
        self.register_alarm("secrets_detected", sensor="secret_like_count",
                            operator=">", threshold=0, cooldown_sec=60)
        self.register_alarm("ci_failing", sensor="ci_failed",
                            operator=">", threshold=0, cooldown_sec=300)
        self.register_alarm("security_touched", sensor="security_file_count",
                            operator=">", threshold=0, cooldown_sec=600)

    def _on_alarm(self, alarm: AlarmDef, data: dict[str, float], ts: float) -> None:
        """Custom alarm handler — triggers review actions."""
        logger.warning("Alarm %s triggered (data=%s)", alarm.alarm_id, data)

        if alarm.alarm_id == "secrets_detected":
            self.actuate("post_review", 2.0)  # REQUEST_CHANGES
        elif alarm.alarm_id == "no_tests":
            self.actuate("post_review", 1.0)  # COMMENT
        elif alarm.alarm_id == "ci_failing":
            self.actuate("apply_label", 3.0)  # label "ci-failing"
        elif alarm.alarm_id == "security_touched":
            self.actuate("apply_label", 4.0)  # label "security-review"


# ─── Sensor functions ────────────────────────────────────────

def _sensor_pr_state(room: CodeReviewRoom) -> dict[str, float]:
    """Fetch PR metadata and expose as numeric sensors."""
    if not room.pr_number:
        return {"pr_open": 0.0, "changed_file_count": 0.0, "test_file_count": 0.0}

    meta = room.gh.fetch_pr_metadata(room.owner, room.repo, room.pr_number)
    return {
        "pr_open": 1.0 if meta.get("state") == "open" else 0.0,
        "changed_file_count": float(meta.get("changed_files", 0)),
        "test_file_count": float(meta.get("test_files", 0)),
    }


def _sensor_ci_status(room: CodeReviewRoom) -> dict[str, float]:
    """Fetch CI check runs and summarise."""
    if not room.pr_number:
        return {"ci_passed": 0.0, "ci_failed": 0.0, "ci_pending": 0.0}

    statuses = room.gh.fetch_ci_status(room.owner, room.repo, room.pr_number)
    return {
        "ci_passed": float(statuses.get("passed", 0)),
        "ci_failed": float(statuses.get("failed", 0)),
        "ci_pending": float(statuses.get("pending", 0)),
    }


def _sensor_diff_metrics(room: CodeReviewRoom) -> dict[str, float]:
    """Analyze the diff for patterns."""
    if not room.pr_number:
        return {"lines_added": 0.0, "lines_removed": 0.0,
                "security_file_count": 0.0, "secret_like_count": 0.0,
                "ci_true_bypass": 0.0}

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)

    lines_added = sum(1 for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++"))
    lines_removed = sum(1 for l in diff.splitlines() if l.startswith("-") and not l.startswith("---"))

    security_files = sum(1 for r in results if r.check_id == "security_file" and not r.passed)
    secret_like = sum(1 for r in results if r.check_id == "secrets" and not r.passed)
    ci_bypass = sum(1 for r in results if r.check_id == "ci_bypass" and not r.passed)

    return {
        "lines_added": float(lines_added),
        "lines_removed": float(lines_removed),
        "security_file_count": float(security_files),
        "secret_like_count": float(secret_like),
        "ci_true_bypass": float(ci_bypass),
    }


# ─── Actuator functions ──────────────────────────────────────

def _actuator_post_review(room: CodeReviewRoom, value: float) -> None:
    """Post a GitHub review. value maps: 0=COMMENT, 1=COMMENT, 2=REQUEST_CHANGES, 3=APPROVE."""
    event_map = {0: "COMMENT", 1: "COMMENT", 2: "REQUEST_CHANGES", 3: "APPROVE"}
    event = event_map.get(int(value), "COMMENT")

    diff = room.gh.fetch_pr_diff(room.owner, room.repo, room.pr_number)
    results = run_all_checks(diff)
    body = _format_review_body(results, event)

    room.gh.post_review(room.owner, room.repo, room.pr_number, body, event)
    room._last_review = {"event": event, "body": body, "ts": time.time()}


def _actuator_post_comment(room: CodeReviewRoom, value: float) -> None:
    """Post a generic comment."""
    room.gh.post_comment(room.owner, room.repo, room.pr_number,
                         "🤖 PLATO Code Review Room monitoring this PR.")


def _actuator_apply_label(room: CodeReviewRoom, value: float) -> None:
    """Apply a label to the PR."""
    label_map = {1: "needs-tests", 2: "secrets-detected",
                 3: "ci-failing", 4: "security-review"}
    label = label_map.get(int(value), "plato-reviewed")
    room.gh.apply_label(room.owner, room.repo, room.pr_number, label)


# ─── Helpers ─────────────────────────────────────────────────

def _format_review_body(results: list[CheckResult], event: str) -> str:
    """Format check results into a markdown review body."""
    lines = ["## 🔍 PLATO Code Review\n"]
    passed = sum(1 for r in results if r.passed)
    failed = len(results) - passed

    if failed == 0:
        lines.append("All automated checks passed. ✅\n")
    else:
        lines.append(f"**{failed} check(s) need attention:**\n")

    for r in results:
        icon = "✅" if r.passed else "❌"
        lines.append(f"- {icon} **{r.name}**: {r.message}")

    if event == "REQUEST_CHANGES":
        lines.append("\n⚠️ Changes requested due to critical findings.")
    elif event == "APPROVE":
        lines.append("\n✅ Approved — all checks passed.")

    return "\n".join(lines)


# ─── CLI ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PLATO Code Review Room")
    parser.add_argument("--repo", required=True, help="owner/repo (e.g. SuperInstance/plato-core)")
    parser.add_argument("--pr", type=int, default=0, help="PR number to review")
    parser.add_argument("--watch", action="store_true", help="Run as long-lived server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=1234)
    parser.add_argument("--token-env", default="GITHUB_TOKEN", help="Env var for GitHub token")
    parser.add_argument("--once", action="store_true", help="Review once and exit")
    args = parser.parse_args()

    import os
    token = os.environ.get(args.token_env, "")
    owner, repo = args.repo.split("/")

    gh = GitHubClient(token)
    room = CodeReviewRoom(gh, owner, repo, args.pr, args.host, args.port)

    if args.once and args.pr:
        # Single review pass
        diff = gh.fetch_pr_diff(owner, repo, args.pr)
        results = run_all_checks(diff)
        body = _format_review_body(results, "COMMENT")
        print(body)
        return

    if args.watch:
        logging.basicConfig(level=logging.INFO,
                            format="%(asctime)s %(name)s %(levelname)s %(message)s")
        room.serve()
    else:
        print(f"Room {room.room_id} configured. Use --watch to start, --once to review PR #{args.pr}")


if __name__ == "__main__":
    main()
