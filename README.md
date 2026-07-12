# PLATO Code Review Room

> Automated code review as a **PLATO engine block** — the first real room in the SuperInstance ecosystem.

[![Tests](https://github.com/SuperInstance/plato-room-code-review/actions/workflows/ci.yml/badge.svg)](https://github.com/SuperInstance/plato-room-code-review/actions/workflows/ci.yml)

## What is this?

A **PLATO Room** that orchestrates automated code review on GitHub PRs. It follows the PLATO architecture:

| Concept | In this room | |
|---------|-------------|---|
| **Sensors** | PR diff, CI status, diff metrics (secrets, tests, security files) | Pull data from GitHub on each tick |
| **Actuators** | Post review, post comment, apply label | Push decisions back to GitHub |
| **Tick loop** | Configurable rate (default 0.1 Hz = every 10s) | Polls for PR state changes |
| **Alarms** | `no_tests`, `secrets_detected`, `ci_failing`, `security_touched` | Fire on policy conditions |
| **History** | Ring buffer of last 1000 ticks | Full audit trail via `history N` command |
| **Policies** | FLUX bytecode rules in `policies/` | Declarative, versioned, reviewable |

The room exposes the standard **PLATO wire protocol** — any PLATO client can connect, read sensors, check alarms, and trigger actuators.

## Quick Start

### Standalone (single review)

```bash
export GITHUB_TOKEN=ghp_your_token_here
python -m plato_room_code_review.room --repo SuperInstance/plato-core --pr 42 --once
```

Prints a formatted review and exits.

### Long-lived server

```bash
export GITHUB_TOKEN=ghp_your_token_here
python -m plato_room_code_review.room --repo SuperInstance/plato-core --watch --port 1234
```

Then connect with any PLATO client:

```python
from plato_core.protocol import PlatoClient

with PlatoClient.connect("localhost", 1234) as client:
    # Auto-receives welcome with sensor list
    welcome = client.recv_response()
    print(f"Connected to {welcome.room_id}")
    print(f"Sensors: {welcome.sensors}")

    # Read current PR state
    client.send("tick")
    tick = client.recv_response()
    print(f"PR state: {tick.data}")

    # Check alarms
    client.send("alarm list")
    alarms = client.recv_response()
    for a in alarms.alarms:
        print(f"  {a.id}: {a.state}")

    # Post a review
    client.send("actuator post_review 1")  # COMMENT review
```

### GitHub Action

```yaml
# .github/workflows/plato-review.yml
name: PLATO Code Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install plato-core plato-room-code-review
      - run: |
          python -m plato_room_code_review.room \
            --repo ${{ github.repository }} \
            --pr ${{ github.event.pull_request.number }} \
            --once
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Review Checks

All checks are **heuristic** (no LLM, no AST parsing) — fast, deterministic, and auditable.

| Check | What it catches | Severity |
|-------|----------------|----------|
| `missing_tests` | PR adds code but no test files | warning |
| `ci_bypass` | `\|\| true`, `continue-on-error`, `set +e` in CI | error |
| `secrets` | AWS keys, API keys, private keys, JWTs, Slack tokens, DB URLs | error |
| `type_hints` | Python functions without type annotations | info |
| `sql_injection` | String concatenation in SQL execute() calls | error |
| `security_file` | Changes to Dockerfiles, CI configs, auth modules | warning |
| `large_diff` | > 500 lines added in a single PR | info |

### Adding a check

```python
# reviewer.py
@check
def check_no_debug_print(diff: str) -> CheckResult:
    """Warn about debug print statements."""
    for line in diff.splitlines():
        if line.startswith("+") and "print(" in line:
            return CheckResult(
                check_id="debug_print",
                name="Debug Print",
                passed=False,
                message="Remove print() before merging",
                severity="warning",
            )
    return CheckResult(
        check_id="debug_print",
        name="Debug Print",
        passed=True,
        message="No debug prints detected.",
    )
```

That's it — the `@check` decorator registers it automatically.

## FLUX Policies

Policies live in `policies/*.flx`. They're declarative rules that the PLATO policy engine evaluates.

```flux
POLICY no_secrets {
    SENSE  secret_like_count
    GUARD   secret_like_count > 0
    ALARM   severity=critical
    ACTUATE post_review value=2
    EMIT    "Potential hardcoded secrets detected"
}
```

### Policy files

| File | Triggers when |
|------|--------------|
| `must_have_tests.flx` | PR adds code but has zero test files |
| `no_secrets.flx` | Diff contains secret-like patterns (AWS keys, API keys, etc.) |
| `ci_must_pass.flx` | Any CI check run has failed |
| `security_files_watch.flx` | PR touches Dockerfiles, CI configs, auth modules |

## Architecture

```
                    PLATO Wire Protocol
                    (TCP, JSON lines)
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     tick command     alarm list      actuator cmd
          │                │                │
          ▼                ▼                ▼
    ┌─────────────────────────────────────────────┐
    │            Code Review Room                 │
    │                                             │
    │  Sensors              Actuators             │
    │  ├─ pr_state          ├─ post_review        │
    │  ├─ ci_status         ├─ post_comment       │
    │  └─ diff_metrics      └─ apply_label        │
    │                                             │
    │  Alarms                                    │
    │  ├─ no_tests (test_file_count < 1)         │
    │  ├─ secrets_detected (secret_like > 0)     │
    │  ├─ ci_failing (ci_failed > 0)             │
    │  └─ security_touched (security_files > 0)  │
    │                                             │
    │  History (1000-tick ring buffer)            │
    └─────────────────────────────────────────────┘
                           │
                    GitHub API
                           │
          ┌────────────────┼────────────────┐
          │                │                │
     Fetch diff      Fetch CI status    Post review
     Fetch metadata  Fetch check runs   Apply label
```

## Testing

```bash
# Install test dependencies
pip install -e ".[test]"

# Run tests
pytest tests/ -v

# Run specific test
pytest tests/test_reviewer.py::TestHardcodedSecrets -v
```

All tests use simulated data — no GitHub API calls needed.

## Extending

### Add a sensor

```python
# In CodeReviewRoom.setup()
self.register_sensor("coverage", _sensor_coverage)

def _sensor_coverage(room):
    # Read coverage report, expose as sensor value
    return {"coverage_pct": 85.0}
```

### Add an alarm

```python
self.register_alarm(
    "low_coverage",
    sensor="coverage_pct",
    operator="<",
    threshold=80.0,
    cooldown_sec=600,
)
```

### Connect multiple rooms

Rooms discover each other through the PLATO mesh registry. A `notification-room` could subscribe to this room's alarms and send Slack messages:

```python
# In another room's setup()
self.register_sensor("cr_alarms", lambda r: {
    alarm_data: plato_client.fetch("code-review-room", "alarm list")
})
```

## License

MIT — see [LICENSE](LICENSE).

## Part of

[SuperInstance](https://github.com/SuperInstance) — the PLATO ecosystem.
