"""Safety guard: built before the response engine, holds veto power over every
decision (docs/03). Checks run in order; the first failure vetoes. This module has no
code path to enforcement that bypasses it -- ``respond/ladder.py`` always calls
``evaluate()`` first.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

PROTECTED_DEVICE_TYPES = {"hub", "gateway", "user-laptop"}
ROLLBACK_SECONDS_DEFAULT = 900
MAX_ACTIONS_PER_DEVICE_PER_HOUR = 5
MAX_ACTIONS_NETWORK_WIDE_PER_HOUR = 30


@dataclass
class KillSwitch:
    """Three independent ways to trip it, per docs/03: "the one you need will be the
    one that is unreachable." File, env var, and (via the API layer) a direct call."""

    _engaged: bool = False
    _flag_path: str = "/tmp/argus_kill_switch.flag"

    def engage(self) -> None:
        self._engaged = True
        with open(self._flag_path, "w") as f:
            f.write("engaged")

    def disengage(self) -> None:
        self._engaged = False
        if os.path.exists(self._flag_path):
            os.remove(self._flag_path)

    def is_engaged(self) -> bool:
        return self._engaged or os.getenv("ARGUS_KILL_SWITCH") == "1" or os.path.exists(self._flag_path)


@dataclass
class ActionRateLimiter:
    per_device: dict[str, list[float]] = field(default_factory=dict)
    network_wide: list[float] = field(default_factory=list)

    def allow(self, device_id: str, now: float | None = None) -> bool:
        now = now if now is not None else time.time()
        cutoff = now - 3600
        self.network_wide = [t for t in self.network_wide if t > cutoff]
        dev_hist = [t for t in self.per_device.get(device_id, []) if t > cutoff]
        self.per_device[device_id] = dev_hist
        if len(dev_hist) >= MAX_ACTIONS_PER_DEVICE_PER_HOUR:
            return False
        if len(self.network_wide) >= MAX_ACTIONS_NETWORK_WIDE_PER_HOUR:
            return False
        return True

    def record(self, device_id: str, now: float | None = None) -> None:
        now = now if now is not None else time.time()
        self.per_device.setdefault(device_id, []).append(now)
        self.network_wide.append(now)


@dataclass
class GuardVerdict:
    allow: bool
    gates_passed: list[str]
    gates_failed: list[str]


def evaluate(
    *, device_type: str, tier: int, risk_score: float, conformal_set: list[str] | None,
    is_drifting: bool, kill_switch: KillSwitch, rate_limiter: ActionRateLimiter, device_id: str,
    enforce_enabled: bool, now: float | None = None,
) -> GuardVerdict:
    passed: list[str] = []
    failed: list[str] = []

    def check(name: str, ok: bool) -> None:
        (passed if ok else failed).append(name)

    check("kill_switch_disengaged", not kill_switch.is_engaged())
    check("dry_run_or_enforce_flag_set", True)  # always recorded; enforce_enabled decides dry_run downstream, not a veto
    check("protected_device_list", device_type not in PROTECTED_DEVICE_TYPES or tier < 4)
    singleton = bool(conformal_set) and len(conformal_set) == 1
    check("conformal_singleton_for_escalation", tier < 2 or singleton)
    check("drift_gate", not is_drifting or tier <= 1)
    thresholds = {0: 0.0, 1: 0.3, 2: 0.5, 3: 0.6, 4: 0.8, 5: 0.0}
    check("risk_threshold", risk_score >= thresholds.get(tier, 1.0))
    check("action_rate_limit", rate_limiter.allow(device_id, now))

    return GuardVerdict(allow=not failed, gates_passed=passed, gates_failed=failed)
