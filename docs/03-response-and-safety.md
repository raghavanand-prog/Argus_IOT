# 03 — Response engine, safety guard, verification

The part most of the literature skips. Safety is built before response, as a separate
component with veto power, so no response path can bypass it.

## Guard checks, evaluated in order — any failure vetoes

1. Kill switch (file + env var + API — all three).
2. Dry-run default (`ARGUS_ENFORCE=false`) — action computed, logged, nothing touches
   the network.
3. Protected-device list — never overridden by a risk score.
4. Conformal gate — singleton set required to escalate past `alert`.
5. Drift gate — a device in `DRIFTING` state caps action at `alert`.
6. Risk threshold per action tier.
7. Irreversibility check — anything not auto-revertible requires approval.
8. Rate limit on ARGUS's own actions (per device/hour and network-wide).
9. Rollback timer — every action carries a TTL, auto-reverted unless renewed. The
   network's default state is unmodified; enforcement is a temporary, actively
   maintained deviation.

## Action ladder

| Tier | Action | Reversible | Gate |
|---|---|---|---|
| 0 | observe | n/a | none |
| 1 | alert | n/a | risk ≥ 0.3 |
| 2 | rate_limit | yes | risk ≥ 0.5, singleton set, not drifting |
| 3 | block_destination | yes | risk ≥ 0.6, singleton set, not drifting |
| 4 | isolate | yes | risk ≥ 0.8, singleton set, not drifting, not protected |
| 5 | require_approval | n/a | irreversible, or high risk on a protected device |

Prefer the narrowest effective action — `block_destination` stops C2 while leaving the
device functional; isolation is the last resort before asking a human.

## Enforcement adapters

One interface (`apply`, `revert`, `list_active`) so the ablation can swap in a no-op.
`DryRunAdapter` is the default and logs intent without touching anything.
`NoOpAdapter` represents the detection-only ("L0") baseline the field actually builds.

## Post-response verification

At T+30s/2m/5m, answers: did the threat stop, did the device recover, did something
legitimate break (the false-isolation detector). Outcomes feed back:
`collateral_damage` raises the action threshold for that device class;
`not_contained` escalates if gates still pass; `contained` closes the loop.

## Metrics this produces

Time-to-detect, time-to-contain (censored when never contained — report the censoring
rate, never a mean over completed cases only), false-isolation rate per device-day,
benign-function disruption rate, containment efficacy. See `argus/verify/` and
`eval/harness.py`.
