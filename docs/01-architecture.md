# 01 — Architecture

## Component diagram

```
Sim/Testbed (device behaviour + attack orchestrator + ground-truth ledger)
   -> Collection (flow assembly)
   -> Feature Extraction (metadata-only)
   -> Device Registry + Enrollment + Baseline  <-- guarded against poisoning
   -> Behaviour Engine <-> Drift Monitor        <-- drift suppresses escalation
   -> Rule/Policy Detection + Calibrated ML Detection (+ conformal gate)
   -> Correlator -> incidents
   -> Risk Engine
   -> Evidence & Explanation Engine (hash-chained bundle)
   -> Safety Guard (veto power) -> Response Decision
   -> Enforcement (dry-run by default)
   -> Post-Response Verification
   -> Append-only Audit Ledger -> feedback into Risk + Behaviour
```

## Seven deliberate changes from a naive linear pipeline

1. **Enrollment + baseline bootstrap** exists explicitly, bounded and policy-guarded — an
   attacker who compromises a device before its baseline is set gets the attack learned
   as "normal" otherwise.
2. **Drift monitor is separate** from the behaviour engine — conflating benign drift
   (firmware update) with compromise is the classic failure of baseline-deviation
   detection. Drift *suppresses* escalation; it never *triggers* it.
3. **Explanation is merged into evidence**, not a separate stage — an explanation that
   can't be verified against the data that produced it isn't evidence.
4. **A safety guard sits before response**, with veto power, as its own component —
   safety can't be an emergent property of the decision engine.
5. **The loop closes** — verification feeds back into risk and behaviour, which is the
   difference between detection-only and closed-loop autonomy.
6. **A single time source** — evidence timelines are worthless if components disagree
   about time.
7. **Metadata-only feature extraction is a stated commitment**, not an open question.

## Data flow contracts

Each stage consumes only the typed schema the previous stage produced, never internal
state — this is what makes the ablation runner possible: a stage becomes a pass-through
without touching its neighbours. See `argus/db/models.py` and the Pydantic schemas in
each module for the concrete contracts.

## Deployment

Two profiles: `dev` (the synthetic sim engine + SQLite + API + console, no Docker
required) and `compose/` (optional real-Docker profile for the original 12-container
testbed, added later per `BUILD-ORDER.md`'s "what to cut" ordering in reverse).
