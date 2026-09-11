# STATUS.md

Last updated: 2026-09-11 (initial build session).

## What works right now (verified by running it, not just reading the code)

- `pytest tests/` — 16/16 passing: feature extraction fixtures, enrollment/refusal,
  detection→correlation→risk integration, all 5 safety-guard mechanisms exercised
  directly, evidence hash-chain tamper detection, and decision replay.
- `make seed` — runs the full loop against SQLite and persists devices, incidents,
  risk assessments, evidence bundles, actions, and verifications. Verified: produces
  14 incidents / 14 evidence bundles / 14 actions on the current two scenarios.
- Evidence replay measured at **100% reproducibility** on the seeded run (see
  `decisions.md` for the wall-clock-leakage bug this caught and fixed).
- FastAPI backend (`argus/api/main.py`) — all endpoints hit and verified with `curl`:
  `/health`, `/devices`, `/incidents`, `/evidence/{id}`, `/evidence/{id}/replay`,
  `/control/status`, `/control/kill-switch`, `/control/seed-demo`, `/actions`.
- React console — built cleanly (`npm run build`), type-checks clean (`tsc --noEmit`),
  and was verified live end-to-end with a browser automation pass: Fleet renders real
  device state, Incidents renders real risk/decision/evidence data and the **live
  replay button actually works** ("✓ Reproduced identically" against the real API),
  Control's kill switch and demo-seed buttons call the real authenticated endpoints.
- `eval/harness.py` — runs a 3-configuration condensed ablation (full system, no
  correlator, no conformal gate) and writes a timestamped results file with a manifest.

## What's stubbed or simplified (named honestly, not hidden)

- **Testbed realism.** The sim engine (`argus/sim/`) is a deterministic statistical
  generator, not 12 real Docker containers with real packet capture / nftables / tc.
  This is the single biggest scope reduction from the original plan — see the "Scope
  decision" in `CLAUDE.md` and `decisions.md`. A `compose/` real-Docker profile is not
  yet built.
- **Attack scenarios.** Only `mirai` and `low_and_slow` are implemented, per
  `BUILD-ORDER.md`'s cut-list priority (these two are explicitly "never cut" — the easy
  case and the hard case). MQTT abuse, ARP spoofing, DNS tunnelling, identity spoofing,
  and OTA spoofing are documented in `docs/00` but not implemented.
- **Rule track.** `policy_detections` and `signature_detections` are real, deterministic
  logic, but `signature_detections` is a threshold stand-in for a real Suricata/ET-Open
  signature engine — there is no actual Suricata integration.
- **Enforcement adapters.** Only `DryRunAdapter` and `NoOpAdapter` exist. `nftables`/
  `tc` adapters that would touch a real network are not built — this repo has never
  run with `ARGUS_ENFORCE=true` against anything real, by design (see CLAUDE.md rule 2).
- **Blast radius.** `BlastRadiusGraph.score()` weights every neighbour equally (0.15
  each) rather than by the neighbour's own device-type criticality, because intra-LAN
  neighbours in the sim are mostly represented as raw IPs without a registry lookup
  back to a device type. Noted in the code; fixing it needs the registry to track
  IP→device-type identity for simulated neighbours too.
- **Evaluation harness statistical power.** `eval/harness.py` runs one seed per
  configuration and reports raw precision/recall/F1 against a trivial "every detection
  is a true positive" count (there's no benign holdout counted as true negatives yet,
  so F1 is uninformative as an absolute number — only the *contrast* between
  configurations is currently meaningful). The original plan's 9-configuration ×
  5-seed ablation with Mann-Whitney U / Holm-Bonferroni is not implemented.
- **Console.** Three screens (Fleet, Incidents+Evidence combined, Control) rather than
  the original plan's four separate screens — Incident detail and Evidence were merged
  into one drawer since they share almost all their data in this build. No dark/light
  theme toggle yet (dark only).
- **Datastore.** SQLite by default (Postgres-compatible via `ARGUS_DATABASE_URL`, same
  SQLAlchemy models) rather than Postgres-only as the original plan specifies — a
  pragmatic default for zero-setup local dev.

## Not implemented at all

- Real packet capture / Zeek / Suricata integration.
- The public CICIoT2023 dataset track and the IoT-23 cross-dataset test (`docs/05`).
- The React console's accessibility pass (keyboard nav audit, AA contrast check) —
  likely fine given the chosen palette but not formally verified.
- SHAP-based feature attribution (Layer 2 explanation) — explanations are currently
  rule-text and calibrated-probability strings only (Layer 1 + a plain-text Layer 3).
- The optional human evaluation of explanations (`research/`).

## Immediate next steps, in priority order

1. Add 2-3 more attack scenarios (MQTT abuse next — it's "Easy-Moderate" per docs/02).
2. Wire the risk engine's blast-radius calculation to the registry so intra-LAN
   neighbours are weighted by real device criticality.
3. Expand `eval/harness.py` to multiple seeds and a proper benign-holdout so F1 is a
   real number, not just a same-scale contrast between ablation configs.
4. A real `nftables`-backed enforcement adapter behind a Linux-only, opt-in flag,
   tested against a throwaway network namespace, never enabled by default.
