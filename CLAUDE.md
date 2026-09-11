# CLAUDE.md — instructions for Claude Code working in this repository

Read this before doing anything. Re-read at the start of a new session.

## What this project is

ARGUS is a closed-loop IoT intrusion detection and autonomous response system, built as
a portfolio-grade engineering project and (optionally) a research artifact. See
`MASTER-PLAN.md` for the contribution claims and `BUILD-ORDER.md` for what to build next.

## Who you are working with

The repository owner is an MCA student targeting Cloud Security / Security Engineering
roles, early-career, hands-on-capable, learning by building. Therefore:

- Explain **why** before **how** when introducing a library, pattern, or architectural
  decision.
- Build the smallest working version of a component, verify it, then extend — don't hand
  over a giant diff.
- Define terms the first time they appear in a file.
- Present real trade-offs rather than silently choosing; record the choice in
  `decisions.md`.

## Non-negotiable rules

1. Never claim something works that hasn't been run. Stubs are named `_stub` and listed
   in `STATUS.md` under "not implemented".
2. Enforcement is dry-run by default (`ARGUS_ENFORCE=false`). Live enforcement requires
   an explicit flag, a protected-device allowlist, a rollback timer, and a working kill
   switch. Never remove these to make a demo easier.
3. Never generate attack traffic against anything outside the project's own
   network/simulation boundary.
4. No fabricated results. A number in docs must come from a run whose command is
   recorded, or it's `TBD`.
5. No secrets in the repo. `.env` is gitignored; `.env.example` has placeholders.
6. Determinism: seeds fixed and recorded for every experiment.
7. Metadata-only features — never write payload-inspecting extractors.

## Repository layout

```
argus/
  sim/          synthetic testbed: device behaviour models, attack scenarios, ground truth
  collector/    flow assembly from simulated/captured traffic
  features/     metadata-only feature extraction
  registry/     device identity, enrollment, declared policy, baselines
  behavior/     deviation scoring + drift monitor
  detect/       rule/policy track + ML track (calibration, conformal gate)
  correlate/    correlator + risk engine
  evidence/     evidence bundle builder, hashing, replay
  respond/      safety guard, response ladder, enforcement adapters (dry-run default)
  verify/       post-response verification
  db/           SQLAlchemy models + session
  api/          FastAPI service
console/        React + TypeScript + Tailwind analyst UI
docs/           design docs (00–15, carried from the original planning bundle)
research/       paper outline, experiment plan, baselines
resume/         resume bullets, interview prep
tests/          pytest suite
eval/           evaluation harness
```

## Scope decision recorded up front

The original plan's testbed (12 real Docker containers with real packet capture) is a
multi-week infra project on its own. This build ships a **synthetic simulation engine**
(`argus/sim/`) that generates the same shaped data — flow records, timing, ground-truth
attack windows — deterministically and fast, so the full detect → respond → verify loop
is real and testable without a live Docker network. `compose/` still provides an optional
real-Docker profile for later. This is a scope decision, not a hidden shortcut — see
`decisions.md`.

## Definition of done for any component

- Typed public interface (Python type hints).
- Tests with real assertions on real behaviour.
- Structured logging where relevant.
- Configuration externalised (env / yaml), not hardcoded.
- `STATUS.md` reflects its actual state.

## Testing expectations

- Unit tests for feature extractors against fixtures with hand-verified values.
- An integration test running the full loop against a scripted attack, asserting an
  alert was raised, an evidence bundle written, and (dry-run) an intended action logged.
- An evidence replay test — feed a stored bundle back through the decision path, assert
  the same decision. This is contribution C2 and is not optional.

## Project memory protocol

Four files, kept current:

- `README.md` — what it is, how to run it, current capability.
- `STATUS.md` — what works, what's stubbed, what's broken, what's next.
- `progress.md` — dated append-only session log.
- `decisions.md` — dated append-only architectural decisions with reasoning.

## Style

Python: type hints, standard library first, dependencies justified. Prefer boring,
readable code — this has to be explained in an interview. Comments explain *why*, not
*what*. Commit messages: imperative mood.

## What to do when unsure

Write the assumption at the top of the file, prefixed `ASSUMPTION:`, and list it in
`STATUS.md`.
