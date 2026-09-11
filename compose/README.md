# compose/ — real-Docker testbed (not yet built)

The current build runs on the synthetic simulation engine in `argus/sim/` (see
`STATUS.md` and `decisions.md` for why). This directory is reserved for the original
plan's real-Docker profile — 12 device containers on an isolated bridge, real packet
capture, real `nftables`/`tc` enforcement — as a documented next step, not a hidden gap.

When built, it should provide three `docker compose` profiles per the original design:

- `testbed` — device containers + attack orchestrator only, no pipeline.
- `pipeline` — collection through response, dry-run enforcement.
- `full` — pipeline + API + console.

See `docs/01-architecture.md`'s "Deployment" section for the target shape.
