# 06 — Vercel deployment

## Why a separate production entrypoint exists

The local/dev system (`argus/api/main.py`) assumes three things a serverless
platform does not give you:

1. **Root / `CAP_NET_ADMIN`.** `argus/testbed/` (the real Linux
   network-namespace testbed — veth pairs, a bridge, `nftables` enforcement)
   needs Linux networking capabilities no serverless sandbox grants. This is a
   permissions wall, not a size or time problem, and there is no workaround
   for it inside a Vercel function.
2. **A persistent filesystem across requests.** `argus/db/models.py` writes to
   a SQLite file on disk. Serverless function instances are not guaranteed to
   survive between invocations, so a live "seed once, then browse" flow the
   way the local API works does not hold up here.
3. **A function size/time budget.** `argus/detect/ml.py`'s real dependencies
   (numpy, scikit-learn, shap, scipy) push close to Vercel's packaged-function
   size limit, and re-fitting a detector on every cold start would be wasteful
   even where it technically fits.

Rather than silently degrade the local API until it happened to run in this
environment, `api/index.py` is a **deliberately smaller, separate** FastAPI
app that is honest about what it can and cannot do in production. It is not
a duplicate of `argus/api/main.py` by accident — it is the subset of that
API that can run truthfully in a serverless sandbox.

## What is genuinely real in production, and what is not

| Capability | Local dev API | Production (Vercel) |
|---|---|---|
| Device / incident / evidence data | Live SQLite, from a real pipeline run you trigger | A static snapshot (`api/seed_snapshot.json`) from one real pipeline run, served from in-memory state |
| Evidence replay (`argus.evidence.replay.replay()`) | Real | **Real, unmodified** — pure stdlib, no ML dependency |
| Kill switch (`argus.respond.guard.KillSwitch`) | Real, persists for the life of the process | **Real, unmodified**, but its state lives in one function instance's memory and is not guaranteed to survive a cold start |
| `/control/seed-demo` | Re-runs the actual pipeline | Resets the in-memory store back to the static snapshot; does **not** re-run the pipeline (documented in the endpoint's own response) |
| Live network-namespace testbed | Available (`make testbed-demo`, Linux only) | Not available — no CAP_NET_ADMIN in the serverless sandbox |
| ML detector fitting (`argus/detect/ml.py`) | Runs at pipeline time | Not invoked — the snapshot already contains its output from the one real run that produced it |

Nothing in the table above is fabricated data dressed up as live computation.
The snapshot is the literal output of `scripts/export_seed_snapshot.py`
running `argus.pipeline.run_demo_pipeline` once, for real — see that script's
own docstring. Replay and the kill switch are the actual production code
paths, not mocks.

## Routing: why `api/index.py`'s routes carry an explicit `/api` prefix

Locally, `console/vite.config.ts` proxies `/api/*` to the dev server on
`:8000` and **strips** the `/api` prefix before forwarding, so
`argus/api/main.py` registers routes at their bare path (`/health`,
`/devices`, ...).

Vercel does not strip anything. `vercel.json`'s rewrite

```json
{ "source": "/api/(.*)", "destination": "/api/index" }
```

sends every `/api/*` request to the single `api/index.py` function, but the
function still sees the **original** request path (`/api/devices`, not
`/devices`). So `api/index.py` mounts an `APIRouter(prefix="/api")` and
registers every route under that prefix, then does
`app.include_router(api)`. This is a real platform difference, not a stylistic
choice, and it is why `api/index.py` cannot simply reuse
`argus/api/main.py`'s route decorators unmodified.

## Dependency footprint

`api/requirements.txt` deliberately installs **only `fastapi`** — not the
project's full `pyproject.toml` (which pulls in numpy/scikit-learn/shap/scipy
for the real ML pipeline). The only `argus` modules `api/index.py` imports are
`argus.evidence.bundle`, `argus.evidence.replay`, and `argus.respond.guard` —
all pure standard-library code with no ML dependency. This was verified, not
assumed: `api/index.py` was run end-to-end (including a real evidence replay)
inside an isolated virtualenv containing nothing but `api/requirements.txt`
before it was ever deployed.

## Build and routing configuration (`vercel.json`)

```json
{
  "buildCommand": "cd console && npm install && npm run build",
  "outputDirectory": "console/dist",
  "rewrites": [
    { "source": "/api/(.*)", "destination": "/api/index" }
  ]
}
```

Vercel auto-detects `api/index.py` (a Python file under `/api` with a
`requirements.txt` alongside it) as a Python serverless function; no
additional `functions` configuration was needed.

## Environment variables required in the Vercel project

| Variable | Required | Purpose |
|---|---|---|
| `ARGUS_ADMIN_TOKEN` | No, but admin actions are disabled without it | Bearer token guarding `/control/kill-switch`, `/control/seed-demo`, and `/evidence/*/replay`. If unset, those three endpoints return `503` with a message naming the missing variable — the read-only endpoints (`/health`, `/devices`, `/incidents`, `/actions`, `/evidence/{id}`) are unaffected. `/health` and `/control/status` both report `admin_token_configured` so this is visible without guessing. |
| `ARGUS_ENFORCE` | No (defaults to `"false"`) | Surfaced read-only in `/health` and `/control/status`; production never calls a real enforcement adapter, so this only reflects the flag's value, it does not gate any live enforcement. |

**Correction (2026-09-18):** an earlier version of `api/index.py` raised `RuntimeError`
at *module import time* if `ARGUS_ADMIN_TOKEN` was unset, which crashed every route —
including the four that need no auth at all — with `FUNCTION_INVOCATION_FAILED`. Caught
after a real deploy exhibited exactly that failure on `/api/health`. Fixed by moving the
check into `require_auth()` (which only the three admin-guarded endpoints depend on), so
a missing *optional* admin credential can no longer take down the whole deployment. See
`decisions.md`'s 2026-09-18 entry.

No secret is committed to the repository. `.env.example` documents the same
variables with placeholder values for local dev.

## What updating the demo data means

`api/seed_snapshot.json` is checked in because Vercel cannot run the real
pipeline live on every request. To refresh it with a new real run:

```bash
python scripts/export_seed_snapshot.py
git add api/seed_snapshot.json
git commit -m "Refresh production demo snapshot"
git push
```

Every value in that file traces back to that one script's run — see its
docstring.

## Known limitations of the production deployment

- The live network-namespace testbed, real `nftables` enforcement, and the
  full ML detector (fitting, calibration, SHAP) do not run in production —
  they require Linux capabilities and a dependency footprint a serverless
  sandbox does not provide. They run locally (`make testbed-demo`,
  `pytest`, `python -m argus.pipeline`).
- `/control/seed-demo` resets to the static snapshot; it does not simulate a
  new pipeline run with different random seeds.
- The kill switch's in-memory state is not guaranteed to survive a cold
  start between requests on Vercel's serverless runtime. This is stated in
  the `/control/status` response's `mode` field and here, not hidden.
