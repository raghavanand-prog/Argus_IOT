# 05 — Data pipeline: the two tracks, and why only one runs here

The original plan specifies two data tracks (see the full text preserved in the
master-plan discussion): the **live track** (testbed capture, closed-loop
evaluation) and the **dataset track** (CICIoT2023 train/test, IoT-23 cross-dataset
test only — comparability to published baselines and a generalisation check).

## Live track: real, running (see `argus/testbed/`, `docs/04b`)

Metadata-only feature extraction, real captured packets, real flow assembly — fully
implemented and tested. This is the track `run_live_demo_pipeline` and
`eval/ablation.py` actually exercise.

## Dataset track: verified infeasible in this environment, not merely skipped

Two things must both be reachable for this track to exist at all: the actual
dataset release, and enough disk (the plan's own budget: ~15GB for a subsampled
parquet set, ~100GB total project budget).

**Verified, not assumed**: this session's outbound network goes through a proxy
with an explicit allowlist (`pypi.org`, `files.pythonhosted.org`, `registry.npmjs.org`,
a handful of other package registries, and Anthropic's own API hosts — see the
proxy status dump in `decisions.md`). A direct request to
`https://www.unb.ca/cic/datasets/iotdataset-2023.html` (CICIoT2023's host) returns
**403 Forbidden** at the proxy, the same failure mode as every other general
website tried in this session (Docker Hub's CDN, for instance — see `docs/04b`).
There is no code path in this environment that can download the actual dataset;
this isn't a time-budget cut, it's a hard environmental constraint, and it's worth
being explicit about the difference (CLAUDE.md rule 4: no fabricated results — the
honest version of "we didn't do X" matters as much for infrastructure claims as for
measurement claims).

### What's built anyway, and why it's not wasted effort

The parts of the dataset track that are pure logic — not "go fetch a file" — are
implemented and tested against a small synthetic fixture that mirrors the target
schema, so they're correct and ready the moment real data is reachable (a different
environment, or a contributor's own machine):

- `argus/data/subsample.py` — the stratified-sampling protocol from the original
  plan: cap any class at N rows, keep smaller classes whole, temporal (never
  random) train/test split, and a `preserve_base_rate_in_test` step so the test
  set's benign:attack ratio matches training rather than an artificially balanced
  split (which would invalidate the false-positive numbers via the base-rate
  fallacy — see `docs/04-evaluation-protocol.md`).
- `argus/data/parity.py` — the live-vs-dataset feature-parity check: compares the
  live extractor's own computed values against a dataset release's pre-extracted
  columns for the same flows, and reports the disagreement rather than assuming
  parity.
- `tests/test_subsampling.py` — six tests against a synthetic fixture (never a
  real download) verifying: capping behaviour, determinism for a fixed seed,
  that different seeds really can select different rows, that a temporal split
  never lets a test-set timestamp precede a training-set timestamp, that base-rate
  preservation tracks the *training* ratio rather than a hardcoded constant, and
  that the parity report flags a real numeric disagreement while silently skipping
  features that have no counterpart in the other track.

### What's still missing, honestly

- No actual CICIoT2023 or IoT-23 data has been fetched, parsed, or evaluated
  against, anywhere in this repository. Every number `eval/harness.py` produces is
  from the live/synthetic tracks only.
- `research/baselines.md`'s B3 (Random Forest on the published CICIoT2023 feature
  set) and B5 (published results, cited only) are not populated with real numbers
  for this reason — see `STATUS.md`.
- The cross-dataset generalisation test (train on CICIoT2023, test on IoT-23) has
  not been run and cannot be, here. Cross-dataset F1 collapse is a documented
  phenomenon in the IoT-IDS literature generally, but see `docs/00`'s correction
  note: an earlier draft of this document cited a specific "~99%→~39%" figure to a
  misattributed source and that number has been removed rather than left uncorrected.

If this project moves to an environment with normal internet access, the sequence
is: download the derived CSV/feature release (not the raw PCAP — see the original
plan's disk-budget reasoning), run `stratified_subsample`, run the parity check
against a small raw-PCAP sample, then wire the result into `eval/ablation.py` as a
third track alongside live and synthetic.
