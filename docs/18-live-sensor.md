# 18 — Live network sensor

A third data track, alongside the synthetic simulation testbed (docs/04b) and the
CICIoT2023 benchmark (docs/17): **real devices on the project owner's own LAN**,
discovered and (optionally) monitored by a small local agent
(`sensor/agent.py`) that reports to a deployed ARGUS API. This document covers
why it exists, exactly which existing components it reuses versus what had to be
built new, the real correctness bug found and fixed while building it, and how to
run it.

**What this is, stated plainly**: real passive network observation from the
machine the sensor runs on. It is **not** a substitute for the CICIoT2023
benchmark (no labelled ground truth exists for live LAN traffic — see docs/17)
and it is **not** the synthetic testbed (no fabricated devices or scripted
attacks — see docs/04b). The console makes this a hard mode split: **Benchmark
Evaluation** vs **Live Network**, never blended.

## 1. Why a separate local sensor

The deployed console (`https://argus-iot-live.vercel.app`) runs as a Vercel
serverless function. It has no route to the project owner's private LAN — Vercel's
network is not the owner's home/office network, and nothing about the deployment
changes that. A local sensor has to run *on* that LAN (a Mac, a Linux box, a
Raspberry Pi) and push what it observes to the deployed API over HTTPS. This is
the architecture the task specified:

```
Real LAN → ARGUS Local Sensor/Agent → device discovery + flow metadata →
ARGUS API → feature extraction → ARGUS IDS → Detection → Incident + Evidence →
Control/Response (dry-run)
```

## 2. Component inventory: reused vs. new

Inspected before writing anything, per the explicit process instruction.

**Reused unmodified:**

| Component | Role in the live-sensor path |
|---|---|
| `argus.testbed.capture.CaptureSession` | Real scapy `AsyncSniffer` wrapper — captures real packets on real interfaces |
| `argus.collector.windows.window_flows` | Buckets flows into fixed windows |
| `argus.features.extract.extract_device_window` | The same 14-feature metadata-only extractor every track uses |
| `argus.detect.rules.signature_detections` | Rule-based detection — device-type-agnostic, works on `device_type="unknown"` |
| `argus.correlate.correlator.correlate` | Groups detections into incidents |
| `argus.risk.engine.assess_risk` | Risk scoring |
| `argus.respond.ladder.decide_and_respond` / `DryRunAdapter` | Response ladder — dry-run only for live devices, always |
| `argus.respond.guard.KillSwitch` / `ActionRateLimiter` | Safety gates, shared with every other track |
| `argus.evidence.bundle.EvidenceLedger` | Hash-chained evidence bundles |
| `argus.registry.enrollment.Baseline` (the dataclass) | Reused as the baseline output shape |

**Required adaptation, and why:**

| Component | Why it couldn't be reused as-is | What was built instead |
|---|---|---|
| Device list | Testbed/synthetic tracks have a pre-provisioned device roster | `sensor/discovery.py`: passive ARP/neighbour-table reads only, `device_type` always `"unknown"` |
| `argus.registry.enrollment.enroll()` | Its policy-violation guard does `FLEET[device_type]` — a hard `KeyError` for any type outside the ten synthetic profiles | `sensor/baseline.py::build_live_baseline()`: same median/MAD baseline math, guard step omitted (there is no declared policy for "unknown" to check against — see that module's docstring) |
| `argus.testbed.pcap_to_flows.packets_to_flows` | Keyed off a testbed's pre-known `DeviceLink` map | `sensor/flows.py::packets_to_live_flows()`: keyed off `discovery.py`'s actually-observed `identifier` map instead |
| `argus.detect.ml.CalibratedDetector` | Needs labelled `calib_vectors`/`calib_labels` (some windows known-benign, some known-attack) to fit its isotonic calibrator and conformal gate — no such labels exist for real LAN traffic, and inventing them would violate the project's no-fabrication rule | `sensor/live_detect.py::LiveAnomalyDetector`: unsupervised `IsolationForest`, scored by percentile rank against a device's own historical baseline — see §4 |
| Enforcement | The nftables adapter (docs/04b) enforces inside the network-namespace testbed only | No enforcement adapter exists for real discovered devices at all. `decide_and_respond` is always called with `enforce_enabled=False` for `scenario="live_network"` — hardcoded, not a runtime flag |
| Post-response verification | `argus.verify` checks a simulated/testbed environment's actual state | Skipped entirely for live incidents — there is no environment-recovery check implemented for a real device, and pretending to verify one would be fabricating a result |

## 3. Safety posture

- **Discovery only, by default.** Running `python -m sensor.agent` at all *is* the
  explicit "start monitoring" action — there is no separate always-on background
  mode. Discovery mode reads the OS's own already-populated ARP/neighbour cache
  (`/proc/net/arp` on Linux, `arp -a` fallback). No ARP requests are sent, no port
  scanning, no OS fingerprinting.
- **Real packet capture is a second, explicit opt-in**: `--enable-capture` plus
  `--interfaces`. This is the more invasive tier and never runs by itself.
- **`--target-host <ip>` scopes capture to one device via a real BPF filter**,
  enforced by the kernel before a packet ever reaches this process — not a
  post-hoc Python filter. Without it, `--enable-capture` captures *all* traffic
  on the given interface(s), which on a network the operator doesn't administer
  (a shared/college/office LAN, for instance) means capturing other people's
  traffic shapes without their consent — outside what passive discovery alone
  is designed for, and the kind of thing that needs the network owner's
  authorization first. `agent.py` prints an explicit warning at startup if
  `--enable-capture` is used without `--target-host`. Verified end-to-end with
  real generated traffic to two different destinations (one the target host,
  one not): the filter genuinely excludes the non-target host's packets at
  capture time, not just at display time (see progress.md's matching entry).
- **No enforcement against real devices, ever.** `enforce_enabled=False` is
  hardcoded in both the local (`argus/pipeline.py::_process_live_detection`) and
  production (`api/index.py::_process_live_detection`) ingestion paths — not a
  flag the operator can override for this track. The existing kill switch still
  governs everything else; it is shared across all tracks, not re-implemented.
- **Never sends traffic to a discovered device.** The sensor only listens.

## 4. The live-network detector, and what it's honest about

`LiveAnomalyDetector` (`sensor/live_detect.py`) is a raw `IsolationForest` fit on
one device's own observed feature-vector windows, scored by percentile rank
against that same fitted baseline's own anomaly-score distribution. Its output is
"how unusual is this window relative to this device's own history" — never a
calibrated probability of attack, and every `Detection` it emits carries
`conformal_set=None` so nothing downstream can mistake it for the benchmark
track's calibrated, conformal-backed output.

### The `MIN_BASELINE_WINDOWS` finding (measured, not guessed)

An earlier version of this floor was **4** — the minimum sample count
`IsolationForest.fit()` accepts before raising. Ad hoc testing against real
captured traffic in this sandbox (real UDP flows to a real ARP-discovered
neighbour, real `CaptureSession` runs) showed that floor produces a **degenerate**
model: every window's score, including the training data's own windows, came back
bit-for-bit identical (`raw=0.4730` for all of them), regardless of how different
a later window actually was. A model that can't be told apart even from itself is
useless.

Re-testing at n=10/20/40 (same real captured baseline windows, replicated with
small jitter to isolate the sample-count question from the traffic-shape
question) showed scores start meaningfully varying by n≈10 and stay usefully
spread by n=20. Separately, root-causing *why* the very first real end-to-end
capture test still produced 0 detections even after raising the floor to 20
surfaced a second real finding: `argus.detect.ml.FEATURE_KEYS` (the 14 tracked
features, reused unmodified from the benchmark track) does not include
`bytes_in_mean` — and the initial test traffic (identical repeated single-port
pings) varied *only* in that untracked field, so all 14 tracked features were
literally constant across the whole baseline. Zero-variance training data is
degenerate for any detector, not a bug in this one. Regenerating baseline traffic
with natural variation in destination ports and timing (still light, still
realistic) and re-running the full capture → flow → feature → baseline → detector
chain produced real, repeated detections once the traffic diverged sharply
(`window 23: n_flows=99 raw=0.6182 pct=100.0 detections=1`, four consecutive
windows, zero false positives across the 20-window baseline and two-window
ramp-up). See `progress.md` for the dated entry with full session transcript
excerpts.

`MIN_BASELINE_WINDOWS = 20` is a practical minimum for a *non-degenerate* model,
not a guarantee of sensitivity to every kind of attack — it is recorded as a
threshold subject to revision once real longitudinal deployment data exists, not
a tuned final answer.

Practical consequence: with the default `--window-seconds 60`, a device needs
about 20 minutes of continuous observation before its first anomaly score is even
possible. This is by design — an unsupervised model fit on too little or too
uniform data is worse than no model, since it will unconditionally NOT alert
(the fail-open direction actually observed above), not a race condition to
engineer around.

## 5. Persistence: what "ephemeral" means here

The local dev API (`argus/api/main.py`) persists everything through the same
SQLAlchemy models the rest of ARGUS uses (`LiveDeviceRow`, `SensorHeartbeatRow`,
plus the shared `IncidentRow`/`EvidenceBundleRow`/`RiskAssessmentRow`/`ActionRow`/
`AuditLogRow`).

The production API (`api/index.py`) has no persistent filesystem across
invocations and no SQLAlchemy/numpy dependency (see that module's own docstring
for the full reasoning). Its `/live/*` endpoints keep live-sensor state in the
warm function instance's own memory — `_LIVE_DEVICES`, `_LIVE_SENSORS`,
`_LIVE_INCIDENTS`, `_LIVE_EVIDENCE` — deliberately separate from `_STATE` (the
CICIoT2023/synthetic snapshot), so a `/control/seed-demo` reset of that snapshot
can never wipe real sensor data, and vice versa. This is the same honestly
documented limitation already in place for the kill switch: state is real while
that instance is warm, and is not guaranteed to survive a cold start. The
correlate → risk → respond → evidence chain itself genuinely runs live in that
function on every `/live/ingest` call — unlike the CICIoT2023 track, this one
isn't serving a precomputed snapshot, because none of its dependencies
(`argus.correlate`, `argus.risk`, `argus.respond`, `argus.evidence`) need numpy or
scikit-learn.

## 6. Running it

```bash
# from the repo root, with the project's Python environment active
python -m sensor.agent --api-url http://localhost:8000 --token $ARGUS_ADMIN_TOKEN

# against the deployed production API
python -m sensor.agent --api-url https://argus-iot-live.vercel.app/api --token $ARGUS_ADMIN_TOKEN

# opt in to real packet capture + flow-based detection
python -m sensor.agent --api-url http://localhost:8000 --token $ARGUS_ADMIN_TOKEN \
  --enable-capture --interfaces eth0 --window-seconds 60
```

Console: the **Live Network** mode tab (obvious, alongside **Benchmark
Evaluation**, in the header) shows real discovered devices, sensor connection
status, and — once a sensor has been running long enough — real detections and
incidents tagged `scenario="live_network"`. With no sensor connected, it shows
"No live network sensor connected," never fabricated rows.

## 7. What is still not implemented

- Enforcement against real devices — intentionally absent, not a stub (see §3).
- Post-response verification for live incidents — intentionally absent (see §2).
- A user-confirmed device-type override (to opt a specific real device into the
  synthetic `FLEET`'s policy detectors) — noted as a possible future extension in
  `sensor/baseline.py`'s docstring, not built.
- macOS `arp -a` parsing is implemented and unit-tested against fixture text, but
  has not been run on real macOS hardware in this session (this sandbox is
  Linux-only); the `/proc/net/arp` path has been exercised against this
  sandbox's own real ARP table.
