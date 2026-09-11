# 02 — Detection & evidence

## Feature groups (metadata-only — see `argus/features/extract.py`)

Every feature must expose a specific attack behaviour or it gets deleted:

- **Volume/shape** — packet/byte counts, size stats each direction. Exposes exfiltration,
  DDoS participation.
- **Timing** — inter-arrival stats, burstiness. Exposes scanning cadence, brute force.
- **Periodicity** — autocorrelation/FFT dominant frequency, jitter coefficient over a
  multi-hour window per (device, destination). Exposes beaconing — this is what the
  low-and-slow hard case lives or dies on.
- **Destination behaviour** — distinct destinations, entropy, new-destination rate, fan-out.
  Exposes scanning, C2 to new infra, lateral movement.
- **DNS** — query rate, name entropy, NXDOMAIN ratio. Exposes tunnelling.
- **TLS** — JA4/JA3-style fingerprint, SNI entropy. A fingerprint change on a device is a
  strong compromise signal.
- **Policy** — boolean violations of the device's declared allowlist. Highest precision,
  zero model required.

## Detection tracks

Rules/policy give precision + free explanations on known attacks; ML gives coverage of
the unknown. Random Forest (supervised) + Isolation Forest (unsupervised, no labels
needed for the live track). Deliberately not deep learning — it would cost weeks and
produce a worse explanation story without the contribution depending on classifier
strength.

**Calibration is mandatory.** Raw classifier scores aren't probabilities; isotonic
regression on a held-out split, ECE + reliability diagram reported.

**Conformal prediction as the autonomy gate.** Escalation above `alert` requires the
conformal prediction set to be a singleton at α — a distribution-free bound on the
error rate of autonomous actions, instead of an arbitrary confidence threshold. Caveat:
this assumes exchangeability, which drift breaks — hence the drift monitor gates
escalation independently.

## Correlation & risk

Detections within a time/entity/chain window become one `Incident`. Risk is a weighted
sum: severity, device criticality, calibrated confidence (penalised by conformal set
size), behavioural deviation, blast radius (from the observed communication graph).
Weights are authored, not learned — a sensitivity analysis (vary ±50%, watch TTC/FIR) is
how that's defended, not by hiding it.

## Evidence bundle

An explanation that can't be verified against the data that produced it isn't evidence.
Every incident that reaches the risk engine gets a hash-chained bundle: feature vector,
model identity + hash, baseline snapshot version, policy version, decision trace,
SHAP-style attribution. `evidence/replay.py` re-runs the decision path from a stored
bundle and compares outcomes — the **decision reproducibility rate** this produces is
contribution C2, published whatever it is.
