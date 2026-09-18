# 17 — CICIoT2023 real-dataset IDS validation

This document is the required 20-section validation report for the CICIoT2023
evaluation track. Every number in it comes from one real, actually-executed run of
`argus.pipeline.run_cicioT2023_evaluation` (`run_id: f28336eb-7b9d-4988-817b-f24047c7f83c`,
generated at `2026-09-18T07:11:57Z`), reproducible by re-running
`scripts/export_cicioT2023_snapshot.py` against the same file with `seed=42`. Nothing
here is invented, interpolated, or hand-tuned to look better than the run produced.

**What this is, stated plainly (per the project owner's explicit instruction not to
overclaim)**: CICIoT2023 is a *publicly available IoT cybersecurity benchmark
dataset* (Canadian Institute for Cybersecurity, University of New Brunswick) — a
static, pre-captured, pre-labelled research dataset. This is **not** live or
production network traffic, and the results below say nothing about real-time
detection performance on a live network. See docs/16-ids-validation.md for that
separate, synthetic-simulation-based validation track.

---

## 1. Dataset

CICIoT2023 (binary, feature-selected FL export) — a derivative export of the
CICIoT2023 IoT intrusion-detection benchmark. The export was not accompanied by a
README or provenance document, so section 6 documents exactly how its 8 columns
were interpreted and what was inferred versus verified.

## 2. Dataset source

Uploaded directly by the project owner as `df_Binary_FL_CICIoT2023.rar` (RAR
archive, ~10.7 MB). Derived from the CICIoT2023 benchmark published by the Canadian
Institute for Cybersecurity (CIC), University of New Brunswick. The original,
full-resolution CICIoT2023 release is hosted at the CIC's own site; this
environment's outbound network proxy blocks that host (confirmed directly, see
docs/05-data-pipeline.md), which is why a direct download was never possible and why
the project owner's upload was the path that worked.

File: `df_Binary_FL_CICIoT2023.csv`, extracted from the RAR archive.
SHA-256 of the full file: `c41ab8b0f624db82bb248e0d89facc11fefb575e53dddb56305f3cf20fde674f`.

## 3. Number of samples

- Full export: 600,000 rows (300,000 labelled `sub_label=0`, 300,000 labelled `sub_label=1` — exactly balanced).
- Used in this run: 5,000 (train, benign-only) + 1,000 (calibration, 500+500) + 2,000 (held-out test, 1,000+1,000) = 8,000 rows drawn from the 600,000, via a seeded stratified partition (section 6). The remaining 592,000 rows were not used.
- All reported metrics below are computed over the 2,000-row **held-out test split only** — never seen during training or calibration.

## 4. Classes

Binary only: `benign` / `attack`. This export collapses CICIoT2023's original,
much finer attack-category taxonomy (DDoS/DoS/Recon/Web-based/Brute-Force/Spoofing/
Mirai-style botnet subclasses, ~34 labels in the full benchmark) down to one binary
label before it reached this project. There is no column in this file identifying
*which* attack category a malicious row belongs to, so **per-attack-category metrics
are not computable from this file** — reported honestly as a limitation (section 20),
not worked around by inventing categories.

## 5. Features

Exactly 8 real, pre-computed numeric columns, used in this fixed order:

`rst_count, ICMP, Min, AVG, IAT, Number, Variance, Weight`

These are *not* raw network-flow fields — no source/destination IP, no port, no full
protocol enumeration (only a single ICMP boolean), no byte counts, no DNS query name,
no TLS/JA4 fingerprint. Whoever produced this export already ran CICIoT2023's own
official feature-extraction pipeline (a CICFlowMeter-style per-flow statistics tool)
and then a feature-selection step down to these 8 columns.

## 6. Preprocessing

Two real steps, both implemented in `argus/data/cicioT2023.py`:

1. **Loading** (`load_rows`): reads the CSV verbatim via `csv.reader`, drops the
   original export's unnamed pandas-index column (bookkeeping, not a feature), and
   type-coerces the 8 feature columns to `float` and the label to `int`. Nothing is
   clipped, imputed, or invented — a row with an unexpected schema raises rather than
   silently coercing.
2. **Vectorisation** (`to_feature_vector`): maps the 8 real columns into ARGUS's
   `FeatureVector.values` dict, by name. This is the *entire* preprocessing step —
   not feature computation, because CICIoT2023 already computed these statistics
   upstream of this export. `flow_id`/`device_id` are synthetic per-row bookkeeping
   identifiers (there is no real device or network identity in this export); the
   timestamp fields are likewise synthetic bookkeeping, not a claim about a real
   capture time this export does not publish.

**Label-mapping assumption** (flagged explicitly, not silently assumed): no README
shipped with this export, so `sub_label=1 → attack` / `sub_label=0 → benign` is an
*inferred* convention. Evidence for the inference: grouped by `sub_label`, rows with
`sub_label=1` have a mean `rst_count` of 1069.8 versus 14.1, and a mean `Variance` of
0.861 versus 0.078, for `sub_label=0` — consistent with flood/DoS-style attack
traffic (frequent connection resets, higher packet-size variance) versus quiet,
uniform benign traffic. If this direction is later found to be inverted, only
`LABEL_MAP` in `argus/data/cicioT2023.py` needs to change.

**Train/calibration/test split**: no timestamp column exists in this export, so
ARGUS's usual temporal split (`argus/data/subsample.py`'s `temporal_split`, used
elsewhere in the dataset-track protocol) does not apply — documented explicitly
rather than silently swapped. Instead, `split_dataset` does a seeded random
stratified partition: benign and attack row lists are each shuffled independently
(seed for benign, seed+1 for attack), then sliced into disjoint, non-overlapping
train/calib/test ranges. Disjointness is structural (non-overlapping slices), not
merely asserted — verified directly in `tests/test_cicioT2023_eval.py`.

## 7. IDS/model

`argus.detect.ml.CalibratedDetector` — the exact same class the synthetic pipeline
uses (IsolationForest → isotonic-regression calibration → inductive conformal
prediction), fit as a **separate instance** on this dataset's own 8 features. This
is the one adjustment the detector needed: `CalibratedDetector`/`ShapExplainer` were
given an injectable `feature_keys` field (default: the synthetic pipeline's 14-key
`FEATURE_KEYS`), so a same-class, separately-fitted instance can be trained on a
different feature space instead of misaligning the flow-trained model's weights
against a dataset that doesn't have those 14 fields. Nothing else about the detector
architecture changed. See `argus/detect/ml.py`'s `CalibratedDetector` docstring.

Only ARGUS's ML detection track runs on this dataset. `policy_detections`,
`signature_detections`, and `identity_detections` (the rule/policy tracks) require
`dst_ip`/`dst_port`/`proto`/`dns_qname`/`tls_ja4` — none of which this export has —
so they produce no detections here, not because they were disabled, but because
they have nothing to key on.

## 8. Detection threshold

Calibrated probability of attack ≥ **0.5** — the exact same threshold
`argus.detect.ml.ml_detections()` already hardcodes for the synthetic pipeline; not
changed or tuned for this dataset.

## 9. Confusion matrix

Computed over the 2,000-row held-out test split (1,000 benign + 1,000 attack),
never touched during training or calibration:

| | Predicted: attack | Predicted: benign |
|---|---|---|
| **Actual: attack** | TP = **1000** | FN = **0** |
| **Actual: benign** | FP = **20** | TN = **980** |

## 10. Accuracy

**99.0%** — (1000 + 980) / 2000.

## 11. Precision

**98.04%** — 1000 / (1000 + 20).

## 12. Recall

**100.0%** — 1000 / (1000 + 0).

## 13. F1

**99.01%** — harmonic mean of precision and recall.

## 14. False Positive Rate

**2.0%** — 20 / (20 + 980).

## 15. False Negative Rate

**0.0%** — 0 / (0 + 1000).

## 16. Number of incidents generated

**1,020 real incidents** — one per test row the detector itself predicted `attack`
(1,000 true positives + 20 false positives). Every one went through ARGUS's real
`correlate → assess_risk → decide_and_respond → evidence` chain and was persisted as
a real `IncidentRow` + `EvidenceBundleRow` (tagged `scenario="cicioT2023_eval"`),
identical in shape to a synthetic-pipeline incident and visible on the same
Incidents page. Zero incidents were created for the 980 correctly-quiet benign rows
or the 0 missed attacks — incident generation is gated on the detector's own
prediction, never on `sub_label` (verified directly in
`tests/test_cicioT2023_eval.py`: every TN record has `incident_id: None`, every
predicted-attack record has a real `incident_id`).

## 17. Example detected records (true positives)

| Record | Ground truth | Prediction | p(attack) | Incident |
|---|---|---|---|---|
| `CICIoT2023-row-12290` | attack | attack | 0.9969 | `ae18e405-47ba-4ea7-812f-2b8fb1a6d9ae` |
| `CICIoT2023-row-318508` | attack | attack | 0.9969 | `996e803c-29c0-4049-9256-a2a42b30ec62` |
| `CICIoT2023-row-265654` | attack | attack | 0.9969 | `8a187da9-ee73-4e4f-a3b5-fba37e4bac5b` |

## 18. Example false positives

| Record | Ground truth | Prediction | p(attack) | Incident |
|---|---|---|---|---|
| `CICIoT2023-row-431010` | benign | attack | 0.9763 | `7c564ae2-6faf-4743-a0fd-69874cc953df` |
| `CICIoT2023-row-224378` | benign | attack | 0.9969 | `a6c536a7-5de5-408e-99ae-06882117f038` |
| `CICIoT2023-row-99235` | benign | attack | 0.9969 | `890cfbe2-7d8f-4766-bc4e-4a9e7e245170` |

All 20 false positives in this run carry a high calibrated score (≥0.97) — the
detector is confidently wrong on these rows, not marginally wrong; their feature
values (elevated `Min`/`AVG`/`rst_count` relative to the bulk of benign traffic) sit
closer to the attack cluster than to the rest of the benign population. This is
reported as-is, not smoothed over.

## 19. Example false negatives

**None occurred in this run** (FN = 0 for this seed and split). Reported honestly
rather than fabricating an example that doesn't exist — a genuinely zero-FN result
on this particular held-out split, not a claim that this detector cannot miss an
attack in general. See section 20 for why this number should not be over-read.

## 20. Limitations

1. **Binary ground truth only.** This export collapses CICIoT2023's original
   attack-category taxonomy to one label; per-attack-category precision/recall
   cannot be computed from this file.
2. **Only the ML detection track is exercised.** The rule/policy/identity tracks
   need IP/port/protocol/DNS/JA4 fields this export never had, so this result says
   nothing about how ARGUS's other three detectors would perform on IoT traffic —
   only about the calibrated-anomaly track.
3. **The `sub_label` direction is inferred, not documented** (section 6) — no README
   shipped with the export.
4. **Post-response verification is skipped** for every CICIoT2023-derived action
   (`_process_cicioT2023_detection` in `argus/pipeline.py`). `verify()` checks
   whether a live/simulated environment recovered after an action, against a
   ground-truth ledger of attack phases with start/end times; a static,
   already-captured dataset row has no environment to re-observe and no such
   phase-based ground truth, so faking a verification outcome would be exactly the
   kind of invented result this validation is meant to avoid.
5. **No temporal split was possible** — no timestamp column exists in this export,
   so train/calib/test are a seeded random stratified partition rather than a
   time-ordered one (unlike, in principle, a dataset with real capture timestamps).
6. **This is an unusually clean separation between classes** for this particular
   8-feature export (see the per-label feature-mean gap noted in section 6) —
   accuracy/F1 this high on a benchmark dataset should not be read as a claim about
   performance against adversarial or evasive real-world traffic, which this
   dataset, by construction, does not contain.
7. **This is a benchmark dataset, not live traffic** (restated per the project
   owner's explicit instruction): nothing here measures production or live-network
   detection performance.
8. **Reproducing this exact result from scratch requires the full 600,000-row
   original file** (not committed to this repository — see `data/cicioT2023/` and
   `.gitignore`), since `split_dataset` draws its train/calib/test rows from the
   full benign/attack pools. The 2,000-row held-out test split *is* committed
   (`argus/data/fixtures/cicioT2023_eval_subset.csv`) and is what
   `tests/test_cicioT2023_eval.py`'s integration test and the production Vercel
   deployment both use directly.

---

## How to reproduce this run

```bash
# needs the full original file at data/cicioT2023/df_Binary_FL_CICIoT2023.csv
# (or set ARGUS_CICIOT2023_CSV to its path)
python scripts/export_cicioT2023_snapshot.py
```

This re-runs `argus.pipeline.run_cicioT2023_evaluation(db, csv_path, seed=42)` from
scratch and re-writes both `api/cicioT2023_eval_snapshot.json` (the production
snapshot) and `argus/data/fixtures/cicioT2023_eval_subset.csv` (the committed test
split). With the same file and seed, every number in this document should reproduce
exactly — that determinism is asserted directly in
`tests/test_cicioT2023_eval.py::test_split_dataset_is_disjoint_deterministic_and_seed_sensitive`.

To run it live against the local dev API instead (real SQLite, real detector
training, every request): `POST /control/run-cicioT2023-eval` with a bearer token
(see `argus/api/main.py`).
