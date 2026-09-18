"""Real CICIoT2023-derived benchmark ingestion + evaluation split.

docs/05 documented that this environment's outbound proxy blocks every reachable
host for CICIoT2023/IoT-23 (verified, not assumed) and that the dataset track was
therefore unrun. That constraint is unchanged; what changed is that the project
owner uploaded a real export of the dataset directly, so no download was needed. See
decisions.md for the dated entry and docs/17-cicioT2023-validation.md for the full
compatibility writeup this module implements.

Source file: ``df_Binary_FL_CICIoT2023.rar`` (RAR archive, ~10.7MB), provided
directly by the project owner. Extracted: ``df_Binary_FL_CICIoT2023.csv`` -- 600,000
rows, 10 columns. This is *not* a raw network-flow dump: whoever produced this export
already ran CICIoT2023's own official feature extraction (a CICFlowMeter-style
per-flow statistics pipeline) and then a feature-selection step down to 8 columns,
discarding IP/port/protocol/byte-count/DNS/JA4 identity fields entirely, and
collapsing the original ~34-class attack taxonomy to one binary label. That is why
this module exists instead of feeding the file through ``argus/features/extract.py``:
the raw fields that function needs were never in this export to begin with, and there
is no way to reconstruct them without inventing values -- which CLAUDE.md rule 4
("no fabricated results") and the project owner's own instructions both forbid.

ASSUMPTION: ``sub_label=1`` means Attack and ``sub_label=0`` means Benign. No README
or metadata file shipped with this export, so this is an *inferred* convention, not a
documented one -- flagged here and in docs/17, not silently assumed. Evidence for the
inference (full table in docs/17): grouped by ``sub_label``, rows with
``sub_label=1`` have a mean ``rst_count`` of ~1070 versus ~14, and a mean
``Variance`` of ~0.86 versus ~0.08, for ``sub_label=0`` -- consistent with
flood/DoS-style attack traffic (frequent connection resets, higher packet-size
variance) versus quiet, uniform benign traffic. If this assumption is later found to
be inverted, only ``LABEL_MAP`` below needs to change; nothing else in this module
hardcodes a direction.
"""

from __future__ import annotations

import csv
import hashlib
import random
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from argus.schemas import FeatureVector

DATASET_NAME = "CICIoT2023 (binary, feature-selected FL export)"
DATASET_SOURCE = (
    "Uploaded directly by the project owner as df_Binary_FL_CICIoT2023.rar; "
    "derived from the CICIoT2023 IoT intrusion-detection benchmark "
    "(Canadian Institute for Cybersecurity, University of New Brunswick)."
)

# The 8 real, pre-computed feature columns this export actually contains. Order
# matters: it is the vector order the dataset-specific detector is trained on.
CICIOT_FEATURE_KEYS = ["rst_count", "ICMP", "Min", "AVG", "IAT", "Number", "Variance", "Weight"]
LABEL_COLUMN = "sub_label"
LABEL_MAP = {0: "benign", 1: "attack"}  # inferred -- see module docstring
EXPECTED_COLUMNS = [*CICIOT_FEATURE_KEYS, LABEL_COLUMN]

# Not a real device or network identity -- there is none in this export (no IPs, no
# device IDs). Used only as the risk engine's device_type lookup key, which falls
# back to a fixed criticality of 0.3 for any type it doesn't recognise
# (argus/risk/engine.py: FLEET.get(device_type)... else 0.3) -- the honest default
# for "this isn't a real device with a declared criticality," not a fabricated one.
DATASET_FLOW_DEVICE_TYPE = "cicioT2023-dataset-flow"

# ml_detections() (argus/detect/ml.py) fires on calibrated p_attack >= 0.5 -- this
# constant exists for reporting/reproducibility, not to change that behaviour.
DETECTION_THRESHOLD = 0.5


@dataclass
class CicioTRow:
    row_index: int  # matches the original export's own row order (verified sequential)
    features: dict[str, float]
    label: int  # raw sub_label, 0 or 1


def sha256_of_file(path: str | Path, chunk_size: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()


def load_rows(csv_path: str | Path) -> list[CicioTRow]:
    """Reads the real CSV as-is. The first (unnamed) column is pandas' own row index
    from the original export -- dropped as bookkeeping, not a feature. Every other
    column is read verbatim; nothing is invented, interpolated, or clipped."""
    rows: list[CicioTRow] = []
    with open(csv_path, newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        col_names = header[1:]
        if col_names != EXPECTED_COLUMNS:
            raise ValueError(
                f"unexpected CICIoT2023 export schema: expected columns "
                f"{EXPECTED_COLUMNS}, got {col_names}"
            )
        for i, raw in enumerate(reader):
            values = raw[1:]
            features = {name: float(v) for name, v in zip(CICIOT_FEATURE_KEYS, values)}
            rows.append(CicioTRow(row_index=i, features=features, label=int(float(values[-1]))))
    return rows


def to_feature_vector(row: CicioTRow, base_ts: datetime) -> FeatureVector:
    """Maps the row's 8 real CICIoT2023 columns into ARGUS's ``FeatureVector``
    contract. This is the entire "preprocessing" step for this dataset: a column
    rename + type coercion, not feature computation -- CICIoT2023's own feature
    extraction (an external, CICFlowMeter-style tool) already computed these 8
    statistics upstream of this export. ARGUS's live extractor
    (argus/features/extract.py) is not invoked here because it operates on raw
    ``FlowRecord``s (IPs, ports, byte counts, DNS, JA4) this export never had.

    ``flow_id``/``device_id`` are per-row synthetic bookkeeping identifiers, not real
    network or device identity -- there is none in this export. ``window_start``/
    ``window_end`` are likewise synthetic bookkeeping (an arbitrary reference instant
    plus the row's index in seconds), not a claim about a real capture time, which
    this export does not publish.
    """
    ts = base_ts + timedelta(seconds=row.row_index)
    return FeatureVector(
        flow_id=f"cicioT2023-row-{row.row_index}",
        device_id=f"cicioT2023-eval-{row.row_index}",
        window_start=ts, window_end=ts,
        values=dict(row.features),
        extractor_version="cicioT2023-v1-passthrough",
    )


@dataclass
class DatasetSplit:
    """Disjoint by construction: each of train/calib/test is a non-overlapping slice
    of an already-shuffled, label-partitioned row list -- never a post-hoc filter
    that could silently leak a row into two splits."""

    train: list[CicioTRow]  # benign-only, fits the unsupervised IsolationForest
    calib: list[CicioTRow]
    calib_labels: list[int]
    test: list[CicioTRow]
    test_labels: list[int]
    seed: int
    n_total_rows: int
    n_train_benign: int
    n_calib_benign: int
    n_calib_attack: int
    n_test_benign: int
    n_test_attack: int


def split_dataset(
    rows: list[CicioTRow], seed: int = 42,
    n_train_benign: int = 5000, n_calib_per_class: int = 500, n_test_per_class: int = 1000,
) -> DatasetSplit:
    """Deterministic, disjoint train/calibration/test partition.

    No timestamp column exists in this export (see module docstring), so the
    temporal split ARGUS's dataset-track protocol otherwise uses
    (argus/data/subsample.py's ``temporal_split``) does not apply here -- documented
    explicitly rather than silently swapped for something that looks similar. This
    uses a seeded random *stratified* partition instead: benign and attack row lists
    are each shuffled independently (same seed for benign, seed+1 for attack, so the
    two shuffles are not accidentally correlated), then sliced into disjoint
    train/calib/test ranges. Re-running with the same seed reproduces the exact same
    three sets, byte for byte (CLAUDE.md rule 6).
    """
    benign = [r for r in rows if r.label == 0]
    attack = [r for r in rows if r.label == 1]

    need_benign = n_train_benign + n_calib_per_class + n_test_per_class
    need_attack = n_calib_per_class + n_test_per_class
    if len(benign) < need_benign:
        raise ValueError(f"need {need_benign} benign rows, dataset has {len(benign)}")
    if len(attack) < need_attack:
        raise ValueError(f"need {need_attack} attack rows, dataset has {len(attack)}")

    benign_shuffled = benign[:]
    random.Random(seed).shuffle(benign_shuffled)
    attack_shuffled = attack[:]
    random.Random(seed + 1).shuffle(attack_shuffled)

    train = benign_shuffled[:n_train_benign]
    calib_benign = benign_shuffled[n_train_benign:n_train_benign + n_calib_per_class]
    test_benign = benign_shuffled[
        n_train_benign + n_calib_per_class:n_train_benign + n_calib_per_class + n_test_per_class
    ]
    calib_attack = attack_shuffled[:n_calib_per_class]
    test_attack = attack_shuffled[n_calib_per_class:n_calib_per_class + n_test_per_class]

    calib = calib_benign + calib_attack
    calib_labels = [0] * len(calib_benign) + [1] * len(calib_attack)
    test = test_benign + test_attack
    test_labels = [0] * len(test_benign) + [1] * len(test_attack)

    return DatasetSplit(
        train=train, calib=calib, calib_labels=calib_labels, test=test, test_labels=test_labels,
        seed=seed, n_total_rows=len(rows), n_train_benign=len(train),
        n_calib_benign=len(calib_benign), n_calib_attack=len(calib_attack),
        n_test_benign=len(test_benign), n_test_attack=len(test_attack),
    )
