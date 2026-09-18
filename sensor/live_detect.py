"""The live-network detector: deliberately *not* argus.detect.ml.CalibratedDetector.

CalibratedDetector's isotonic calibration and conformal prediction set both
need labelled calibration data (some feature vectors known to be "attack",
some known to be "benign") to produce a meaningful calibrated probability or
a valid conformal set -- see argus/detect/ml.py's fit(): "train_vectors:
benign-only... calib_vectors/calib_labels: held-out... used both to fit the
isotonic calibrator and to compute conformal nonconformity scores". Real live
LAN traffic has no such labels; nothing tells this sensor which of a user's
real devices, if any, were ever actually compromised. Fabricating labels to
satisfy that fit() signature would be exactly the kind of invented ground
truth the project's own no-fabrication rule forbids.

So this is a genuinely different, unsupervised detector: a raw IsolationForest
fit on a device's own observed baseline window (never claimed as "confirmed
benign" -- just "this device's own typical behaviour, as actually observed"),
scored by percentile rank against that same baseline's own anomaly-score
distribution. The output is "how unusual is this window relative to this
device's own history", not a calibrated probability of attack, and it is
labelled that way everywhere it surfaces (Detection.explanation, evidence,
console copy) so it is never confused with the benchmark/synthetic tracks'
calibrated output.

Same feature schema as the synthetic/CICIoT2023 ML track by design --
argus.detect.ml.FEATURE_KEYS are the exact 14 features argus.features.extract.
extract_device_window computes from real FlowRecords, and that extractor is
reused unmodified for live traffic (see sensor/agent.py). Only the model and
its scoring/threshold logic differ, because the calibration inputs differ.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest

from argus.detect.ml import FEATURE_KEYS
from argus.schemas import Detection, FeatureVector

ANOMALY_PERCENTILE = 95.0  # flag a window scoring more extreme than 95% of this device's own baseline

# Measured, not guessed: an earlier version of this floor was 4 (the minimum sample
# count IsolationForest.fit() accepts without erroring). Ad hoc testing against real
# captured windows (see progress.md) showed that floor produces a *degenerate* model --
# every window, including the training data itself, scored identically (baseline
# min==max raw score), so nothing could ever be flagged regardless of how different it
# was. Re-testing at n=10/20/40 (real captured baseline windows, replicated with small
# jitter) showed scores start meaningfully varying by n=10 and stay usefully spread by
# n=20. 20 is a practical minimum for a *non-degenerate* model, not a guarantee of
# sensitivity -- it will still take this many capture windows (20 x --window-seconds)
# before a device's first anomaly score is even possible.
MIN_BASELINE_WINDOWS = 20


def _vectorise(fv: FeatureVector) -> np.ndarray:
    return np.array([fv.values.get(k, 0.0) for k in FEATURE_KEYS], dtype=float)


@dataclass
class LiveAnomalyDetector:
    device_id: str
    model: IsolationForest = field(default_factory=lambda: IsolationForest(random_state=42, contamination="auto"))
    _baseline_scores: np.ndarray = field(default_factory=lambda: np.array([]))
    fitted: bool = False

    def fit(self, baseline_vectors: list[FeatureVector]) -> bool:
        """Returns False (and leaves the detector unfitted) if there isn't
        enough baseline data to fit a meaningful model -- see
        MIN_BASELINE_WINDOWS above for how that floor was measured, not
        guessed. Below it, this honestly declines to produce a score rather
        than fitting a model too degenerate to mean anything."""
        if len(baseline_vectors) < MIN_BASELINE_WINDOWS:
            return False
        X = np.vstack([_vectorise(fv) for fv in baseline_vectors])
        self.model.fit(X)
        self._baseline_scores = -self.model.score_samples(X)  # higher = more anomalous
        self.fitted = True
        return True

    def score(self, fv: FeatureVector) -> tuple[float, float]:
        """Returns (raw_anomaly_score, percentile_rank_against_own_baseline).
        Not a probability -- an unsupervised anomaly score, scored only
        against this device's own prior behaviour."""
        if not self.fitted:
            return 0.0, 0.0
        x = _vectorise(fv).reshape(1, -1)
        raw = float(-self.model.score_samples(x)[0])
        percentile = float((self._baseline_scores < raw).mean() * 100)
        return raw, percentile


def live_anomaly_detections(device_id: str, fv: FeatureVector, detector: LiveAnomalyDetector,
                             ts: datetime) -> list[Detection]:
    raw_score, percentile = detector.score(fv)
    if not detector.fitted or percentile < ANOMALY_PERCENTILE:
        return []
    return [Detection(
        detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="live-anomaly",
        signal_name="unsupervised_baseline_deviation",
        severity=min(1.0, percentile / 100), confidence=min(1.0, percentile / 100),
        explanation=(
            f"{device_id}'s traffic in this window scored more anomalous than {percentile:.0f}% of its "
            f"own observed baseline (unsupervised IsolationForest, raw score {raw_score:.3f}). This is a "
            f"relative-to-self anomaly score, not a calibrated probability of attack -- no labelled ground "
            f"truth exists for live LAN traffic to calibrate against (see sensor/live_detect.py)."
        ),
        evidence_refs=[fv.flow_id],
        conformal_set=None,  # never claim a conformal guarantee this detector cannot legitimately provide
    )]
