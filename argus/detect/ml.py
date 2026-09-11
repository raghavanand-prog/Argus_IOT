"""ML detection track: Isolation Forest (unsupervised, live track) + calibration +
conformal prediction gate (docs/02).

Deliberately simple models, on purpose (see MASTER-PLAN.md non-goals: not a SOTA
classifier). What matters for the project's actual contribution (C3/C4) is that scores
are *calibrated* and that autonomous escalation is *gated* on a conformal prediction
set, not raw model strength.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.isotonic import IsotonicRegression

from argus.schemas import Detection, FeatureVector

FEATURE_KEYS = [
    "flow_count", "bytes_out_mean", "bytes_out_std", "bytes_ratio", "mean_iat_s",
    "burstiness", "periodicity_score", "distinct_destinations", "destination_entropy",
    "fanout_rate", "distinct_dns_qnames", "dns_qname_entropy_mean", "dns_qname_length_mean",
    "distinct_ja4",
]


def _vectorise(fv: FeatureVector) -> np.ndarray:
    return np.array([fv.values.get(k, 0.0) for k in FEATURE_KEYS], dtype=float)


@dataclass
class CalibratedDetector:
    """Isolation Forest + isotonic calibration + an inductive conformal wrapper.

    Kept under ~100 lines by design (docs/02: "prefer writing it -- it is short, it
    must be understood to be defended in an interview, and the dependency is not worth
    it" -- referring to the conformal wrapper specifically; we apply the same standard
    to the whole detector).
    """

    model: IsolationForest = field(default_factory=lambda: IsolationForest(random_state=42, contamination=0.1))
    calibrator: IsotonicRegression = field(default_factory=lambda: IsotonicRegression(out_of_bounds="clip"))
    _calib_nonconformity: np.ndarray = field(default_factory=lambda: np.array([]))
    alpha: float = 0.05
    fitted: bool = False

    def fit(self, train_vectors: list[FeatureVector], calib_vectors: list[FeatureVector], calib_labels: list[int]) -> None:
        """``train_vectors``: benign-only, fits the unsupervised model.
        ``calib_vectors``/``calib_labels``: held-out, disjoint from training, used both
        to fit the isotonic calibrator and to compute conformal nonconformity scores --
        never touched during training (docs/02: "never on training or test data")."""
        X_train = np.vstack([_vectorise(fv) for fv in train_vectors])
        self.model.fit(X_train)

        X_calib = np.vstack([_vectorise(fv) for fv in calib_vectors])
        raw_scores = -self.model.score_samples(X_calib)  # higher = more anomalous
        y = np.array(calib_labels, dtype=float)
        self.calibrator.fit(raw_scores, y)

        calibrated = self.calibrator.predict(raw_scores)
        # nonconformity for the true class: for attack (y=1) it's (1 - p_attack);
        # for benign (y=0) it's p_attack. Store the "attack" class nonconformity set,
        # used below to build the conformal prediction set at inference time.
        self._calib_nonconformity = np.where(y == 1, 1 - calibrated, calibrated)
        self.fitted = True

    def score(self, fv: FeatureVector) -> tuple[float, list[str]]:
        """Returns (calibrated_probability_of_attack, conformal_set).
        conformal_set in {"benign"}, {"attack"}, or {"benign","attack"} (uncertain)."""
        if not self.fitted:
            return 0.0, ["benign", "attack"]
        x = _vectorise(fv).reshape(1, -1)
        raw = -self.model.score_samples(x)[0]
        p_attack = float(self.calibrator.predict([raw])[0])

        # inductive conformal prediction: include a label in the set if its
        # nonconformity score would not be "surprising" relative to the calibration
        # set at significance level alpha (docs/02's ~100-line wrapper, here inline).
        conformal_set: list[str] = []
        for label, nonconf in (("benign", p_attack), ("attack", 1 - p_attack)):
            rank = (self._calib_nonconformity >= nonconf).sum() + 1
            p_value = rank / (len(self._calib_nonconformity) + 1)
            if p_value > self.alpha:
                conformal_set.append(label)
        if not conformal_set:
            conformal_set = ["benign", "attack"]  # never return an empty set
        return p_attack, conformal_set

    def empirical_coverage(self, test_vectors: list[FeatureVector], test_labels: list[int]) -> float:
        """Fraction of test points whose true label is inside the conformal set --
        should land within tolerance of (1 - alpha) (docs/02's verification step)."""
        hits = 0
        for fv, y in zip(test_vectors, test_labels):
            _, cset = self.score(fv)
            true_label = "attack" if y == 1 else "benign"
            hits += true_label in cset
        return hits / max(len(test_vectors), 1)


def ml_detections(device_id: str, fv: FeatureVector, detector: CalibratedDetector, ts: datetime) -> list[Detection]:
    p_attack, conformal_set = detector.score(fv)
    if p_attack < 0.5:
        return []
    return [Detection(
        detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="ml",
        signal_name="isolation_forest_anomaly", severity=min(1.0, p_attack),
        confidence=p_attack,
        explanation=(
            f"Calibrated anomaly probability {p_attack:.2f} for {device_id}; "
            f"conformal set at alpha={detector.alpha}: {conformal_set}."
        ),
        evidence_refs=[fv.flow_id],
        conformal_set=conformal_set,
    )]
