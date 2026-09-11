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
import shap
from sklearn.ensemble import IsolationForest, RandomForestClassifier
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


@dataclass
class ShapExplainer:
    """Layer 2 explanation (docs/09): TreeSHAP over a supervised RandomForest,
    trained on the same labelled calibration split ``CalibratedDetector`` uses --
    exact, not an approximation (docs/09: "Use TreeSHAP -- exact for tree models,
    fast, and not an approximation that needs its own caveats").

    Honest scope note: the original plan trains this on the full CICIoT2023
    labelled dataset track; that track isn't reachable in this environment (see
    docs/05 and STATUS.md), so this is trained on the same small labelled
    calibration split as the conformal detector. It explains real model behaviour
    on real (if limited) data -- it just hasn't seen as much of it as the original
    design assumed it would.
    """

    model: RandomForestClassifier = field(
        default_factory=lambda: RandomForestClassifier(n_estimators=100, random_state=42, max_depth=6)
    )
    _explainer: object = field(default=None, repr=False)
    fitted: bool = False

    def fit(self, vectors: list[FeatureVector], labels: list[int]) -> None:
        if len(set(labels)) < 2 or len(vectors) < 4:
            return  # can't fit or explain a classifier without both classes
        X = np.vstack([_vectorise(fv) for fv in vectors])
        y = np.array(labels)
        self.model.fit(X, y)
        self._explainer = shap.TreeExplainer(self.model)
        self.fitted = True

    def explain(self, fv: FeatureVector, top_n: int = 5) -> list[dict]:
        if not self.fitted:
            return []
        x = _vectorise(fv).reshape(1, -1)
        raw = self._explainer.shap_values(x)
        # shap>=0.45 with a binary RandomForestClassifier returns (n_samples,
        # n_features, n_classes); take the positive ("attack") class, class index 1
        contributions = raw[0, :, 1] if raw.ndim == 3 else raw[1][0]
        pairs = sorted(zip(FEATURE_KEYS, x[0], contributions), key=lambda t: -abs(t[2]))
        return [
            {"name": name, "value": round(float(val), 4), "contribution": round(float(contrib), 4)}
            for name, val, contrib in pairs[:top_n]
        ]


def ml_detections(device_id: str, fv: FeatureVector, detector: CalibratedDetector, ts: datetime,
                   explainer: ShapExplainer | None = None) -> list[Detection]:
    p_attack, conformal_set = detector.score(fv)
    if p_attack < 0.5:
        return []
    attribution = explainer.explain(fv) if explainer is not None else None
    explanation = (
        f"Calibrated anomaly probability {p_attack:.2f} for {device_id}; "
        f"conformal set at alpha={detector.alpha}: {conformal_set}."
    )
    if attribution:
        top = attribution[0]
        explanation += f" Top contributing feature: {top['name']}={top['value']} (SHAP {top['contribution']:+.3f})."
    return [Detection(
        detection_id=str(uuid.uuid4()), ts=ts, device_id=device_id, source="ml",
        signal_name="isolation_forest_anomaly", severity=min(1.0, p_attack),
        confidence=p_attack,
        explanation=explanation,
        evidence_refs=[fv.flow_id],
        conformal_set=conformal_set,
        attribution=attribution,
    )]
