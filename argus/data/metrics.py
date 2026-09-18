"""Binary confusion-matrix metrics, computed from actual prediction/ground-truth
pairs -- never hardcoded. Kept dependency-free (plain arithmetic) rather than pulled
from sklearn.metrics, since the whole point is that every number here traces to a
formula anyone can check by eye, the same "boring, readable code" standard as the
rest of this project.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ConfusionMatrix:
    tp: int
    tn: int
    fp: int
    fn: int

    @property
    def total(self) -> int:
        return self.tp + self.tn + self.fp + self.fn

    def to_dict(self) -> dict[str, int]:
        return {"tp": self.tp, "tn": self.tn, "fp": self.fp, "fn": self.fn}


def confusion_matrix(y_true: list[int], y_pred: list[int]) -> ConfusionMatrix:
    """``y_true``/``y_pred``: 1 = attack, 0 = benign. Neither list may influence the
    other's construction by the time this is called -- that guarantee lives in the
    caller (the evaluation pipeline never reads ``y_true`` before computing
    ``y_pred``)."""
    if len(y_true) != len(y_pred):
        raise ValueError(f"length mismatch: {len(y_true)} true labels vs {len(y_pred)} predictions")
    tp = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 1)
    tn = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 0)
    fp = sum(1 for t, p in zip(y_true, y_pred) if t == 0 and p == 1)
    fn = sum(1 for t, p in zip(y_true, y_pred) if t == 1 and p == 0)
    return ConfusionMatrix(tp=tp, tn=tn, fp=fp, fn=fn)


def binary_metrics(cm: ConfusionMatrix) -> dict[str, float]:
    """All values in [0, 1]; a metric whose denominator is zero (e.g. no positive
    ground-truth rows at all) reports 0.0 rather than raising, since that's a
    property of the input split, not a bug -- but it should never happen for the
    class-balanced test split this evaluation pipeline builds."""
    total = cm.total
    accuracy = (cm.tp + cm.tn) / total if total else 0.0
    precision = cm.tp / (cm.tp + cm.fp) if (cm.tp + cm.fp) else 0.0
    recall = cm.tp / (cm.tp + cm.fn) if (cm.tp + cm.fn) else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) else 0.0
    fpr = cm.fp / (cm.fp + cm.tn) if (cm.fp + cm.tn) else 0.0
    fnr = cm.fn / (cm.fn + cm.tp) if (cm.fn + cm.tp) else 0.0
    return {
        "accuracy": accuracy, "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fpr, "false_negative_rate": fnr,
    }


def classify_outcome(y_true: int, y_pred: int) -> str:
    if y_true == 1 and y_pred == 1:
        return "TP"
    if y_true == 0 and y_pred == 0:
        return "TN"
    if y_true == 0 and y_pred == 1:
        return "FP"
    return "FN"
