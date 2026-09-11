"""Behaviour engine: deviation = |observed - baseline_median| / (MAD + epsilon),
aggregated across feature groups, normalised to [0,1] (docs/02, "deliberately simple").

Deliberately simple: this component's job is to produce an interpretable per-device
signal, not to be a detector on its own. A complicated deviation score would just be a
second, uninterpretable model competing with the ML layer.
"""

from __future__ import annotations

from argus.registry.enrollment import Baseline
from argus.schemas import FeatureVector

EPSILON = 1e-6


def deviation_score(baseline: Baseline, fv: FeatureVector) -> tuple[float, dict[str, float]]:
    per_feature: dict[str, float] = {}
    for k, observed in fv.values.items():
        median = baseline.medians.get(k)
        mad = baseline.mads.get(k)
        if median is None or mad is None:
            continue
        per_feature[k] = abs(observed - median) / (mad + EPSILON)

    if not per_feature:
        return 0.0, {}

    raw = sum(per_feature.values()) / len(per_feature)
    # squash to [0,1] with a soft cap so one wild feature can't blow the score past 1
    normalised = min(1.0, raw / (raw + 3.0))
    return normalised, per_feature
