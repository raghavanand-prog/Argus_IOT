"""sensor.live_detect.LiveAnomalyDetector: real assertions, not smoke tests.

MIN_BASELINE_WINDOWS was raised from an earlier value of 4 to 20 after ad hoc
testing against real captured traffic (see docs/18-live-sensor.md and
progress.md) showed 4 produces a *degenerate* model -- every window, including
the training data itself, scored identically, so nothing could ever be
flagged. These tests pin that finding down: fit() must refuse below the floor,
and a genuinely different window must actually rank above ANOMALY_PERCENTILE
once there's enough (varied) baseline data -- not just "some" data, since a
baseline with zero real variance is exactly the degenerate case that motivated
raising the floor in the first place.
"""

import random
import uuid
from datetime import UTC, datetime

from argus.schemas import FeatureVector
from sensor.live_detect import (
    ANOMALY_PERCENTILE,
    MIN_BASELINE_WINDOWS,
    LiveAnomalyDetector,
    live_anomaly_detections,
)

NORMAL_BASE = {
    "flow_count": 2.0, "bytes_out_mean": 40.0, "bytes_out_std": 5.0, "bytes_ratio": 0.5,
    "mean_iat_s": 0.3, "burstiness": 0.1, "periodicity_score": 0.2, "distinct_destinations": 1.0,
    "destination_entropy": 0.0, "fanout_rate": 0.5, "distinct_dns_qnames": 0.0,
    "dns_qname_entropy_mean": 0.0, "dns_qname_length_mean": 0.0, "distinct_ja4": 0.0,
}
ANOMALOUS = {
    "flow_count": 100.0, "bytes_out_mean": 1200.0, "bytes_out_std": 0.0, "bytes_ratio": 0.0,
    "mean_iat_s": 0.03, "burstiness": -0.99, "periodicity_score": 0.99, "distinct_destinations": 80.0,
    "destination_entropy": 4.0, "fanout_rate": 0.01, "distinct_dns_qnames": 0.0,
    "dns_qname_entropy_mean": 0.0, "dns_qname_length_mean": 0.0, "distinct_ja4": 0.0,
}


def _fv(values):
    now = datetime.now(UTC)
    return FeatureVector(flow_id=str(uuid.uuid4()), device_id="dev-1", window_start=now, window_end=now, values=values)


def _varied_baseline(n: int, seed: int = 1) -> list[FeatureVector]:
    rng = random.Random(seed)
    out = []
    for _ in range(n):
        v = dict(NORMAL_BASE)
        v["flow_count"] += rng.choice([-1, 0, 0, 1])
        v["bytes_out_mean"] += rng.uniform(-8, 8)
        v["mean_iat_s"] += rng.uniform(-0.05, 0.05)
        out.append(_fv(v))
    return out


def test_fit_refuses_below_floor():
    det = LiveAnomalyDetector(device_id="dev-1")
    assert det.fit(_varied_baseline(MIN_BASELINE_WINDOWS - 1)) is False
    assert det.fitted is False


def test_fit_succeeds_at_floor():
    det = LiveAnomalyDetector(device_id="dev-1")
    assert det.fit(_varied_baseline(MIN_BASELINE_WINDOWS)) is True
    assert det.fitted is True


def test_score_on_unfitted_detector_is_inert():
    det = LiveAnomalyDetector(device_id="dev-1")
    raw, pct = det.score(_fv(ANOMALOUS))
    assert (raw, pct) == (0.0, 0.0)


def test_genuinely_different_window_scores_above_anomaly_percentile():
    det = LiveAnomalyDetector(device_id="dev-1")
    assert det.fit(_varied_baseline(30)) is True
    raw, pct = det.score(_fv(ANOMALOUS))
    assert pct >= ANOMALY_PERCENTILE


def test_live_anomaly_detections_produces_real_detection_with_no_conformal_claim():
    det = LiveAnomalyDetector(device_id="dev-1")
    det.fit(_varied_baseline(30))
    dets = live_anomaly_detections("dev-1", _fv(ANOMALOUS), det, datetime.now(UTC))
    assert len(dets) == 1
    d = dets[0]
    assert d.device_id == "dev-1"
    assert d.source == "live-anomaly"
    assert d.conformal_set is None  # never claim a guarantee this detector can't provide
    assert 0.0 < d.severity <= 1.0


def test_a_normal_window_does_not_trigger_a_detection():
    det = LiveAnomalyDetector(device_id="dev-1")
    det.fit(_varied_baseline(30))
    normal_probe = dict(NORMAL_BASE)
    dets = live_anomaly_detections("dev-1", _fv(normal_probe), det, datetime.now(UTC))
    assert dets == []
