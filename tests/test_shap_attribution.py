"""Tests for the SHAP attribution layer (docs/09 Layer 2)."""

from datetime import datetime, timedelta

from argus.detect.ml import CalibratedDetector, ShapExplainer, ml_detections
from argus.features.extract import extract_device_window
from argus.sim.engine import default_fleet, run_benign_window, run_scenario


def _fit_detector_and_explainer(seed: int = 7):
    devices = default_fleet()
    train_flows = run_benign_window(devices, datetime(2026, 1, 1), 60, seed=seed)
    from argus.collector.windows import window_flows

    train_windows = window_flows(train_flows, window_seconds=120)
    train_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in train_windows if w[2]]
    train_fvs = [fv for fv in train_fvs if fv.values]

    calib_fvs = list(train_fvs[:20])
    calib_labels = [0] * len(calib_fvs)
    attack_flows, _ = run_scenario("mirai", "smart-plug-00", datetime(2026, 1, 1), seed=seed + 1)
    for w in window_flows(attack_flows, window_seconds=300):
        fv = extract_device_window("smart-plug-00", w[2], w[0], w[1])
        if fv.values:
            calib_fvs.append(fv)
            calib_labels.append(1)

    detector = CalibratedDetector()
    detector.fit(train_fvs, calib_fvs, calib_labels)
    explainer = ShapExplainer()
    explainer.fit(calib_fvs, calib_labels)
    return detector, explainer


def test_shap_explainer_fits_and_explains_a_real_detection():
    detector, explainer = _fit_detector_and_explainer()
    assert explainer.fitted

    attack_flows, _ = run_scenario("mirai", "smart-plug-00", datetime(2026, 1, 2), seed=99)
    from argus.collector.windows import window_flows

    windows = window_flows(attack_flows, window_seconds=300)
    fv = extract_device_window("smart-plug-00", windows[0][2], windows[0][0], windows[0][1])

    contributions = explainer.explain(fv)
    assert len(contributions) <= 5
    assert all({"name", "value", "contribution"} <= c.keys() for c in contributions)
    # sorted by |contribution| descending
    magnitudes = [abs(c["contribution"]) for c in contributions]
    assert magnitudes == sorted(magnitudes, reverse=True)


def test_ml_detections_carry_attribution_when_explainer_given():
    detector, explainer = _fit_detector_and_explainer()
    attack_flows, _ = run_scenario("mirai", "smart-plug-00", datetime(2026, 1, 2), seed=99)
    from argus.collector.windows import window_flows

    windows = window_flows(attack_flows, window_seconds=300)
    fv = extract_device_window("smart-plug-00", windows[0][2], windows[0][0], windows[0][1])

    dets_without = ml_detections("smart-plug-00", fv, detector, datetime(2026, 1, 2))
    dets_with = ml_detections("smart-plug-00", fv, detector, datetime(2026, 1, 2), explainer=explainer)

    if dets_without:  # only meaningful if the detector actually fired on this window
        assert dets_without[0].attribution is None
        assert dets_with[0].attribution is not None
        assert "SHAP" in dets_with[0].explanation


def test_unfitted_explainer_returns_empty_list_not_an_error():
    explainer = ShapExplainer()
    fv = extract_device_window("x", [], datetime(2026, 1, 1), datetime(2026, 1, 1) + timedelta(minutes=1))
    assert explainer.explain(fv) == []
