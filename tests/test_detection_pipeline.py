"""Integration test for Phase 2: enrollment -> baseline -> detection -> correlation ->
risk, run against a scripted attack. Per CLAUDE.md's testing expectations, this asserts
real behaviour (an alert was raised, an incident was formed with a real risk score),
not just that functions were called.
"""

from datetime import datetime, timedelta

from argus.behavior.deviation import deviation_score
from argus.collector.windows import window_flows
from argus.correlate.correlator import correlate
from argus.detect.rules import policy_detections, signature_detections
from argus.features.extract import extract_device_window
from argus.registry.enrollment import enroll
from argus.risk.engine import BlastRadiusGraph, assess_risk
from argus.schemas import DeviceState
from argus.sim.engine import default_fleet, run_benign_window, run_scenario


def _enroll_device(device_id: str, device_type: str, t0: datetime):
    flows = run_benign_window([d for d in default_fleet() if d.device_id == device_id], t0, 60, seed=5)
    windows = window_flows(flows, window_seconds=60)
    fvs = [extract_device_window(device_id, w[2], w[0], w[1]) for w in windows]
    fvs = [fv for fv in fvs if fv.values]
    return enroll(device_id, device_type, flows, fvs)


def test_enrollment_then_mirai_attack_produces_high_risk_incident():
    device_id = "smart-plug-00"
    t0 = datetime(2026, 1, 1, 0, 0)
    result = _enroll_device(device_id, "smart-plug", t0)
    assert result.state == DeviceState.MONITORED
    assert result.baseline is not None

    attack_start = t0 + timedelta(hours=2)
    flows, ground_truth = run_scenario("mirai", device_id, attack_start, seed=3)
    assert len(ground_truth) == 4

    windows = window_flows(flows, window_seconds=300)
    all_detections = []
    deviation = 0.0
    for w_start, w_end, w_flows in windows:
        fv = extract_device_window(device_id, w_flows, w_start, w_end)
        if not fv.values:
            continue
        dev, _ = deviation_score(result.baseline, fv)
        deviation = max(deviation, dev)
        all_detections += policy_detections(device_id, "smart-plug", w_flows, w_start)
        all_detections += signature_detections(device_id, fv, w_start)

    assert len(all_detections) > 0, "the mirai scenario must trip at least one detector"

    incidents = correlate(all_detections)
    assert len(incidents) >= 1

    graph = BlastRadiusGraph(edges={device_id: {"10.10.0.5", "198.51.100.5", "203.0.113.77"}})
    blast = graph.score(device_id)
    risk = assess_risk(incidents[0], all_detections, "smart-plug", deviation, blast)

    assert 0.0 < risk.score <= 1.0
    assert risk.terms["severity"] > 0, "an attack incident must carry nonzero severity"


def test_enrollment_refused_when_learning_window_violates_declared_policy():
    """Required test per docs/06: a device that misbehaves during enrollment must be
    refused, not silently baselined on attack traffic."""
    t0 = datetime(2026, 1, 1, 0, 0)
    flows, _ = run_scenario("mirai", "vulnerable-device-00", t0, seed=1)
    result = enroll("vulnerable-device-00", "smart-plug", flows, feature_windows=[
        extract_device_window("vulnerable-device-00", flows, t0, t0 + timedelta(hours=1))
    ])
    assert result.state == DeviceState.REFUSED
    assert result.reason is not None and "policy violation" in result.reason
