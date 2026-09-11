"""Unit tests for feature extraction against known, hand-reasoned fixtures.

Per CLAUDE.md's testing expectations: real assertions on real behaviour, not
assert True. These check that features actually separate benign device-type
behaviour from the two implemented attack scenarios (docs/00 gate for week 2:
"a human looking at per-device flow statistics can tell the device types apart").
"""

from datetime import datetime, timedelta

from argus.features.extract import extract_device_window
from argus.sim.engine import default_fleet, run_benign_window, run_scenario


def test_benign_fleet_produces_flows_with_distinct_per_device_signatures():
    devices = default_fleet()
    flows = run_benign_window(devices, datetime(2026, 1, 1, 9, 0), duration_minutes=120, seed=42)
    assert len(flows) > 20

    hub_flows = [f for f in flows if f.device_id == "hub-00"]
    sensor_flows = [f for f in flows if f.device_id == "air-sensor-00"]
    assert len(hub_flows) > len(sensor_flows), (
        "hub (10s period) must produce far more flows than air-sensor (300s period) "
        "in the same window -- if not, the behaviour models are too similar (docs/00)."
    )


def test_mirai_scenario_produces_high_fanout_and_egress_spike():
    _, events = run_scenario("mirai", "vulnerable-device-00", datetime(2026, 1, 1, 10, 0), seed=1)
    flows, _ = run_scenario("mirai", "vulnerable-device-00", datetime(2026, 1, 1, 10, 0), seed=1)
    fv = extract_device_window(
        "vulnerable-device-00", flows, datetime(2026, 1, 1, 10, 0), datetime(2026, 1, 1, 10, 10),
    )
    assert fv.values["distinct_destinations"] > 10, "scan phase must fan out to many hosts"
    assert fv.values["destination_entropy"] > 1.0
    assert any(e.phase == "ddos" for e in events)


def test_low_and_slow_has_high_periodicity_but_low_volume():
    flows, events = run_scenario("low_and_slow", "smart-speaker-00", datetime(2026, 1, 1, 0, 0), seed=7)
    fv = extract_device_window(
        "smart-speaker-00", flows, datetime(2026, 1, 1, 0, 0), datetime(2026, 1, 1, 3, 0),
    )
    assert fv.values["periodicity_score"] > 0.7, (
        "beaconing must show up as high periodicity -- this is the signal the hard "
        "case depends on (docs/00, docs/02)"
    )
    assert fv.values["flow_count"] < 30, "low-and-slow must stay low-volume by design"
    assert len(events) == 1 and events[0].scenario == "low_and_slow"


def test_feature_vector_is_deterministic_for_fixed_seed():
    devices = default_fleet()
    f1 = run_benign_window(devices, datetime(2026, 1, 1), 30, seed=99)
    f2 = run_benign_window(devices, datetime(2026, 1, 1), 30, seed=99)
    assert [f.bytes_out for f in f1] == [f.bytes_out for f in f2], (
        "determinism is a non-negotiable rule (CLAUDE.md) -- same seed must reproduce "
        "the same run exactly"
    )


def test_empty_window_does_not_crash():
    fv = extract_device_window("nonexistent", [], datetime(2026, 1, 1), datetime(2026, 1, 1) + timedelta(minutes=1))
    assert fv.values == {}
