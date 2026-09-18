"""sensor.baseline.build_live_baseline: real assertions against real FlowRecord/
FeatureVector inputs, and the documented "no policy guard" behaviour (see the
module's own docstring for why -- FLEET[device_type] would KeyError on
device_type='unknown', which is the whole point of not calling it here)."""

from datetime import UTC, datetime

from argus.schemas import FeatureVector, FlowRecord
from sensor.baseline import build_live_baseline


def _flow(dst_ip="10.0.0.1", dst_port=443, ts=None):
    ts = ts or datetime.now(UTC)
    return FlowRecord(
        flow_id="f1", device_id="dev-1", ts_start=ts, ts_end=ts,
        src_ip="192.168.1.50", dst_ip=dst_ip, dst_port=dst_port, proto="tcp",
        pkts_out=3, pkts_in=2, bytes_out=300, bytes_in=200,
        tls_ja4=None, dns_qname=None, label="unknown",
    )


def _fv(values):
    now = datetime.now(UTC)
    return FeatureVector(flow_id="f1", device_id="dev-1", window_start=now, window_end=now, values=values)


def test_no_data_returns_none():
    assert build_live_baseline("dev-1", [], []) is None


def test_builds_median_mad_baseline_from_real_flows():
    flows = [_flow(dst_ip="10.0.0.1"), _flow(dst_ip="10.0.0.2")]
    fv = _fv({"flow_count": 2.0, "bytes_out_mean": 150.0})
    baseline = build_live_baseline("dev-1", flows, [fv])
    assert baseline is not None
    assert baseline.device_id == "dev-1"
    assert baseline.device_type == "unknown"  # never invented
    assert baseline.medians["flow_count"] == 2.0
    assert baseline.destinations == {"10.0.0.1": 1, "10.0.0.2": 1}


def test_never_raises_keyerror_for_unknown_device_type():
    # this is the whole point of the module: argus.registry.policy.violates_policy
    # does FLEET["unknown"], which would KeyError. build_live_baseline must not
    # go anywhere near that path.
    flows = [_flow()]
    fv = _fv({"flow_count": 1.0})
    baseline = build_live_baseline("dev-1", flows, [fv])
    assert baseline is not None
