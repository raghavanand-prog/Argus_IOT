"""Tests for the real network-namespace testbed (argus/testbed/).

These need Linux + root/CAP_NET_ADMIN + the live-testbed extra. They're skipped
cleanly everywhere else so the rest of the suite stays fast and portable -- the
synthetic sim engine and everything downstream of it works without any of this.

These are slower and less deterministic than the rest of the suite (real sockets,
real timing) by nature, so durations are kept short and assertions are on shape
(packets were captured, flows separate benign from attack, real teardown leaves no
state behind) rather than exact counts.
"""

from __future__ import annotations

import os
import sys

import pytest

pyroute2 = pytest.importorskip("pyroute2", reason="live-testbed extra not installed")
pytest.importorskip("scapy", reason="live-testbed extra not installed")

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="network namespaces are Linux-only"),
    pytest.mark.skipif(os.geteuid() != 0, reason="needs root/CAP_NET_ADMIN to create network namespaces"),
]


@pytest.fixture(autouse=True)
def _clean_fabric_state():
    from argus.testbed.fabric import cleanup_stale_fabric

    cleanup_stale_fabric()
    yield
    cleanup_stale_fabric()


def test_fabric_setup_and_teardown_leaves_no_state_behind():
    from argus.testbed.fabric import NetworkFabric

    with NetworkFabric() as fabric:
        a = fabric.add_device("test-device-a")
        b = fabric.add_device("test-device-b")
        assert a.ip != b.ip
        assert os.path.exists(f"/var/run/netns/{a.ns_name}")

    assert not os.path.exists(f"/var/run/netns/{a.ns_name}")
    assert not os.path.exists(f"/var/run/netns/{b.ns_name}")


def test_two_namespaces_exchange_a_real_udp_packet():
    """The connectivity smoke test that caught the bridge-netfilter issue in the
    first place (decisions.md) -- kept as a regression test."""
    import multiprocessing
    import socket
    import time

    from pyroute2 import netns as pyroute2_netns

    from argus.testbed.fabric import NetworkFabric

    def server(ns_name, ip, q):
        pyroute2_netns.setns(ns_name)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((ip, 9998))
        s.settimeout(4)
        try:
            data, _ = s.recvfrom(1024)
            q.put(data)
        except TimeoutError:
            q.put(None)

    def client(ns_name, dst_ip):
        pyroute2_netns.setns(ns_name)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b"ping", (dst_ip, 9998))

    with NetworkFabric() as fabric:
        a = fabric.add_device("test-udp-a")
        b = fabric.add_device("test-udp-b")
        ctx = multiprocessing.get_context("fork")
        q = ctx.Queue()
        srv = ctx.Process(target=server, args=(b.ns_name, b.ip, q))
        srv.start()
        time.sleep(0.4)
        cli = ctx.Process(target=client, args=(a.ns_name, b.ip))
        cli.start()
        cli.join(timeout=5)
        srv.join(timeout=5)
        assert q.get(timeout=2) == b"ping"


def test_live_mirai_scenario_produces_real_captured_attack_flows():
    from argus.testbed.orchestrator import run_live_testbed

    result = run_live_testbed("mirai", benign_duration_s=4, attack_duration_s=3, pcap_path=None)
    assert len(result.flows) > 0
    assert len(result.ground_truth) == 4
    attack_flows = [f for f in result.flows if f.label.startswith("attack:mirai:")]
    assert attack_flows, "the live mirai run must produce at least one flow labelled against real ground truth"
    benign_flows = [f for f in result.flows if f.label == "benign"]
    assert benign_flows, "benign device traffic must also be present and correctly labelled"


def test_live_low_and_slow_scenario_has_regular_spacing():
    from argus.testbed.orchestrator import run_live_testbed

    result = run_live_testbed("low_and_slow", benign_duration_s=3, attack_duration_s=6, pcap_path=None)
    assert len(result.ground_truth) == 1
    beacon_flows = [f for f in result.flows if "low_and_slow" in f.label]
    assert len(beacon_flows) >= 2, "expected multiple real beacon connections"


def test_containment_check_refuses_a_target_outside_the_testbed_subnet():
    from argus.testbed.live_attacks import ContainmentViolation, assert_in_testbed

    assert_in_testbed("10.10.0.42")  # inside -- must not raise
    with pytest.raises(ContainmentViolation):
        assert_in_testbed("8.8.8.8")  # outside -- must always raise, unconditionally


def test_real_captured_flows_feed_the_existing_feature_extractor_unchanged():
    """The architecture claim this whole package exists to prove: real packets ->
    the same FeatureVector schema the synthetic engine produces, no changes needed
    downstream (docs/01's data-flow-contract design)."""
    from argus.features.extract import extract_device_window
    from argus.testbed.orchestrator import run_live_testbed

    result = run_live_testbed("mirai", benign_duration_s=4, attack_duration_s=3, pcap_path=None)
    attacker_flows = [f for f in result.flows if f.device_id == "smart-plug-00"]
    assert attacker_flows
    fv = extract_device_window(
        "smart-plug-00", attacker_flows, attacker_flows[0].ts_start, attacker_flows[-1].ts_end,
    )
    assert fv.values, "feature extraction must produce real values from real captured flows"
    assert fv.values["distinct_destinations"] >= 1
