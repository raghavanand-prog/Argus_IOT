"""Real nftables enforcement tests. Per docs/10: "a safety mechanism that has never
been exercised is decoration" -- applies equally to the enforcement adapter itself,
not just the guard that gates it. Every assertion here is on actual, observed
socket behaviour (a connection that really succeeds or really fails), not on
whether ``nft`` returned exit code 0.
"""

from __future__ import annotations

import multiprocessing
import os
import socket
import sys
import time

import pytest

pytest.importorskip("pyroute2", reason="live-testbed extra not installed")

pytestmark = [
    pytest.mark.skipif(sys.platform != "linux", reason="nftables bridge-family filtering is Linux-only"),
    pytest.mark.skipif(os.geteuid() != 0, reason="needs root/CAP_NET_ADMIN"),
]

CTX = multiprocessing.get_context("fork")


def _echo_server(ns_name: str, ip: str, port: int, duration: float) -> None:
    from pyroute2 import netns as pyroute2_netns

    pyroute2_netns.setns(ns_name)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(5)
    end = time.time() + duration
    while time.time() < end:
        s.settimeout(max(0.05, end - time.time()))
        try:
            conn, _ = s.accept()
            conn.close()
        except TimeoutError:
            break
    s.close()


def _connect_ok(ns_name: str, dst_ip: str, dst_port: int, timeout: float, q) -> None:
    from pyroute2 import netns as pyroute2_netns

    pyroute2_netns.setns(ns_name)
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((dst_ip, dst_port))
        q.put(True)
    except OSError:
        q.put(False)


def _try_connect(ns_name: str, dst_ip: str, dst_port: int, timeout: float = 1.0) -> bool:
    q = CTX.Queue()
    p = CTX.Process(target=_connect_ok, args=(ns_name, dst_ip, dst_port, timeout, q))
    p.start()
    p.join(timeout=timeout + 2)
    return q.get(timeout=2)


@pytest.fixture
def fabric():
    from argus.respond.adapters.nft_adapter import flush_all
    from argus.testbed.fabric import NetworkFabric, cleanup_stale_fabric

    cleanup_stale_fabric()
    flush_all()
    with NetworkFabric() as fab:
        yield fab
    flush_all()


def test_isolate_tier_blocks_and_revert_restores_real_connectivity(fabric):
    from argus.respond.adapters.nft_adapter import NftablesAdapter

    victim = fabric.add_device("victim-iso")
    attacker = fabric.add_device("attacker-iso")
    srv = CTX.Process(target=_echo_server, args=(victim.ns_name, victim.ip, 9100, 20))
    srv.start()
    time.sleep(0.4)

    assert _try_connect(attacker.ns_name, victim.ip, 9100) is True

    adapter = NftablesAdapter()
    adapter.apply("iso-1", tier=4, device_id="attacker-iso", iface=attacker.root_iface)
    assert _try_connect(attacker.ns_name, victim.ip, 9100) is False, "isolated device must not reach anything"

    adapter.revert("iso-1")
    assert _try_connect(attacker.ns_name, victim.ip, 9100) is True, "connectivity must be restored after revert"

    srv.join(timeout=3)


def test_block_destination_is_narrower_than_isolate(fabric):
    """block_destination (tier 3) should stop traffic to the named target while
    leaving the device able to reach a *different* host -- the "narrowest effective
    action" principle from docs/10, verified against two real targets."""
    from argus.respond.adapters.nft_adapter import NftablesAdapter

    blocked_target = fabric.add_device("blocked-target")
    other_target = fabric.add_device("other-target")
    attacker = fabric.add_device("attacker-blockdst")

    srv1 = CTX.Process(target=_echo_server, args=(blocked_target.ns_name, blocked_target.ip, 9200, 20))
    srv2 = CTX.Process(target=_echo_server, args=(other_target.ns_name, other_target.ip, 9200, 20))
    srv1.start()
    srv2.start()
    time.sleep(0.4)

    adapter = NftablesAdapter()
    adapter.apply("blockdst-1", tier=3, device_id="attacker-blockdst",
                   iface=attacker.root_iface, dst_ip=blocked_target.ip)

    assert _try_connect(attacker.ns_name, blocked_target.ip, 9200) is False
    assert _try_connect(attacker.ns_name, other_target.ip, 9200) is True, (
        "block_destination must not collaterally block a different, unrelated destination"
    )

    adapter.revert("blockdst-1")
    assert _try_connect(attacker.ns_name, blocked_target.ip, 9200) is True

    srv1.join(timeout=3)
    srv2.join(timeout=3)


def test_kill_switch_equivalent_flush_removes_every_rule_at_once(fabric):
    from argus.respond.adapters.nft_adapter import NftablesAdapter, flush_all

    victim = fabric.add_device("victim-flush")
    attacker = fabric.add_device("attacker-flush")
    srv = CTX.Process(target=_echo_server, args=(victim.ns_name, victim.ip, 9300, 20))
    srv.start()
    time.sleep(0.4)

    adapter = NftablesAdapter()
    adapter.apply("flush-1", tier=4, device_id="attacker-flush", iface=attacker.root_iface)
    assert _try_connect(attacker.ns_name, victim.ip, 9300) is False

    flush_all()  # the single call the kill switch makes in live-enforcement mode
    assert _try_connect(attacker.ns_name, victim.ip, 9300) is True, (
        "flush_all must restore connectivity exactly like disengaging a real kill switch"
    )

    srv.join(timeout=3)


def test_live_adapter_wrapper_conforms_to_the_ladder_call_shape(fabric):
    """The exact 3-arg call ladder.decide_and_respond() already makes against any
    adapter -- proves LiveNftablesAdapter is a drop-in replacement for
    DryRunAdapter, no ladder changes required."""
    from argus.respond.adapters.live_adapter import LiveNftablesAdapter

    victim = fabric.add_device("victim-wrap")
    attacker = fabric.add_device("attacker-wrap")
    srv = CTX.Process(target=_echo_server, args=(victim.ns_name, victim.ip, 9400, 20))
    srv.start()
    time.sleep(0.4)

    adapter = LiveNftablesAdapter(links=fabric.links)
    result = adapter.apply("wrap-1", 4, "attacker-wrap")  # exactly ladder.py's call shape
    assert result["dry_run"] is False

    assert _try_connect(attacker.ns_name, victim.ip, 9400) is False
    adapter.revert("wrap-1")
    assert _try_connect(attacker.ns_name, victim.ip, 9400) is True

    srv.join(timeout=3)
