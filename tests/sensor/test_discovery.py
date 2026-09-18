"""Real assertions on sensor.discovery's parsing/state logic (CLAUDE.md's testing
expectations) -- fixture text shaped exactly like real /proc/net/arp and `arp -a`
output, not fabricated network fields presented as live data."""

from datetime import datetime

from sensor.discovery import (
    DiscoveryState,
    ObservedNeighbour,
    _normalise_mac,
    _parse_arp_a_output,
    _read_proc_net_arp,
)

PROC_NET_ARP_FIXTURE = """\
IP address       HW type     Flags       HW address            Mask     Device
192.168.1.1      0x1         0x2         B8:27:EB:11:22:33     *        eth0
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0
192.168.1.99     0x1         0x2         34:EA:34:AA:BB:CC     *        eth0
"""

ARP_A_FIXTURE = """\
? (192.168.1.1) at b8:27:eb:11:22:33 [ether] on eth0
? (192.168.1.99) at 34:ea:34:aa:bb:cc [ether] on eth0
? (192.168.1.200) at <incomplete> on eth0
"""


def test_normalise_mac_rejects_incomplete_and_zero():
    assert _normalise_mac("00:00:00:00:00:00") is None
    assert _normalise_mac("<incomplete>") is None
    assert _normalise_mac("b8:27:eb:11:22:33") == "B8:27:EB:11:22:33"


def test_read_proc_net_arp_skips_incomplete_entries(tmp_path):
    path = tmp_path / "arp"
    path.write_text(PROC_NET_ARP_FIXTURE)
    neighbours = _read_proc_net_arp(str(path))
    # the 0x0-flag (incomplete) row must be dropped, not surfaced with a fake MAC
    assert {n.ip for n in neighbours} == {"192.168.1.1", "192.168.1.99"}
    by_ip = {n.ip: n for n in neighbours}
    assert by_ip["192.168.1.1"].mac == "B8:27:EB:11:22:33"
    assert by_ip["192.168.1.1"].interface == "eth0"


def test_parse_arp_a_output_resolves_macs_and_marks_incomplete_as_unresolved():
    # unlike _read_proc_net_arp (which drops incomplete kernel entries outright via
    # the flags check), arp -a has no equivalent flag to filter on -- an
    # "<incomplete>" entry is kept with mac=None, matching ObservedNeighbour's own
    # documented semantics ("None if the OS's own neighbour entry has no resolved
    # MAC yet"), not silently dropped.
    neighbours = _parse_arp_a_output(ARP_A_FIXTURE)
    assert {n.ip for n in neighbours} == {"192.168.1.1", "192.168.1.99", "192.168.1.200"}
    by_ip = {n.ip: n for n in neighbours}
    assert by_ip["192.168.1.99"].mac == "34:EA:34:AA:BB:CC"
    assert by_ip["192.168.1.200"].mac is None


def test_discovery_state_looks_up_vendor_and_tracks_first_last_seen():
    state = DiscoveryState()
    t1 = datetime(2026, 1, 1, 0, 0, 0)
    neighbours = [ObservedNeighbour(ip="192.168.1.99", mac="34:EA:34:AA:BB:CC", interface="eth0")]
    state._devices  # noqa: B018 -- sanity: internal store starts empty
    for n in neighbours:
        identifier = f"mac-{n.mac.replace(':', '').lower()}"
        assert identifier not in state._devices

    # simulate two polls at different times against the same neighbour table
    import sensor.discovery as discovery_mod

    original = discovery_mod.read_neighbour_table
    discovery_mod.read_neighbour_table = lambda: neighbours
    try:
        devices_t1 = state.poll(now=t1)
        assert len(devices_t1) == 1
        d = devices_t1[0]
        assert d.ip == "192.168.1.99"
        assert d.vendor == "Espressif (ESP8266/ESP32)"
        assert d.device_type == "unknown"
        assert d.first_seen == t1 and d.last_seen == t1

        t2 = datetime(2026, 1, 1, 0, 5, 0)
        devices_t2 = state.poll(now=t2)
        assert len(devices_t2) == 1  # same device, not duplicated
        assert devices_t2[0].first_seen == t1  # unchanged
        assert devices_t2[0].last_seen == t2  # updated
    finally:
        discovery_mod.read_neighbour_table = original


def test_discovery_state_falls_back_to_ip_identifier_without_mac():
    state = DiscoveryState()
    neighbours = [ObservedNeighbour(ip="192.168.1.5", mac=None, interface="eth0")]

    import sensor.discovery as discovery_mod

    original = discovery_mod.read_neighbour_table
    discovery_mod.read_neighbour_table = lambda: neighbours
    try:
        devices = state.poll(now=datetime(2026, 1, 1))
        assert devices[0].identifier == "ip-192.168.1.5"
        assert devices[0].vendor is None
    finally:
        discovery_mod.read_neighbour_table = original
