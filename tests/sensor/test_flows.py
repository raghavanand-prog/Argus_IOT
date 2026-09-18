"""sensor.flows.packets_to_live_flows against real scapy packet objects built
in-memory (the same technique argus/testbed's own capture tests use) -- not a
live capture, but real Packet objects with real fields, exercised through the
actual assembly logic."""

from scapy.all import IP, UDP, Ether

from sensor.flows import packets_to_live_flows


def _udp_packet(src, sport, dst, dport, payload=b"x", ts=0.0):
    pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload
    pkt.time = ts
    return pkt


def test_unknown_endpoints_are_dropped():
    packets = [_udp_packet("10.0.0.5", 1234, "10.0.0.6", 5678, ts=1.0)]
    flows = packets_to_live_flows(packets, known_identifiers={})
    assert flows == []


def test_flow_attributed_to_known_device_regardless_of_direction():
    known = {"192.168.1.50": "mac-aabbccddeeff"}
    packets = [
        _udp_packet("192.168.1.50", 40000, "8.8.8.8", 53, payload=b"query", ts=1.0),
        _udp_packet("8.8.8.8", 53, "192.168.1.50", 40000, payload=b"response-payload", ts=1.1),
    ]
    flows = packets_to_live_flows(packets, known)
    assert len(flows) == 1
    f = flows[0]
    assert f.device_id == "mac-aabbccddeeff"
    assert f.src_ip == "192.168.1.50"
    assert f.dst_ip == "8.8.8.8"
    assert f.pkts_out == 1  # the query, sent by the device
    assert f.pkts_in == 1  # the response
    assert f.bytes_out > 0 and f.bytes_in > 0
    assert f.label == "unknown"  # no ground truth exists for real LAN traffic


def test_distinct_destination_ports_produce_distinct_flows():
    known = {"192.168.1.50": "mac-aabbccddeeff"}
    packets = [
        _udp_packet("192.168.1.50", 40000, "10.0.0.9", 100, ts=1.0),
        _udp_packet("192.168.1.50", 40001, "10.0.0.9", 200, ts=1.1),
        _udp_packet("192.168.1.50", 40002, "10.0.0.9", 300, ts=1.2),
    ]
    flows = packets_to_live_flows(packets, known)
    assert len(flows) == 3
    assert all(f.device_id == "mac-aabbccddeeff" for f in flows)


def test_tcp_and_non_ip_packets_handled():
    from scapy.all import TCP

    known = {"192.168.1.50": "mac-aabbccddeeff"}
    packets = [
        Ether() / IP(src="192.168.1.50", dst="1.1.1.1") / TCP(sport=1234, dport=443),
        Ether(),  # no IP layer at all -- must be dropped, not crash
    ]
    packets[0].time = 1.0
    flows = packets_to_live_flows(packets, known)
    assert len(flows) == 1
    assert flows[0].proto == "tcp"
