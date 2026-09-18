"""Real client-against-real-server tests for sensor/control/pjlink.py. Each
test starts a real MockPJLinkServer (a real TCP socket server on 127.0.0.1)
and connects PJLinkClient to it over a real socket -- exercising the actual
wire protocol exchange, not a mocked object. This is the rigor available
without real projector hardware (none was on hand -- see
docs/19-device-control.md); it proves the client's request/response handling
against a protocol-faithful server, honestly short of hardware verification.
"""

import pytest

from sensor.control.pjlink import PJLinkClient, PJLinkError
from tests.control.mock_pjlink_server import MockPJLinkServer


@pytest.fixture
def no_auth_server():
    server = MockPJLinkServer(password=None)
    server.start()
    yield server
    server.stop()


@pytest.fixture
def auth_server():
    server = MockPJLinkServer(password="secret123")
    server.start()
    yield server
    server.stop()


def test_probe_detects_real_pjlink_device(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    assert client.probe() is True


def test_probe_returns_false_for_non_pjlink_port():
    # nothing listening on this port at all
    client = PJLinkClient(host="127.0.0.1", port=1)
    assert client.probe(timeout=0.5) is False


def test_query_power_no_auth(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    assert client.query_power() == "off"


def test_power_on_then_query_reflects_real_state_change(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    client.power_on()
    assert client.query_power() == "on"
    assert no_auth_server.state["power"] == "1"


def test_power_off(no_auth_server):
    no_auth_server.state["power"] = "1"
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    client.power_off()
    assert no_auth_server.state["power"] == "0"


def test_query_input_and_set_input(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    client.set_input("21")
    assert client.query_input() == "21"


def test_query_mute(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    assert client.query_mute() == "av-unmuted"


def test_query_name(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    assert client.query_name() == "Mock Test Projector"


def test_auth_with_correct_password_succeeds(auth_server):
    client = PJLinkClient(host="127.0.0.1", port=auth_server.port, password="secret123")
    assert client.query_power() == "off"


def test_auth_with_wrong_password_raises(auth_server):
    client = PJLinkClient(host="127.0.0.1", port=auth_server.port, password="wrong-password")
    with pytest.raises(PJLinkError, match="authorization error"):
        client.query_power()


def test_auth_required_but_no_password_configured_raises(auth_server):
    client = PJLinkClient(host="127.0.0.1", port=auth_server.port, password=None)
    with pytest.raises(PJLinkError, match="requires PJLink authentication"):
        client.query_power()


def test_connection_refused_raises_pjlink_error():
    client = PJLinkClient(host="127.0.0.1", port=1, timeout=0.5)
    with pytest.raises(PJLinkError, match="connection to"):
        client.query_power()


def test_undefined_command_maps_to_real_error_meaning(no_auth_server):
    client = PJLinkClient(host="127.0.0.1", port=no_auth_server.port)
    with pytest.raises(PJLinkError, match="undefined command"):
        client._send_command("%1ZZZZ ?")
