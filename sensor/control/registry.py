"""Capability-based device control: the "is this device controllable" chain
(reachable? protocol identifiable? supported? authorized?) and the single
enforcement checkpoint every control action -- CLI or cloud-queued -- must
pass through.

This is the module that makes "authorization lives locally on the sensor" a
real security property, not just a storage location: execute_command() below
checks the LOCAL AuthorizationStore itself, every single time, regardless of
who is asking. A command relayed from the cloud console is treated exactly
the same as one typed at this machine's own CLI -- if this machine's local
file doesn't say the device is authorized, nothing happens, full stop. A
stolen ARGUS_ADMIN_TOKEN alone can queue a cloud command, but it can never
make this machine act on an unauthorized device.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sensor.control.audit import AuditLog, ControlAuditEntry
from sensor.control.authorization import AuthorizationStore
from sensor.control.credentials import get_credential
from sensor.control.pjlink import PJLinkClient, PJLinkError

PJLINK_CAPABILITIES = ["power", "input", "mute", "status"]

SUPPORTED_ACTIONS = {"get_status", "power_on", "power_off", "mute_on", "mute_off"}
# Actions the user must explicitly confirm before they execute (docs/19,
# section 7 of the project owner's spec) -- disruptive/state-changing;
# get_status is a harmless read, needs no confirmation.
CONFIRMATION_REQUIRED_ACTIONS = {"power_on", "power_off", "mute_on", "mute_off"}


@dataclass
class DeviceCapability:
    identifier: str
    ip: str
    reachable: bool
    protocol: str | None
    capabilities: list[str] = field(default_factory=list)
    detail: str = ""


def probe_capability(identifier: str, ip: str, timeout: float = 3.0, port: int = 4352) -> DeviceCapability:
    """A single, explicit, user-requested probe against one device -- never
    called automatically against every discovered device (that would be a
    network-wide scan, which the project's safety requirements explicitly
    rule out). Currently checks PJLink only; the framework is built to add
    more documented protocols without changing this shape. ``port`` defaults
    to the standard PJLink port but is overridable (real devices occasionally
    run it non-standard, and it lets tests point this at a real mock server)."""
    client = PJLinkClient(host=ip, timeout=timeout, port=port)
    if client.probe(timeout=timeout):
        return DeviceCapability(
            identifier=identifier, ip=ip, reachable=True, protocol="pjlink",
            capabilities=list(PJLINK_CAPABILITIES), detail="responded with a real PJLink greeting",
        )
    return DeviceCapability(
        identifier=identifier, ip=ip, reachable=False, protocol=None, capabilities=[],
        detail="no PJLink response on port 4352 -- no other documented control protocol is implemented yet",
    )


def execute_command(
    identifier: str, ip: str, action: str, *,
    auth_store: AuthorizationStore, audit_log: AuditLog, requested_by: str = "local-cli",
    port: int = 4352,
) -> dict:
    """The one enforcement checkpoint. Always re-checks LOCAL authorization,
    always writes an audit entry (success, failure, AND denial -- an audit
    trail that only records successes isn't an audit trail). Never raises --
    every outcome, including a programming error in this function's own
    protocol call, is caught and recorded rather than crashing whatever
    process called this (the sensor's main loop, or the CLI)."""
    authorized_device = auth_store.get(identifier)

    if authorized_device is None:
        entry = ControlAuditEntry(
            device_identifier=identifier, device_ip=ip, action=action, protocol="unknown",
            result="DENIED", authorization_state="not_authorized", requested_by=requested_by,
            detail="device is not authorized for control on this machine",
        )
        audit_log.record(entry)
        return {"result": "DENIED", "detail": entry.detail}

    if action not in SUPPORTED_ACTIONS:
        entry = ControlAuditEntry(
            device_identifier=identifier, device_ip=ip, action=action, protocol=authorized_device.protocol,
            result="FAILURE", authorization_state="authorized", requested_by=requested_by,
            detail=f"unsupported action: {action!r}",
        )
        audit_log.record(entry)
        return {"result": "FAILURE", "detail": entry.detail}

    if authorized_device.protocol != "pjlink":
        entry = ControlAuditEntry(
            device_identifier=identifier, device_ip=ip, action=action, protocol=authorized_device.protocol,
            result="FAILURE", authorization_state="authorized", requested_by=requested_by,
            detail=f"no control implementation for protocol {authorized_device.protocol!r}",
        )
        audit_log.record(entry)
        return {"result": "FAILURE", "detail": entry.detail}

    password = get_credential(identifier)
    client = PJLinkClient(host=ip, password=password, port=port)
    try:
        detail = _run_pjlink_action(client, action)
        entry = ControlAuditEntry(
            device_identifier=identifier, device_ip=ip, action=action, protocol="pjlink",
            result="SUCCESS", authorization_state="authorized", requested_by=requested_by, detail=detail,
        )
        audit_log.record(entry)
        return {"result": "SUCCESS", "detail": detail}
    except PJLinkError as e:
        entry = ControlAuditEntry(
            device_identifier=identifier, device_ip=ip, action=action, protocol="pjlink",
            result="FAILURE", authorization_state="authorized", requested_by=requested_by, detail=str(e),
        )
        audit_log.record(entry)
        return {"result": "FAILURE", "detail": str(e)}


def _run_pjlink_action(client: PJLinkClient, action: str) -> str:
    if action == "get_status":
        return f"power={client.query_power()}, mute={client.query_mute()}"
    if action == "power_on":
        client.power_on()
        return "power on command sent"
    if action == "power_off":
        client.power_off()
        return "power off command sent"
    if action == "mute_on":
        client.set_mute("31")
        return "audio/video mute engaged"
    if action == "mute_off":
        client.set_mute("30")
        return "audio/video mute released"
    raise PJLinkError(f"unsupported action: {action!r}")  # unreachable given SUPPORTED_ACTIONS check above
