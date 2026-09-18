"""Device-control command queue + state mirror (docs/19-device-control.md).

The cloud (this module, backing both argus/api/main.py locally and
api/index.py in production) is the authoritative *queue* -- a console click
becomes a row here with status="pending" -- but it is never the authority on
whether a command is *allowed*. That decision is made on the sensor itself,
against its own local authorization file, every time, independent of
anything this module or the console ever claims. A row this module creates
is a request, not a grant.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy.orm import Session

from argus.db.models import ControlAuditRow, ControlCommandRow, LiveDeviceRow


def queue_control_command(db: Session, *, sensor_id: str, device_identifier: str, action: str) -> dict:
    command_id = str(uuid.uuid4())
    row = ControlCommandRow(
        command_id=command_id, sensor_id=sensor_id, device_identifier=device_identifier,
        action=action, requested_at=datetime.utcnow(), status="pending",
    )
    db.add(row)
    db.commit()
    return {"command_id": command_id, "status": "pending"}


def list_pending_commands(db: Session, sensor_id: str) -> list[dict]:
    rows = (
        db.query(ControlCommandRow)
        .filter_by(sensor_id=sensor_id, status="pending")
        .order_by(ControlCommandRow.requested_at)
        .all()
    )
    return [
        {"command_id": r.command_id, "device_identifier": r.device_identifier, "action": r.action,
         "requested_at": r.requested_at.isoformat()}
        for r in rows
    ]


def report_command_result(db: Session, command_id: str, status: str, result: dict) -> bool:
    row = db.query(ControlCommandRow).filter_by(command_id=command_id).first()
    if row is None:
        return False
    row.status = status
    row.result = result
    row.completed_at = datetime.utcnow()
    db.commit()
    return True


def upsert_control_device_state(db: Session, sensor_id: str, control_devices: list[dict]) -> None:
    """``control_devices``: dicts with identifier, protocol, capabilities,
    authorized -- exactly what the sensor's own local state says right now.
    Only updates devices the sensor actually reports; a device this sensor
    has never mentioned is left alone (it may belong to a different sensor)."""
    for d in control_devices:
        row = db.query(LiveDeviceRow).filter_by(identifier=d["identifier"]).first()
        if row is None:
            continue  # the device itself must already exist via normal /live/ingest discovery
        row.control_protocol = d.get("protocol")
        row.control_capabilities = d.get("capabilities", [])
        row.authorized = d.get("authorized", False)
    db.commit()


def append_control_audit(db: Session, sensor_id: str, entries: list[dict]) -> None:
    for e in entries:
        db.add(ControlAuditRow(
            ts=datetime.fromisoformat(e["ts"]), sensor_id=sensor_id,
            device_identifier=e["device_identifier"], device_ip=e["device_ip"],
            action=e["action"], protocol=e["protocol"], result=e["result"],
            authorization_state=e["authorization_state"],
        ))
    db.commit()


def list_control_audit(db: Session, limit: int = 200) -> list[dict]:
    rows = db.query(ControlAuditRow).order_by(ControlAuditRow.ts.desc()).limit(limit).all()
    return [
        {"ts": r.ts.isoformat(), "sensor_id": r.sensor_id, "device_identifier": r.device_identifier,
         "device_ip": r.device_ip, "action": r.action, "protocol": r.protocol, "result": r.result,
         "authorization_state": r.authorization_state}
        for r in rows
    ]
