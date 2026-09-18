"""Local CLI for device-control authorization and action execution --
runnable with:

    python -m sensor.control_cli <subcommand> ...

This is deliberately a *separate* CLI from sensor.agent: authorization and
control are occasional, interactive, human-in-the-loop decisions (someone at
this specific machine choosing to trust a specific device), not part of the
continuous discovery/detection poll loop. It's also the reason console
"Device Control" buttons can't execute anything directly (see
docs/19-device-control.md) -- clicking [Authorize] or [Power Off] in the
cloud console queues an intent; running the command here is what actually
authorizes or acts, and it's the only place that ever does.

Subcommands (all one-off, interactive, human-at-this-machine actions):
  discover-capability <ip>          -- probe one device for a supported protocol (PJLink)
  authorize <ip> [--mac MAC]        -- explicitly trust a device for control (after probing it)
  revoke <ip-or-identifier>         -- remove authorization
  list                              -- show all currently-authorized devices
  set-credential <ip-or-identifier> -- store a password for a device (e.g. PJLink auth), securely
  status <ip-or-identifier>         -- query real device status (no confirmation needed)
  power-on / power-off / mute-on / mute-off <ip-or-identifier> [--yes]
                                     -- disruptive actions; prompt for confirmation unless --yes

Commands queued from the cloud console (a click on a Device Control page
button) are fulfilled separately and continuously by `sensor.agent`'s own
poll loop (--enable-control), not by this CLI -- see that module and
docs/19-device-control.md.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sensor.control.audit import AuditLog
from sensor.control.authorization import AuthorizationStore
from sensor.control.credentials import delete_credential, set_credential
from sensor.control.registry import (
    CONFIRMATION_REQUIRED_ACTIONS,
    execute_command,
    probe_capability,
)
from sensor.identifier import device_identifier


def _resolve_identifier(auth_store: AuthorizationStore, ip_or_identifier: str) -> tuple[str, str]:
    """Accepts either a raw IP (looked up against stored authorized devices
    by IP, falling back to the ip-<ip> convention) or an already-built
    identifier. Returns (identifier, ip)."""
    if ip_or_identifier.startswith(("mac-", "ip-")):
        device = auth_store.get(ip_or_identifier)
        if device is None:
            print(f"'{ip_or_identifier}' is not a currently-authorized identifier.", file=sys.stderr)
            sys.exit(1)
        return ip_or_identifier, device.ip

    ip = ip_or_identifier
    for device in auth_store.list():
        if device.ip == ip:
            return device.identifier, ip
    return device_identifier(ip, None), ip


def cmd_discover_capability(args: argparse.Namespace) -> int:
    print(f"Probing {args.ip} for a supported control protocol (PJLink, TCP port 4352)...")
    identifier = device_identifier(args.ip, args.mac)
    cap = probe_capability(identifier, args.ip)
    if cap.protocol:
        print(f"  {args.ip}: PJLink detected. Capabilities: {', '.join(cap.capabilities)}")
        print(f"  Suggested identifier: {identifier}")
        print(f"  Next: python -m sensor.control_cli authorize {args.ip}" + (f" --mac {args.mac}" if args.mac else ""))
    else:
        print(f"  {args.ip}: no supported control protocol detected ({cap.detail}).")
        print("  ARGUS has no documented control interface for this device.")
    return 0


def cmd_authorize(args: argparse.Namespace) -> int:
    auth_store = AuthorizationStore()
    identifier = device_identifier(args.ip, args.mac)
    cap = probe_capability(identifier, args.ip)
    if not cap.protocol:
        print(f"Refusing to authorize {args.ip}: no supported control protocol detected ({cap.detail}).", file=sys.stderr)
        print("Only devices with a real, detected, supported protocol can be authorized.", file=sys.stderr)
        return 1
    auth_store.authorize(identifier, args.ip, args.mac, cap.protocol, cap.capabilities)
    print(f"Authorized {identifier} ({args.ip}) for {cap.protocol} control: {', '.join(cap.capabilities)}")
    print("Status: AUTHORIZED FOR CONTROL")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    auth_store = AuthorizationStore()
    identifier, _ip = _resolve_identifier(auth_store, args.device)
    if auth_store.revoke(identifier):
        print(f"Revoked authorization for {identifier}.")
        return 0
    print(f"{identifier} was not authorized.", file=sys.stderr)
    return 1


def cmd_list(_args: argparse.Namespace) -> int:
    auth_store = AuthorizationStore()
    devices = auth_store.list()
    if not devices:
        print("No devices authorized for control.")
        return 0
    for d in devices:
        print(f"{d.identifier}  ip={d.ip}  protocol={d.protocol}  capabilities={','.join(d.capabilities)}  authorized_at={d.authorized_at}")
    return 0


def cmd_set_credential(args: argparse.Namespace) -> int:
    auth_store = AuthorizationStore()
    identifier, _ip = _resolve_identifier(auth_store, args.device)
    secret = getpass.getpass(f"Password for {identifier}: ")
    backend = set_credential(identifier, secret)
    if backend == "keychain":
        print("Stored in the OS keychain.")
    else:
        print("No OS keychain available here -- stored in ~/.argus/credentials.json with owner-only (0600) permissions.")
    return 0


def cmd_delete_credential(args: argparse.Namespace) -> int:
    auth_store = AuthorizationStore()
    identifier, _ip = _resolve_identifier(auth_store, args.device)
    delete_credential(identifier)
    print(f"Deleted stored credential for {identifier}, if any.")
    return 0


def _run_action(args: argparse.Namespace, action: str) -> int:
    auth_store = AuthorizationStore()
    audit_log = AuditLog()
    identifier, ip = _resolve_identifier(auth_store, args.device)

    device = auth_store.get(identifier)
    if device is None:
        print(f"{identifier} is not authorized for control on this machine.", file=sys.stderr)
        print("Run 'python -m sensor.control_cli authorize <ip>' first.", file=sys.stderr)
        return 1

    if action in CONFIRMATION_REQUIRED_ACTIONS and not args.yes:
        print(f"You are about to send '{action}' to:\n")
        print(f"  {identifier}")
        print(f"  {ip}")
        print(f"  protocol: {device.protocol}")
        print("\nThis device is authorized for control.\n")
        answer = input("Confirm? [y/N] ").strip().lower()
        if answer != "y":
            print("Cancelled.")
            return 1

    result = execute_command(identifier, ip, action, auth_store=auth_store, audit_log=audit_log)
    print(f"{result['result']}: {result['detail']}")
    return 0 if result["result"] == "SUCCESS" else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("discover-capability", help="Probe one device for a supported control protocol")
    p.add_argument("ip")
    p.add_argument("--mac", default=None)
    p.set_defaults(func=cmd_discover_capability)

    p = sub.add_parser("authorize", help="Authorize a device for control (after probing it)")
    p.add_argument("ip")
    p.add_argument("--mac", default=None)
    p.set_defaults(func=cmd_authorize)

    p = sub.add_parser("revoke", help="Remove authorization for a device")
    p.add_argument("device", help="IP or identifier")
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("list", help="List all authorized devices")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("set-credential", help="Store a password for a device's control protocol")
    p.add_argument("device", help="IP or identifier")
    p.set_defaults(func=cmd_set_credential)

    p = sub.add_parser("delete-credential", help="Delete a stored credential for a device")
    p.add_argument("device", help="IP or identifier")
    p.set_defaults(func=cmd_delete_credential)

    for action, help_text in [
        ("status", "Query real device status (no confirmation needed)"),
        ("power-on", "Power on an authorized device"),
        ("power-off", "Power off an authorized device"),
        ("mute-on", "Engage audio/video mute"),
        ("mute-off", "Release audio/video mute"),
    ]:
        p = sub.add_parser(action, help=help_text)
        p.add_argument("device", help="IP or identifier")
        p.add_argument("--yes", action="store_true", help="Skip the confirmation prompt")
        action_name = {"status": "get_status", "power-on": "power_on", "power-off": "power_off",
                        "mute-on": "mute_on", "mute-off": "mute_off"}[action]
        p.set_defaults(func=lambda a, act=action_name: _run_action(a, act))

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
