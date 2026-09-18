"""The ARGUS local sensor -- runnable with one command:

    python -m sensor.agent --api-url http://localhost:8000 --token <ARGUS_ADMIN_TOKEN>

Default behaviour is passive discovery only: reads the OS's own ARP/
neighbour cache on a fixed interval and reports discovered devices to the
configured ARGUS API. Nothing is sent onto the network, nothing is scanned,
no traffic is captured. This *is* the explicit "start monitoring" action --
running this command is the user's deliberate choice; there is no separate
always-on background mode.

Real packet capture (and therefore flow-based detection) is a separate,
explicit opt-in: --enable-capture, plus the interfaces to capture on. This is
the more invasive tier the safety requirements call out, so it never runs by
itself.

The sensor never takes any response action -- no blocking, no isolation, no
packets sent to a discovered device. It only detects and reports; the
existing kill switch and dry-run default in ARGUS's response ladder govern
everything downstream of that, unchanged.
"""

from __future__ import annotations

import argparse
import socket
import sys
import time
from dataclasses import asdict
from datetime import UTC, datetime

from sensor.client import ArgusApiClient
from sensor.control.audit import AuditLog
from sensor.control.authorization import AuthorizationStore
from sensor.control.registry import execute_command
from sensor.discovery import DiscoveryState

# Everything below is capture-mode-only (needs scapy, an optional dependency --
# see pyproject.toml's `live-testbed` extra) and is imported lazily, inside
# run(), only when --enable-capture is actually passed. Discovery-only mode is
# documented as the safe, no-elevated-privilege default; importing scapy just
# to start the process in that mode would silently break that promise for
# anyone who installed the base package (`pip install -e .`) without the
# capture extra, which is exactly what happened on first real-world use (a
# real bug, not hypothetical -- see progress.md).


def _device_to_payload(d) -> dict:
    return {
        "identifier": d.identifier, "ip": d.ip, "mac": d.mac, "vendor": d.vendor,
        "device_type": d.device_type, "interface": d.interface, "hostname": d.hostname,
        "discovery_sources": d.discovery_sources,
        "first_seen": d.first_seen.isoformat(), "last_seen": d.last_seen.isoformat(),
        "flow_count": d.flow_count, "monitored": d.monitored,
    }


def _detection_to_payload(det) -> dict:
    payload = asdict(det)
    payload["ts"] = det.ts.isoformat()
    return payload


def _import_capture_stack():
    """Imports everything capture mode needs, and only capture mode -- see the
    module-level comment above for why this must not happen at import time."""
    try:
        from argus.collector.windows import window_flows
        from argus.detect.rules import signature_detections
        from argus.features.extract import extract_device_window
        from argus.testbed.capture import CaptureSession
        from sensor.baseline import build_live_baseline
        from sensor.flows import packets_to_live_flows
        from sensor.live_detect import (
            MIN_BASELINE_WINDOWS,
            LiveAnomalyDetector,
            live_anomaly_detections,
        )
    except ImportError as e:
        raise ImportError(
            "--enable-capture needs the optional 'live-testbed' extra (scapy, for real "
            "packet capture) -- install it with: pip install -e '.[live-testbed]'"
        ) from e
    return {
        "window_flows": window_flows, "signature_detections": signature_detections,
        "extract_device_window": extract_device_window, "CaptureSession": CaptureSession,
        "build_live_baseline": build_live_baseline, "packets_to_live_flows": packets_to_live_flows,
        "MIN_BASELINE_WINDOWS": MIN_BASELINE_WINDOWS, "LiveAnomalyDetector": LiveAnomalyDetector,
        "live_anomaly_detections": live_anomaly_detections,
    }


def run(args: argparse.Namespace) -> int:
    sensor_id = args.sensor_id or f"sensor-{socket.gethostname()}"
    client = ArgusApiClient(base_url=args.api_url, token=args.token)

    cap_stack = None
    if args.enable_capture:
        try:
            cap_stack = _import_capture_stack()
        except ImportError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1

    mdns = None
    if args.enable_mdns:
        try:
            from sensor.mdns import MDNSListener
        except ImportError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            return 1
        mdns = MDNSListener()
        mdns.start()

    print(f"ARGUS local sensor starting -- sensor_id={sensor_id}")
    print(f"  target API: {args.api_url}")
    reachable, detail = client.check_reachable()
    print(f"  connection check: {'OK' if reachable else 'FAILED'} ({detail})")
    if not reachable:
        print("  Cannot reach the configured ARGUS API. Check --api-url and that the API is running.")
        return 1

    print(f"  discovery mode: passive ARP/neighbour-table read (interval {args.poll_interval}s)")
    if args.enable_capture:
        print(f"  capture mode: ENABLED on interfaces {args.interfaces} -- real packet capture, opt-in")
        if args.target_host:
            print(f"    scoped to --target-host {args.target_host} only (BPF filter, enforced by the kernel --")
            print("    no other device's traffic is ever captured, let alone reported)")
        else:
            print("    WARNING: no --target-host set -- this captures ALL traffic on the given interface(s).")
            print("    On a network you don't administer (e.g. a shared/college/office LAN), that captures other")
            print("    people's traffic shapes without their consent. Use --target-host <ip> to scope this to a")
            print("    single device you own, or get explicit authorization from the network owner first.")
    else:
        print("  capture mode: disabled (device discovery only -- pass --enable-capture to detect on real traffic)")
    if args.resolve_hostnames:
        print(f"  hostname resolution: ENABLED (reverse DNS, bounded to {args.max_hostname_lookups_per_poll} new lookups/poll)")
    if args.enable_mdns:
        print("  mDNS discovery: ENABLED (standard multicast-DNS queries, same mechanism any Chromecast/AirPlay finder uses)")
    if args.enable_control:
        print("  device control: ENABLED -- fulfills commands queued from the console, but ONLY for devices")
        print("    authorized on THIS machine (~/.argus/authorized_devices.json). The cloud can queue a request;")
        print("    it can never grant authorization -- that only ever happens via 'python -m sensor.control_cli")
        print("    authorize <ip>', run here, by you.")
    print("  Never sends traffic to discovered devices. Never blocks or isolates anything.")
    print()

    discovery = DiscoveryState(
        resolve_hostnames=args.resolve_hostnames, mdns=mdns,
        max_hostname_lookups_per_poll=args.max_hostname_lookups_per_poll,
    )
    try:
        return _run_loop(args, client, sensor_id, discovery, cap_stack)
    finally:
        if mdns is not None:
            mdns.stop()


def _fulfil_control_commands(client, sensor_id, auth_store, audit_log, audit_entries_reported: int) -> int:
    """Reports this machine's own local authorization/capability state and
    any new local audit entries, then fetches and fulfils commands the
    console has queued for this sensor -- each one re-checked against the
    LOCAL AuthorizationStore by execute_command(), never trusting the queue
    entry itself as authorization (see sensor/control/registry.py's module
    docstring). Returns the updated audit_entries_reported count. A failure
    anywhere here (network error, one bad command) is caught and logged,
    never allowed to crash the sensor's main loop -- same principle as the
    ingest submission just above it."""
    try:
        control_devices = [
            {"identifier": d.identifier, "protocol": d.protocol, "capabilities": d.capabilities, "authorized": True}
            for d in auth_store.list()
        ]
        all_entries = audit_log.read_all()
        new_entries = all_entries[audit_entries_reported:]
        client.report_control_state(sensor_id, control_devices, new_entries)
        audit_entries_reported = len(all_entries)

        pending = client.poll_control_commands(sensor_id)
        for cmd in pending:
            result = execute_command(
                cmd["device_identifier"], _ip_for(auth_store, cmd["device_identifier"]) or "",
                cmd["action"], auth_store=auth_store, audit_log=audit_log, requested_by="cloud-console",
            )
            status = "fulfilled" if result["result"] == "SUCCESS" else result["result"].lower()
            client.report_command_result(cmd["command_id"], status, result)
            print(f"  [control] {cmd['action']} on {cmd['device_identifier']}: {result['result']} -- {result['detail']}")
            # execute_command already wrote its own local audit entry; report it next poll too
        if pending:
            all_entries = audit_log.read_all()
            client.report_control_state(sensor_id, control_devices, all_entries[audit_entries_reported:])
            audit_entries_reported = len(all_entries)
    except Exception as e:  # noqa: BLE001 -- one failed control cycle must not crash the sensor loop
        print(f"  [control] FAILED to sync with API: {e}")
    return audit_entries_reported


def _ip_for(auth_store, identifier: str) -> str | None:
    device = auth_store.get(identifier)
    return device.ip if device else None


def _run_loop(args, client, sensor_id, discovery, cap_stack) -> int:
    baselines: dict[str, object] = {}
    detectors: dict[str, object] = {}
    feature_history: dict[str, list] = {}
    flow_counts: dict[str, int] = {}

    auth_store = AuthorizationStore() if args.enable_control else None
    audit_log = AuditLog() if args.enable_control else None
    audit_entries_reported = 0

    iteration = 0
    while True:
        iteration += 1
        devices = discovery.poll()
        known_identifiers = {d.ip: d.identifier for d in devices}
        detections_payload: list[dict] = []

        if args.enable_capture:
            bpf_filter = f"host {args.target_host}" if args.target_host else None
            cap = cap_stack["CaptureSession"](ifaces=args.interfaces, bpf_filter=bpf_filter)
            cap.start()
            time.sleep(args.window_seconds)
            packets = cap.stop()
            flows = cap_stack["packets_to_live_flows"](packets, known_identifiers)
            windows = cap_stack["window_flows"](flows, window_seconds=args.window_seconds)

            for w_start, w_end, w_flows in windows:
                dev_id = w_flows[0].device_id
                fv = cap_stack["extract_device_window"](dev_id, w_flows, w_start, w_end)
                if not fv.values:
                    continue
                flow_counts[dev_id] = flow_counts.get(dev_id, 0) + len(w_flows)
                history = feature_history.setdefault(dev_id, [])
                history.append(fv)

                if dev_id not in baselines:
                    # median/MAD identity baseline only needs one window -- build it as soon as
                    # a device has any observed traffic
                    baseline = cap_stack["build_live_baseline"](dev_id, w_flows, [fv])
                    if baseline:
                        baselines[dev_id] = baseline

                detector = detectors.get(dev_id)
                if detector is None or not detector.fitted:
                    # LiveAnomalyDetector.fit() itself declines to fit below MIN_BASELINE_WINDOWS
                    # (sensor/live_detect.py) -- keep accumulating this device's own windows until
                    # there's enough to fit a meaningful model, then fit once. Never score against
                    # an unfitted detector: live_anomaly_detections() already refuses to, but there's
                    # no point running signature_detections on a device we haven't finished baselining.
                    if len(history) >= cap_stack["MIN_BASELINE_WINDOWS"]:
                        detector = cap_stack["LiveAnomalyDetector"](device_id=dev_id)
                        detector.fit(history)
                        detectors[dev_id] = detector
                    continue

                ts = datetime.now(UTC)
                dets = list(cap_stack["signature_detections"](dev_id, fv, ts))
                dets += cap_stack["live_anomaly_detections"](dev_id, fv, detector, ts)
                detections_payload.extend(_detection_to_payload(d) for d in dets)

            for d in devices:
                d.flow_count = flow_counts.get(d.identifier, 0)
                # "monitored" means real anomaly detection is actually running for this device,
                # not just that an identity baseline exists -- a device still accumulating its
                # first MIN_BASELINE_WINDOWS windows has no fitted detector yet
                det = detectors.get(d.identifier)
                d.monitored = det is not None and det.fitted
        else:
            for d in devices:
                d.flow_count = 0
                d.monitored = False

        try:
            result = client.ingest(
                sensor_id=sensor_id, hostname=socket.gethostname(),
                monitoring_active=args.enable_capture,
                devices=[_device_to_payload(d) for d in devices],
                detections=detections_payload,
            )
            print(
                f"[{datetime.now().strftime('%H:%M:%S')}] poll #{iteration}: "
                f"{len(devices)} device(s) observed, {len(detections_payload)} detection(s), "
                f"{result.get('incidents_generated', 0)} incident(s) generated"
            )
        except Exception as e:  # noqa: BLE001 -- a single failed submission must not crash the sensor loop
            print(f"[{datetime.now().strftime('%H:%M:%S')}] poll #{iteration}: FAILED to submit to API: {e}")

        if args.enable_control:
            audit_entries_reported = _fulfil_control_commands(
                client, sensor_id, auth_store, audit_log, audit_entries_reported,
            )

        if args.once:
            return 0
        if not args.enable_capture:
            # capture mode already spends window_seconds sniffing, which paces the loop
            # on its own; discovery-only mode needs its own explicit pacing.
            time.sleep(args.poll_interval)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ARGUS local sensor: passive LAN device discovery + optional real flow-based detection.",
    )
    parser.add_argument("--api-url", required=True, help="ARGUS API base URL, e.g. http://localhost:8000 or https://argus-iot-live.vercel.app/api")
    parser.add_argument("--token", required=True, help="ARGUS_ADMIN_TOKEN for the target API")
    parser.add_argument("--sensor-id", default=None, help="Defaults to sensor-<hostname>")
    parser.add_argument("--poll-interval", type=float, default=30.0, help="Seconds between discovery polls (discovery-only mode)")
    parser.add_argument("--window-seconds", type=float, default=60.0, help="Capture window length in capture mode")
    parser.add_argument("--enable-capture", action="store_true", help="Opt in to real packet capture + flow-based detection")
    parser.add_argument("--interfaces", nargs="+", default=["eth0"], help="Interfaces to capture on, if --enable-capture")
    parser.add_argument(
        "--target-host", default=None,
        help="Scope --enable-capture to exactly one device's IP via a real BPF filter (enforced by the kernel, "
             "not a post-hoc filter) -- no other device's traffic is ever captured. Strongly recommended on any "
             "network you don't administer yourself; without it, --enable-capture captures ALL traffic on the "
             "given interface(s).",
    )
    parser.add_argument("--once", action="store_true", help="Run a single poll and exit (for testing)")
    parser.add_argument(
        "--resolve-hostnames", action="store_true",
        help="Opt in to reverse-DNS hostname lookups for discovered devices (a real network call, bounded per "
             "poll -- off by default, matching passive-minimal discovery).",
    )
    parser.add_argument(
        "--max-hostname-lookups-per-poll", type=int, default=5,
        help="Cap on new reverse-DNS lookups per poll, if --resolve-hostnames is set (keeps a large network's "
             "neighbour table from making a single poll take hours).",
    )
    parser.add_argument(
        "--enable-mdns", action="store_true",
        help="Opt in to mDNS/Bonjour discovery (standard multicast-DNS queries -- the same mechanism any "
             "Chromecast/AirPlay/printer-finder app uses, not port scanning). Off by default.",
    )
    parser.add_argument(
        "--enable-control", action="store_true",
        help="Opt in to fulfilling device-control commands queued from the console (e.g. a [Power Off] click). "
             "Every command is re-checked against THIS machine's own local authorization store "
             "(~/.argus/authorized_devices.json, managed via 'python -m sensor.control_cli') before anything "
             "happens -- the cloud can request, never authorize. Off by default.",
    )
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
