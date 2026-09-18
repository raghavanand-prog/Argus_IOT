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
        "device_type": d.device_type, "interface": d.interface,
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
    else:
        print("  capture mode: disabled (device discovery only -- pass --enable-capture to detect on real traffic)")
    print("  Never sends traffic to discovered devices. Never blocks or isolates anything.")
    print()

    discovery = DiscoveryState()
    baselines: dict[str, object] = {}
    detectors: dict[str, object] = {}
    feature_history: dict[str, list] = {}
    flow_counts: dict[str, int] = {}

    iteration = 0
    while True:
        iteration += 1
        devices = discovery.poll()
        known_identifiers = {d.ip: d.identifier for d in devices}
        detections_payload: list[dict] = []

        if args.enable_capture:
            cap = cap_stack["CaptureSession"](ifaces=args.interfaces)
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
    parser.add_argument("--once", action="store_true", help="Run a single poll and exit (for testing)")
    args = parser.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
