"""ARGUS local sensor/agent: passive device discovery + optional real packet
capture on a real LAN, feeding the exact same detection pipeline the synthetic
and CICIoT2023 tracks use (argus/collector, argus/features, argus/detect,
argus/correlate, argus/risk, argus/respond, argus/evidence). See docs/18-live-
sensor.md for the full architecture and why the live detection stack differs
from the calibrated-conformal one (no ground truth exists for real live
traffic to calibrate against).

Runs as a separate, standalone process from the ARGUS API/console -- on the
user's own Mac or Linux/Raspberry Pi, on their own LAN, with only the
permissions the user's OS already grants it (no elevated privileges required
for discovery; real packet capture is opt-in and needs whatever capture
permission the OS requires, exactly like any packet sniffer).
"""
