"""Flow windowing: turns a raw flow stream into fixed-size per-device windows for
feature extraction (docs/05's "30s rolling window" idea, simplified for the sim engine).
"""

from __future__ import annotations

from datetime import datetime, timedelta

from argus.schemas import FlowRecord


def window_flows(flows: list[FlowRecord], window_seconds: int = 60
                  ) -> list[tuple[datetime, datetime, list[FlowRecord]]]:
    if not flows:
        return []
    flows = sorted(flows, key=lambda f: f.ts_start)
    start = flows[0].ts_start
    end = flows[-1].ts_end
    windows: list[tuple[datetime, datetime, list[FlowRecord]]] = []
    cur = start
    while cur < end:
        w_end = cur + timedelta(seconds=window_seconds)
        in_window = [f for f in flows if cur <= f.ts_start < w_end]
        if in_window:
            windows.append((cur, w_end, in_window))
        cur = w_end
    return windows


def device_ids_in(flows: list[FlowRecord]) -> list[str]:
    seen: list[str] = []
    for f in flows:
        if f.device_id not in seen:
            seen.append(f.device_id)
    return seen
