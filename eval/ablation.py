"""The A0-A8 ablation (docs/13 §3) -- the central experiment. Disables the
correlator, risk engine, conformal gate, drift monitor, and detection tracks in
turn, and measures the effect on both detection metrics (F1) and containment
metrics (TTC, FIR, containment efficacy). The argument this table exists to test
(H1/H2, MASTER-PLAN.md): components that barely move F1 should substantially move
containment metrics.

Each configuration toggles *real* parameters on the *real* pipeline code -- there is
no separate "ablation-mode" implementation to drift out of sync with the real one:

- A1 (no correlator): bypasses ``correlate()`` with a one-incident-per-detection
  pass-through.
- A2 (no risk engine): ``assess_risk``'s own ``weights`` parameter, set to
  severity-only -- "fixed action per severity" in docs/13's words.
- A3 (no conformal gate): forces every conformal set to a singleton, i.e. escalation
  is never blocked by an uncertain prediction.
- A4 (no drift monitor): the drift monitor is never updated or consulted.
- A5 (no policy layer): ``policy_detections`` is skipped; rules + ML remain.
- A6 (detection-only, the field's L0 system): detections/incidents/risk are computed
  exactly as in A0, but the response ladder and verification are never invoked --
  identical detection metrics to A0 by construction, zero containment.
- A7 (rules only): ``ml_detections`` is skipped.
- A8 (ML only): ``policy_detections`` and ``signature_detections`` are skipped.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timedelta

from argus.behavior.drift import DeviceDriftMonitor
from argus.collector.windows import window_flows
from argus.correlate.correlator import correlate
from argus.detect.ml import CalibratedDetector, ml_detections
from argus.detect.rules import (
    identity_detections,
    policy_detections,
    signature_detections,
)
from argus.features.extract import device_ja4_set, extract_device_window
from argus.registry.enrollment import enroll
from argus.respond.guard import ActionRateLimiter, KillSwitch
from argus.respond.ladder import DryRunAdapter, decide_and_respond
from argus.risk.engine import BlastRadiusGraph, assess_risk
from argus.schemas import Incident
from argus.sim.engine import (
    build_ip_to_type,
    default_fleet,
    run_benign_window,
    run_scenario,
)
from argus.verify.verification import verify

SEVERITY_ONLY_WEIGHTS = {"severity": 1.0, "criticality": 0.0, "confidence": 0.0, "deviation": 0.0, "blast_radius": 0.0}
WINDOW_SECONDS = 300
SCENARIOS = (("mirai", "smart-plug-00", "smart-plug"), ("low_and_slow", "smart-speaker-00", "smart-speaker"))


@dataclass(frozen=True)
class AblationConfig:
    name: str
    use_correlator: bool = True
    risk_weights: dict | None = None
    force_singleton_conformal: bool = False
    use_drift_monitor: bool = True
    use_policy: bool = True
    use_rules: bool = True
    use_ml: bool = True
    enable_response: bool = True


CONFIGS: list[AblationConfig] = [
    AblationConfig("A0_full_system"),
    AblationConfig("A1_no_correlator", use_correlator=False),
    AblationConfig("A2_no_risk_engine", risk_weights=SEVERITY_ONLY_WEIGHTS),
    AblationConfig("A3_no_conformal_gate", force_singleton_conformal=True),
    AblationConfig("A4_no_drift_monitor", use_drift_monitor=False),
    AblationConfig("A5_no_policy_layer", use_policy=False),
    AblationConfig("A6_detection_only", enable_response=False),
    AblationConfig("A7_rules_only", use_ml=False),
    AblationConfig("A8_ml_only", use_policy=False, use_rules=False),
]


@dataclass
class WindowLabel:
    is_attack: bool
    detected: bool


@dataclass
class ConfigRunResult:
    config_name: str
    seed: int
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    time_to_detect_s: float | None = None
    time_to_contain_s: float | None = None
    contained: bool = False
    false_isolation_events: int = 0
    alerts_raised: int = 0
    incidents_raised: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0


def _detect_window(cfg: AblationConfig, dev_id: str, dev_type: str, w_flows: list, w_start: datetime,
                    detector: CalibratedDetector, baseline) -> list:
    fv = extract_device_window(dev_id, w_flows, w_start, w_start + timedelta(seconds=WINDOW_SECONDS))
    if not fv.values:
        return []
    detections = []
    if cfg.use_policy:
        detections += policy_detections(dev_id, dev_type, w_flows, w_start)
    if cfg.use_rules:
        detections += signature_detections(dev_id, fv, w_start)
    if cfg.use_ml:
        dets = ml_detections(dev_id, fv, detector, w_start)
        if cfg.force_singleton_conformal:
            dets = [
                dataclasses.replace(d, conformal_set=[d.conformal_set[0]] if d.conformal_set else ["attack"])
                for d in dets
            ]
        detections += dets
    if baseline is not None:
        detections += identity_detections(dev_id, device_ja4_set(dev_id, w_flows), baseline, w_start)
    return detections


def run_one(cfg: AblationConfig, scenario: str, dev_id: str, dev_type: str, seed: int) -> ConfigRunResult:
    result = ConfigRunResult(config_name=cfg.name, seed=seed)
    t0 = datetime(2026, 1, 1, 0, 0)

    devices = default_fleet()
    device = next(d for d in devices if d.device_id == dev_id)

    enroll_flows = run_benign_window([device], t0, duration_minutes=60, seed=seed)
    enroll_windows = window_flows(enroll_flows, window_seconds=90)
    fvs = [extract_device_window(dev_id, w[2], w[0], w[1]) for w in enroll_windows]
    fvs = [fv for fv in fvs if fv.values]
    enrollment = enroll(dev_id, dev_type, enroll_flows, fvs)
    baseline = enrollment.baseline

    train_flows = run_benign_window(devices, t0 + timedelta(hours=6), 120, seed=seed + 100)
    train_windows = window_flows(train_flows, window_seconds=120)
    train_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in train_windows if w[2]]
    train_fvs = [fv for fv in train_fvs if fv.values]

    calib_flows = run_benign_window(devices, t0 + timedelta(hours=12), 40, seed=seed + 200)
    calib_windows = window_flows(calib_flows, window_seconds=120)
    calib_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in calib_windows if w[2]]
    calib_fvs = [fv for fv in calib_fvs if fv.values]
    calib_labels = [0] * len(calib_fvs)
    attack_flows_for_calib, _ = run_scenario(scenario, dev_id, t0, seed=seed + 300)
    for w in window_flows(attack_flows_for_calib, window_seconds=WINDOW_SECONDS):
        fv = extract_device_window(dev_id, w[2], w[0], w[1])
        if fv.values:
            calib_fvs.append(fv)
            calib_labels.append(1)

    detector = CalibratedDetector()
    detector.fit(train_fvs, calib_fvs, calib_labels)

    # The evaluation window: real benign traffic for this device across a period,
    # with the attack scenario's flows layered into the middle of it -- so windows
    # genuinely split into a benign holdout (before/after) and an attack region,
    # not "every window is attack" (which would make F1 uninformative).
    attack_start = t0 + timedelta(hours=2)
    attack_flows, ground_truth = run_scenario(scenario, dev_id, attack_start, seed=seed + 10)
    attack_span_end = max((e.t_end for e in ground_truth), default=attack_start)
    pre_benign = run_benign_window([device], attack_start - timedelta(minutes=30), 30, seed=seed + 11)
    post_benign = run_benign_window([device], attack_span_end, 30, seed=seed + 12)

    all_flows = sorted([*pre_benign, *attack_flows, *post_benign], key=lambda f: f.ts_start)
    windows = window_flows(all_flows, window_seconds=WINDOW_SECONDS)

    drift_monitor = DeviceDriftMonitor()
    all_detections = []
    window_labels: list[WindowLabel] = []
    for w_start, w_end, w_flows in windows:
        is_attack_window = any(
            ev.t_start <= w_start <= ev.t_end or ev.t_start <= w_end <= ev.t_end or (w_start <= ev.t_start and w_end >= ev.t_end)
            for ev in ground_truth
        )
        dets = _detect_window(cfg, dev_id, dev_type, w_flows, w_start, detector, baseline)
        all_detections += dets
        window_labels.append(WindowLabel(is_attack=is_attack_window, detected=bool(dets)))

        if cfg.use_drift_monitor and baseline is not None:
            fv = extract_device_window(dev_id, w_flows, w_start, w_end)
            if fv.values:
                drift_monitor.update(dev_id, fv.values)

    for wl in window_labels:
        if wl.is_attack and wl.detected:
            result.tp += 1
        elif wl.is_attack and not wl.detected:
            result.fn += 1
        elif not wl.is_attack and wl.detected:
            result.fp += 1
        else:
            result.tn += 1

    first_detection_ts = min((d.ts for d in all_detections if d.ts >= attack_start), default=None)
    first_attack_ts = min((e.t_start for e in ground_truth), default=None)
    if first_detection_ts and first_attack_ts:
        result.time_to_detect_s = (first_detection_ts - first_attack_ts).total_seconds()

    if not all_detections:
        return result

    incidents: list[Incident] = (
        correlate(all_detections) if cfg.use_correlator else _passthrough_incidents(all_detections)
    )
    result.incidents_raised = len(incidents)
    det_map = {d.detection_id: d for d in all_detections}
    ip_to_type = build_ip_to_type(devices)
    graph = BlastRadiusGraph(edges={dev_id: {f.dst_ip for f in attack_flows}})
    blast = graph.score(dev_id, device_type_of=ip_to_type.get)
    is_drifting = drift_monitor.is_drifting(dev_id) if cfg.use_drift_monitor else False

    kill_switch = KillSwitch()
    rate_limiter = ActionRateLimiter()
    adapter = DryRunAdapter()

    for incident in incidents:
        incident_dets = [det_map[i] for i in incident.detection_ids if i in det_map]
        # deviation (the behaviour engine's median/MAD score) is left at 0 here,
        # consistently across every config -- it's not part of what's being
        # ablated, and folding it in would need a per-window deviation history this
        # harness doesn't otherwise track; severity/confidence/blast_radius still
        # vary genuinely per config via cfg.risk_weights and cfg.force_singleton_conformal
        risk = assess_risk(incident, all_detections, dev_type, 0.0, blast, weights=cfg.risk_weights)
        best_conformal = next((d.conformal_set for d in incident_dets if d.conformal_set), None)
        result.alerts_raised += 1

        if not cfg.enable_response:
            continue  # A6: detection-only -- never respond, never verify, zero containment by construction

        outcome = decide_and_respond(
            device_id=dev_id, device_type=dev_type, risk_score=risk.score,
            conformal_set=best_conformal, is_drifting=is_drifting,
            kill_switch=kill_switch, rate_limiter=rate_limiter,
            enforce_enabled=False, adapter=adapter, now=incident.last_seen.timestamp(),
        )
        if outcome.action_id:
            vr = verify(outcome.action_id, dev_id, incident.last_seen, outcome.tier, ground_truth)
            if vr.outcome == "contained" and not result.contained:
                result.contained = True
                if first_attack_ts:
                    result.time_to_contain_s = (incident.last_seen - first_attack_ts).total_seconds()
            elif vr.outcome == "collateral_damage":
                result.false_isolation_events += 1

    return result


def _passthrough_incidents(detections: list) -> list[Incident]:
    return [
        Incident(
            incident_id=d.detection_id, first_seen=d.ts, last_seen=d.ts,
            device_ids=[d.device_id], detection_ids=[d.detection_id],
            chain_position=d.signal_name, agreement_score=0.0,
        )
        for d in detections
    ]


def run_ablation(seeds: list[int] | None = None) -> dict[str, list[ConfigRunResult]]:
    seeds = seeds or [1, 2, 3, 4, 5]
    results: dict[str, list[ConfigRunResult]] = {cfg.name: [] for cfg in CONFIGS}
    for cfg in CONFIGS:
        for seed in seeds:
            per_scenario = [run_one(cfg, scenario, dev_id, dev_type, seed) for scenario, dev_id, dev_type in SCENARIOS]
            merged = ConfigRunResult(
                config_name=cfg.name, seed=seed,
                tp=sum(r.tp for r in per_scenario), fp=sum(r.fp for r in per_scenario),
                fn=sum(r.fn for r in per_scenario), tn=sum(r.tn for r in per_scenario),
                time_to_detect_s=_first_not_none(r.time_to_detect_s for r in per_scenario),
                time_to_contain_s=_first_not_none(r.time_to_contain_s for r in per_scenario),
                contained=any(r.contained for r in per_scenario),
                false_isolation_events=sum(r.false_isolation_events for r in per_scenario),
                alerts_raised=sum(r.alerts_raised for r in per_scenario),
                incidents_raised=sum(r.incidents_raised for r in per_scenario),
            )
            results[cfg.name].append(merged)
    return results


def _first_not_none(values):
    for v in values:
        if v is not None:
            return v
    return None
