"""The orchestrator: wires every module in docs/01's component diagram into one
runnable loop, and persists the result to the datastore. This is what the API reads
from and what `scripts/seed_demo.py` calls to populate a demo database.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from argus.behavior.deviation import deviation_score
from argus.behavior.drift import DeviceDriftMonitor
from argus.collector.windows import window_flows
from argus.correlate.correlator import correlate
from argus.db.models import (
    ActionRow, AuditLogRow, DeviceRow, EvidenceBundleRow, IncidentRow,
    RiskAssessmentRow, VerificationRow,
)
from argus.detect.ml import CalibratedDetector, ml_detections
from argus.detect.rules import policy_detections, signature_detections
from argus.evidence.bundle import EvidenceLedger
from argus.features.extract import extract_device_window
from argus.registry.enrollment import enroll
from argus.respond.guard import ActionRateLimiter, KillSwitch
from argus.respond.ladder import DryRunAdapter, decide_and_respond
from argus.risk.engine import BlastRadiusGraph, assess_risk
from argus.schemas import DeviceState
from argus.sim.engine import default_fleet, run_benign_window, run_scenario
from argus.verify.verification import verify

ENFORCE = os.getenv("ARGUS_ENFORCE", "false").lower() == "true"
CONFORMAL_ALPHA = float(os.getenv("ARGUS_CONFORMAL_ALPHA", "0.05"))


def run_demo_pipeline(db: Session, seed: int = 42) -> dict:
    """Runs enrollment -> a benign window -> two attack scenarios -> the full detect/
    respond/verify loop, and persists devices, incidents, risk, evidence bundles,
    actions and verifications. Returns a small summary dict for logging."""

    devices = default_fleet()
    t0 = datetime(2026, 1, 1, 0, 0)
    ledger = EvidenceLedger()
    kill_switch = KillSwitch()
    rate_limiter = ActionRateLimiter()
    drift_monitor = DeviceDriftMonitor()
    adapter = DryRunAdapter()

    baselines: dict[str, object] = {}
    for dev in devices:
        flows = run_benign_window([dev], t0, duration_minutes=90, seed=seed)
        windows = window_flows(flows, window_seconds=90)
        fvs = [extract_device_window(dev.device_id, w[2], w[0], w[1]) for w in windows]
        fvs = [fv for fv in fvs if fv.values]
        result = enroll(dev.device_id, dev.device_type, flows, fvs)
        baselines[dev.device_id] = result.baseline

        db.merge(DeviceRow(
            device_id=dev.device_id, device_type=dev.device_type,
            criticality=result.baseline and 0.3 or 0.3,
            state=result.state.value, last_seen=t0,
        ))
    db.commit()

    # train the ML detector on a longer benign corpus (train) + a labelled calibration
    # split with a few injected attack-shaped vectors, disjoint from training (docs/02:
    # "never on training or test data")
    train_flows = run_benign_window(devices, t0 + timedelta(hours=6), 240, seed=seed + 1)
    train_windows = window_flows(train_flows, window_seconds=120)
    train_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in train_windows if w[2]]
    train_fvs = [fv for fv in train_fvs if fv.values]

    calib_flows_benign = run_benign_window(devices, t0 + timedelta(hours=12), 60, seed=seed + 2)
    calib_windows = window_flows(calib_flows_benign, window_seconds=120)
    calib_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in calib_windows if w[2]]
    calib_fvs = [fv for fv in calib_fvs if fv.values]
    calib_labels = [0] * len(calib_fvs)

    for scenario, dev_id in (("mirai", "smart-plug-00"), ("low_and_slow", "smart-speaker-00")):
        flows, _ = run_scenario(scenario, dev_id, t0, seed=seed + 3)
        windows = window_flows(flows, window_seconds=300)
        for w in windows:
            fv = extract_device_window(dev_id, w[2], w[0], w[1])
            if fv.values:
                calib_fvs.append(fv)
                calib_labels.append(1)

    detector = CalibratedDetector(alpha=CONFORMAL_ALPHA)
    detector.fit(train_fvs, calib_fvs, calib_labels)

    summary = {"incidents": 0, "bundles": 0, "actions": 0}

    for scenario, dev_id, dev_type in (
        ("mirai", "smart-plug-00", "smart-plug"),
        ("low_and_slow", "smart-speaker-00", "smart-speaker"),
    ):
        attack_start = t0 + timedelta(hours=2)
        flows, ground_truth = run_scenario(scenario, dev_id, attack_start, seed=seed + 10)
        windows = window_flows(flows, window_seconds=300)
        detections = []
        deviation = 0.0
        baseline = baselines.get(dev_id)
        for w_start, w_end, w_flows in windows:
            fv = extract_device_window(dev_id, w_flows, w_start, w_end)
            if not fv.values:
                continue
            if baseline:
                dev, _ = deviation_score(baseline, fv)
                deviation = max(deviation, dev)
                drift_monitor.update(dev_id, fv.values)
            detections += policy_detections(dev_id, dev_type, w_flows, w_start)
            detections += signature_detections(dev_id, fv, w_start)
            detections += ml_detections(dev_id, fv, detector, w_start)

        if not detections:
            continue
        incidents = correlate(detections)
        det_map = {d.detection_id: d for d in detections}

        graph = BlastRadiusGraph(edges={dev_id: {f.dst_ip for f in flows}})
        blast = graph.score(dev_id)
        is_drifting = drift_monitor.is_drifting(dev_id)

        for incident in incidents:
            risk = assess_risk(incident, detections, dev_type, deviation, blast)
            incident_dets = [det_map[i] for i in incident.detection_ids if i in det_map]
            best_conformal = next((d.conformal_set for d in incident_dets if d.conformal_set), None)

            outcome = decide_and_respond(
                device_id=dev_id, device_type=dev_type, risk_score=risk.score,
                conformal_set=best_conformal, is_drifting=is_drifting,
                kill_switch=kill_switch, rate_limiter=rate_limiter,
                enforce_enabled=ENFORCE, adapter=adapter,
                now=incident.last_seen.timestamp(),
            )

            bundle = ledger.append(
                incident_id=incident.incident_id,
                device={"device_id": dev_id, "device_type": dev_type, "is_drifting": is_drifting},
                feature_vector={"window": incident.chain_position},
                detection={
                    "sources": list({d.source for d in incident_dets}),
                    "conformal_set": best_conformal,
                    "signals": [d.signal_name for d in incident_dets],
                    "explanations": [d.explanation for d in incident_dets],
                },
                baseline={"version": 1 if baseline else 0},
                risk={"score": risk.score, "terms": risk.terms},
                decision={
                    "action": outcome.action, "tier": outcome.tier, "dry_run": outcome.dry_run,
                    "gates_passed": outcome.guard.gates_passed, "gates_failed": outcome.guard.gates_failed,
                },
                trace=[f"detected via {d.source}:{d.signal_name}" for d in incident_dets] + [
                    f"correlated into incident {incident.incident_id}",
                    f"risk={risk.score:.2f}", f"guard_verdict={'allow' if outcome.guard.allow else 'veto'}",
                    f"action={outcome.action}",
                ],
            )
            summary["bundles"] += 1

            db.add(IncidentRow(
                incident_id=incident.incident_id, device_id=dev_id,
                first_seen=incident.first_seen, last_seen=incident.last_seen,
                chain_position=incident.chain_position, agreement_score=incident.agreement_score,
                detection_sources=",".join({d.source for d in incident_dets}), scenario=scenario,
            ))
            db.add(RiskAssessmentRow(incident_id=incident.incident_id, score=risk.score, terms=risk.terms))
            db.add(EvidenceBundleRow(
                bundle_id=bundle.bundle_id, incident_id=incident.incident_id,
                created_at=bundle.created_at, device=bundle.device, feature_vector=bundle.feature_vector,
                detection=bundle.detection, baseline=bundle.baseline, risk=bundle.risk,
                decision=bundle.decision, trace=bundle.trace, prev_bundle_hash=bundle.prev_bundle_hash,
                merkle_root=bundle.merkle_root,
            ))
            summary["incidents"] += 1

            if outcome.action_id:
                db.add(ActionRow(
                    action_id=outcome.action_id, bundle_id=bundle.bundle_id, device_id=dev_id,
                    tier=outcome.tier, action=outcome.action, dry_run=outcome.dry_run,
                    applied_at=incident.last_seen,
                ))
                vr = verify(outcome.action_id, dev_id, incident.last_seen, outcome.tier, ground_truth)
                db.add(VerificationRow(
                    action_id=outcome.action_id, outcome=vr.outcome,
                    checked_at=vr.checked_at, offset_seconds=vr.offset_seconds,
                ))
                summary["actions"] += 1

            db.add(AuditLogRow(actor="argus-pipeline", event_type="decision", payload={
                "incident_id": incident.incident_id, "action": outcome.action, "dry_run": outcome.dry_run,
            }))

        if is_drifting:
            db.merge(DeviceRow(device_id=dev_id, device_type=dev_type, criticality=0.3,
                                state=DeviceState.DRIFTING.value, is_drifting=True, last_seen=t0))

    db.commit()
    return summary
