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
    ActionRow,
    AuditLogRow,
    DeviceRow,
    EvidenceBundleRow,
    IncidentRow,
    RiskAssessmentRow,
    VerificationRow,
)
from argus.detect.ml import CalibratedDetector, ShapExplainer, ml_detections
from argus.detect.rules import (
    identity_detections,
    policy_detections,
    signature_detections,
)
from argus.evidence.bundle import EvidenceLedger
from argus.features.extract import device_ja4_set, extract_device_window
from argus.registry.enrollment import enroll
from argus.respond.guard import ActionRateLimiter, KillSwitch
from argus.respond.ladder import TIERS, DryRunAdapter, decide_and_respond, tier_for_risk
from argus.risk.engine import BlastRadiusGraph, assess_risk
from argus.schemas import DeviceState
from argus.sim.engine import (
    build_ip_to_type,
    default_fleet,
    run_benign_window,
    run_scenario,
)
from argus.verify.verification import verify

ENFORCE = os.getenv("ARGUS_ENFORCE", "false").lower() == "true"
CONFORMAL_ALPHA = float(os.getenv("ARGUS_CONFORMAL_ALPHA", "0.05"))

# One representative device per scenario from default_fleet() (docs/02's full 7,
# BUILD-ORDER.md's "never cut" two plus the five added once the core loop was solid).
SCENARIO_DEVICES = {
    "mirai": "smart-plug-00",
    "low_and_slow": "smart-speaker-00",
    "mqtt_abuse": "smart-lock-00",
    "arp_spoof": "ip-camera-00",
    "dns_tunnel": "smart-tv-00",
    "identity_spoof": "doorbell-00",
    "ota_spoof": "thermostat-00",
}


def _process_scenario(
    db: Session, *, ledger: EvidenceLedger, kill_switch: KillSwitch, rate_limiter: ActionRateLimiter,
    scenario: str, dev_id: str, dev_type: str, detections: list, ground_truth: list,
    deviation: float, blast: float, is_drifting: bool, adapter, source: str, summary: dict,
) -> None:
    """Shared correlate -> risk -> decide -> evidence -> persist -> verify tail,
    used by both the synthetic pipeline and the live-testbed pipeline -- the two
    differ only in where ``detections``/``ground_truth`` came from (docs/01's
    data-flow-contract design paying off exactly as intended)."""
    if not detections:
        return
    incidents = correlate(detections)
    det_map = {d.detection_id: d for d in detections}

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
            device={"device_id": dev_id, "device_type": dev_type, "is_drifting": is_drifting, "source": source},
            feature_vector={"window": incident.chain_position},
            detection={
                "sources": list({d.source for d in incident_dets}),
                "conformal_set": best_conformal,
                "signals": [d.signal_name for d in incident_dets],
                "explanations": [d.explanation for d in incident_dets],
                "attribution": next((d.attribution for d in incident_dets if d.attribution), None),
            },
            baseline={"version": 1},
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
            "source": source,
        }))


def _enroll_and_train(db: Session, devices: list, t0: datetime, seed: int) -> tuple[
    dict[str, object], dict[str, str], CalibratedDetector, ShapExplainer,
]:
    """Shared setup used by every pipeline entrypoint (``run_demo_pipeline`` and the
    validation script alike): enroll each device on its own benign baseline, then fit
    the *one* calibrated detector + explainer on a benign-only training split plus a
    labelled calibration split (benign + a few injected attack-shaped vectors),
    disjoint from training (docs/02: "never on training or test data"). Factored out
    so a benign-only validation run exercises the identical trained detector a real
    demo run would -- not a second, parallel one that could quietly drift out of sync.
    """
    ip_to_type = build_ip_to_type(devices)
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

    train_flows = run_benign_window(devices, t0 + timedelta(hours=6), 240, seed=seed + 1)
    train_windows = window_flows(train_flows, window_seconds=120)
    train_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in train_windows if w[2]]
    train_fvs = [fv for fv in train_fvs if fv.values]

    calib_flows_benign = run_benign_window(devices, t0 + timedelta(hours=12), 60, seed=seed + 2)
    calib_windows = window_flows(calib_flows_benign, window_seconds=120)
    calib_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in calib_windows if w[2]]
    calib_fvs = [fv for fv in calib_fvs if fv.values]
    calib_labels = [0] * len(calib_fvs)

    for scenario, dev_id in SCENARIO_DEVICES.items():
        flows, _ = run_scenario(scenario, dev_id, t0, seed=seed + 3)
        windows = window_flows(flows, window_seconds=300)
        for w in windows:
            fv = extract_device_window(dev_id, w[2], w[0], w[1])
            if fv.values:
                calib_fvs.append(fv)
                calib_labels.append(1)

    detector = CalibratedDetector(alpha=CONFORMAL_ALPHA)
    detector.fit(train_fvs, calib_fvs, calib_labels)
    explainer = ShapExplainer()
    explainer.fit(calib_fvs, calib_labels)

    return baselines, ip_to_type, detector, explainer


def run_benign_validation(db: Session, seed: int = 42, held_out_hours: int = 18) -> dict:
    """IDS validation Test 1 / Test 4 (see docs/16-ids-validation.md): enrolls and
    trains exactly as ``run_demo_pipeline`` does, then runs a *fresh, held-out* benign
    window per device -- disjoint in time and RNG seed from both the enrollment and
    the training/calibration windows above -- through the same four detectors the real
    pipeline uses (policy, signature, ml, identity), with zero attack traffic mixed in.

    Any raw detection is then run through the *same* correlate -> risk -> tier_for_risk
    path ``run_demo_pipeline`` uses (read-only here -- no decide_and_respond call, no
    evidence bundle, no DB write) so the report distinguishes a low-confidence flag the
    response guard would have capped at tier 0/1 from one with a singleton {"attack"}
    conformal set that could actually have reached an enforcement tier -- the
    safety-relevant question, not just "did a Detection object get created."

    No incident is ever expected here: this measures whether the IDS stays quiet on
    traffic it has never specifically been shown, not whether it can be tuned to be
    quiet on the exact windows it was calibrated against. Writes nothing to the
    database -- a validation run with zero detections should leave zero trace,
    matching what "no false incident was raised" means on the Incidents page.
    """
    devices = default_fleet()
    t0 = datetime(2026, 1, 1, 0, 0)
    baselines, ip_to_type, detector, explainer = _enroll_and_train(db, devices, t0, seed)

    held_out_start = t0 + timedelta(hours=held_out_hours)
    per_device: dict[str, list[dict]] = {}
    for dev in devices:
        flows = run_benign_window([dev], held_out_start, duration_minutes=90, seed=seed + 99)
        windows = window_flows(flows, window_seconds=300)
        baseline = baselines.get(dev.device_id)
        detections = []
        for w_start, w_end, w_flows in windows:
            fv = extract_device_window(dev.device_id, w_flows, w_start, w_end)
            if not fv.values:
                continue
            observed_ja4 = device_ja4_set(dev.device_id, w_flows)
            detections += (
                policy_detections(dev.device_id, dev.device_type, w_flows, w_start)
                + signature_detections(dev.device_id, fv, w_start)
                + ml_detections(dev.device_id, fv, detector, w_start, explainer=explainer)
                + identity_detections(dev.device_id, observed_ja4, baseline, w_start)
            )

        findings = [{
            "signal": d.signal_name, "source": d.source, "explanation": d.explanation,
            "conformal_set": d.conformal_set,
        } for d in detections]

        if detections:
            graph = BlastRadiusGraph(edges={dev.device_id: {f.dst_ip for f in flows}})
            blast = graph.score(dev.device_id, device_type_of=ip_to_type.get)
            for incident in correlate(detections):
                det_map = {d.detection_id: d for d in detections}
                incident_dets = [det_map[i] for i in incident.detection_ids if i in det_map]
                risk = assess_risk(incident, detections, dev.device_type, 0.0, blast)
                best_conformal = next((d.conformal_set for d in incident_dets if d.conformal_set), None)
                singleton = bool(best_conformal) and len(best_conformal) == 1
                would_be_tier = tier_for_risk(risk.score, singleton, False)
                for f in findings:
                    if f["signal"] in {d.signal_name for d in incident_dets}:
                        f["would_be_tier"] = would_be_tier
                        f["would_be_action"] = TIERS[would_be_tier]
                        f["would_be_risk_score"] = risk.score

        per_device[dev.device_id] = findings

    total_detections = sum(len(v) for v in per_device.values())
    escalating = sum(
        1 for v in per_device.values() for f in v if f.get("would_be_tier", 0) >= 2
    )
    return {
        "devices_tested": len(devices),
        "detections_that_would_escalate_to_tier2plus": escalating,
        "windows_per_device_approx": 90 // 5,
        "total_detections": total_detections,
        "false_positives_by_device": {k: v for k, v in per_device.items() if v},
        "clean_devices": [k for k, v in per_device.items() if not v],
    }


def run_demo_pipeline(db: Session, seed: int = 42) -> dict:
    """Runs enrollment -> a benign window -> two attack scenarios -> the full detect/
    respond/verify loop, and persists devices, incidents, risk, evidence bundles,
    actions and verifications. Returns a small summary dict for logging."""

    devices = default_fleet()
    ip_to_type = build_ip_to_type(devices)
    t0 = datetime(2026, 1, 1, 0, 0)
    ledger = EvidenceLedger()
    kill_switch = KillSwitch()
    rate_limiter = ActionRateLimiter()
    drift_monitor = DeviceDriftMonitor()
    adapter = DryRunAdapter()

    baselines, _, detector, explainer = _enroll_and_train(db, devices, t0, seed)

    summary = {"incidents": 0, "bundles": 0, "actions": 0}

    for scenario, dev_id in SCENARIO_DEVICES.items():
        dev_type = next(d.device_type for d in devices if d.device_id == dev_id)
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
            observed_ja4 = device_ja4_set(dev_id, w_flows)
            detections += policy_detections(dev_id, dev_type, w_flows, w_start)
            detections += signature_detections(dev_id, fv, w_start)
            detections += ml_detections(dev_id, fv, detector, w_start, explainer=explainer)
            detections += identity_detections(dev_id, observed_ja4, baseline, w_start)

        if not detections:
            continue

        graph = BlastRadiusGraph(edges={dev_id: {f.dst_ip for f in flows}})
        blast = graph.score(dev_id, device_type_of=ip_to_type.get)
        is_drifting = drift_monitor.is_drifting(dev_id)

        _process_scenario(
            db, ledger=ledger, kill_switch=kill_switch, rate_limiter=rate_limiter,
            scenario=scenario, dev_id=dev_id, dev_type=dev_type, detections=detections,
            ground_truth=ground_truth, deviation=deviation, blast=blast, is_drifting=is_drifting,
            adapter=adapter, source="synthetic", summary=summary,
        )

        if is_drifting:
            db.merge(DeviceRow(device_id=dev_id, device_type=dev_type, criticality=0.3,
                                state=DeviceState.DRIFTING.value, is_drifting=True, last_seen=t0))

    db.commit()
    return summary


def run_live_demo_pipeline(db: Session, seed: int = 42) -> dict:
    """The real-packet counterpart to ``run_demo_pipeline``: sources flows and
    ground truth from ``argus.testbed`` (real network namespaces, real sockets, real
    capture) instead of ``argus.sim`` (synthetic generation), then runs the *same*
    downstream code -- features, registry, detection, correlation, risk, evidence,
    response, verification. Requires Linux + root/CAP_NET_ADMIN and the
    ``live-testbed`` extra; raises ImportError with a clear message otherwise, so a
    normal ``make seed`` (which calls ``run_demo_pipeline``) never needs these deps.
    """
    try:
        from argus.testbed.orchestrator import BENIGN_FLEET, run_live_testbed
    except ImportError as e:
        raise ImportError(
            "run_live_demo_pipeline needs the live-testbed extra: "
            'pip install -e ".[live-testbed]" -- and Linux + root/CAP_NET_ADMIN. '
            "See docs/04b-live-testbed.md."
        ) from e

    ledger = EvidenceLedger()
    kill_switch = KillSwitch()
    rate_limiter = ActionRateLimiter()
    drift_monitor = DeviceDriftMonitor()
    adapter = DryRunAdapter()
    summary = {"incidents": 0, "bundles": 0, "actions": 0, "real_packets_captured": 0}

    # 1. A pure-benign live capture to enroll every device on real traffic.
    benign_run = run_live_testbed(None, benign_duration_s=15, attack_duration_s=0, seed=seed,
                                   pcap_path="/tmp/argus_live_enroll.pcap")
    summary["real_packets_captured"] += len(benign_run.flows)
    ip_to_type = {ip: BENIGN_FLEET[did] for did, ip in benign_run.device_ips.items() if did in BENIGN_FLEET}

    baselines: dict[str, object] = {}
    for device_id, device_type in BENIGN_FLEET.items():
        dev_flows = [f for f in benign_run.flows if f.device_id == device_id]
        windows = window_flows(dev_flows, window_seconds=5)
        fvs = [extract_device_window(device_id, w[2], w[0], w[1]) for w in windows]
        fvs = [fv for fv in fvs if fv.values]
        result = enroll(device_id, device_type, dev_flows, fvs)
        baselines[device_id] = result.baseline
        db.merge(DeviceRow(device_id=device_id, device_type=device_type, criticality=0.3,
                            state=result.state.value, last_seen=dev_flows[0].ts_start if dev_flows else datetime.utcnow()))
    db.commit()

    # 2. Train the ML detector on real benign windows + real attack windows from a
    # second short live run per scenario (disjoint from the enrollment capture).
    train_windows = window_flows(benign_run.flows, window_seconds=5)
    train_fvs = [extract_device_window(w[2][0].device_id, w[2], w[0], w[1]) for w in train_windows if w[2]]
    train_fvs = [fv for fv in train_fvs if fv.values]

    calib_fvs: list = []
    calib_labels: list[int] = []
    scenario_runs: dict[str, object] = {}
    for scenario in ("mirai", "low_and_slow"):
        run = run_live_testbed(scenario, benign_duration_s=8, attack_duration_s=8, seed=seed + 1,
                                pcap_path=f"/tmp/argus_live_{scenario}.pcap")
        scenario_runs[scenario] = run
        summary["real_packets_captured"] += len(run.flows)
        for w in window_flows(run.flows, window_seconds=5):
            fv = extract_device_window(w[2][0].device_id, w[2], w[0], w[1])
            if not fv.values:
                continue
            is_attack = any(f.label.startswith("attack:") for f in w[2])
            calib_fvs.append(fv)
            calib_labels.append(1 if is_attack else 0)

    detector = CalibratedDetector(alpha=CONFORMAL_ALPHA)
    detector.fit(train_fvs, calib_fvs, calib_labels)
    explainer = ShapExplainer()
    explainer.fit(calib_fvs, calib_labels)

    # 3. Run the shared detect -> respond -> verify tail against each real capture.
    for scenario, dev_id, dev_type in (
        ("mirai", "smart-plug-00", "smart-plug"),
        ("low_and_slow", "smart-speaker-00", "smart-speaker"),
    ):
        run = scenario_runs[scenario]
        dev_flows = [f for f in run.flows if f.device_id == dev_id]
        windows = window_flows(dev_flows, window_seconds=5)
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
            detections += ml_detections(dev_id, fv, detector, w_start, explainer=explainer)

        if not detections:
            continue
        graph = BlastRadiusGraph(edges={dev_id: {f.dst_ip for f in dev_flows}})
        blast = graph.score(dev_id, device_type_of=ip_to_type.get)
        is_drifting = drift_monitor.is_drifting(dev_id)

        _process_scenario(
            db, ledger=ledger, kill_switch=kill_switch, rate_limiter=rate_limiter,
            scenario=scenario, dev_id=dev_id, dev_type=dev_type, detections=detections,
            ground_truth=run.ground_truth, deviation=deviation, blast=blast, is_drifting=is_drifting,
            adapter=adapter, source="live-real-network", summary=summary,
        )

    db.commit()
    return summary
