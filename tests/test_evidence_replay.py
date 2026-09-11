"""Evidence replay test -- this IS contribution C2 and is not optional (CLAUDE.md,
docs/02). Builds bundles across the demo pipeline's actual decisions and asserts a
measured, high reproducibility rate, plus that hash-chain tampering is detectable.
"""

from argus.evidence.bundle import EvidenceLedger
from argus.evidence.replay import replay, reproducibility_rate


def _sample_bundle(ledger: EvidenceLedger, risk_score: float, conformal_set, tier: int, action: str):
    return ledger.append(
        incident_id="inc-1",
        device={"device_id": "d1", "device_type": "smart-plug", "is_drifting": False},
        feature_vector={"window": "w1"},
        detection={"sources": ["ml"], "conformal_set": conformal_set, "signals": ["isolation_forest_anomaly"]},
        baseline={"version": 1},
        risk={"score": risk_score, "terms": {"severity": 0.5}},
        decision={"action": action, "tier": tier, "dry_run": True, "gates_passed": [], "gates_failed": []},
        trace=["t1"],
    )


def test_replay_reproduces_decision_for_consistent_bundles():
    ledger = EvidenceLedger()
    bundles = [
        _sample_bundle(ledger, 0.85, ["attack"], 4, "isolate"),
        _sample_bundle(ledger, 0.2, ["benign"], 0, "observe"),
        _sample_bundle(ledger, 0.55, ["attack"], 2, "rate_limit"),
    ]
    for b in bundles:
        result = replay(b)
        assert result.reproduced, f"expected reproducible decision, got {result}"
    assert reproducibility_rate(bundles) == 1.0


def test_replay_flags_a_bundle_whose_stored_decision_does_not_match_its_own_inputs():
    ledger = EvidenceLedger()
    # a bundle whose stored decision claims "isolate" but whose risk score/conformal
    # set would never produce that tier -- simulates the non-determinism replay exists
    # to catch (docs/09)
    tampered = _sample_bundle(ledger, 0.1, ["benign"], 4, "isolate")
    result = replay(tampered)
    assert not result.reproduced
    assert result.replayed_action != "isolate"


def test_hash_chain_detects_tampering():
    ledger = EvidenceLedger()
    _sample_bundle(ledger, 0.85, ["attack"], 4, "isolate")
    _sample_bundle(ledger, 0.3, ["benign"], 1, "alert")
    assert ledger.verify_chain() is True

    ledger._bundles[0].risk["score"] = 0.99  # simulate tampering with a stored bundle
    assert ledger.verify_chain() is False, "altering an old bundle must break the hash chain"
