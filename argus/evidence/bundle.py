"""Evidence bundle: contribution C2. An explanation that can't be verified against the
data that produced it isn't evidence (docs/02). Every bundle is hashed and chained to
the previous bundle's hash, so altering an old bundle breaks every later link -- this
is integrity within the trusted computing base, not a non-repudiation claim against
someone with root on the host (docs/02, docs/14 -- stated honestly, not oversold).
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


def _hash_obj(obj: Any) -> str:
    payload = json.dumps(obj, sort_keys=True, default=str).encode()
    return hashlib.sha256(payload).hexdigest()


@dataclass
class EvidenceBundle:
    bundle_id: str
    incident_id: str
    created_at: str
    device: dict[str, Any]
    feature_vector: dict[str, Any]
    detection: dict[str, Any]
    baseline: dict[str, Any]
    risk: dict[str, Any]
    decision: dict[str, Any]
    trace: list[str]
    prev_bundle_hash: str
    merkle_root: str = field(init=False, default="")

    def __post_init__(self) -> None:
        parts = {
            "device": self.device, "feature_vector": self.feature_vector,
            "detection": self.detection, "baseline": self.baseline,
            "risk": self.risk, "decision": self.decision, "trace": self.trace,
            "prev_bundle_hash": self.prev_bundle_hash,
        }
        self.merkle_root = _hash_obj(parts)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EvidenceLedger:
    """Append-only, hash-chained. In-memory + a list; the DB layer persists it."""

    def __init__(self) -> None:
        self._bundles: list[EvidenceBundle] = []

    @property
    def last_hash(self) -> str:
        return self._bundles[-1].merkle_root if self._bundles else "genesis"

    def append(self, incident_id: str, device: dict, feature_vector: dict, detection: dict,
               baseline: dict, risk: dict, decision: dict, trace: list[str]) -> EvidenceBundle:
        bundle = EvidenceBundle(
            bundle_id=str(uuid.uuid4()), incident_id=incident_id,
            created_at=datetime.now(UTC).isoformat(),
            device=device, feature_vector=feature_vector, detection=detection,
            baseline=baseline, risk=risk, decision=decision, trace=trace,
            prev_bundle_hash=self.last_hash,
        )
        self._bundles.append(bundle)
        return bundle

    def verify_chain(self) -> bool:
        prev = "genesis"
        for b in self._bundles:
            if b.prev_bundle_hash != prev:
                return False
            recomputed = EvidenceBundle(
                bundle_id=b.bundle_id, incident_id=b.incident_id, created_at=b.created_at,
                device=b.device, feature_vector=b.feature_vector, detection=b.detection,
                baseline=b.baseline, risk=b.risk, decision=b.decision, trace=b.trace,
                prev_bundle_hash=b.prev_bundle_hash,
            )
            if recomputed.merkle_root != b.merkle_root:
                return False
            prev = b.merkle_root
        return True

    def all(self) -> list[EvidenceBundle]:
        return list(self._bundles)
