"""Dataset-track subsampling protocol (docs/05), implemented dataset-agnostically
so it's testable and ready to run without ever having downloaded anything --
because it can't be, in this environment (see docs/05-data-pipeline.md for why,
verified rather than assumed).

Operates on plain ``list[dict]`` rows rather than pandas, so it has no new heavy
dependency and works identically whether the rows came from a real CICIoT2023 CSV
release or (as in tests/test_subsampling.py) a small synthetic fixture that mimics
the same shape.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass


@dataclass
class SamplingReport:
    """Per docs/05: "Emit a sampling report: per-class counts before and after,
    the seed, the file hashes." -- this is that report, over whatever rows were
    actually passed in."""

    seed: int
    cap: int
    per_class_before: dict[str, int]
    per_class_after: dict[str, int]
    total_before: int
    total_after: int
    input_hash: str


def _hash_rows(rows: list[dict]) -> str:
    payload = json.dumps(rows, sort_keys=True, default=str).encode()
    return hashlib.sha256(payload).hexdigest()


def stratified_subsample(rows: list[dict], label_key: str, cap: int, seed: int) -> tuple[list[dict], SamplingReport]:
    """Caps any class at ``cap`` rows, keeping every class with fewer in full
    (docs/05: "Rationale: the raw class distribution is dominated by DDoS
    variants; without capping, a classifier scores well by learning one class").
    Deterministic for a fixed seed -- required per CLAUDE.md rule 6."""
    rng = random.Random(seed)
    by_class: dict[str, list[dict]] = {}
    for r in rows:
        by_class.setdefault(str(r[label_key]), []).append(r)

    before = {k: len(v) for k, v in by_class.items()}
    after: dict[str, int] = {}
    sampled: list[dict] = []
    for cls, items in by_class.items():
        chosen = rng.sample(items, cap) if len(items) > cap else list(items)
        after[cls] = len(chosen)
        sampled.extend(chosen)

    report = SamplingReport(
        seed=seed, cap=cap, per_class_before=before, per_class_after=after,
        total_before=len(rows), total_after=len(sampled), input_hash=_hash_rows(rows),
    )
    return sampled, report


def temporal_split(rows: list[dict], ts_key: str, test_fraction: float = 0.2) -> tuple[list[dict], list[dict]]:
    """Never random -- sorted by timestamp, the last ``test_fraction`` becomes the
    test set (docs/01, citing Pendlebury et al.: "random splits over time-ordered
    data leak the future into training")."""
    ordered = sorted(rows, key=lambda r: r[ts_key])
    split_idx = int(len(ordered) * (1 - test_fraction))
    return ordered[:split_idx], ordered[split_idx:]


def preserve_base_rate_in_test(train: list[dict], test: list[dict], label_key: str,
                                benign_label: str, seed: int) -> list[dict]:
    """docs/05: "Preserve realistic benign-to-attack ratio in the test set only.
    Training may be rebalanced; the test set must reflect operational base rates or
    the base-rate fallacy invalidates the false-positive numbers." Given a desired
    benign fraction (read from ``train``'s own ratio, since that's the only real
    signal this function has about "operational" rates absent an actual dataset),
    downsamples the *attack* rows in ``test`` to match it -- benign rows are never
    the scarce class in a real deployment, so they're never the one downsampled."""
    train_benign = sum(1 for r in train if str(r[label_key]) == benign_label)
    train_ratio = train_benign / len(train) if train else 0.5

    test_benign = [r for r in test if str(r[label_key]) == benign_label]
    test_attack = [r for r in test if str(r[label_key]) != benign_label]
    if not test_benign or not test_attack:
        return test

    target_attack_count = int(len(test_benign) * (1 - train_ratio) / max(train_ratio, 1e-9))
    rng = random.Random(seed)
    if target_attack_count < len(test_attack):
        test_attack = rng.sample(test_attack, target_attack_count)
    return test_benign + test_attack
