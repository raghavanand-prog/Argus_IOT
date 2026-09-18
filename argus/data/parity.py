"""Feature-parity check between the live track's own extractor
(argus/features/extract.py) and a dataset release's pre-extracted feature columns
(docs/05: "compute features through the live path and compare to the dataset's own
published values for the same flows... the size of that disagreement is a number
the paper should report, because it bounds how much the cross-track comparison can
be trusted").

Dataset-agnostic by the same design as subsample.py: takes a mapping from the live
extractor's feature names to whatever column names the dataset release uses, so it
works against any release with the same general shape.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class ParityResult:
    feature_name: str
    live_value: float
    dataset_value: float
    absolute_difference: float
    relative_difference: float | None  # None when dataset_value == 0


def compare_feature(feature_name: str, live_value: float, dataset_value: float) -> ParityResult:
    diff = abs(live_value - dataset_value)
    rel = diff / abs(dataset_value) if dataset_value != 0 else None
    return ParityResult(feature_name, live_value, dataset_value, diff, rel)


def parity_report(live_values: dict[str, float], dataset_values: dict[str, float],
                   name_map: dict[str, str]) -> list[ParityResult]:
    """``name_map``: live feature name -> dataset column name. Only features present
    in both (after mapping) are compared -- a feature the live extractor computes
    that the dataset release doesn't publish is not a parity failure, it's just not
    comparable, and is silently skipped rather than reported as a mismatch."""
    results = []
    for live_name, dataset_col in name_map.items():
        if live_name in live_values and dataset_col in dataset_values:
            results.append(compare_feature(live_name, live_values[live_name], dataset_values[dataset_col]))
    return results
