"""Statistics for the ablation (docs/13 §3): non-parametric throughout ("metrics
here are skewed and censored, and normality assumptions are not defensible"),
Mann-Whitney U per pairwise comparison, Holm-Bonferroni correction across the
comparison family, Cliff's delta as the effect size reported alongside every
p-value. With 5 seeds, statistical power is limited by design -- report effect
sizes as primary and treat small differences as inconclusive rather than
significant (docs/13's own instruction, taken literally here).
"""

from __future__ import annotations

from dataclasses import dataclass

from scipy import stats as scipy_stats


def median(xs: list[float]) -> float:
    xs = sorted(xs)
    n = len(xs)
    if n == 0:
        return float("nan")
    mid = n // 2
    return xs[mid] if n % 2 else (xs[mid - 1] + xs[mid]) / 2


def iqr(xs: list[float]) -> tuple[float, float]:
    xs = sorted(xs)
    n = len(xs)
    if n < 2:
        return (float("nan"), float("nan"))
    q1 = xs[n // 4]
    q3 = xs[(3 * n) // 4]
    return (q1, q3)


def cliffs_delta(a: list[float], b: list[float]) -> float:
    """Effect size in [-1, 1]: fraction of pairs where a > b minus fraction where
    a < b. |delta| < 0.147 negligible, < 0.33 small, < 0.474 medium, else large
    (Romano et al. thresholds, standard for this statistic)."""
    if not a or not b:
        return 0.0
    gt = sum(1 for x in a for y in b if x > y)
    lt = sum(1 for x in a for y in b if x < y)
    return (gt - lt) / (len(a) * len(b))


def holm_bonferroni(p_values: list[float]) -> list[float]:
    """Adjusted p-values, family-wise. Returns adjusted values in the *original*
    order of ``p_values``."""
    n = len(p_values)
    indexed = sorted(range(n), key=lambda i: p_values[i])
    adjusted = [0.0] * n
    running_max = 0.0
    for rank, i in enumerate(indexed):
        adj = min(1.0, p_values[i] * (n - rank))
        running_max = max(running_max, adj)
        adjusted[i] = running_max
    return adjusted


@dataclass
class Comparison:
    metric: str
    config_name: str
    baseline_median: float
    config_median: float
    p_value: float
    p_value_adjusted: float | None
    cliffs_delta: float
    effect_size_label: str


def _effect_label(delta: float) -> str:
    d = abs(delta)
    if d < 0.147:
        return "negligible"
    if d < 0.33:
        return "small"
    if d < 0.474:
        return "medium"
    return "large"


def mann_whitney(a: list[float], b: list[float]) -> float:
    if len(set(a)) == 1 and a == b:
        return 1.0
    try:
        _, p = scipy_stats.mannwhitneyu(a, b, alternative="two-sided")
        return float(p)
    except ValueError:
        return 1.0  # identical/degenerate samples -- scipy raises rather than returning p=1


def compare_configs(baseline: list[float], others: dict[str, list[float]], metric: str) -> list[Comparison]:
    raw_p = []
    partial = []
    for name, values in others.items():
        p = mann_whitney(baseline, values)
        delta = cliffs_delta(baseline, values)
        raw_p.append(p)
        partial.append((name, values, p, delta))

    adjusted = holm_bonferroni(raw_p)
    return [
        Comparison(
            metric=metric, config_name=name,
            baseline_median=median(baseline), config_median=median(values),
            p_value=p, p_value_adjusted=adj, cliffs_delta=delta, effect_size_label=_effect_label(delta),
        )
        for (name, values, p, delta), adj in zip(partial, adjusted)
    ]
