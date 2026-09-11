"""Unit tests for the ablation's statistics helpers (eval/stats.py) -- pure
functions, fast, no simulation involved."""

from eval.stats import cliffs_delta, holm_bonferroni, iqr, median


def test_median_odd_and_even():
    assert median([1, 3, 2]) == 2
    assert median([1, 2, 3, 4]) == 2.5


def test_cliffs_delta_identical_distributions_is_zero():
    assert cliffs_delta([1, 2, 3], [1, 2, 3]) == 0.0


def test_cliffs_delta_fully_separated_is_plus_or_minus_one():
    assert cliffs_delta([10, 11, 12], [1, 2, 3]) == 1.0
    assert cliffs_delta([1, 2, 3], [10, 11, 12]) == -1.0


def test_holm_bonferroni_is_monotonically_non_decreasing_with_rank():
    raw = [0.01, 0.04, 0.03, 0.20]
    adjusted = holm_bonferroni(raw)
    # every adjusted p must be >= its raw p (correction never makes things look
    # more significant than they are)
    for r, a in zip(raw, adjusted):
        assert a >= r


def test_holm_bonferroni_matches_hand_computed_example():
    # sorted raw: 0.01, 0.02, 0.03 -> multipliers 3,2,1 -> 0.03, 0.04, 0.03
    # then cumulative max (monotonic): 0.03, 0.04, 0.04
    raw = [0.02, 0.01, 0.03]
    adjusted = holm_bonferroni(raw)
    assert adjusted[1] == 0.03  # smallest raw p (0.01) gets multiplier 3
    assert adjusted[0] == 0.04  # 0.02 * 2 = 0.04
    assert adjusted[2] == 0.04  # 0.03 * 1 = 0.03, but cumulative max with prior (0.04) wins


def test_iqr_on_small_sample():
    q1, q3 = iqr([1, 2, 3, 4, 5, 6, 7, 8])
    assert q1 < median([1, 2, 3, 4, 5, 6, 7, 8]) < q3
