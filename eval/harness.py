"""Evaluation harness (docs/04, docs/13): produces every metric from one command.

Run: ``python -m eval.harness`` (or ``make evaluate``). Writes a timestamped,
git-commit-stamped results file under ``results/<timestamp>/results.json`` -- every
number in `research/` or `resume/` must trace back to a file here (docs/13's
writing discipline), or it doesn't get written down as a measurement.

This runs the full A0-A8 ablation (eval/ablation.py) at 5 seeds per configuration
against a real benign holdout, and reports H1/H2's central comparison: does F1 move
in step with containment metrics (time-to-contain, false-isolation rate), or not.
"""

from __future__ import annotations

import json
import subprocess
from datetime import datetime
from pathlib import Path

from eval.ablation import CONFIGS, run_ablation
from eval.stats import compare_configs, iqr, median

DEFAULT_SEEDS = [1, 2, 3, 4, 5]


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=Path(__file__).parent.parent,
        ).decode().strip()
    except Exception:
        return "unknown"


def summarise(results: dict[str, list]) -> dict:
    summary = {}
    for name, runs in results.items():
        f1s = [r.f1 for r in runs]
        precisions = [r.precision for r in runs]
        recalls = [r.recall for r in runs]
        ttcs = [r.time_to_contain_s for r in runs if r.time_to_contain_s is not None]
        censoring_rate = 1 - (len(ttcs) / len(runs)) if runs else 0.0
        firs = [float(r.false_isolation_events) for r in runs]
        contained_rate = sum(r.contained for r in runs) / len(runs) if runs else 0.0

        summary[name] = {
            "n_seeds": len(runs),
            "f1_median": median(f1s), "f1_iqr": iqr(f1s),
            "precision_median": median(precisions), "recall_median": median(recalls),
            "time_to_contain_median_s": median(ttcs) if ttcs else None,
            "time_to_contain_censoring_rate": censoring_rate,
            "contained_rate": contained_rate,
            "false_isolation_events_median": median(firs),
            "alerts_raised_median": median([float(r.alerts_raised) for r in runs]),
        }
    return summary


def run_evaluation(seeds: list[int] | None = None) -> dict:
    seeds = seeds or DEFAULT_SEEDS
    results = run_ablation(seeds)
    summary = summarise(results)

    baseline_runs = results["A0_full_system"]
    other_names = [c.name for c in CONFIGS if c.name != "A0_full_system"]

    f1_comparisons = compare_configs(
        [r.f1 for r in baseline_runs],
        {name: [r.f1 for r in results[name]] for name in other_names},
        metric="f1",
    )
    ttc_comparisons = compare_configs(
        [r.time_to_contain_s for r in baseline_runs if r.time_to_contain_s is not None] or [0.0],
        {
            name: ([r.time_to_contain_s for r in results[name] if r.time_to_contain_s is not None] or [0.0])
            for name in other_names
        },
        metric="time_to_contain_s",
    )
    fir_comparisons = compare_configs(
        [float(r.false_isolation_events) for r in baseline_runs],
        {name: [float(r.false_isolation_events) for r in results[name]] for name in other_names},
        metric="false_isolation_events",
    )

    # The H1/H2 argument in one place: for each non-A0 config, did F1 move a lot
    # while containment (TTC/FIR) barely moved, or the reverse? "Large" effect size
    # on F1 with "negligible/small" on containment (or vice versa) is the pattern
    # the central claim depends on -- reported per-config, not asserted globally.
    h2_table = []
    for f1c, ttcc, firc in zip(f1_comparisons, ttc_comparisons, fir_comparisons):
        h2_table.append({
            "config": f1c.config_name,
            "f1_effect": f1c.effect_size_label, "f1_cliffs_delta": round(f1c.cliffs_delta, 3),
            "ttc_effect": ttcc.effect_size_label, "ttc_cliffs_delta": round(ttcc.cliffs_delta, 3),
            "fir_effect": firc.effect_size_label, "fir_cliffs_delta": round(firc.cliffs_delta, 3),
        })

    manifest = {
        "seeds": seeds, "git_commit": _git_commit(),
        "generated_at": datetime.utcnow().isoformat(),
        "configurations": [c.name for c in CONFIGS],
    }

    return {
        "manifest": manifest,
        "summary": summary,
        "statistical_comparisons": {
            "f1_vs_A0": [vars(c) for c in f1_comparisons],
            "time_to_contain_vs_A0": [vars(c) for c in ttc_comparisons],
            "false_isolation_vs_A0": [vars(c) for c in fir_comparisons],
        },
        "h1_h2_argument_table": h2_table,
    }


def main() -> None:
    output = run_evaluation()
    out_dir = Path(__file__).parent.parent / "results" / datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "results.json"
    out_file.write_text(json.dumps(output, indent=2, default=str))
    print(f"wrote {out_file}\n")

    print(f"{'config':<20} {'F1':>6} {'TTC(s)':>8} {'censor%':>8} {'contain%':>9} {'FIR':>5}")
    for name, s in output["summary"].items():
        ttc = f"{s['time_to_contain_median_s']:.0f}" if s["time_to_contain_median_s"] is not None else "  --"
        print(f"{name:<20} {s['f1_median']:>6.2f} {ttc:>8} "
              f"{s['time_to_contain_censoring_rate']*100:>7.0f}% {s['contained_rate']*100:>8.0f}% "
              f"{s['false_isolation_events_median']:>5.1f}")

    print("\nH1/H2 argument table (effect of each ablation relative to A0_full_system):")
    print(f"{'config':<20} {'F1 effect':>12} {'TTC effect':>12} {'FIR effect':>12}")
    for row in output["h1_h2_argument_table"]:
        print(f"{row['config']:<20} {row['f1_effect']:>12} {row['ttc_effect']:>12} {row['fir_effect']:>12}")


if __name__ == "__main__":
    main()
