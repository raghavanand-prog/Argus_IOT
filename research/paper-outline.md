# Paper outline

Working title (unchanged from `MASTER-PLAN.md`): *Detection Is Not Containment:
Measuring Closed-Loop Response Quality in IoT Intrusion Detection*.

**Status**: outline only, not drafted. Per `docs/13`'s writing discipline ("no
number in the paper that does not trace to a file in `results/`"), this stays an
outline — not prose — until the dataset-track and multi-scenario live-testbed gaps
in `STATUS.md` are closed enough that the Evaluation section could be written
honestly. Writing draft prose around numbers that will change would just create
rework.

**Venue strategy** (unchanged): arXiv preprint first, then a workshop/second-tier
venue appropriate for a solo first paper (ACM WiSec, IEEE CNS, ACSAC, DIMVA, or an
IoT-security workshop) — not a top-4 conference, not a journal promise.

## Section-by-section, with current evidentiary status

1. **Introduction** — the deployment gap (Sallam et al. 2026's 29/32 offline-only
   finding), the alert-as-output-not-outcome framing, C1–C4. *Ready to write* — the
   argument doesn't depend on unmeasured numbers.
2. **Background and related work** — IoT IDS evaluation practice, ENTRUST and the
   autonomous-cyber-defence benchmarks, evidence/provenance/explainability
   literature. *Ready to write.*
3. **Threat model and setting** — condensed `docs/00`. *Ready to write* — but must
   be updated to describe the actual testbed (network namespaces, `docs/04b`), not
   the originally planned Docker containers, since the paper cannot claim
   infrastructure that wasn't built.
4. **System design** — condensed `docs/01`, `docs/02`, `docs/03`. *Ready to write*,
   same caveat as above about describing the real testbed honestly.
5. **Evidence-bound decisions** — `docs/09`, the C2 contribution. *Partially ready*:
   the mechanism is real and tested (100% replay reproducibility measured, see
   `research/experiment-plan.md`), but this is 19 bundles from one seeded run, not
   "at least 100 stored bundles" as the original plan's gate specifies. Needs a
   larger run before the number is paper-worthy, not because the mechanism is
   unproven but because the sample is small.
6. **Evaluation** — *the section that determines whether this paper can be written
   yet*. T1 (dataset detection) and T3 (cross-dataset) cannot be written at all —
   no dataset-track numbers exist, and `docs/05` documents why. T2 (live-loop
   response metrics) and T5 (the ablation) have real numbers now
   (`research/experiment-plan.md`), but at 2 scenarios and 5 seeds rather than the
   original protocol's fuller scenario coverage. T6 (evidence reproducibility) has
   one real number (100% on 19 bundles) needing a larger run.
7. **Discussion**, **8. Limitations** — *ready to write once §6 is finished*, and
   given the gaps above, this paper's limitations section would need to be
   substantial and honest about the dataset-track and scenario-coverage gaps — see
   `STATUS.md` for the full list, which is effectively a limitations-section draft
   already.
8. **Conclusion and artifact** — restate; artifact availability (this repository).

## What would need to happen before drafting prose

1. Run the dataset track (needs an environment with real internet access — this
   one's outbound proxy blocks it, verified in `docs/05`) or explicitly reframe the
   paper as testbed-only (the original plan's own §7 kill-criterion fallback: "cut
   the dataset track entirely, running testbed-only — at the cost of comparability
   to published baselines").
2. Run the full 7-scenario ablation, not just the 2 `BUILD-ORDER.md` marks
   "never cut" (`mirai`, `low_and_slow`) — `mqtt_abuse`, `arp_spoof`, `dns_tunnel`,
   `identity_spoof`, `ota_spoof` are implemented (`argus/sim/attacks.py`) but not
   yet wired into `eval/ablation.py`'s scenario loop.
3. A larger evidence-replay run (≥100 bundles, the original plan's own gate).
4. Either run the human evaluation of explanations or commit to reporting its
   absence as a named limitation (`docs/09` already frames it this way).

`docs/00`–`docs/04b` collectively are most of §§1–5's actual source material and
are already written to the standard a paper section would need — the work
remaining here is measurement, not writing.
