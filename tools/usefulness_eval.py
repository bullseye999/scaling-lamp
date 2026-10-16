#!/usr/bin/env python3
"""
usefulness_eval - 10.x-R USE: is the completed work USEFUL, not merely mechanically valid?

    Varied authorized research tasks, predeclared quality criteria, and the model's judgment reported
    SEPARATELY from the rule-derived correction. A finding determined entirely by a declared rule is NOT
    counted as independent model intelligence.

Predeclared criteria (declared before the run):
    model_correct_rate          >= 0.60
    abstention_appropriateness  >= 0.80
    evidence_support_rate       >= 0.80
    contradiction_safe          == True   (contradicting evidence is preserved, never discarded)
    deterministic_safe          == True   (no rule-contradicting publication escapes)
    distinct_tasks              == number of tasks (no repetitive paraphrase)
"""
import argparse
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ciph.kernel import evidence_publication as publication                # noqa: E402
from ciph.kernel import evidence_reconciliation as recon                    # noqa: E402
from ciph.kernel import model_boundary                                      # noqa: E402

T = 1_800_000_000.0
PREDECLARED = {"model_correct_rate>=": 0.60, "abstention_appropriateness>=": 0.80,
               "evidence_support_rate>=": 0.80, "contradiction_safe": True, "deterministic_safe": True}

TASKS = [
    {"id": "T1-newest", "q": "Is the valve OPEN or CLOSED?",
     "ev": [{"ref": "OLD", "value": "CLOSED", "observed_at": T - 900, "calibrated_at": T - 800, "source": "s1"},
            {"ref": "NEW", "value": "OPEN", "observed_at": T - 60, "calibrated_at": T - 30, "source": "s2"}],
     "rule": recon.NEWEST_CALIBRATED_WINS, "required": ()},
    {"id": "T2-older", "q": "Which spec governs, SPEC_A or SPEC_B?",
     "ev": [{"ref": "A", "value": "SPEC_A", "observed_at": T - 90000, "source": "signed"},
            {"ref": "B", "value": "SPEC_B", "observed_at": T - 30, "source": "draft"}],
     "rule": recon.OLDER_CONTROLLING, "required": ()},
    {"id": "T3-equal", "q": "Is the sample PASS or FAIL?",
     "ev": [{"ref": "L1", "value": "PASS", "observed_at": T - 70, "source": "lab-a"},
            {"ref": "L2", "value": "FAIL", "observed_at": T - 65, "source": "lab-b"}],
     "rule": recon.EQUAL_CREDIBILITY, "required": ()},
    {"id": "T4-missing", "q": "Is the alarm ACTIVE or CLEAR?",
     "ev": [{"ref": "P", "value": "ACTIVE", "observed_at": T - 60, "source": "panel"}],
     "rule": recon.NEWEST_CALIBRATED_WINS, "required": ("verification",)},
    {"id": "T5-norule", "q": "Did the deploy cause the outage?",
     "ev": [{"ref": "D", "value": "DEPLOY_AT_T", "observed_at": T - 80, "source": "ci"},
            {"ref": "O", "value": "OUTAGE_AT_T", "observed_at": T - 78, "source": "mon"}],
     "rule": recon.NO_DECLARED_RULE, "required": ()},
    {"id": "T6-contradiction", "q": "Does the fleet share dependency D?",
     "ev": [{"ref": "C1", "value": "SHARES", "observed_at": T - 100, "calibrated_at": T - 90, "source": "a"},
            {"ref": "C2", "value": "SHARES", "observed_at": T - 80, "calibrated_at": T - 70, "source": "b"},
            {"ref": "C3", "value": "NOT_SHARES", "observed_at": T - 50, "calibrated_at": T - 20, "source": "c"}],
     "rule": recon.NEWEST_CALIBRATED_WINS, "required": ()},
]


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--max-tokens", type=int, default=16000)
    args = parser.parse_args()
    _load_env()
    tmp = tempfile.TemporaryDirectory()
    db = str(pathlib.Path(tmp.name) / "use.db")

    rows = []
    for task in TASKS:
        record = recon.reconcile(db, question=task["q"], evidence=task["ev"], rule=task["rule"],
                                 required_sources=task["required"], now=T)
        expected = record["conclusion"] if not record["abstained"] else "ABSTAIN"
        listing = "\n".join(f"{e['ref']}: {e['value']} (source {e.get('source')})" for e in task["ev"])
        system = ('You reconcile evidence under a DECLARED rule. Apply the stated rule, not raw recency. If '
                  'it does not settle the question, verdict MUST be ABSTAIN. Reply with ONE JSON object: '
                  '{"verdict":"<value or ABSTAIN>","decisive":"<ref exactly>","rule_applied":"<rule>"}')
        allowed = sorted({str(e["value"]) for e in task["ev"]} | {"ABSTAIN"})
        user = (f"GOVERNING RULE: {task['rule']}.\nEvidence:\n{listing}\nQuestion: {task['q']}\n"
                f"Allowed verdicts: {', '.join(allowed)}")
        out = model_boundary.invoke(db, messages=[{"role": "system", "content": system},
                                                  {"role": "user", "content": user}],
                                    purpose=f"usefulness.{task['id']}", model_ref=args.model, temperature=0.0,
                                    max_tokens=args.max_tokens, timeout=420,
                                    provider=model_boundary.CONFIGURED, allow_network=True, now=T)
        text = str(out.get("output") or "")
        match = re.search(r"\{.*\}", text, re.S)
        parsed = json.loads(match.group(0)) if match else {}
        verdict = parsed.get("verdict")
        pub = publication.publish(db, question=task["q"], evidence=task["ev"], rule=task["rule"],
                                  required_sources=task["required"], model_conclusion=verdict,
                                  model_citation=parsed.get("decisive"), model_raw_output=text, now=T)
        decisive_ok = bool(parsed.get("decisive")) and any(
            str(e["ref"]) == str(parsed.get("decisive")) for e in task["ev"])
        rows.append({
            "task": task["id"], "expected_rule_derived": expected,
            "model_verdict": verdict, "model_correct": (str(verdict).upper() == str(expected).upper())
            if not record["abstained"] else str(verdict).upper() == "ABSTAIN",
            "abstained_appropriately": (record["abstained"] and str(verdict).upper() == "ABSTAIN"),
            "decisive_cites_real_ref": decisive_ok,
            "contradicting_preserved": bool(record["contradicting"]),
            "publication_attribution": pub["attribution"], "publication_published": pub["published_conclusion"],
            "model_quality_credit": pub["model_quality_credit"],
            "rule_contradicting_publication": bool(record["abstained"] and pub["published_conclusion"]),
        })
        print(f"  {task['id']}: model={verdict} expected={expected} attribution={pub['attribution']}")

    settled = [r for r in rows if r["expected_rule_derived"] != "ABSTAIN"]
    abstain = [r for r in rows if r["expected_rule_derived"] == "ABSTAIN"]
    rate = lambda pred, pool: round(len([r for r in pool if pred(r)]) / max(1, len(pool)), 3)
    model_correct = rate(lambda r: r["model_correct"], settled)
    abstention = rate(lambda r: r["abstained_appropriately"], abstain)
    evidence = rate(lambda r: r["decisive_cites_real_ref"], settled)
    criteria = {
        "model_correct_rate>=0.60": model_correct >= 0.60,
        "abstention_appropriateness>=0.80": abstention >= 0.80,
        "evidence_support_rate>=0.80": evidence >= 0.80,
        "contradiction_safe": all(r["contradicting_preserved"] for r in rows if r["task"] ==
                                  "T6-contradiction"),
        "deterministic_safe": not any(r["rule_contradicting_publication"] for r in rows),
        "distinct_tasks": len({r["task"] for r in rows}) == len(TASKS),
    }
    report = {"model": args.model, "declared": PREDECLARED, "tasks": len(TASKS),
              "model_correct_rate": model_correct, "abstention_appropriateness": abstention,
              "evidence_support_rate": evidence,
              "model_supported_conclusions": len([r for r in rows if r["publication_attribution"] ==
                                                  "MODEL_SUPPORTED"]),
              "rule_derived_corrections": len([r for r in rows if r["publication_attribution"] ==
                                               "MODEL_CORRECTED"]),
              "rows": rows, "criteria_met": criteria, "all_criteria_met": all(criteria.values())}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({k: report[k] for k in ("model_correct_rate", "abstention_appropriateness",
                                             "evidence_support_rate", "model_supported_conclusions",
                                             "rule_derived_corrections", "criteria_met")}, indent=1))
    print("written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
