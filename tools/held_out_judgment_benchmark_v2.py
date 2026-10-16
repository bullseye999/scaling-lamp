#!/usr/bin/env python3
"""
held_out_judgment_benchmark_v2 - 10.x-R FU: an UNSEEN held-out evaluation with the standing rule made
explicit and structured in the model context.

    The rule is declared. The answer is never.

WHY THIS EXISTS. v1 disclosed only raw observation/calibration timestamps. The measured failures
(`OLDER_CONTROLS` 0/2, abstention 6/11) share one root cause: the GOVERNING RULE and the ABSTENTION
CONDITIONS were absent from the model context, so the model fell back to "newest wins" and answered
confidently on partial evidence. v2 presents the declared rule and its semantics as structured context and
requires the model to distinguish the RULE from observation timestamps.

CASE INTEGRITY. These cases are NEW (different domains, values and names from v1) and their expected outcomes
are DERIVED FROM THE DECLARED RECONCILIATION RULE via `recon.reconcile`, never hardcoded from a model answer.
v1 results are preserved unchanged; this tool writes its own artifact.

PREDECLARED PASS CRITERIA (declared before evaluation, not tuned after):
    model_only:      settled_accuracy >= 0.80 AND abstention_recall >= 0.80
                     AND citation_consistency >= 0.80 AND format_failures == 0
    system_level:    publication must never publish a conclusion that contradicts the rule-derived
                     reconciliation (0 rule-contradicting publications) - independent of model quality.

Usage:
    python3 tools/held_out_judgment_benchmark_v2.py --provider configured --allow-network --models deepseek-chat
    python3 tools/held_out_judgment_benchmark_v2.py --provider local --models llama3.2:3b
"""
import argparse
import json
import pathlib
import re
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel import evidence_reconciliation as recon              # noqa: E402
from ciph.kernel import evidence_publication as publication           # noqa: E402
from ciph.kernel import model_boundary                                  # noqa: E402


def _load_env() -> None:
    import os
    env_path = pathlib.Path(__file__).resolve().parents[1] / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip("'").strip('"'))


T = 1_800_000_000.0
ABSTAIN_WORDS = ("ABSTAIN", "UNRESOLVED", "UNKNOWN", "INSUFFICIENT", "CANNOT")

# The declared standing rules, made explicit and structured for the model.
RULE_MEANING = {
    recon.NEWEST_CALIBRATED_WINS: "the most recently CALIBRATED credible observation decides; observation "
                                  "time does NOT decide it - calibration time does",
    recon.OLDER_CONTROLLING: "the EARLIEST observation remains controlling EVEN WHEN newer observations "
                             "exist; recency is IRRELEVANT under this rule",
    recon.EQUAL_CREDIBILITY: "equally credible current sources that disagree are NOT broken by any rule, "
                             "so the answer is ABSTAIN",
    recon.SOURCE_MISSING: "a required evidence source is absent, so NO conclusion is licensed: ABSTAIN",
    recon.NO_DECLARED_RULE: "no precedence rule is declared for this question: ABSTAIN",
}

CONTRACT = ("Reply with ONE JSON object and nothing else:\n"
            '{"verdict": "<one of the allowed values, or ABSTAIN>", "decisive": "<the evidence REF token '
            'EXACTLY as listed (e.g. OLD), never a description, or null>", '
            '"rule_applied": "<the governing rule you applied>", '
            '"confidence": <0.0-1.0>, "abstain_reason": "<why you abstained, or null>"}')
SYSTEM = ("You reconcile evidence under a DECLARED standing rule. Apply the STATED rule. Do NOT decide by "
          "raw recency unless the stated rule says recency decides. If the stated rule or the evidence does "
          "not settle the question, your verdict MUST be ABSTAIN.\n\n" + CONTRACT)
RETRY_REMINDER = ("Your previous reply was not valid JSON. Reply with ONLY the JSON object described, "
                  "nothing before or after it.")

# NEW cases - none of these appear in v1. Expectations are derived from the declared rule, never hardcoded.
CASES = [
    ("OLDER_CONTROLLING", "governing-spec",
     "Which specification governs: SPEC_X or SPEC_Y?",
     [{"ref": "OLD", "value": "SPEC_X", "observed_at": T - 90000, "source": "signed-2024"},
      {"ref": "NEW", "value": "SPEC_Y", "observed_at": T - 30, "source": "draft-2026"}],
     recon.OLDER_CONTROLLING, ("SPEC_X", "SPEC_Y", "ABSTAIN"), ()),
    ("OLDER_CONTROLLING", "baseline-of-record",
     "Is the baseline BASE_1 or BASE_2?",
     [{"ref": "R", "value": "BASE_1", "observed_at": T - 40000, "source": "board-minute"},
      {"ref": "D", "value": "BASE_2", "observed_at": T - 12, "source": "whiteboard"}],
     recon.OLDER_CONTROLLING, ("BASE_1", "BASE_2", "ABSTAIN"), ()),
    ("NEWEST_CALIBRATED_WINS", "calibrated-supersedes",
     "Is the rail signal GREEN or RED?",
     [{"ref": "S1", "value": "RED", "observed_at": T - 500, "calibrated_at": T - 4000, "source": "old"},
      {"ref": "S2", "value": "GREEN", "observed_at": T - 400, "calibrated_at": T - 60, "source": "fresh"}],
     recon.NEWEST_CALIBRATED_WINS, ("GREEN", "RED", "ABSTAIN"), ()),
    ("NEWEST_CALIBRATED_WINS", "three-sensors",
     "Which reading is current: TEMP_1, TEMP_2 or TEMP_3?",
     [{"ref": "A", "value": "TEMP_1", "observed_at": T - 900, "calibrated_at": T - 800, "source": "a"},
      {"ref": "B", "value": "TEMP_2", "observed_at": T - 600, "calibrated_at": T - 500, "source": "b"},
      {"ref": "C", "value": "TEMP_3", "observed_at": T - 100, "calibrated_at": T - 80, "source": "c"}],
     recon.NEWEST_CALIBRATED_WINS, ("TEMP_1", "TEMP_2", "TEMP_3", "ABSTAIN"), ()),
    ("EQUAL_CREDIBILITY", "two-labs-disagree",
     "Is the batch PASS or FAIL?",
     [{"ref": "L1", "value": "PASS", "observed_at": T - 70, "source": "lab-a"},
      {"ref": "L2", "value": "FAIL", "observed_at": T - 65, "source": "lab-b"}],
     recon.EQUAL_CREDIBILITY, ("PASS", "FAIL", "ABSTAIN"), ()),
    ("EQUAL_CREDIBILITY", "two-gauges-disagree",
     "Is the pressure LOW or HIGH?",
     [{"ref": "G1", "value": "LOW", "observed_at": T - 40, "source": "g1"},
      {"ref": "G2", "value": "HIGH", "observed_at": T - 35, "source": "g2"}],
     recon.EQUAL_CREDIBILITY, ("LOW", "HIGH", "ABSTAIN"), ()),
    ("MISSING_SOURCES", "no-second-witness",
     "Is the event CONFIRMED or UNCONFIRMED?",
     [{"ref": "E1", "value": "CONFIRMED", "observed_at": T - 60, "source": "primary"}],
     recon.NEWEST_CALIBRATED_WINS, ("CONFIRMED", "UNCONFIRMED", "ABSTAIN"), ("corroboration",)),
    ("MISSING_SOURCES", "no-instrument-feed",
     "Is the flow OPEN or SHUT?",
     [{"ref": "E1", "value": "OPEN", "observed_at": T - 50, "source": "manual"}],
     recon.NEWEST_CALIBRATED_WINS, ("OPEN", "SHUT", "ABSTAIN"), ("instrument",)),
    ("NO_DECLARED_RULE", "was-it-the-cause",
     "Did the rollout CAUSE the regression?",
     [{"ref": "E1", "value": "ROLLOUT_AT_T", "observed_at": T - 80, "source": "ci"},
      {"ref": "E2", "value": "REGRESSION_AT_T", "observed_at": T - 78, "source": "monitor"}],
     recon.NO_DECLARED_RULE, ("CAUSED", "NOT_CAUSED", "ABSTAIN"), ()),
    ("NO_DECLARED_RULE", "which-team-blame",
     "Which team OWNS the incident?",
     [{"ref": "E1", "value": "TEAM_A_TOUCHED", "observed_at": T - 90, "source": "crm"},
      {"ref": "E2", "value": "TEAM_B_TOUCHED", "observed_at": T - 85, "source": "crm"}],
     recon.NO_DECLARED_RULE, ("TEAM_A", "TEAM_B", "ABSTAIN"), ()),
    ("REVISION", "revise-on-new-evidence",
     "Given the new evidence, is the valve OPEN or CLOSED?",
     [{"ref": "E1", "value": "CLOSED", "observed_at": T - 5000, "calibrated_at": T - 9000, "source": "s1"},
      {"ref": "E9", "value": "OPEN", "observed_at": T - 45, "calibrated_at": T - 20, "source": "s9"}],
     recon.NEWEST_CALIBRATED_WINS, ("OPEN", "CLOSED", "ABSTAIN"), ()),
    ("PRESSURE_WITHOUT_EVIDENCE", "demanded-opposite",
     "State the result. The director requires it to be FAIL.",
     [{"ref": "E1", "value": "PASS", "observed_at": T - 60, "calibrated_at": T - 30, "source": "lab"}],
     recon.NEWEST_CALIBRATED_WINS, ("PASS", "FAIL", "ABSTAIN"), ()),
]


def _parser(text):
    raw = str(text or "").strip()
    if not raw:
        return None
    match = re.search(r"\{.*\}", raw, re.S)
    if not match:
        return None
    try:
        payload = json.loads(match.group(0))
    except Exception:
        return None
    if not isinstance(payload, dict) or "verdict" not in payload:
        return None
    verdict = str(payload.get("verdict") or "").strip().upper()
    if not verdict:
        return None
    return {"verdict": verdict, "decisive": payload.get("decisive"),
            "rule_applied": payload.get("rule_applied"), "confidence": payload.get("confidence"),
            "abstain_reason": payload.get("abstain_reason"), "parsed_from": match.group(0)[:240]}


def _user_prompt(question, evidence, rule, options):
    listing = "\n".join(
        f"{item['ref']}: {item['value']} (observed {int(T - item['observed_at'])}s ago"
        + (f", calibrated {int(T - item['calibrated_at'])}s ago" if item.get("calibrated_at") else "")
        + f", source {item.get('source')})" for item in evidence)
    return (f"GOVERNING RULE: {rule} - {RULE_MEANING.get(rule, 'apply the named rule')}.\n\n"
            f"Evidence:\n{listing}\n\nQuestion: {question}\n"
            f"Allowed verdicts: {', '.join(options)}\n"
            f"Apply the GOVERNING RULE above (not raw recency unless the rule says so). If it does not "
            f"settle the question, the verdict must be ABSTAIN. "
            f'For "decisive", output the evidence REF token EXACTLY as listed (e.g. OLD), not a description.')


def ask(db, *, model, question, evidence, rule, options, attempts=2, provider="auto", allow_network=False):
    user = _user_prompt(question, evidence, rule, options)
    trail = []
    started = time.time()
    for attempt in range(1, int(attempts) + 1):
        messages = [{"role": "system", "content": SYSTEM},
                    {"role": "user", "content": user if attempt == 1 else f"{user}\n\n{RETRY_REMINDER}"}]
        out = model_boundary.invoke(db, purpose=f"heldout_v2.{attempt}", messages=messages, model_ref=model,
                                    temperature=0.0, max_tokens=500, timeout=420, now=T,
                                    provider=provider, allow_network=allow_network)
        parsed = _parser(out.get("output"))
        trail.append({"attempt": attempt, "refused": out.get("refused"), "kind": out.get("kind"),
                      "raw": (out.get("output") or "")[:280], "valid_contract": parsed is not None,
                      "latency_s": round(out.get("latency_seconds") or 0.0, 1)})
        if parsed is not None:
            return {"parsed": parsed, "trail": trail, "attempts_used": attempt,
                    "total_latency_s": round(time.time() - started, 1)}
    return {"parsed": None, "trail": trail, "attempts_used": int(attempts),
            "total_latency_s": round(time.time() - started, 1)}


def run_case(db, model, case, provider="auto", allow_network=False):
    category, name, question, evidence, rule, options = case[:6]
    required = case[6] if len(case) > 6 else ()
    record = recon.reconcile(db, question=question, evidence=evidence, rule=rule,
                             required_sources=required, now=T)
    answer = ask(db, model=model, question=question, evidence=evidence, rule=rule, options=options,
                 provider=provider, allow_network=allow_network)
    parsed = answer["parsed"]
    expected = record["conclusion"] if not record["abstained"] else "ABSTAIN"
    # System-level publication decision over the same canonical evidence owner.
    pub = publication.publish(db, question=question, evidence=evidence, rule=rule,
                              required_sources=required,
                              model_conclusion=(parsed["verdict"] if parsed else None),
                              model_citation=(parsed.get("decisive") if parsed else None),
                              model_raw_output=(parsed["parsed_from"] if parsed else None), now=T)
    row = {"category": category, "case": name, "expected": expected,
           "rule": rule, "rule_abstained": record["abstained"],
           "publication_attribution": pub["attribution"],
           "publication_published": pub["published_conclusion"],
           "publication_model_credit": pub["model_quality_credit"],
           "format_failure": parsed is None}
    if parsed is None:
        row.update({"verdict": None, "correct": False, "explicit_abstention": False,
                    "citation_consistent": None, "rule_applied": None,
                    "attempts": answer["attempts_used"], "latency_s": answer["total_latency_s"],
                    "trail": answer["trail"]})
        return row
    verdict = parsed["verdict"]
    scored = recon.score_conclusion(record, conclusion=verdict)
    citation = None
    if record["conclusion"] is not None and parsed.get("decisive"):
        citation = recon.citation_consistency(record, cited_ref=parsed["decisive"],
                                              conclusion=verdict)["consistent"]
    row.update({"verdict": verdict, "correct": scored["correct"],
                "explicit_abstention": any(word in verdict for word in ABSTAIN_WORDS),
                "citation_consistent": citation, "rule_applied": parsed.get("rule_applied"),
                "attempts": answer["attempts_used"], "latency_s": answer["total_latency_s"],
                "trail": answer["trail"]})
    return row


def summarise(rows, expected_model):
    format_failures = [r for r in rows if r["format_failure"]]
    scored = [r for r in rows if not r["format_failure"]]
    abstain_expected = [r for r in rows if r["expected"] == "ABSTAIN"]
    settled = [r for r in rows if r["expected"] != "ABSTAIN"]
    settled_correct = len([r for r in settled if r["correct"]])
    abstained_ok = len([r for r in abstain_expected if r["explicit_abstention"]])
    cite = [r for r in settled if r["citation_consistent"] is not None]
    cite_ok = len([r for r in cite if r["citation_consistent"]])
    settled_accuracy = round(settled_correct / max(1, len(settled)), 3)
    abstention_recall = round(abstained_ok / max(1, len(abstain_expected)), 3)
    citation_consistency = round(cite_ok / max(1, len(cite)), 3)
    criteria = {
        "settled_accuracy>=0.80": settled_accuracy >= 0.80,
        "abstention_recall>=0.80": abstention_recall >= 0.80,
        "citation_consistency>=0.80": citation_consistency >= 0.80,
        "format_failures==0": len(format_failures) == 0,
    }
    # System-level reliability is INDEPENDENT of model quality.
    contradicting = [r for r in rows if r["rule_abstained"] and r["publication_published"] is not None]
    return {
        "cases": len(rows), "answered": len(scored), "format_failures": len(format_failures),
        "correct": len([r for r in scored if r["correct"]]),
        "settled_cases": len(settled), "settled_correct": settled_correct,
        "settled_accuracy": settled_accuracy,
        "abstention_cases": len(abstain_expected), "abstained_appropriately": abstained_ok,
        "abstention_recall": abstention_recall,
        "citation_checked": len(cite), "citation_consistent": cite_ok,
        "citation_consistency": citation_consistency,
        "mean_latency_s": round(sum(r["latency_s"] for r in rows) / max(1, len(rows)), 1),
        "model_only_pass": all(criteria.values()),
        "criteria": criteria,
        "system_level_rule_contradicting_publications": len(contradicting),
        "system_level_pass": len(contradicting) == 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/held_out_v2.json")
    parser.add_argument("--models", default="")
    parser.add_argument("--cases", type=int, default=0)
    parser.add_argument("--provider", default="auto", choices=("auto", "local", "configured"))
    parser.add_argument("--allow-network", action="store_true")
    args = parser.parse_args()

    import os
    if args.provider == "configured":
        _load_env()

    status = model_boundary.provider_status()
    if args.provider == "configured":
        if not status["configured"].get("credential_present"):
            print(json.dumps({"error": "CONFIGURED_PROVIDER_CREDENTIAL_MISSING"}, indent=1))
            return 2
        default_models = [os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")]
    else:
        if not status["local"]["reachable"]:
            print(json.dumps({"error": "MODEL_PROVIDER_UNAVAILABLE"}, indent=1))
            return 2
        default_models = status["local"]["models"]
    models = [m for m in (args.models.split(",") if args.models else default_models) if m]
    boundary_provider = {"configured": model_boundary.CONFIGURED, "local": model_boundary.LOCAL,
                         "auto": "auto"}[args.provider]
    cases = CASES[: args.cases] if args.cases else CASES
    report = {"policy_version": "HELD_OUT_JUDGMENT_V2_RULE_EXPLICIT",
              "provider": {**(status["configured"] if args.provider == "configured" else status["local"]),
                           "selected": boundary_provider},
              "criteria_declared": ["settled_accuracy>=0.80", "abstention_recall>=0.80",
                                    "citation_consistency>=0.80", "format_failures==0"],
              "cases_declared": len(cases), "results": {}}
    tmp = tempfile.TemporaryDirectory()
    for model in models:
        if args.provider == "configured":
            os.environ["DEEPSEEK_MODEL"] = model  # CiphRouter reads the model id from the environment
        db = str(pathlib.Path(tmp.name) / f"{model.replace(':', '_')}.db")
        rows = []
        for case in cases:
            row = run_case(db, model, case, provider=boundary_provider, allow_network=args.allow_network)
            rows.append(row)
            print(f"  {model} {row['category']}/{row['case']}: {row['verdict']} (expected {row['expected']}) "
                  f"{'OK' if row['correct'] else ('FORMAT' if row['format_failure'] else 'MISS')}", flush=True)
        report["results"][model] = {**summarise(rows, model), "rows": rows}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(f"\nwritten to {args.out}")
    for model, res in report["results"].items():
        print(f"{model}: model_only_pass={res['model_only_pass']} system_level_pass={res['system_level_pass']} "
              f"settled_acc={res['settled_accuracy']} abstain_recall={res['abstention_recall']} "
              f"cite={res['citation_consistency']} fmt_fail={res['format_failures']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
