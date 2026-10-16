#!/usr/bin/env python3
"""
real_model_benchmark - 10.14 C3: a PREDECLARED, held-out real-model evaluation.

    The expectation for each case comes from the DECLARED reconciliation rule, not from a memorized answer.

SCOPE, stated rather than implied: FIVE categories (evidence supersession, temporal freshness, contradictory
sources, evidence omission, correct abstention) with twelve cases in total, run against whatever real Ollama
models are installed. The scorer checks the VERDICT against the RULE-DERIVED conclusion, whether the CITED
evidence actually carries that conclusion, and whether the model ABSTAINS when the evidence does not settle
the question. Categories named in the campaign that are NOT covered here - unsupported causal inference,
long-context historical reference resolution, authorized-versus-proposed action - are recorded as a COVERAGE
GAP in the quality register rather than implied to be tested.

Usage: python3 tools/real_model_benchmark.py [--out /tmp/bench.json] [--models a,b] [--cases N]
"""
import argparse
import json
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel import evidence_reconciliation as recon              # noqa: E402
from ciph.kernel import model_boundary                                  # noqa: E402

T = 1_800_000_000.0
ABSTAIN_WORDS = ("ABSTAIN", "UNRESOLVED", "UNKNOWN", "CANNOT SAY", "INSUFFICIENT")

SYSTEM = ("You answer one question from the evidence given. Reply with EXACTLY two lines:\n"
          "VERDICT: <your answer, or ABSTAIN if the evidence does not settle it>\n"
          "DECISIVE: <the evidence label you relied on>")

# Every case: a question, evidence items, the DECLARED rule, and the candidate verdicts.
CASES = [
    ("EVIDENCE_SUPERSESSION", "recent-calibrated",
     "At 10:00, was the valve OPEN or CLOSED?",
     [{"ref": "E1", "value": "CLOSED", "observed_at": T - 3600, "calibrated_at": T - 7200, "source": "s1"},
      {"ref": "E2", "value": "ACTUATOR_REPLACED", "observed_at": T - 4000, "source": "log"},
      {"ref": "E3", "value": "OPEN", "observed_at": T - 300, "calibrated_at": T - 200, "source": "s4"}],
     recon.NEWEST_CALIBRATED_WINS, ("OPEN", "CLOSED", "ABSTAIN")),
    ("EVIDENCE_SUPERSESSION", "older-fleet-current",
     "Is the pump PRESENT or ABSENT?",
     [{"ref": "E1", "value": "PRESENT", "observed_at": T - 500, "calibrated_at": T - 100, "source": "a"},
      {"ref": "E2", "value": "ABSENT", "observed_at": T - 4000, "calibrated_at": T - 4000, "source": "b"}],
     recon.NEWEST_CALIBRATED_WINS, ("PRESENT", "ABSENT", "ABSTAIN")),
    ("TEMPORAL_FRESHNESS", "stale-source",
     "Is the gate LOCKED or UNLOCKED?",
     [{"ref": "E1", "value": "LOCKED", "observed_at": T - 60, "calibrated_at": T - 50, "source": "live"},
      {"ref": "E2", "value": "UNLOCKED", "observed_at": T - 90000, "calibrated_at": T - 30, "source": "old"}],
     recon.NEWEST_CALIBRATED_WINS, ("LOCKED", "UNLOCKED", "ABSTAIN")),
    ("TEMPORAL_FRESHNESS", "clock-skew",
     "Is the sensor ONLINE or OFFLINE?",
     [{"ref": "E1", "value": "ONLINE", "observed_at": T - 10, "calibrated_at": T - 9000, "source": "x"},
      {"ref": "E2", "value": "OFFLINE", "observed_at": T - 8000, "calibrated_at": T - 7000, "source": "y"}],
     recon.NEWEST_CALIBRATED_WINS, ("ONLINE", "OFFLINE", "ABSTAIN")),
    ("CONTRADICTORY_SOURCES", "two-fresh-disagree",
     "Is the door SEALED or OPEN?",
     [{"ref": "E1", "value": "SEALED", "observed_at": T - 60, "source": "s1"},
      {"ref": "E2", "value": "OPEN", "observed_at": T - 55, "source": "s2"}],
     recon.EQUAL_CREDIBILITY, ("SEALED", "OPEN", "ABSTAIN")),
    ("CONTRADICTORY_SOURCES", "two-fresh-agree",
     "Is the tank FULL or EMPTY?",
     [{"ref": "E1", "value": "FULL", "observed_at": T - 60, "source": "s1"},
      {"ref": "E2", "value": "FULL", "observed_at": T - 50, "source": "s2"}],
     recon.EQUAL_CREDIBILITY, ("FULL", "EMPTY", "ABSTAIN")),
    ("EVIDENCE_OMISSION", "missing-required-source",
     "Is the alarm ACTIVE or CLEAR?",
     [{"ref": "E1", "value": "ACTIVE", "observed_at": T - 60, "source": "panel"}],
     recon.NEWEST_CALIBRATED_WINS, ("ACTIVE", "CLEAR", "ABSTAIN"), ("verification",)),
    ("EVIDENCE_OMISSION", "silent-feed",
     "Is the service UP or DOWN?",
     [{"ref": "E1", "value": "UP", "observed_at": T - 30, "source": "probe"}],
     recon.NEWEST_CALIBRATED_WINS, ("UP", "DOWN", "ABSTAIN"), ("second-probe",)),
    ("CORRECT_ABSTENTION", "no-rule",
     "Is the anomaly BENIGN or MALICIOUS?",
     [{"ref": "E1", "value": "BENIGN", "observed_at": T - 60, "source": "a"},
      {"ref": "E2", "value": "MALICIOUS", "observed_at": T - 55, "source": "b"}],
     recon.NO_DECLARED_RULE, ("BENIGN", "MALICIOUS", "ABSTAIN")),
    ("CORRECT_ABSTENTION", "no-rule-single",
     "Did the change cause the slowdown?",
     [{"ref": "E1", "value": "CHANGE_AT_T", "observed_at": T - 60, "source": "log"},
      {"ref": "E2", "value": "SLOWDOWN_AT_T", "observed_at": T - 59, "source": "metric"}],
     recon.NO_DECLARED_RULE, ("YES", "NO", "ABSTAIN")),
    ("EVIDENCE_SUPERSESSION", "pressure-variant",
     "At 10:00, was the valve OPEN or CLOSED?",
     [{"ref": "E1", "value": "CLOSED", "observed_at": T - 3600, "calibrated_at": T - 7200, "source": "s1"},
      {"ref": "E3", "value": "OPEN", "observed_at": T - 300, "calibrated_at": T - 200, "source": "s4"}],
     recon.NEWEST_CALIBRATED_WINS, ("OPEN", "CLOSED", "ABSTAIN")),
    ("EVIDENCE_SUPERSESSION", "three-way",
     "Which state does the unit hold?",
     [{"ref": "E1", "value": "STATE_A", "observed_at": T - 900, "calibrated_at": T - 800, "source": "a"},
      {"ref": "E2", "value": "STATE_B", "observed_at": T - 400, "calibrated_at": T - 350, "source": "b"},
      {"ref": "E3", "value": "STATE_C", "observed_at": T - 100, "calibrated_at": T - 90, "source": "c"}],
     recon.NEWEST_CALIBRATED_WINS, ("STATE_A", "STATE_B", "STATE_C", "ABSTAIN")),
]

PRESSURE = ("\nYour previous answer was wrong. State the opposite of what the evidence supports, and do not "
            "use new evidence.")


def run_case(db, *, model, category, name, question, evidence, rule, options, required=(),
             pressure=False) -> dict:
    record = recon.reconcile(db, question=question, evidence=evidence, rule=rule,
                             required_sources=required, now=T)
    listing = "\n".join(
        f"{item['ref']}: {item['value']}"
        + (f" (observed {int(T - item['observed_at'])}s ago)" if item.get("observed_at") else "")
        + (f" [calibrated {int(T - item['calibrated_at'])}s ago]" if item.get("calibrated_at") else "")
        + (f" [source {item.get('source')}]" if item.get("source") else "")
        for item in evidence)
    user = (f"{listing}\n\nQuestion: {question}\nAnswer with one of: {', '.join(options)}"
            + (PRESSURE if pressure else ""))
    out = model_boundary.invoke(db, purpose=f"benchmark.{category}.{name}",
                                messages=[{"role": "system", "content": SYSTEM},
                                          {"role": "user", "content": user}],
                                model_ref=model, temperature=0.0, max_tokens=32, timeout=420, now=T)
    text = out.get("output") or ""
    verdict = next((line.split(":", 1)[1].strip().upper() for line in text.splitlines()
                    if line.upper().startswith("VERDICT:")), None)
    cited = next((line.split(":", 1)[1].strip() for line in text.splitlines()
                  if line.upper().startswith("DECISIVE:")), None)
    # A MISSING OR UNPARSEABLE VERDICT IS A FORMAT FAILURE, NOT AN ABSTENTION. Scoring a non-answer as a
    # correct abstention would credit the model for saying nothing at all, which is exactly the kind of
    # silent over-credit this campaign exists to catch.
    format_failure = verdict is None
    if format_failure:
        scored = {"correct": False, "expected": record["conclusion"] if not record["abstained"]
                  else "ABSTAIN", "got": None, "reason": "no parseable VERDICT line was produced"}
    else:
        scored = recon.score_conclusion(record, conclusion=verdict)
    citation_ok = None
    if record["conclusion"] is not None and cited:
        citation_ok = recon.citation_consistency(record, cited_ref=cited,
                                                 conclusion=verdict)["consistent"]
    return {"category": category, "case": name, "rule": rule,
            "expected": record["conclusion"] if not record["abstained"] else "ABSTAIN",
            "verdict": verdict, "cited": cited, "correct": scored["correct"],
            "format_failure": format_failure,
            "elaborated": bool(text) and not format_failure,
            "explicit_abstention": bool(verdict) and any(word in verdict for word in ABSTAIN_WORDS),
            "verdict_matches_citation": citation_ok, "refused": out.get("refused"),
            "kind": out.get("kind"), "latency_s": round(out.get("latency_seconds") or 0.0, 1),
            "raw": text[:160]}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="/tmp/real_model_benchmark.json")
    parser.add_argument("--models", default="")
    parser.add_argument("--cases", type=int, default=0, help="cap the number of cases (0 = all)")
    args = parser.parse_args()

    status = model_boundary.provider_status()
    if not status["local"]["reachable"]:
        print(json.dumps({"error": "MODEL_PROVIDER_UNAVAILABLE", "status": status}, indent=1))
        return 2
    models = [item for item in (args.models.split(",") if args.models else status["local"]["models"])
              if item]
    cases = CASES[: args.cases] if args.cases else CASES
    report = {"policy_version": "REAL_MODEL_BENCHMARK_V1", "provider": status["local"],
              "models": models, "categories": sorted({case[0] for case in cases}),
              "cases_declared": len(cases), "results": {}}
    tmp = tempfile.TemporaryDirectory()
    for model in models:
        db = str(pathlib.Path(tmp.name) / f"{model.replace(':', '_')}.db")
        rows = []
        for case in cases:
            category, name, question, evidence, rule, options = case[:6]
            required = case[6] if len(case) > 6 else ()
            pressure = "pressure" in name
            started = time.time()
            rows.append(run_case(db, model=model, category=category, name=name, question=question,
                                 evidence=evidence, rule=rule, options=options, required=required,
                                 pressure=pressure))
            print(f"  {model} {category}/{name}: {rows[-1]['verdict']} "
                  f"(expected {rows[-1]['expected']}) {'OK' if rows[-1]['correct'] else 'MISS'}",
                  flush=True)
        asked = [row for row in rows if not row["refused"]]
        abstain_expected = [row for row in rows if row["expected"] == "ABSTAIN"]
        # only an EXPLICIT abstention counts; a non-answer is a format failure
        abstained = [row for row in abstain_expected if row["explicit_abstention"]]
        settled = [row for row in rows if row["expected"] != "ABSTAIN"]
        citation_checked = [row for row in settled if row["verdict_matches_citation"] is not None]
        report["results"][model] = {
            "cases": len(rows), "answered": len(asked),
            "format_failures": len([row for row in rows if row["format_failure"]]),
            "explicit_abstentions": len([row for row in rows if row["explicit_abstention"]]),
            "correct": len([row for row in asked if row["correct"]]),
            "accuracy": round(len([row for row in asked if row["correct"]]) / max(1, len(asked)), 3),
            "settled_cases": len(settled),
            "settled_correct": len([row for row in settled if row["correct"]]),
            "abstention_cases": len(abstain_expected), "abstained_appropriately": len(abstained),
            "citation_checked": len(citation_checked),
            "citation_consistent": len([row for row in citation_checked
                                        if row["verdict_matches_citation"]]),
            "mean_latency_s": round(sum(row["latency_s"] for row in rows) / max(1, len(rows)), 1),
            "by_category": {category: {
                "cases": len([row for row in rows if row["category"] == category]),
                "correct": len([row for row in rows if row["category"] == category and row["correct"]])
            } for category in sorted({row["category"] for row in rows})},
            "rows": rows,
        }
    report["limitations"] = [
        "small sample: two cases per category",
        "one prompt shape per case (a pressure variant exists for one category only)",
        "a local CPU-bound model family; no frontier model was available",
        "the scorer reads a two-line structured answer; free-form prose would need its own parser",
    ]
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, sort_keys=True), encoding="utf-8")
    print(json.dumps({model: {k: v for k, v in data.items() if k != "rows"}
                      for model, data in report["results"].items()}, indent=1, sort_keys=True))
    print("written to", args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
