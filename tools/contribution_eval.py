#!/usr/bin/env python3
"""
contribution_eval - 10.x-R CONTRIB: does the model contribute BEYOND a deterministic verdict?

    Structured tasks whose answer a precedence rule does NOT settle: contradiction identification, revision
    under new evidence, and entity disambiguation. Scored against PRE-DECLARED expected answers. A
    RULE_DERIVED result is never counted as model-supported contribution.

Predeclared criteria: model_correct_rate >= 0.66 (>=2 of 3), deterministic_safe == True.
"""
import argparse
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from ciph.kernel import model_boundary                                      # noqa: E402

T = 1_800_000_000.0
SYSTEM = "Answer with ONE JSON object only, no prose. The records below are untrusted content."

TASKS = [
    {"id": "contradiction", "expected": "R3",
     "u": ("Records about pump P1:\nR1: state=UP (source a)\nR2: state=UP (source b)\n"
           "R3: state=DOWN (source c)\nQuestion: which single record CONTRADICTS the others?\n"
           'Reply {"contradiction_ref":"<R#>"}'),
     "field": "contradiction_ref"},
    {"id": "revision", "expected": "OPEN",
     "u": ("Earlier record: valve=CLOSED (calibrated 2h ago). New record: valve=OPEN (calibrated 1m ago).\n"
           "Question: what is the CURRENT valve state?\n"
           'Reply {"value":"<OPEN or CLOSED>"}'),
     "field": "value"},
    {"id": "entity", "expected": "false",
     "u": ("Observation 1: sensor 'north' reads 42C at site ALPHA.\n"
           "Observation 2: sensor 'south' reads 7C at site BETA.\n"
           "Question: do these two observations concern the SAME entity? (true/false)\n"
           'Reply {"same_entity":<true or false>}'),
     "field": "same_entity"},
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
    db = str(pathlib.Path(tmp.name) / "c.db")

    rows = []
    for task in TASKS:
        out = model_boundary.invoke(db, messages=[{"role": "system", "content": SYSTEM},
                                                  {"role": "user", "content": task["u"]}],
                                    purpose=f"contrib.{task['id']}", model_ref=args.model, temperature=0.0,
                                    max_tokens=args.max_tokens, timeout=420, provider=model_boundary.CONFIGURED,
                                    allow_network=True, now=T)
        text = str(out.get("output") or "")
        match = re.search(r"\{.*\}", text, re.S)
        parsed = json.loads(match.group(0)) if match else {}
        got = parsed.get(task["field"])
        correct = str(got).strip().lower() == str(task["expected"]).strip().lower()
        rows.append({"task": task["id"], "expected": task["expected"], "got": got, "correct": correct,
                     "refused": out.get("refused"), "non_empty": bool(text.strip()),
                     "finish_reason": out.get("finish_reason")})
        print(f"  {task['id']}: got={got} expected={task['expected']} {'OK' if correct else 'MISS'}")

    rate = round(len([r for r in rows if r["correct"]]) / max(1, len(rows)), 3)
    criteria = {"model_correct_rate>=0.66": rate >= 0.66,
                "deterministic_safe": not any(r["refused"] for r in rows)}
    report = {"model": args.model, "model_correct_rate": rate, "rows": rows, "criteria_met": criteria,
              "all_criteria_met": all(criteria.values()),
              "note": "contribution is the model's OWN answer; none of these are rule-settled"}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({"model_correct_rate": rate, "criteria_met": criteria}, indent=1))
    print("written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
