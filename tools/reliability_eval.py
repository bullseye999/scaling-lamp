#!/usr/bin/env python3
"""
reliability_eval - 10.x-R REL: measure the configured primary model THROUGH the actual Ciph boundary.

    Predeclared criteria (declared before the run, not tuned after):
        transport_success_rate >= 0.95
        non_empty_rate         >= 0.80
        format_compliance      >= 0.80
    Sample size: --samples (default 8).

Reports separately: transport success, non-empty completion, format compliance, refusal categories, usage and
latency. A successful transport is NOT equated with useful cognition.
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
from ciph.kernel import model_boundary                                   # noqa: E402

SYSTEM = ('You reconcile evidence under a DECLARED rule. Reply with ONE JSON object: '
          '{"verdict":"<value or ABSTAIN>","decisive":"<ref exactly>","rule_applied":"<rule>"}')
USER = ("GOVERNING RULE: NEWEST_CALIBRATED_WINS.\nEvidence:\n"
        "src_a: alpha depends on libcore v1 (source a)\n"
        "src_b: beta depends on libcore v1 (source b)\n"
        "src_c: gamma depends on other lib v2 (source c)\n"
        "Question: Do the services share libcore? Allowed verdicts: libcore, other, ABSTAIN")
PREDECLARED = {"transport_success_rate>=": 0.95, "non_empty_rate>=": 0.80, "format_compliance>=": 0.80}


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=8)
    parser.add_argument("--max-tokens", type=int, default=16000)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    _load_env()
    import os
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-v4-pro")
    tmp = tempfile.TemporaryDirectory()
    db = str(pathlib.Path(tmp.name) / "rel.db")

    rows = []
    for index in range(args.samples):
        started = time.time()
        out = model_boundary.invoke(db, messages=[{"role": "system", "content": SYSTEM},
                                                  {"role": "user", "content": USER}],
                                    purpose=f"reliability.{index}", model_ref=model, temperature=0.0,
                                    max_tokens=args.max_tokens, timeout=420,
                                    provider=model_boundary.CONFIGURED, allow_network=True, now=time.time())
        text = str(out.get("output") or "")
        match = re.search(r"\{.*\}", text, re.S)
        parsed = None
        try:
            parsed = json.loads(match.group(0)) if match else None
        except Exception:
            parsed = None
        rows.append({"sample": index, "refused": bool(out.get("refused")),
                     "refusal_reason": out.get("refusal_reason"), "finish_reason": out.get("finish_reason"),
                     "usage": out.get("usage"), "model_identity": out.get("model_identity"),
                     "non_empty": bool(text.strip()), "format_ok": bool(parsed and "verdict" in parsed),
                     "verdict": (parsed or {}).get("verdict"), "latency_s": round(time.time() - started, 1)})
        print(f"  sample {index}: refused={out.get('refused')} finish={out.get('finish_reason')} "
              f"non_empty={bool(text.strip())} fmt={bool(parsed and 'verdict' in parsed)} "
              f"verdict={(parsed or {}).get('verdict')} lat={rows[-1]['latency_s']}s")

    def rate(pred):
        return round(len([r for r in rows if pred(r)]) / max(1, len(rows)), 3)

    transport = rate(lambda r: r["refusal_reason"] not in (model_boundary.NO_PROVIDER,) and
                     not str(r["refusal_reason"] or "").startswith(model_boundary.PROVIDER_ERROR))
    non_empty = rate(lambda r: r["non_empty"])
    fmt = rate(lambda r: r["format_ok"])
    report = {"model": model, "samples": len(rows), "max_tokens": args.max_tokens,
              "predeclared": PREDECLARED,
              "transport_success_rate": transport, "non_empty_rate": non_empty,
              "format_compliance": fmt,
              "refusal_counts": {str(r["refusal_reason"]): len([x for x in rows
                                                                if x["refusal_reason"] == r["refusal_reason"]])
                                 for r in rows},
              "mean_latency_s": round(sum(r["latency_s"] for r in rows) / max(1, len(rows)), 1),
              "criteria_met": {"transport": transport >= 0.95, "non_empty": non_empty >= 0.80,
                               "format": fmt >= 0.80},
              "rows": rows}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(f"\ntransport={transport} non_empty={non_empty} format={fmt} "
          f"criteria_met={report['criteria_met']} mean_lat={report['mean_latency_s']}s")
    print("written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
