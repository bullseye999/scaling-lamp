#!/usr/bin/env python3
"""
model_diagnostics - 10.x-R DIAG: why does the configured primary model return empty content?

    Capture SAFE metadata only. No credentials, no prompts, no reasoning content.

For each sample we record: requested vs served model, finish_reason, usage counts (incl. reasoning tokens
when exposed), whether final `content` was present, whether `reasoning_content` was present (boolean only),
latency, and the error category when the request failed. This distinguishes EMPTY_MODEL_OUTPUT from a
transport failure, rate limiting, a malformed response or an unavailable provider.

Usage:
    python3 tools/model_diagnostics.py --samples 12 --max-tokens 4000 --out FILE
"""
import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PROMPT_SYSTEM = ('You reconcile evidence under a DECLARED rule. Reply with ONE JSON object: '
                 '{"verdict":"<value or ABSTAIN>","decisive":"<ref exactly>","rule_applied":"<rule>"}')
PROMPT_USER = ("GOVERNING RULE: NEWEST_CALIBRATED_WINS.\nEvidence:\n"
               "src_a: alpha depends on libcore v1 (source a)\n"
               "src_b: beta depends on libcore v1 (source b)\n"
               "src_c: gamma depends on other lib v2 (source c)\n"
               "Question: Do the services share libcore? Allowed verdicts: libcore, other, ABSTAIN")


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def _metadata(response, requested_model, latency, budget):
    choice = response.choices[0] if getattr(response, "choices", None) else None
    message = getattr(choice, "message", None) if choice is not None else None
    content = getattr(message, "content", None) if message is not None else None
    reasoning = getattr(message, "reasoning_content", None) if message is not None else None
    usage = getattr(response, "usage", None)
    details = getattr(usage, "completion_tokens_details", None) if usage is not None else None
    return {
        "requested_model": requested_model,
        "served_model": getattr(response, "model", None),
        "response_id_present": bool(getattr(response, "id", None)),
        "finish_reason": getattr(choice, "finish_reason", None) if choice is not None else None,
        "choices_count": len(getattr(response, "choices", []) or []),
        "content_present": bool(content),
        "content_len": len(content or ""),
        "reasoning_content_present": bool(reasoning),
        "prompt_tokens": getattr(usage, "prompt_tokens", None) if usage is not None else None,
        "completion_tokens": getattr(usage, "completion_tokens", None) if usage is not None else None,
        "total_tokens": getattr(usage, "total_tokens", None) if usage is not None else None,
        "reasoning_tokens": getattr(details, "reasoning_tokens", None) if details is not None else None,
        "requested_output_budget": budget,
        "latency_s": round(latency, 2),
        "provider_responded": True,
        "error_category": None,
    }


def _classify(exc):
    name = type(exc).__name__
    text = str(exc)
    if "429" in text or "rate" in text.lower():
        return "RATE_LIMITED"
    if "timeout" in name.lower() or "timeout" in text.lower():
        return "TRANSPORT_TIMEOUT"
    if "connection" in name.lower() or "Connection" in text:
        return "TRANSPORT_CONNECTION"
    if "401" in text or "403" in text:
        return "AUTH"
    if "5" in text[:1] and "server" in text.lower():
        return "PROVIDER_5XX"
    return f"SDK_{name}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=12)
    parser.add_argument("--max-tokens", type=int, default=4000)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    _load_env()

    from openai import OpenAI
    import os
    key = os.environ["DEEPSEEK_API_KEY"]
    base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com/v1")
    model = os.environ.get("DEEPSEEK_MODEL", "deepseek-chat")
    client = OpenAI(api_key=key, base_url=base, timeout=120.0, max_retries=0)  # no SDK auto-retry: we measure

    samples = []
    for index in range(args.samples):
        started = time.time()
        try:
            response = client.chat.completions.create(
                model=model, messages=[{"role": "system", "content": PROMPT_SYSTEM},
                                       {"role": "user", "content": PROMPT_USER}],
                temperature=0.0, max_tokens=args.max_tokens)
            meta = _metadata(response, model, time.time() - started, args.max_tokens)
        except Exception as exc:                                          # noqa: BLE001
            meta = {"requested_model": model, "served_model": None, "finish_reason": None,
                    "choices_count": 0, "content_present": False, "content_len": 0,
                    "reasoning_content_present": False, "requested_output_budget": args.max_tokens,
                    "latency_s": round(time.time() - started, 2), "provider_responded": False,
                    "error_category": _classify(exc)}
        meta["sample"] = index
        samples.append(meta)
        print(f"  sample {index}: served={meta['served_model']} finish={meta['finish_reason']} "
              f"content={meta['content_present']}({meta['content_len']}) comp_tok={meta.get('completion_tokens')} "
              f"reason_tok={meta.get('reasoning_tokens')} err={meta['error_category']}")

    responded = [s for s in samples if s["provider_responded"]]
    non_empty = [s for s in samples if s["content_present"]]
    report = {"samples": len(samples), "max_tokens": args.max_tokens, "model_requested": model,
              "transport_success_rate": round(len(responded) / max(1, len(samples)), 3),
              "non_empty_rate": round(len(non_empty) / max(1, len(samples)), 3),
              "empty_but_responded": len([s for s in responded if not s["content_present"]]),
              "finish_reasons": sorted({str(s["finish_reason"]) for s in responded}),
              "reasoning_present_any": any(s["reasoning_content_present"] for s in samples),
              "detail": samples}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(f"\ntransport_success={report['transport_success_rate']} non_empty={report['non_empty_rate']} "
          f"empty_but_responded={report['empty_but_responded']} finish={report['finish_reasons']}")
    print("written to", args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
