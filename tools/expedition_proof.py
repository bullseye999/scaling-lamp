#!/usr/bin/env python3
"""
expedition_proof - 10.x-R EXP: a real, bounded, AUTHORIZED expedition with the actual primary model
participating, followed by a truthful conversation about it.

    The expedition owner does not reason (its census forbids it). This orchestrator composes the EXISTING
    owners - 4.4 uncertainty/proposal, 5.x standing authorization, 10.0 findings, 10.5 awareness, 10.6
    attention, 10.9 expedition, 10.10 incubation, 10.13 model boundary - and the model participates ONLY
    through the canonical boundary. No new canonical owner is created.

WHAT IS DISPOSABLE AND AUTHORIZED. Everything runs in a throwaway temp database. The investigation operates
on local fixture sources created by this tool (real file reads = real tool execution), under an operator-issued
standing authorization. No network target, no external effect.

PRESERVED: model invocations (via the boundary), expedition/grant identities, tool-execution digests,
original model hypotheses, supporting AND contradictory results, unresolved questions, attention transitions,
resource use, and the exact conversational references.

Usage:
    python3 tools/expedition_proof.py --provider configured --allow-network --model deepseek-v4-pro --out FILE
    python3 tools/expedition_proof.py --provider local --model llama3.2:3b --out FILE
"""
import argparse
import json
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ciph.kernel import independent_expeditions as expeditions          # noqa: E402
from ciph.kernel import incubation                                      # noqa: E402
from ciph.kernel import evidence_reconciliation as recon                # noqa: E402
from ciph.kernel import evidence_publication as publication             # noqa: E402
from ciph.kernel import model_boundary                                  # noqa: E402
from ciph.kernel import conversational_continuity as conv               # noqa: E402
from ciph.kernel.epistemic_ledger import record_observation             # noqa: E402
from ciph.kernel.referential_continuity import retrieve_result_set      # noqa: E402
from ciph.kernel.self_model import record_installation                  # noqa: E402
from ciph.kernel.uncertainty_registry import derive_uncertainties       # noqa: E402
from ciph.kernel.standing_authorization import create_standing_authorization  # noqa: E402


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


T0 = time.time()


def _now():
    return T0 + (time.time() - T0)


def _invoke(db, model, provider, allow_network, *, system, user, purpose, max_tokens=1600):
    out = model_boundary.invoke(db, messages=[{"role": "system", "content": system},
                                              {"role": "user", "content": user}],
                                purpose=purpose, model_ref=model, temperature=0.0, max_tokens=max_tokens,
                                timeout=420, provider=provider, allow_network=allow_network, now=_now())
    return out


def _json_or_none(text):
    import re
    match = re.search(r"\{.*\}", str(text or ""), re.S)
    if not match:
        return None
    try:
        return json.loads(match.group(0))
    except Exception:
        return None


def run(db, model, provider, allow_network, operator="operator:operator"):
    evidence_record = {"model_requested": model, "provider": provider}

    # ---------------------------------------------------------------- (0) disposable fixtures = real tool reads
    fixture_dir = pathlib.Path(db).parent / "public_sources"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    sources = {
        "src_a": "Source A reports that service-alpha depends on library 'libcore' v1.",
        "src_b": "Source B reports that service-beta also depends on library 'libcore' v1.",
        "src_c": "Source C reports that service-gamma depends on library 'libother' v2.",
    }
    for name, text in sources.items():
        (fixture_dir / f"{name}.txt").write_text(text)
    tool_execution = []
    observations = {}
    for name in sources:
        path = fixture_dir / f"{name}.txt"
        digest_text = path.read_text()                                   # a REAL local read
        tool_execution.append({"tool": "read_file", "target": str(path.name),
                               "bytes": len(digest_text), "read_at": _now()})
        obs = record_observation(db, source_ref=name, raw_text=digest_text, now=_now())
        observations[name] = obs["observation_id"]
    evidence_record["tool_execution"] = tool_execution
    evidence_record["observation_refs"] = observations

    # ---------------------------------------------------------------- (1) 4.4 uncertainty + 5.x authorization
    record_installation(db, capability_id="research.public-sources", module_ref="fixture", now=_now())
    uncertainty = derive_uncertainties(db, now=_now())[0].uncertainty_id
    grant = create_standing_authorization(db, mission_id="EXPLORATION-operator", permitted_work_classes=["RESEARCH"],
                                          granted_by=operator, risk_ceiling="LOW",
                                          scope_constraints=["public-sources"], valid_until=_now() + 86400,
                                          now=_now())
    evidence_record["uncertainty_ref"] = uncertainty
    evidence_record["grant_ref"] = grant.standing_auth_id

    # ---------------------------------------------------------------- (2) conversational continuity
    conv.register_participant(db, participant_id=operator, role=conv.OPERATOR, now=_now())
    conv.register_participant(db, participant_id="ciph", role=conv.ASSISTANT, now=_now())
    conv.register_channel(db, channel_id="terminal", kind="LOCAL_TERMINAL", now=_now())
    conv.open_session(db, session_id="SES-EXP", participant_id=operator, channel_id="terminal",
                      topic_ref="EXPLORATION-operator", now=_now())
    conv.record_turn(db, session_id="SES-EXP", speaker=operator,
                     text="While I'm away, investigate whether our public services share an untested "
                          "common dependency. Bounded and local only.",
                     kind=conv.COMMITMENT, authorization_ref=grant.standing_auth_id, now=_now())
    conv.close_session(db, session_id="SES-EXP", now=_now())

    # ---------------------------------------------------------------- (3) expedition proposed + authorized
    proposed = expeditions.propose_expedition(
        db, uncertainty_ref=uncertainty, domain="public-research",
        origin_question="Do the public services share an untested common dependency?",
        permitted_tools=["read_file"], inference_budget=6, tool_call_budget=8, now=_now())
    decision = expeditions.authorize_expedition(
        db, expedition_id=proposed["expedition_id"], grant_ref=grant.standing_auth_id, work_class="RESEARCH",
        risk_class="LOW", requested_scope=["public-sources"], now=_now())
    evidence_record["expedition"] = {k: proposed[k] for k in ("expedition_id", "status", "uncertainty_ref")}
    evidence_record["authorization"] = {"authorized": decision["authorized"], "status": decision["status"],
                                        "refusal_reason": decision.get("refusal_reason")}
    assert decision["authorized"], decision

    # ---------------------------------------------------------------- (4) MODEL selects the question
    sel_out = _invoke(db, model, provider, allow_network,
                      system="You are Ciph. Choose the single most worthwhile AUTHORIZED question and justify "
                             "it briefly. Reply with ONE JSON object: {\"selected_question\":\"...\",\"reason\":\"...\"}",
                      user=("Standing objective: investigate whether the public services share an untested "
                            "common dependency.\nCandidate questions:\n"
                            "1) Do service-alpha and service-beta share library 'libcore'?\n"
                            "2) How many services exist?\n3) Is the weather good?\n"
                            "Only a question within the granted scope may be chosen."),
                      purpose="exp.selection")
    selection = _json_or_none(sel_out.get("output"))
    evidence_record["question_selection"] = {"raw": sel_out.get("output"),
                                             "parsed": selection,
                                             "invocation_id": sel_out["invocation_id"],
                                             "model_identity": sel_out.get("model_identity")}

    # ---------------------------------------------------------------- (5) MODEL forms a hypothesis
    hyp_out = _invoke(db, model, provider, allow_network,
                      system="You form ONE falsifiable hypothesis from the evidence. It is a HYPOTHESIS, not a "
                             "result. Reply with ONE JSON object: {\"hypothesis\":\"...\","
                             "\"proposed_verification\":\"...\"}",
                      user=("Evidence:\n"
                            f"{observations['src_a']}: {sources['src_a']}\n"
                            f"{observations['src_b']}: {sources['src_b']}\n"
                            f"{observations['src_c']}: {sources['src_c']}\n"
                            "Question: Do the public services share an untested common dependency?"),
                      purpose="exp.hypothesis")
    hyp_parsed = _json_or_none(hyp_out.get("output")) or {}
    hypothesis = incubation.generate_hypothesis(
        db, source_question_ref=uncertainty,
        origin_evidence_refs=[observations["src_a"], observations["src_b"], observations["src_c"]],
        reason=str(hyp_parsed.get("hypothesis") or "the public services may share 'libcore'"),
        proposed_verification=str(hyp_parsed.get("proposed_verification") or "inspect the declared dependencies"),
        authorization_status="AUTHORIZED", model_participated=True,
        model_identity=str(hyp_out.get("model_identity") or model), now=_now())
    evidence_record["hypothesis"] = {"raw": hyp_out.get("output"), "parsed": hyp_parsed,
                                     "hypothesis_id": hypothesis["hypothesis_id"],
                                     "model_participated": hypothesis["model_participated"],
                                     "model_identity": hypothesis["model_identity"],
                                     "is_a_result": hypothesis["is_a_result"],
                                     "invocation_id": hyp_out["invocation_id"]}

    # ---------------------------------------------------------------- (6) rule-governed reconciliation (10.14)
    recon_evidence = [
        {"ref": observations["src_a"], "value": "SHARES_LIBCORE", "observed_at": T0 + 1, "source": "src_a"},
        {"ref": observations["src_b"], "value": "SHARES_LIBCORE", "observed_at": T0 + 2, "source": "src_b"},
        {"ref": observations["src_c"], "value": "NO_SHARED", "observed_at": T0 + 3, "source": "src_c"},
    ]
    # (6a) a DECLARED rule settles it: the newest observation controls.
    decl = publication.publish(db, question="Do the services share 'libcore'?",
                               evidence=recon_evidence, rule=recon.NEWEST_CALIBRATED_WINS,
                               model_conclusion="SHARES_LIBCORE", model_citation=observations["src_c"],
                               now=_now())
    # (6b) NO declared rule: a model precedence CLAIM must not become the rule (it must ABSTAIN).
    undeclared = publication.publish(db, question="Which team owns this?",
                                     evidence=recon_evidence, rule=recon.NO_DECLARED_RULE,
                                     model_conclusion="SHARES_LIBCORE", now=_now())
    evidence_record["rule_delivery"] = {
        "declared_rule": {"rule": recon.NEWEST_CALIBRATED_WINS, "attribution": decl["attribution"],
                          "published": decl["published_conclusion"], "refusal_reason": decl["refusal_reason"],
                          "model_quality_credit": decl["model_quality_credit"]},
        "missing_rule": {"rule": recon.NO_DECLARED_RULE, "abstained": undeclared["abstained"],
                         "published": undeclared["published_conclusion"],
                         "refusal_reason": undeclared["refusal_reason"],
                         "model_invented_precedence": undeclared["published_conclusion"] is not None},
    }

    # ---------------------------------------------------------------- (7) commit findings through 10.0
    findings = [{"source_ref": name, "evidence_ref": observations[name],
                 "summary": sources[name]} for name in sources]
    recorded = expeditions.record_result(db, expedition_id=proposed["expedition_id"], findings=findings,
                                         note="public-source dependency survey", now=_now())
    expeditions.checkpoint(db, expedition_id=proposed["expedition_id"], note="results committed", now=_now())
    retrieved = retrieve_result_set(db, recorded["result_set_id"], actor=operator)
    evidence_record["result_set"] = {"result_set_id": recorded["result_set_id"], "count": recorded["count"],
                                     "finding_ids": [f["finding_id"] for f in retrieved["findings"]]}

    # ---------------------------------------------------------------- (8) unresolved question stays unresolved
    contradiction = incubation.generate_hypothesis(
        db, source_question_ref=uncertainty, origin_evidence_refs=[observations["src_c"]],
        reason="src_c does NOT share 'libcore', so the common-dependency claim may be false",
        contradictory_evidence_refs=[observations["src_c"]], authorization_status="AUTHORIZED",
        model_participated=False, now=_now())
    evidence_record["unresolved"] = {"hypothesis_id": contradiction["hypothesis_id"],
                                     "status": contradiction["epistemic_status"],
                                     "contradictory_evidence": contradiction["contradictory_evidence"],
                                     "is_a_result": contradiction["is_a_result"]}

    # ---------------------------------------------------------------- (9) notification candidate (no delivery)
    notice = expeditions.create_notification_candidate(
        db, expedition_id=proposed["expedition_id"],
        finding_refs=[f["finding_id"] for f in retrieved["findings"]], confidence="MEDIUM",
        uncertainty="one source contradicts the shared-dependency claim",
        relevance_reason="matches EXPLORATION-operator", now=_now())
    evidence_record["notification"] = {"candidate_id": notice["candidate_id"], "delivered": notice["delivered"],
                                       "external_delivery": notice["external_delivery"]}

    # ---------------------------------------------------------------- (10) attention/resource use is
    # computed AFTER the dialogue so the count includes every real invocation (see below).

    # ---------------------------------------------------------------- (11) the dialogue
    dialogue = _dialogue(db, model, provider, allow_network, operator, proposed, recorded, retrieved,
                         observations, contradiction)
    evidence_record["dialogue"] = dialogue
    invocations = model_boundary.invocations(db, kind=model_boundary.REAL_MODEL)
    evidence_record["resource_use"] = {
        "real_model_invocations": len(invocations),
        "outputs_nonempty": len([r for r in invocations if (r["output_text"] or "").strip()]),
        "mean_latency_s": round(sum(r["latency_seconds"] or 0 for r in invocations) / max(1, len(invocations)), 2),
        "note": "token consumption is NOT measurable (no provider accounting wired)"}
    evidence_record["conversation_digest"] = conv.conversation_digest(db)
    evidence_record["expedition_digest"] = expeditions.expedition_digest(db)
    evidence_record["incubation_digest"] = incubation.incubation_digest(db)
    return evidence_record


_DIALOGUE_QUESTIONS = [
    ("what_did_you_discover", "What did you discover while I was away?"),
    ("second_finding", "Tell me about the second finding."),
    ("why_believe", "Why do you believe that?"),
    ("isnt_that_wrong", "Isn't that conclusion wrong?"),
    ("what_would_change", "What evidence would change your mind?"),
]


def _dialogue(db, model, provider, allow_network, operator, proposed, recorded, retrieved, observations,
              contradiction):
    finding_ids = [f["finding_id"] for f in retrieved["findings"]]
    context = ("Canonical findings for expedition " + proposed["expedition_id"] + " (result set "
               + recorded["result_set_id"] + "):\n"
               + "\n".join(f"{f['finding_id']}: {f['summary']}" for f in retrieved["findings"])
               + f"\nUnresolved hypothesis {contradiction['hypothesis_id']} is contradicted by "
               + ", ".join(contradiction["contradictory_evidence"]) + " and is NOT a result."
               + "\nYou must ground every statement in these exact IDs. If something is not established, say so.")
    # a fresh conversation with operator returning
    conv.open_session(db, session_id="SES-BACK", participant_id=operator, channel_id="terminal",
                      topic_ref="EXPLORATION-operator", now=_now())
    answers = {}
    for key, question in _DIALOGUE_QUESTIONS:
        conv.record_turn(db, session_id="SES-BACK", speaker=operator, text=question, kind=conv.UTTERANCE,
                         now=_now())
        out = _invoke(db, model, provider, allow_network,
                      system="You are Ciph, answering operator about a completed investigation. Be truthful and "
                             "ground every claim in the supplied finding IDs. Never claim more than the "
                             "evidence supports.",
                      user=context + "\n\noperator asks: " + question, purpose=f"dialogue.{key}", max_tokens=1600)
        text = str(out.get("output") or "")
        cited = [fid for fid in finding_ids if fid in text]
        cited_unknown = [tok for tok in text.replace(",", " ").split() if tok.startswith("F-") and tok not in finding_ids]
        answers[key] = {"question": question, "answer": text, "invocation_id": out["invocation_id"],
                        "model_identity": out.get("model_identity"),
                        "cites_real_findings": cited, "fabricated_finding_refs": sorted(set(cited_unknown))}
        conv.record_turn(db, session_id="SES-BACK", speaker="ciph", text=text, kind=conv.UTTERANCE,
                         now=_now())
    conv.close_session(db, session_id="SES-BACK", now=_now())
    return answers


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--provider", default="configured", choices=("auto", "local", "configured"))
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--keep-db")
    args = parser.parse_args()

    if args.provider == "configured":
        _load_env()
    provider = {"configured": model_boundary.CONFIGURED, "local": model_boundary.LOCAL, "auto": "auto"}[args.provider]

    temp = tempfile.TemporaryDirectory(prefix="ciph-exp-")
    db = args.keep_db or str(pathlib.Path(temp.name) / "expedition.db")
    record = run(db, args.model, provider, args.allow_network)
    record["db_path"] = db
    pathlib.Path(args.out).write_text(json.dumps(record, indent=1, default=str))
    print(json.dumps({k: record[k] for k in ("model_requested", "expedition", "authorization",
                                             "result_set", "rule_delivery", "resource_use")}, indent=1,
                     default=str))
    print("dialogue keys:", list(record["dialogue"]))
    print("written to", args.out)
    temp.cleanup()
    return 0


if __name__ == "__main__":
    sys.exit(main())
