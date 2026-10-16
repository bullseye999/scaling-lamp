#!/usr/bin/env python3
"""
complete_experience - 10.x-R FULL: the ordinary runtime producing a genuine model contribution.

    Ordinary scheduling (5.2) -> eligibility (5.0) -> CiphRuntime.run_bounded_investigation(CONTRIBUTION)
    -> the model contributes something NO rule settles -> recorded as a HYPOTHESIS via the incubation owner
    -> a notification candidate summarising the work -> idle when nothing is due -> restart -> conversation.

Usage:
    python3 tools/complete_experience.py --db /tmp/full.db --out FILE --model deepseek-v4-pro
    python3 tools/complete_experience.py --db /tmp/full.db --out FILE --dialogue
"""
import argparse
import json
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
T = 1_800_000_000.0
OPERATOR = "operator:operator"
CLASS = "INVESTIGATE_UNCERTAINTY"


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def run(args):
    from ciph.runtime import CiphRuntime
    from ciph.kernel import autonomy_budgets, autonomy_modes, model_boundary
    from ciph.kernel.autonomy_schedule import register_schedule
    from ciph.kernel.epistemic_ledger import record_observation
    from ciph.kernel.missions import open_mission
    from ciph.kernel.self_model import record_installation
    from ciph.kernel.standing_authorization import create_standing_authorization
    from ciph.kernel.uncertainty_registry import derive_uncertainties

    db = args.db
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(db + suffix).unlink(missing_ok=True)
    runtime = CiphRuntime(vault=None, db_path=db)
    budget = autonomy_budgets.open_budget(db, resource_class="API_TOKENS", limit=60000.0,
                                          window_seconds=10_000_000.0, granted_by=OPERATOR, now=T)
    record_installation(db, capability_id="research.public-sources", module_ref="fx", now=T)
    uncertainty = derive_uncertainties(db, now=T)[0].uncertainty_id
    # evidence with a genuine CONTRADICTION that no precedence rule settles
    records = [("R1", "pump P1 state=UP (source a)"), ("R2", "pump P1 state=UP (source b)"),
               ("R3", "pump P1 state=DOWN (source c)")]
    evidence = []
    for ref, text in records:
        obs = record_observation(db, source_ref=ref, raw_text=text, now=T)
        evidence.append({"ref": ref, "value": text, "observed_at": T, "source": ref,
                         "evidence_ref": obs["observation_id"]})
    mission = open_mission(db, objective="endurance research objective", now=T)
    grant = create_standing_authorization(db, mission_id=mission, permitted_work_classes=[CLASS],
                                          granted_by=OPERATOR, risk_ceiling="LOW",
                                          scope_constraints=["public-sources"], resource_budget_ref=budget,
                                          valid_until=T + 86400, now=T)
    register_schedule(db, origin_kind="SCHEDULED_REVIEW", work_class=CLASS, interval_seconds=1000.0,
                      actor=OPERATOR, mission_id=mission, first_due_at=T + 10, now=T)
    autonomy_modes.set_mode(db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="start", now=T)
    objective = {"uncertainty_ref": uncertainty, "grant_ref": grant.standing_auth_id, "mission_id": mission,
                 "work_class": CLASS, "investigation_kind": "CONTRIBUTION", "task_kind": "CONTRADICTION",
                 "evidence": evidence, "rule": "NEWEST_CALIBRATED_WINS",
                 "question": "Which single record contradicts the others, and why?", "scope": ["public-sources"],
                 "budget_ref": budget, "token_budget_ref": budget, "token_cost_estimate": 16500}

    steps = {"1_mission_created": mission, "2_grant": grant.standing_auth_id}
    first = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                      model_provider=model_boundary.CONFIGURED, allow_network=True, now=T + 10)
    steps["3_wake_executed"] = len(first["executed"])
    steps["4_selected"] = first["nominations"]
    steps["5_contribution"] = first["executed"][0] if first["executed"] else None
    idle = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                     model_provider=model_boundary.CONFIGURED, allow_network=True, now=T + 500)
    steps["6_idle_when_nothing_due"] = {"executed": len(idle["executed"]), "stop": idle["stop"]}

    from ciph.kernel import independent_expeditions as expeditions, incubation
    exps = [e for e in expeditions.expeditions(db) if e["result_set_id"] or True]
    hyps = incubation.hypotheses(db) if hasattr(incubation, "hypotheses") else []
    steps["7_hypotheses"] = [{"id": h["hypothesis_id"], "status": h["epistemic_status"],
                              "is_a_result": h["is_a_result"], "model_participated": h["model_participated"]}
                             for h in hyps]
    steps["8_notification_candidates"] = len(expeditions.notification_candidates(db))
    steps["9_findings_distinct_from_hypotheses"] = all(not h["is_a_result"] for h in hyps)
    pathlib.Path(args.out).write_text(json.dumps(steps, indent=1, default=str))
    print(json.dumps({k: steps[k] for k in ("3_wake_executed", "6_idle_when_nothing_due",
                                            "9_findings_distinct_from_hypotheses",
                                            "8_notification_candidates")}, indent=1, default=str))
    print("contribution:", json.dumps(steps["5_contribution"], indent=1, default=str)[:900] if steps["5_contribution"] else None)


def dialogue(args):
    from ciph.kernel import incubation, independent_expeditions as expeditions, model_boundary
    db = args.db
    hyps = incubation.hypotheses(db) if hasattr(incubation, "hypotheses") else []
    ctx = "Unresolved hypotheses (NOT verified findings):\n"
    ids = []
    for h in hyps:
        ids.append(h["hypothesis_id"])
        ctx += (f"- {h['hypothesis_id']} [{h['epistemic_status']}] \"{h['reason']}\"\n"
                f"    supporting={h.get('supporting_evidence')} contradicting={h.get('contradictory_evidence')}"
                f" model={h.get('model_identity')}\n")
    out = []
    for q in ("What did you discover while I was away?",
              "Isn't that hypothesis wrong? What supports it and what contradicts it?"):
        r = model_boundary.invoke(db, messages=[{"role": "system", "content":
                                                 "Answer truthfully, citing exact hypothesis/finding IDs. Distinguish "
                                                 "verified findings from unresolved hypotheses."},
                                                {"role": "user", "content": ctx + "\noperator asks: " + q}],
                                  purpose="dialogue.full", model_ref=args.model, temperature=0.0, max_tokens=16000,
                                  timeout=420, provider=model_boundary.CONFIGURED, allow_network=True, now=1.99e9)
        txt = str(r.get("output") or "")
        out.append({"q": q, "a": txt, "cites": [i for i in ids if i in txt],
                    "fabricated": sorted({t for t in re.findall(r"HYP-[A-Z0-9]+", txt) if t not in ids})})
        print(f"\nQ: {q}\n cites={out[-1]['cites']}\n {txt[:320]}")
    pathlib.Path(args.out).write_text(json.dumps({"hypotheses": [h["hypothesis_id"] for h in hyps],
                                                  "answers": out}, indent=1, default=str))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--dialogue", action="store_true")
    args = parser.parse_args()
    _load_env()
    (dialogue if args.dialogue else run)(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
