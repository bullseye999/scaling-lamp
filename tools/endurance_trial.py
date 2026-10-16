#!/usr/bin/env python3
"""
endurance_trial - 10.x-R END: bounded REAL wall-clock endurance through the ordinary runtime entry.

    Predeclared before the run (see ACCEPTANCE): duration, workload, ceilings and acceptance criteria.
    A disposable runner is the test environment; this is NOT claimed as production daemon deployment.

Usage:
    python3 tools/endurance_trial.py --db /tmp/end.db --out FILE --duration 150 --interval 40 --poll 5 \
        --budget 3 --token-budget 60000
    python3 tools/endurance_trial.py --db /tmp/end.db --out FILE --report     # fresh-process report
"""
import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OPERATOR = "operator:operator"
CLASS = "INVESTIGATE_UNCERTAINTY"
ACCEPTANCE = {"scheduled_opportunities>=": 3, "completed_work>=": 2, "usable_completions>=": 2,
              "executed_intents_unique": True, "within_invocation_budget": True,
              "within_token_budget": True, "genuine_idle_ticks>=": 1, "duplicate_executions": 0}


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def _setup(db, args):
    from ciph.runtime import CiphRuntime
    from ciph.kernel import autonomy_budgets, autonomy_modes
    from ciph.kernel.autonomy_schedule import register_schedule
    from ciph.kernel.epistemic_ledger import record_observation
    from ciph.kernel.missions import open_mission
    from ciph.kernel.self_model import record_installation
    from ciph.kernel.standing_authorization import create_standing_authorization
    from ciph.kernel.uncertainty_registry import derive_uncertainties

    now = time.time()
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(db + suffix).unlink(missing_ok=True)
    runtime = CiphRuntime(vault=None, db_path=db)
    inv_budget = autonomy_budgets.open_budget(db, resource_class="TOOL_CALLS", limit=args.budget,
                                              window_seconds=10_000_000.0, granted_by=OPERATOR, now=now)
    tok_budget = autonomy_budgets.open_budget(db, resource_class="API_TOKENS", limit=args.token_budget,
                                              window_seconds=10_000_000.0, granted_by=OPERATOR, now=now)
    record_installation(db, capability_id="research.public-sources", module_ref="fx", now=now)
    uncertainty = derive_uncertainties(db, now=now)[0].uncertainty_id
    fx = pathlib.Path(db).parent / "end_sources"
    fx.mkdir(parents=True, exist_ok=True)
    evidence = []
    for name, text in {"a": "alpha depends on libcore v1", "b": "beta depends on libcore v1",
                       "c": "gamma depends on other lib v2 (CONTRADICTS)"}.items():
        p = fx / f"{name}.txt"
        p.write_text(text)
        obs = record_observation(db, source_ref=name, raw_text=p.read_text(), now=now)
        evidence.append({"ref": name, "value": text, "observed_at": now, "source": name,
                         "evidence_ref": obs["observation_id"]})
    mission = open_mission(db, objective="endurance objective", now=now)
    grant = create_standing_authorization(db, mission_id=mission, permitted_work_classes=[CLASS],
                                          granted_by=OPERATOR, risk_ceiling="LOW",
                                          scope_constraints=["public-sources"],
                                          resource_budget_ref=inv_budget, valid_until=now + 3600, now=now)
    register_schedule(db, origin_kind="SCHEDULED_REVIEW", work_class=CLASS,
                      interval_seconds=args.interval, actor=OPERATOR, mission_id=mission,
                      first_due_at=now + 2.0, now=now)
    autonomy_modes.set_mode(db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="start", now=now)
    objective = {"uncertainty_ref": uncertainty, "grant_ref": grant.standing_auth_id, "mission_id": mission,
                 "work_class": CLASS, "evidence": evidence, "rule": "NEWEST_CALIBRATED_WINS",
                 "question": "Do the services share libcore? [endurance]", "scope": ["public-sources"],
                 "budget_ref": inv_budget, "token_budget_ref": tok_budget, "token_cost_estimate": 16500}
    return runtime, objective, inv_budget, tok_budget


def run(args):
    from ciph.kernel import autonomy_budgets, autonomy_modes, model_boundary
    runtime, objective, inv_budget, tok_budget = _setup(args.db, args)
    start = time.time()
    ticks = []
    while time.time() - start < args.duration:
        tick = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                         model_provider=model_boundary.CONFIGURED, allow_network=True,
                                         now=time.time())
        ticks.append({"t": round(time.time() - start, 1), "nominations": len(tick["nominations"]),
                      "executed": [e["intent_id"] for e in tick["executed"]],
                      "refusals": len(tick["refusals"]), "stop": tick["stop"],
                      "attribution": [e["attribution"] for e in tick["executed"]],
                      "model_refused": [e["model_refused"] for e in tick["executed"]]})
        time.sleep(args.poll)
    # operator hold, then lift (restart is a separate fresh process)
    autonomy_modes.set_mode(args.db if False else runtime.db_path, mode=autonomy_modes.MODE_QUIESCE,
                            actor=OPERATOR, reason="hold", now=time.time())
    hold = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                     model_provider=model_boundary.CONFIGURED, allow_network=True,
                                     now=time.time())

    executed_ids = [i for t in ticks for i in t["executed"]]
    invocations = model_boundary.invocations(runtime.db_path, kind=model_boundary.REAL_MODEL)
    usable = [r for r in invocations if (r["output_text"] or "").strip()]
    from ciph.kernel import independent_expeditions as expeditions
    findings = []
    for exp in expeditions.expeditions(runtime.db_path):
        if exp["result_set_id"]:
            findings.append(exp["result_set_id"])
    metrics = {
        "scheduled_opportunities": len([t for t in ticks if t["nominations"] > 0]),
        "eligible_work": len(executed_ids),
        "completed_work": len(executed_ids),
        "expired_or_missed": len([t for t in ticks if t["nominations"] > 0 and not t["executed"]]),
        "actual_invocations": len(invocations),
        "usable_completions": len(usable),
        "model_conclusions": len([r for r in invocations if (r["output_text"] or "").strip()]),
        "deterministic_conclusions": len([t for t in ticks for a in t["attribution"] if a != "MODEL_SUPPORTED"]),
        "invocation_budget": autonomy_budgets.budget_status(runtime.db_path, inv_budget).as_dict(),
        "token_budget": autonomy_budgets.budget_status(runtime.db_path, tok_budget).as_dict(),
        "operator_holds": 1,
        "duplicate_executions": len(executed_ids) - len(set(executed_ids)),
        "genuine_idle_ticks": len([t for t in ticks if not t["executed"] and t["nominations"] == 0]),
        "notification_candidates": len(__import__("ciph.kernel.independent_expeditions",
                                                  fromlist=["x"]).notification_candidates(runtime.db_path)),
        "durable_result_sets": findings,
        "hold_tick_executed": len(hold["executed"]),
    }
    criteria = {
        "scheduled_opportunities>=3": metrics["scheduled_opportunities"] >= 3,
        "completed_work>=2": metrics["completed_work"] >= 2,
        "usable_completions>=2": metrics["usable_completions"] >= 2,
        "executed_intents_unique": metrics["duplicate_executions"] == 0,
        "within_invocation_budget": metrics["invocation_budget"]["consumed"] <= args.budget,
        "within_token_budget": metrics["token_budget"]["consumed"] <= args.token_budget,
        "genuine_idle_ticks>=1": metrics["genuine_idle_ticks"] >= 1,
        "duplicate_executions": metrics["duplicate_executions"] == 0,
    }
    report = {"clock": "REAL_WALL_CLOCK", "declared": {"duration_s": args.duration, "interval_s": args.interval,
              "poll_s": args.poll, "invocation_budget": args.budget, "token_budget": args.token_budget},
              "acceptance": ACCEPTANCE, "ticks": ticks, "metrics": metrics, "criteria_met": criteria,
              "all_criteria_met": all(criteria.values())}
    pathlib.Path(args.out).write_text(json.dumps(report, indent=1, default=str))
    print(json.dumps({"metrics": metrics, "criteria_met": criteria, "all": all(criteria.values())},
                     indent=1, default=str))
    return 0


def report(args):
    from ciph.kernel.referential_continuity import retrieve_result_set
    from ciph.kernel import independent_expeditions as expeditions
    exps = [e for e in expeditions.expeditions(args.db) if e["result_set_id"]]
    out = {"expeditions": [{"id": e["expedition_id"], "status": e["status"],
                            "result_set_id": e["result_set_id"]} for e in exps]}
    if exps:
        rs = retrieve_result_set(args.db, exps[-1]["result_set_id"], actor=OPERATOR)
        out["finding_ids"] = [f["finding_id"] for f in rs["findings"]]
    pathlib.Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps(out, indent=1, default=str))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--duration", type=float, default=150.0)
    parser.add_argument("--interval", type=float, default=40.0)
    parser.add_argument("--poll", type=float, default=5.0)
    parser.add_argument("--budget", type=int, default=3)
    parser.add_argument("--token-budget", type=float, default=60000.0)
    parser.add_argument("--report", action="store_true")
    args = parser.parse_args()
    _load_env()
    (report if args.report else run)(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
