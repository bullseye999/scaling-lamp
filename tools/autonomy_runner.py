#!/usr/bin/env python3
"""
autonomy_runner - 10.x-R WALL: the minimal deployed caller for `CiphRuntime.run_autonomy_tick`.

    This is a CLOCK, not a scheduler. It sleeps until the next real due moment and calls the runtime; 5.2
    still owns whether/when work is nominated, 5.0 still decides eligibility. It creates no owner and no
    parallel path.

Usage (bounded, disposable):
    python3 tools/autonomy_runner.py --db /tmp/wall.db --model deepseek-v4-pro --budget 4 \
        --cycles 3 --interval 6 --out FILE
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


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--budget", type=int, default=4)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--interval", type=float, default=6.0)
    parser.add_argument("--restart-check", action="store_true")
    args = parser.parse_args()
    _load_env()

    from ciph.runtime import CiphRuntime
    from ciph.kernel import autonomy_budgets, autonomy_modes, model_boundary
    from ciph.kernel.autonomy_schedule import register_schedule
    from ciph.kernel.epistemic_ledger import record_observation
    from ciph.kernel.missions import open_mission
    from ciph.kernel.self_model import record_installation
    from ciph.kernel.standing_authorization import create_standing_authorization
    from ciph.kernel.uncertainty_registry import derive_uncertainties

    now = time.time()
    db = args.db
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(db + suffix).unlink(missing_ok=True)
    runtime = CiphRuntime(vault=None, db_path=db)
    budget_ref = autonomy_budgets.open_budget(db, resource_class="API_TOKENS", limit=args.budget,
                                              window_seconds=10_000_000.0, granted_by=OPERATOR, now=now)
    record_installation(db, capability_id="research.public-sources", module_ref="fx", now=now)
    uncertainty = derive_uncertainties(db, now=now)[0].uncertainty_id
    fx = pathlib.Path(db).parent / "wall_sources"
    fx.mkdir(parents=True, exist_ok=True)
    evidence = []
    for name, text in {"a": "alpha depends on libcore v1", "b": "beta depends on libcore v1",
                       "c": "gamma depends on other lib v2 (CONTRADICTS)"}.items():
        path = fx / f"{name}.txt"
        path.write_text(text)
        obs = record_observation(db, source_ref=name, raw_text=path.read_text(), now=now)
        evidence.append({"ref": name, "value": text, "observed_at": now, "source": name,
                         "evidence_ref": obs["observation_id"]})
    mission = open_mission(db, objective="wall-clock objective", now=now)
    grant = create_standing_authorization(db, mission_id=mission, permitted_work_classes=[CLASS],
                                          granted_by=OPERATOR, risk_ceiling="LOW",
                                          scope_constraints=["public-sources"], resource_budget_ref=budget_ref,
                                          valid_until=now + 3600, now=now)
    schedule = register_schedule(db, origin_kind="SCHEDULED_REVIEW", work_class=CLASS,
                                 interval_seconds=args.interval, actor=OPERATOR, mission_id=mission,
                                 first_due_at=now + 1.0, now=now)
    autonomy_modes.set_mode(db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="start", now=now)

    objective = {"uncertainty_ref": uncertainty, "grant_ref": grant.standing_auth_id, "mission_id": mission,
                 "work_class": CLASS, "evidence": evidence, "rule": "NEWEST_CALIBRATED_WINS",
                 "question": "Do the services share libcore? [wall]", "scope": ["public-sources"],
                 "budget_ref": budget_ref}

    record = {"clock": "REAL_WALL_CLOCK", "interval_s": args.interval, "cycles": args.cycles,
              "budget_limit": args.budget, "ticks": []}
    start = time.time()
    for cycle in range(args.cycles):
        wake = schedule and time.time()
        # wait for the next real due moment (bounded)
        while time.time() < start + (cycle + 1) * args.interval:
            time.sleep(0.5)
        tick = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                         model_provider=model_boundary.CONFIGURED, allow_network=True,
                                         now=time.time())
        record["ticks"].append({"cycle": cycle, "wall_offset_s": round(time.time() - start, 1),
                                "executed": len(tick["executed"]), "nominations": len(tick["nominations"]),
                                "stop": tick["stop"], "budget_remaining":
                                autonomy_budgets.budget_status(db, budget_ref, now=time.time()).remaining})

    # operator hold -> the next wake must be idle/blocked, not busy
    autonomy_modes.set_mode(db, mode=autonomy_modes.MODE_QUIESCE, actor=OPERATOR, reason="hold",
                            now=time.time())
    held = runtime.run_autonomy_tick(objective=objective, model_ref=args.model,
                                     model_provider=model_boundary.CONFIGURED, allow_network=True,
                                     now=time.time() + args.interval)
    record["hold_tick"] = {"executed": len(held["executed"]), "stop": held["stop"]}
    autonomy_modes.set_mode(db, mode=autonomy_modes.MODE_NORMAL, actor=OPERATOR, reason="lift",
                            now=time.time())
    record["wall_elapsed_s"] = round(time.time() - start, 1)
    record["budget_final"] = autonomy_budgets.budget_status(db, budget_ref, now=time.time()).as_dict()
    pathlib.Path(args.out).write_text(json.dumps(record, indent=1, default=str))
    print(json.dumps(record, indent=1, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
