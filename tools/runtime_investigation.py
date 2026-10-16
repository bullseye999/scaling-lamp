#!/usr/bin/env python3
"""
runtime_investigation - drive the ORDINARY CiphRuntime through one bounded, authorized investigation.

    The driver seeds AUTHORIZED STATE and calls ONE runtime method. It does NOT stage the workflow.

Selection, authorization, attention, model inference and durable recording are performed by
`CiphRuntime.run_bounded_investigation`, which composes the existing owners. This is the bridge the proof
script stood in for.

Usage:
    python3 tools/runtime_investigation.py --db /tmp/rt.db --model deepseek-v4-pro --provider configured \
        --allow-network --out FILE
    python3 tools/runtime_investigation.py --db /tmp/rt.db --followup      # fresh process, historical Q
"""
import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _load_env():
    import os
    for line in (ROOT / ".env").read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))


def _seed(db, operator="operator:operator"):
    from ciph.kernel.epistemic_ledger import record_observation
    from ciph.kernel.self_model import record_installation
    from ciph.kernel.uncertainty_registry import derive_uncertainties
    from ciph.kernel.standing_authorization import create_standing_authorization

    now = time.time()
    fixture_dir = pathlib.Path(db).parent / "runtime_sources"
    fixture_dir.mkdir(parents=True, exist_ok=True)
    sources = {
        "alpha": "Service alpha depends on library 'libcore' v1 per source A.",
        "beta": "Service beta depends on library 'libcore' v1 per source B.",
        "gamma": "Service gamma depends on library 'libother' v2 per source C.",
    }
    evidence = []
    for name, text in sources.items():
        path = fixture_dir / f"{name}.txt"
        path.write_text(text)
        read_back = path.read_text()                                   # a REAL local read
        obs = record_observation(db, source_ref=f"src_{name}", raw_text=read_back, now=now)
        evidence.append({"ref": f"src_{name}", "value": text, "observed_at": now,
                         "source": f"src_{name}", "evidence_ref": obs["observation_id"]})
    record_installation(db, capability_id="research.public-sources", module_ref="fixture", now=now)
    uncertainty = derive_uncertainties(db, now=now)[0].uncertainty_id
    grant = create_standing_authorization(db, mission_id="EXPLORATION-operator",
                                          permitted_work_classes=["RESEARCH"], granted_by=operator,
                                          risk_ceiling="LOW", scope_constraints=["public-sources"],
                                          valid_until=now + 86400, now=now)
    return evidence, uncertainty, grant.standing_auth_id


def run(args):
    from ciph.runtime import CiphRuntime
    from ciph.kernel import evidence_reconciliation as recon
    from ciph.kernel import model_boundary

    db = args.db
    for suffix in ("", "-wal", "-shm"):
        pathlib.Path(db + suffix).unlink(missing_ok=True)
    runtime = CiphRuntime(vault=None, db_path=db)                       # the ORDINARY runtime
    evidence, uncertainty, grant_ref = _seed(db)

    provider = {"configured": model_boundary.CONFIGURED, "local": model_boundary.LOCAL,
                "auto": "auto"}[args.provider]
    result = runtime.run_bounded_investigation(
        objective_ref=uncertainty, grant_ref=grant_ref, model_ref=args.model, evidence=evidence,
        rule=recon.NEWEST_CALIBRATED_WINS,
        question="Do the public services share library 'libcore'?", origin_question="shared dependency?",
        model_provider=provider, allow_network=args.allow_network)
    record = {"driver": "tools/runtime_investigation.py", "db": db, "grant_ref": grant_ref,
              "uncertainty_ref": uncertainty, "runtime_method": "CiphRuntime.run_bounded_investigation",
              "stages_driven_by_driver": 0, "result": result}
    pathlib.Path(args.out).write_text(json.dumps(record, indent=1, default=str))
    print(json.dumps(result, indent=1, default=str))
    print("written to", args.out)


def followup(args):
    from ciph.kernel import independent_expeditions as expeditions
    from ciph.kernel import model_boundary
    from ciph.kernel.referential_continuity import retrieve_result_set
    from ciph.kernel import conversational_continuity as conv

    db = args.db
    exp = expeditions.expeditions(db)[0]
    rs = retrieve_result_set(db, exp["result_set_id"], actor="operator:operator")
    fids = [f["finding_id"] for f in rs["findings"]]
    ctx = ("Canonical findings for expedition " + exp["expedition_id"] + " (result set "
           + exp["result_set_id"] + "):\n"
           + "\n".join(f"{f['finding_id']}: {f['summary']}" for f in rs["findings"]))
    out = model_boundary.invoke(
        db, messages=[{"role": "system", "content": "Answer truthfully, grounding in the exact finding IDs."},
                      {"role": "user", "content": ctx + "\n\noperator asks: Which finding mentioned 'libcore' "
                                                        "and which source contradicted it?"}],
        purpose="runtime.followup", model_ref=args.model, temperature=0.0, max_tokens=4000, timeout=420,
        provider=model_boundary.CONFIGURED, allow_network=True, now=time.time())
    text = str(out.get("output") or "")
    record = {"db": db, "expedition_id": exp["expedition_id"], "result_set_id": exp["result_set_id"],
              "finding_ids": fids, "conversation_digest": conv.conversation_digest(db),
              "answer": text, "cites_real_findings": [f for f in fids if f in text],
              "served_model": out.get("model_identity"), "kind": out.get("kind")}
    pathlib.Path(args.out).write_text(json.dumps(record, indent=1, default=str))
    print(json.dumps(record, indent=1, default=str))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--model", default="deepseek-v4-pro")
    parser.add_argument("--provider", default="configured", choices=("auto", "local", "configured"))
    parser.add_argument("--allow-network", action="store_true")
    parser.add_argument("--followup", action="store_true")
    args = parser.parse_args()
    if args.provider == "configured":
        _load_env()
    (followup if args.followup else run)(args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
