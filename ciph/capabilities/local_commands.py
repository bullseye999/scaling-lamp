"""Explicit local operator capabilities; no raw-module command fallback.

Inspection reports establish what the local stores contain, not external truth.
Each operation has its own manifest, fixed implementation and validated inputs.
"""
import json
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ciph.capabilities.base import BaseCapability
from ciph.contracts.enums import AuthorizationTier, NetworkPolicy, ReversibilityClass, RiskTier
from ciph.kernel.policy_engine import CapabilityManifest


@dataclass(frozen=True)
class LocalCommand:
    command: str
    operation: str
    description: str
    aliases: tuple = ()
    argument: str = ""
    mutation: bool = False

    @property
    def capability(self):
        return "operator." + self.operation


LOCAL_COMMANDS = (
    LocalCommand("/status", "status", "Inspect runtime uptime, job counts and curiosity pause state", ("/project-status", "/engine-status")),
    LocalCommand("/modules", "capabilities", "List governed capabilities and their execution policies", ("/module-status", "/inventory")),
    LocalCommand("/jobs", "jobs", "List the 50 most recent governed jobs"),
    LocalCommand("/job-status", "job", "Inspect one governed job without exposing tokens or input payloads", (), "job_id"),
    LocalCommand("/result", "result", "Retrieve a job's cryptographically verified execution result", (), "job_id"),
    LocalCommand("/auth-status", "authority", "Inspect enrolled authority roles and status; no key material"),
    LocalCommand("/integrity-check", "integrity", "Verify the local event hash chain (not a security certification)"),
    LocalCommand("/memory-stats", "memory_stats", "Count encrypted memory records and canonical claim states", ("/memory-status", "/memory-health")),
    LocalCommand("/reality-check", "worldview", "Inspect current usable, evidenced claims", ("/world-map",)),
    LocalCommand("/hypotheses", "hypotheses", "Inspect current hypotheses and disputed claims"),
    LocalCommand("/inspect", "claim", "Inspect a canonical claim and its current usability", (), "claim_id"),
    LocalCommand("/memory-timeline", "transitions", "Show recent canonical claim transitions", ("/mind-log",)),
    LocalCommand("/what-changed", "events", "Show recent event metadata without raw payloads"),
    LocalCommand("/curiosity-status", "curiosity_status", "Inspect durable internal questions, quotas and pause state", ("/curiosity", "/curiousity", "/curiousity-status")),
    LocalCommand("/curiosity-off", "curiosity_pause", "Pause autonomous curiosity; requires an authorization grant and reason", ("/curiousity-off",), "reason", True),
    LocalCommand("/curiosity-on", "curiosity_resume", "Resume curiosity eligibility without resetting quota or starting a thread", ("/curiousity-on",), "reason", True),
    LocalCommand("/profile", "profile", "Read stored operator profile assertions", ("/my-profile", "/operator-profile")),
    LocalCommand("/narrative-timeline", "narrative", "Read stored narrative milestones", ("/timeline",)),
    LocalCommand("/memory-graph", "entity_links", "Read stored entity relationships; these are unverified records", ("/graph",)),
    LocalCommand("/opsec-history", "opsec_history", "Read past OPSEC telemetry; does not run a fresh network audit", ("/opsec-trends",)),
    LocalCommand("/bounty-scope", "bounty_scopes", "Read stored bounty scope records; records do not confer grants", ("/bounty-rules",)),
    LocalCommand("/bounty-report", "bounty_reports", "List stored report metadata; does not generate or send reports"),
    LocalCommand("/watchtower", "watchtower_history", "Read stored watchtower events without launching a monitor"),
    LocalCommand("/blueprints", "blueprints", "Read stored blueprint records without running experimental evolution"),
    LocalCommand("/recon-diff", "recon_diff", "Compare the two latest stored reconnaissance snapshots", (), "target"),
    LocalCommand("/assets", "asset_inventory", "Read stored reconnaissance assets and counts; records are unverified", ("/asset-inventory", "/global-assets")),
    LocalCommand("/briefing", "briefing", "Summarize local jobs, usable claims and curiosity state", ("/daily-brief", "/morning-brief", "/today")),
    LocalCommand("/command-status", "commands", "Show command coverage and deferred legacy families"),
    LocalCommand("/alignment-check", "alignment_check", "Read stored evolution and alignment audit records", ("/interrogation-audit",)),
    LocalCommand("/convo-summary", "convo_summary", "Read stored conversation log metadata and context tags"),
    LocalCommand("/changelog", "changelog", "Read recorded audit changelog entries from staging"),
    LocalCommand("/predictions", "predictions", "Read stored match predictions without external network calls"),
)


# Fixed SELECT lists exclude configuration, credentials and executable payloads.
RECORDS = {
    "profile": ("operator_profile", "id,category,key_enc,value_enc,confidence,updated_at", "updated_at", {"key_enc": "key", "value_enc": "value"}),
    "narrative": ("narrative_timeline", "id,timestamp,encrypted_summary,encrypted_targets,encrypted_decisions,context_tag", "timestamp", {"encrypted_summary": "summary", "encrypted_targets": "targets", "encrypted_decisions": "decisions"}),
    "entity_links": ("entity_graph", "id,source_entity,relation,target_entity,details_enc,updated_at", "updated_at", {"details_enc": "details"}),
    "opsec_history": ("opsec_history", "id,timestamp,score,exit_ip,latency_ms,status,details", "timestamp", {}),
    "bounty_scopes": ("bounty_scopes", "id,timestamp,program_name,encrypted_scope_json,is_active", "timestamp", {"encrypted_scope_json": "scope"}),
    "bounty_reports": ("bounty_reports_index", "id,timestamp,target,vuln_type,cvss_score,severity,status", "timestamp", {}),
    "watchtower_history": ("watchtower_events", "id,timestamp,target,event_type,details,severity", "timestamp", {}),
    "blueprints": ("cognitive_blueprints", "id,domain,topic_enc,core_axiom_enc,mechanics_enc,human_subtext_enc,strategic_application_enc,created_at", "created_at", {"topic_enc": "topic", "core_axiom_enc": "core_axiom", "mechanics_enc": "mechanics", "human_subtext_enc": "human_subtext", "strategic_application_enc": "strategic_application"}),
    "recon_diff": ("recon_snapshots", "id,timestamp,target,encrypted_snapshot_json,asset_count", "timestamp", {"encrypted_snapshot_json": "snapshot"}),
    "asset_inventory": ("recon_snapshots", "id,timestamp,target,asset_count", "timestamp", {}),
    "alignment_check": ("evolution_audit_log", "id,audit_date,expeditions_reviewed,cross_domain_connections_count,alignment_score,blind_spots_enc,next_day_agenda_enc,created_at", "created_at", {"blind_spots_enc": "blind_spots", "next_day_agenda_enc": "next_day_agenda"}),
    "convo_summary": ("conversations", "id,timestamp,context_tag", "timestamp", {}),
}


def validate_parameters(spec, params):
    allowed = {spec.argument} if spec.argument else set()
    if not isinstance(params, dict) or set(params) != allowed:
        raise ValueError("INVALID_ARGUMENTS: unexpected or missing parameter")
    if spec.argument:
        value = params[spec.argument]
        if not isinstance(value, str) or not value.strip() or len(value) > 512 or any(ord(c) < 32 for c in value):
            raise ValueError("INVALID_ARGUMENTS: expected bounded nonempty text")


def report(data, semantics="Local record snapshot; stored assertions are not verified domain truth."):
    # Bound persisted output and terminal rendering without silently dropping records.
    encoded = json.dumps(data, ensure_ascii=True, sort_keys=True, allow_nan=False)
    if len(encoded.encode()) > 65536:
        raise ValueError("REPORT_TOO_LARGE: narrow the requested record")
    return {"report_data": data, "semantics": semantics}


class LocalOperatorCapability(BaseCapability):
    def __init__(self, runtime, spec):
        if spec not in LOCAL_COMMANDS:
            raise ValueError("UNREGISTERED_OPERATOR_COMMAND")
        self.runtime = runtime
        self.spec = spec

    @property
    def manifest(self):
        s = self.spec
        return CapabilityManifest(s.capability, s.description,
            RiskTier.LOW if s.mutation else RiskTier.NONE, NetworkPolicy.OFFLINE_ONLY,
            ReversibilityClass.REVERSIBLE if s.mutation else ReversibilityClass.READ_ONLY,
            AuthorizationTier.MANDATORY_INTERRUPT if s.mutation else AuthorizationTier.AUTO)

    def _rows(self, sql, parameters=()):
        with self.runtime.event_store._get_connection() as conn:
            return [dict(row) for row in conn.execute(sql, parameters)]

    def _jobs(self, identity=None):
        # Deliberately exclude params, execution_token, pending_receipt and raw errors.
        columns = "job_id,capability,status,attempt_number,receipt_id,created_at,started_at,completed_at"
        if identity is not None:
            rows = self._rows(f"SELECT {columns} FROM ciph_ipc_jobs WHERE job_id=?", (identity,))
        else:
            rows = self._rows(f"SELECT {columns} FROM ciph_ipc_jobs ORDER BY created_at DESC,job_id LIMIT 50")
        return rows

    def _status(self):
        return {"uptime_seconds": round(max(0, time.time()-self.runtime.started_at), 2),
            "capabilities": len(self.runtime.registry.list_names()),
            "jobs_by_status": self._rows("SELECT status,COUNT(*) AS count FROM ciph_ipc_jobs GROUP BY status"),
            "curiosity": self.runtime.question_dag.store.state()}

    def _claims(self, states=None):
        candidates = self._rows("SELECT claim_id FROM ciph_active_claims WHERE migration_status='CANONICAL' AND subject NOT LIKE 'operator.%' ORDER BY updated_at DESC,claim_id LIMIT 100")
        claims = []
        for row in candidates:
            c = (self.runtime.worldview.get_canonical_claim(row["claim_id"]) if states
                 else self.runtime.worldview.get_usable_claim(row["claim_id"]))
            if c and c.lifecycle_state.value != "ARCHIVED" and (not states or c.epistemic_state.value in states):
                claims.append({"claim_id": c.claim_id, "subject": c.subject, "predicate": c.predicate,
                    "state": c.epistemic_state.value, "lifecycle": c.lifecycle_state.value,
                    "assurance": c.assurance_score, "fresh": c.is_fresh()})
                if len(claims) == 25:
                    break
        return claims

    def _vault_records(self, op, params):
        vault = self.runtime.vault
        if vault is None:
            raise RuntimeError("VAULT_UNAVAILABLE")
        table, columns, order, encrypted = RECORDS[op]
        where, args = (" WHERE target=?", (params["target"].lower(),)) if op == "recon_diff" else ("", ())
        if op == "bounty_scopes":
            where = " WHERE is_active=1"
        limit = 2 if op == "recon_diff" else 26
        # Use the vault connection because an injected vault may have its own DB.
        conn = vault._get_connection()
        try:
            cursor = conn.execute(f"SELECT {columns} FROM {table}{where} ORDER BY {order} DESC,id DESC LIMIT ?", (*args, limit))
            names = [col[0] for col in cursor.description]
            data = [dict(zip(names, row)) for row in cursor.fetchall()]
        finally:
            conn.close()
        for row in data:
            for column, label in encrypted.items():
                ciphertext = row.pop(column)
                if not ciphertext:
                    raise ValueError("CORRUPT_STORED_RECORD")
                decoded = vault._decrypt(ciphertext)
                row[label] = json.loads(decoded) if column.endswith("_json") else decoded
        if op == "recon_diff":
            changes = None
            if len(data) == 2:
                new, old = data[0]["snapshot"], data[1]["snapshot"]
                if not isinstance(new, dict) or not isinstance(old, dict):
                    raise ValueError("INVALID_RECON_SNAPSHOT")
                changes = {k: {"previous_present": k in old, "current_present": k in new,
                               "previous": old.get(k), "current": new.get(k)}
                           for k in sorted(new.keys() | old.keys()) if (k in old) != (k in new) or old.get(k) != new.get(k)}
            return {"target": params["target"], "snapshot_ids": [d["id"] for d in data],
                    "comparison": "INSUFFICIENT_HISTORY" if len(data)<2 else "COMPARED_STORED_SNAPSHOTS", "changes": changes}
        return {"records": data[:25], "truncated": len(data)>25}

    def _changelog(self):
        changelog_path = Path(getattr(self.runtime, "repo_root", ".")) / "ciph_changelog.json"
        if not changelog_path.exists():
            changelog_path = Path("ciph_changelog.json")
        entries = []
        if changelog_path.exists():
            try:
                raw = json.loads(changelog_path.read_text())
                if isinstance(raw, list):
                    entries = raw
            except Exception:
                pass
        return {"records": entries[-25:], "truncated": len(entries) > 25}

    def _predictions(self):
        pred_dir = Path("ciph_predictions")
        predictions = []
        if pred_dir.exists() and pred_dir.is_dir():
            for path in sorted(pred_dir.glob("*.json")):
                try:
                    content = json.loads(path.read_text())
                    if isinstance(content, dict):
                        predictions.append({
                            "match_id": content.get("match_id", path.stem),
                            "home_team": content.get("home_team"),
                            "away_team": content.get("away_team"),
                            "predicted_at": content.get("predicted_at"),
                            "outcome": content.get("layers", {}).get("math", {}).get("outcome", "UNKNOWN")
                        })
                except Exception:
                    continue
        return {"records": predictions[:25], "truncated": len(predictions) > 25}

    def run(self, params, context=None):
        validate_parameters(self.spec, params)
        r, op = self.runtime, self.spec.operation
        if op == "status":
            data = self._status()
        elif op == "capabilities":
            data = [{"name": m.name, "description": m.description, "network": m.network_policy.value,
                     "authorization": m.authorization.value, "origin": r.registry.code_origin(m.name)}
                    for m in sorted(r.registry.list_manifests(), key=lambda m: m.name)]
        elif op == "jobs":
            data = self._jobs()
        elif op in ("job", "result"):
            rows = self._jobs(params["job_id"])
            data = {"found": bool(rows), "job": rows[0] if rows else None}
            if op == "result" and rows and rows[0]["receipt_id"]:
                from ciph.workers.receipts import ExecutionReceipt
                job = r.queue.get_job(params["job_id"])
                events = r.event_store.get_events(aggregate_id=job["receipt_id"], event_type="ExecutionReceiptStoredEvent", limit=2)
                if len(events) != 1 or not r.event_store.verify_integrity()[0]:
                    raise ValueError("UNVERIFIABLE_JOB_RESULT")
                receipt = ExecutionReceipt.from_dict(events[0]["payload"])
                if (not receipt.verify_signature(trust_registry=r.trust_registry)
                        or receipt.job_id != job["job_id"] or receipt.receipt_id != job["receipt_id"]
                        or receipt.capability != job["capability"]
                        or receipt.input_hash != ExecutionReceipt.hash_payload(job["params"])
                        or receipt.idempotency_key != job["idempotency_key"]
                        or receipt.attempt_number != job["attempt_number"]
                        or receipt.worker_signature != job["worker_signature"]):
                    raise ValueError("UNVERIFIABLE_JOB_RESULT")
                data["result"] = receipt.results
                data["outcome"] = receipt.outcome.value
            elif op == "result":
                data["result"] = None
        elif op == "authority":
            data = []
            for identity in (r.operator_key_id, r.kernel_key_id, r.worker_key_id):
                key = r.trust_registry.get_key(identity)
                data.append({"identity": identity, "enrolled": bool(key),
                             "role": str(key.get("role")) if key else None})
        elif op == "integrity":
            valid, bad_event = r.event_store.verify_integrity()
            data = {"hash_chain_valid": valid, "first_invalid_event": bad_event}
        elif op == "memory_stats":
            if r.vault is None:
                raise RuntimeError("VAULT_UNAVAILABLE")
            conn = r.vault._get_connection()
            try:
                count = conn.execute("SELECT COUNT(*) FROM command_memory").fetchone()[0]
            finally:
                conn.close()
            data = {"command_records": count,
                    "claims": self._rows("SELECT state AS epistemic_state,lifecycle_state,COUNT(*) AS count FROM ciph_active_claims WHERE migration_status='CANONICAL' GROUP BY state,lifecycle_state")}
        elif op in ("worldview", "hypotheses"):
            data = self._claims(["HYPOTHESIZED", "DISPUTED"] if op == "hypotheses" else None)
        elif op == "claim":
            c = r.worldview.get_canonical_claim(params["claim_id"])
            data = {"found": c is not None, "claim": c.to_dict() if c else None,
                    "usable": r.worldview.get_usable_claim(params["claim_id"]) is not None}
        elif op == "transitions":
            data = r.worldview.get_transitions(limit=25)
        elif op == "events":
            data = self._rows("SELECT event_id,event_type,aggregate_id,timestamp FROM ciph_event_store ORDER BY event_id DESC LIMIT 25")
        elif op == "curiosity_status":
            qs = r.question_dag._questions
            data = {"budget": r.question_dag.store.state(),
                    "questions_by_status": dict(Counter(q.status.value for q in qs.values())),
                    "max_inquiries_per_hour": r.curiosity_daemon.max_inquiries_per_hour,
                    "max_cost_per_hour": r.curiosity_daemon.max_cost_per_hour,
                    "background_thread_running": r.curiosity_daemon.running,
                    "network": "OFFLINE_ONLY"}
        elif op == "curiosity_pause":
            r.question_dag.store.pause("OPERATOR_PAUSED: " + params["reason"])
            data = r.question_dag.store.state()
        elif op == "curiosity_resume":
            r.resume_curiosity(params["reason"])
            data = r.question_dag.store.state()
        elif op == "briefing":
            data = {"runtime": self._status(), "usable_claims": self._claims()}
        elif op == "commands":
            from ciph.capabilities.command_retirement import coverage
            data = coverage(r.command_registry)
        elif op == "changelog":
            data = self._changelog()
        elif op == "predictions":
            data = self._predictions()
        else:
            data = self._vault_records(op, params)
        return report(data)


def register_local_capabilities(runtime):
    for spec in LOCAL_COMMANDS:
        runtime.register_capability(LocalOperatorCapability(runtime, spec), code_origin="internal")


def register_local_commands(registry):
    from ciph.capabilities.commands import CommandDefinition, _assign_arguments
    import shlex
    for spec in LOCAL_COMMANDS:
        def parser(text, spec=spec):
            params = _assign_arguments(shlex.split(text), [spec.argument] if spec.argument else [])
            validate_parameters(spec, params)
            return params
        registry.register(CommandDefinition(command=spec.command, capability_name=spec.capability,
            description=spec.description, aliases=list(spec.aliases),
            param_keys=[spec.argument] if spec.argument else [], parser_func=parser,
            authorization_tier=AuthorizationTier.MANDATORY_INTERRUPT if spec.mutation else AuthorizationTier.AUTO,
            help_example=spec.command + (' "' + spec.argument + '"' if spec.argument else '')))
