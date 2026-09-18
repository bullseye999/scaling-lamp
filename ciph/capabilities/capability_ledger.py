"""
ciph.capabilities.capability_ledger - Empirical Capability Ledger & Maintenance Leases (CIPH 4.0 Blueprint Phase 9).

Derives self-knowledge strictly from verified, hash-chained ExecutionReceipts and authenticated attempt evidence.
Enforces complete pagination, snapshot consistency, operational reliability gates, conflict detection,
and disk-backed metric finalization.
"""
import os
import sys
import time
import uuid
import json
import math
import sqlite3
import hashlib
import platform
import importlib.metadata
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

from ciph.memory.event_store import EventStore
from ciph.capabilities.registry import CapabilityRegistry
from ciph.kernel.policy_engine import CapabilityManifest
from ciph.kernel.crypto_identity import KeyRole, ExecutionToken
from ciph.workers.receipts import ExecutionReceipt, generate_environment_fingerprint, JobState
from ciph.contracts.enums import OutcomeCategory, NetworkPolicy
from ciph.contracts.base import canonical_json


# =====================================================================
# 1. ENUMS & CONSTANTS
# =====================================================================

class CapabilityEvidenceState(str, Enum):
    NONE                            = "NONE"                            # Zero qualifying runs on record
    HISTORICAL_UNBOUND              = "HISTORICAL_UNBOUND"              # Historical runs exist, but lack authenticated manifest/token bindings
    HISTORICAL_VERSION_MISMATCH     = "HISTORICAL_VERSION_MISMATCH"     # Runs exist, but only on older manifest versions
    HISTORICAL_ENVIRONMENT_MISMATCH = "HISTORICAL_ENVIRONMENT_MISMATCH" # Runs exist on current version, but different OS/Python/fingerprint
    HISTORICAL_STALE                = "HISTORICAL_STALE"                # Qualifying success on current version/env, but older than TTL_fresh
    CURRENT_VERSION_OBSERVED_UNPROVEN = "CURRENT_VERSION_OBSERVED_UNPROVEN" # Authenticated current version runs exist, but 0 clean successes
    CURRENT_VERSION_PROVEN          = "CURRENT_VERSION_PROVEN"          # Qualifying clean success on current version/env within TTL_fresh


class CapabilityHealthStatus(str, Enum):
    UNREGISTERED            = "UNREGISTERED"            # Historical receipts exist, but capability not in current registry
    UNTESTED                = "UNTESTED"                # Registered, but EvidenceState == NONE
    LEGACY_UNVERIFIED       = "LEGACY_UNVERIFIED"       # Historical receipts exist under legacy rules, but 0 verified runs under current rules
    HISTORICAL_ONLY         = "HISTORICAL_ONLY"         # EvidenceState in (UNBOUND, VERSION_MISMATCH, ENV_MISMATCH, STALE) with 0 fresh runs
    DEPENDENCY_UNVERIFIED   = "DEPENDENCY_UNVERIFIED"   # Registered, but dependency check status is UNKNOWN
    DEPENDENCY_FAILED       = "DEPENDENCY_FAILED"       # Registered, but dependency check status is FAIL
    POLICY_RESTRICTED_ONLY  = "POLICY_RESTRICTED_ONLY"  # 100% of current version runs were POLICY_BLOCKED
    PARTIAL_ONLY            = "PARTIAL_ONLY"            # Current version runs produced only PARTIAL_SUCCESS (0 failures, 0 clean successes)
    FAILING                 = "FAILING"                 # Current version has failures and ZERO successes (e.g. 1 or 2 runs, 100% fail)
    INCONCLUSIVE_SAMPLE     = "INCONCLUSIVE_SAMPLE"     # Fresh success exists, but (successes + failures) < 3 and failure_rate >= 0.20
    DEGRADED                = "DEGRADED"                # (successes + failures) >= 3 and failure_rate >= 0.20
    OPERATIONAL_DEGRADED    = "OPERATIONAL_DEGRADED"    # Operational failure rate >= 0.20 (e.g. excessive timeouts / unreachable)
    INTEGRITY_CONFLICT      = "INTEGRITY_CONFLICT"      # Multiple conflicting receipts detected for same execution attempt
    UNAVAILABLE             = "UNAVAILABLE"             # Scan incomplete, chain broken, or storage tampered
    VERIFIED_ACTIVE         = "VERIFIED_ACTIVE"         # Registered + Dependency PASS + CURRENT_VERSION_PROVEN + defect_rate < 0.20 + op_rate < 0.20


class DependencyCheckResult(str, Enum):
    PASS    = "PASS"
    FAIL    = "FAIL"
    UNKNOWN = "UNKNOWN"


# Host fingerprints emitted by earlier revisions of generate_environment_fingerprint() on this host.
# Retained only so pre-split receipts stay readable; auditable here so it can be retired deliberately.
LEGACY_HOST_FINGERPRINTS = frozenset({
    "0ddd61b019988b0c",
    "783f15eb124a91a6",
    "8ce034727544faa3",
})

MAX_EVENT_ROW_BYTES = 1_048_576      # 1 MB max individual event row
MAX_RETAINED_ANCHORS = 50           # Fixed upper bound for lightweight recent anchors per capability
MAX_RETAINED_CONFLICTS = 10         # Upper bound for conflict reasons


# =====================================================================
# 2. DATA CONTRACTS (IMMUTABLE TUPLES)
# =====================================================================

@dataclass(frozen=True)
class DependencyHealthEvidence:
    capability_name: str
    status: DependencyCheckResult
    checked_at: float
    source: str
    declared_modules: Tuple[str, ...]
    missing_modules: Tuple[str, ...]
    environment_fingerprint: str
    freshness_ttl_seconds: float = 3600.0

    def is_fresh(self, now: float) -> bool:
        if not (math.isfinite(self.checked_at) and math.isfinite(self.freshness_ttl_seconds) and self.freshness_ttl_seconds > 0):
            return False
        if not math.isfinite(now):
            return False
        # Reject future-dated checks beyond 1.0s grace
        if self.checked_at > now + 1.0:
            return False
        age = now - self.checked_at
        return 0 <= age <= self.freshness_ttl_seconds


@dataclass(frozen=True)
class ExecutionEvidenceAnchor:
    receipt_id: str
    event_id: int
    job_id: str
    attempt_number: int
    executed_at: float
    outcome: OutcomeCategory
    exit_code: int
    latency_ms: Optional[float]
    output_hash: str
    worker_id: str
    environment_fingerprint: Optional[str]
    bound_manifest_version: Optional[str]
    observed_transport: str
    tested_target: Optional[str]


@dataclass(frozen=True)
class LedgerScanCheckpoint:
    attempted_barrier_id: int
    attempted_barrier_hash: str
    last_verified_event_id: int
    last_verified_event_hash: str
    verification_status: str             # "VERIFIED_COMPLETE" | "VERIFIED_EMPTY" | "TAMPERED_EVENT_STORE" | "UNAVAILABLE"
    is_complete: bool
    total_events_scanned: int
    qualifying_receipts_count: int
    duplicate_replays_count: int
    conflicting_receipts_count: int
    reconciliation_events_count: int
    reconciled_jobs_count: int
    unverifiable_receipts_count: int
    scan_timestamp: float
    unresolved_reconciled_jobs_count: int = 0
    legacy_verified_receipts_count: int = 0


@dataclass(frozen=True)
class EmpiricalCapabilityProfile:
    capability_name: str
    registered_in_manifest: bool
    current_manifest_version: Optional[str]
    evidence_state: CapabilityEvidenceState
    health_status: CapabilityHealthStatus

    # Current-version & current-environment metrics
    current_version_attempts: int
    current_version_clean_successes: int
    current_version_defect_failures: int
    current_version_operational_failures: int
    current_version_policy_blocked: int
    current_version_partial: int

    # Rates: None if denominator is 0
    defect_failure_rate: Optional[float]        # defect_failures / (clean_successes + defect_failures)
    operational_failure_rate: Optional[float]   # operational_failures / (clean_successes + operational_failures)
    overall_success_rate: Optional[float]       # clean_successes / total_execution_attempts

    # Timestamps & latencies
    last_qualifying_success_at: Optional[float]
    last_attempt_at: Optional[float]
    clean_success_latency_p50_ms: Optional[float]
    clean_success_latency_p95_ms: Optional[float]
    clean_success_latency_avg_ms: Optional[float]

    # Lifetime / historical metrics
    lifetime_total_attempts: int
    lifetime_reconciled_jobs: int

    # Boundary & environmental evidence
    declared_network_policy: Optional[str]
    observed_transports: Tuple[str, ...]
    tested_targets: Tuple[str, ...]
    recent_evidence_anchors: Tuple[ExecutionEvidenceAnchor, ...]
    conflict_reasons: Tuple[str, ...]


# =====================================================================
# 3. BOUNDED STATIC DEPENDENCY INSPECTOR
# =====================================================================

class StaticDependencyInspector:
    """
    Performs bounded static inspection of distribution metadata without
    importing modules, running package code, or executing find_spec finders.
    """

    @classmethod
    def check_declared_modules(
        cls,
        capability_name: str,
        declared_modules: Tuple[str, ...],
        current_env_fingerprint: str,
        checked_at: Optional[float] = None
    ) -> DependencyHealthEvidence:
        now = checked_at if checked_at is not None else time.time()
        if not declared_modules:
            return DependencyHealthEvidence(
                capability_name=capability_name,
                status=DependencyCheckResult.PASS,
                checked_at=now,
                source="STATIC_METADATA_INSPECTION",
                declared_modules=(),
                missing_modules=(),
                environment_fingerprint=current_env_fingerprint
            )

        # Standard library package names
        import sys
        stdlib_names = set(sys.builtin_module_names)
        if hasattr(sys, "stdlib_module_names"):
            stdlib_names |= sys.stdlib_module_names

        # Top-level packages to distribution mapping (Python 3.10+ standard library)
        try:
            pkg_dist_map = importlib.metadata.packages_distributions()
        except Exception:
            pkg_dist_map = {}

        # Collect installed distribution names safely via metadata (zero imports)
        installed_dists = set()
        try:
            for dist in importlib.metadata.distributions():
                name = dist.metadata.get("Name")
                if name:
                    installed_dists.add(name.lower().replace("-", "_"))
                    installed_dists.add(name.lower())
        except Exception:
            return DependencyHealthEvidence(
                capability_name=capability_name,
                status=DependencyCheckResult.UNKNOWN,
                checked_at=now,
                source="STATIC_METADATA_INSPECTION",
                declared_modules=declared_modules,
                missing_modules=declared_modules,
                environment_fingerprint=current_env_fingerprint
            )

        missing = []
        for mod in declared_modules:
            top_level = mod.split(".")[0].lower()
            normalized = top_level.replace("-", "_")

            if top_level in stdlib_names or normalized in stdlib_names:
                continue
            if top_level in pkg_dist_map or normalized in pkg_dist_map:
                continue
            if top_level in installed_dists or normalized in installed_dists:
                continue

            # Fallback to direct distribution metadata query
            try:
                importlib.metadata.distribution(top_level)
                continue
            except Exception:
                pass
            try:
                importlib.metadata.distribution(normalized)
                continue
            except Exception:
                pass

            missing.append(mod)

        status = DependencyCheckResult.PASS if not missing else DependencyCheckResult.FAIL
        return DependencyHealthEvidence(
            capability_name=capability_name,
            status=status,
            checked_at=now,
            source="STATIC_METADATA_INSPECTION",
            declared_modules=declared_modules,
            missing_modules=tuple(missing),
            environment_fingerprint=current_env_fingerprint
        )


# =====================================================================
# 4. STRICT HISTORICAL RECEIPT PARSER
# =====================================================================

class StrictHistoricalReceiptParser:
    """
    Parses historical execution receipt dictionaries without applying
    dataclass default factories, rejecting invalid types, non-finite timestamps,
    and unverified payload hashes without backfilling plausible defaults.
    """

    @staticmethod
    def is_strict_int(val: Any) -> bool:
        return isinstance(val, int) and not isinstance(val, bool)

    @staticmethod
    def is_finite_number(val: Any) -> bool:
        if isinstance(val, bool):
            return False
        if not isinstance(val, (int, float)):
            return False
        return math.isfinite(val)

    @staticmethod
    def parse_raw_receipt(payload: Dict[str, Any]) -> Tuple[Optional[ExecutionReceipt], Dict[str, Any]]:
        """
        Validates structure and constructs an ExecutionReceipt strictly using
        the fields present in the payload. Returns (None, error_dict) on malformed data.
        """
        if not isinstance(payload, dict):
            return None, {"error": "PAYLOAD_NOT_A_DICT"}

        cap_name = payload.get("capability")
        if not isinstance(cap_name, str) or not cap_name:
            return None, {"error": "MISSING_OR_INVALID_CAPABILITY"}

        receipt_id = payload.get("receipt_id")
        if not isinstance(receipt_id, str) or not receipt_id:
            return None, {"error": "MISSING_OR_INVALID_RECEIPT_ID", "capability": cap_name}

        job_id = payload.get("job_id")
        if not isinstance(job_id, str) or not job_id:
            return None, {"error": "MISSING_OR_INVALID_JOB_ID", "capability": cap_name}

        started_at = payload.get("started_at")
        completed_at = payload.get("completed_at")
        if not StrictHistoricalReceiptParser.is_finite_number(started_at) or not StrictHistoricalReceiptParser.is_finite_number(completed_at):
            return None, {"error": "NON_FINITE_OR_INVALID_TIMESTAMPS", "capability": cap_name}

        started_at = float(started_at)
        completed_at = float(completed_at)
        if not (0.0 <= started_at <= completed_at):
            return None, {"error": "TIMESTAMP_ORDER_VIOLATION", "capability": cap_name}

        attempt_num = payload.get("attempt_number", 1)
        if not StrictHistoricalReceiptParser.is_strict_int(attempt_num) or attempt_num < 1:
            return None, {"error": "INVALID_ATTEMPT_NUMBER", "capability": cap_name}

        exit_code = payload.get("exit_code")
        if not StrictHistoricalReceiptParser.is_strict_int(exit_code):
            return None, {"error": "INVALID_EXIT_CODE", "capability": cap_name}

        schema_ver = str(payload.get("schema_version", "4.1"))
        if schema_ver not in ("4.0", "4.1"):
            return None, {"error": "UNSUPPORTED_SCHEMA_VERSION", "capability": cap_name}

        results = payload.get("results")
        if not isinstance(results, dict):
            return None, {"error": "INVALID_RESULTS_DICT", "capability": cap_name}

        output_hash = str(payload.get("output_hash", ""))
        expected_out_hash = ExecutionReceipt.hash_payload(results)
        if not output_hash or output_hash != expected_out_hash:
            # Check era-correct legacy hashing: proves old receipts weren't altered, grants no credit
            try:
                legacy_out_hash = hashlib.sha256(json.dumps(results).encode('utf-8')).hexdigest()
                if output_hash and output_hash == legacy_out_hash:
                    return None, {
                        "error": "LEGACY_FORMAT_RECEIPT",
                        "capability": cap_name,
                        "legacy_hash_verified": True,
                        "receipt_id": receipt_id,
                        "job_id": job_id,
                    }
            except Exception:
                pass
            return None, {"error": "OUTPUT_HASH_PAYLOAD_MISMATCH", "capability": cap_name}

        raw_fingerprint = payload.get("environment_fingerprint")
        provenance = payload.get("provenance") or {}
        if not isinstance(provenance, dict):
            provenance = {}

        outcome_val = payload.get("outcome")
        try:
            outcome = OutcomeCategory(outcome_val) if outcome_val else OutcomeCategory.EXECUTION_ERROR
        except Exception:
            outcome = OutcomeCategory.EXECUTION_ERROR

        policy_val = payload.get("requested_network_policy")
        try:
            policy = NetworkPolicy(policy_val) if policy_val else NetworkPolicy.OFFLINE_ONLY
        except Exception:
            policy = NetworkPolicy.OFFLINE_ONLY

        side_effects = payload.get("side_effects")
        if side_effects is not None:
            if not isinstance(side_effects, list) or not all(isinstance(x, str) for x in side_effects):
                return None, {"error": "INVALID_SIDE_EFFECTS_LIST", "capability": cap_name}
        else:
            side_effects = []

        receipt = ExecutionReceipt(
            receipt_id=receipt_id,
            job_id=job_id,
            capability=cap_name,
            target=payload.get("target"),
            started_at=started_at,
            completed_at=completed_at,
            input_hash=str(payload.get("input_hash", "")),
            output_hash=output_hash,
            exit_code=exit_code,
            outcome=outcome,
            results=results,
            side_effects=side_effects,
            idempotency_key=payload.get("idempotency_key"),
            attempt_number=attempt_num,
            requested_network_policy=policy,
            actual_transport_used=str(payload.get("actual_transport_used", "UNKNOWN")),
            worker_id=str(payload.get("worker_id", "")),
            worker_signature=payload.get("worker_signature"),
            worker_key_id=payload.get("worker_key_id"),
            artifact_ref=payload.get("artifact_ref"),
            environment_fingerprint=str(raw_fingerprint) if raw_fingerprint is not None else "",
            error_class=payload.get("error_class"),
            backtrace=payload.get("backtrace"),
            error_message=payload.get("error_message"),
            provenance=provenance,
            schema_version=schema_ver
        )

        has_complete_provenance = bool(
            provenance.get("execution_token_hash") and
            provenance.get("token_id") and
            provenance.get("manifest_version") and
            provenance.get("manifest_hash") and
            provenance.get("parameters_hash") and
            provenance.get("plan_hash") and
            provenance.get("step_id")
        )

        metadata = {
            "has_explicit_fingerprint": raw_fingerprint is not None and str(raw_fingerprint).strip() != "",
            "raw_fingerprint": raw_fingerprint,
            "has_complete_provenance": has_complete_provenance,
            "bound_manifest_version": provenance.get("manifest_version"),
            "execution_token_hash": provenance.get("execution_token_hash"),
            "token_id": provenance.get("token_id"),
            "manifest_hash": provenance.get("manifest_hash"),
            "parameters_hash": provenance.get("parameters_hash"),
            "plan_hash": provenance.get("plan_hash"),
            "step_id": provenance.get("step_id"),
        }
        return receipt, metadata


# =====================================================================
# 5. CAPABILITY LEDGER (STEP 1 ENGINE)
# =====================================================================

class CapabilityLedger:
    """
    Empirical Capability Ledger (Phase 9 Step 1).
    Grounds CIPH's self-knowledge strictly in verifiable execution history from EventStore.
    Enforces snapshot isolation, complete token lineage, disk-backed exact metrics,
    two-sided conflict resolution, and conservative fail-closed error handling.
    """

    def __init__(
        self,
        event_store: EventStore,
        registry: CapabilityRegistry,
        worker_secret_key: Optional[bytes] = None,
        trust_registry: Optional[Any] = None,
        db_path: Optional[str] = None
    ):
        self.event_store = event_store
        self.registry = registry
        self.worker_secret_key = worker_secret_key
        self.trust_registry = trust_registry
        self.db_path = db_path or getattr(event_store, "db_path", "ciph_vault.db")

    def compile_empirical_ledger(
        self,
        freshness_ttl_seconds: float = 14 * 86400.0,
        dependency_evidence_map: Optional[Dict[str, DependencyHealthEvidence]] = None,
        current_time: Optional[float] = None,
        require_active_key_at_scan: bool = True
    ) -> Tuple[Dict[str, EmpiricalCapabilityProfile], LedgerScanCheckpoint]:
        """
        Compiles the empirical capability ledger using an explicit read snapshot transaction,
        frozen public trust records, complete genesis hash-chain verification,
        bounded cursor pagination, temp-table deduplication, and bi-directional conflict purge.
        """
        now = current_time if current_time is not None else time.time()
        current_env = generate_environment_fingerprint()

        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA busy_timeout = 10000;")
            conn.execute("PRAGMA temp_store = FILE;")
            conn.execute("PRAGMA cache_size = -2000;")
            conn.execute("BEGIN DEFERRED;")
        except Exception:
            checkpoint = LedgerScanCheckpoint(
                attempted_barrier_id=0, attempted_barrier_hash="UNKNOWN",
                last_verified_event_id=0, last_verified_event_hash="UNKNOWN",
                verification_status="UNAVAILABLE", is_complete=False,
                total_events_scanned=0, qualifying_receipts_count=0, duplicate_replays_count=0,
                conflicting_receipts_count=0, reconciliation_events_count=0, reconciled_jobs_count=0,
                unverifiable_receipts_count=0, scan_timestamp=now, unresolved_reconciled_jobs_count=0
            )
            all_caps = {m.name for m in self.registry.list_manifests()}
            profiles = {
                cap_name: self._empty_unavailable_profile(cap_name, "DATABASE_CONNECTION_FAILURE")
                for cap_name in sorted(all_caps)
            }
            return profiles, checkpoint

        try:
            # 1. LOAD FROZEN TRUST SNAPSHOT WITHIN TRANSACTION
            trust_snapshot: Dict[str, Dict[str, Any]] = {}
            try:
                cur = conn.execute("SELECT key_id, role, public_key_hex, created_at, valid_until, status FROM ciph_trust_registry;")
                for r in cur.fetchall():
                    trust_snapshot[r["key_id"]] = {
                        "key_id": r["key_id"],
                        "role": getattr(r["role"], "value", r["role"]),
                        "public_key_hex": r["public_key_hex"],
                        "created_at": float(r["created_at"]),
                        "valid_until": float(r["valid_until"]) if r["valid_until"] is not None else None,
                        "status": str(r["status"])
                    }
            except sqlite3.OperationalError:
                trust_snapshot = {}

            def verify_ed25519_signature(key_id: str, required_role: str, payload_bytes: bytes, sig_hex: str, completed_at: float) -> Tuple[bool, str]:
                if not key_id or not sig_hex:
                    return False, "MISSING_KEY_OR_SIG"
                rec = trust_snapshot.get(key_id)
                if not rec:
                    return False, "KEY_NOT_ENROLLED"
                role_val = getattr(rec["role"], "value", rec["role"])
                if role_val != required_role:
                    return False, f"ROLE_MISMATCH_{role_val}_REQUIRED_{required_role}"

                # Reject future timestamps beyond 1.0s grace
                if completed_at > now + 1.0:
                    return False, "FUTURE_TIMESTAMP"

                if require_active_key_at_scan:
                    if rec["status"] != "ACTIVE":
                        return False, f"KEY_STATUS_{rec['status']}"
                    if rec["valid_until"] is not None and now > rec["valid_until"] + 1.0:
                        return False, "KEY_EXPIRED_AT_SCAN"
                else:
                    if rec["status"] == "REVOKED":
                        return False, "KEY_REVOKED"
                    if rec["created_at"] > completed_at + 1.0:
                        return False, "KEY_NOT_YET_VALID_AT_EXECUTION"
                    if rec["valid_until"] is not None and completed_at > rec["valid_until"] + 1.0:
                        return False, "KEY_EXPIRED_AT_EXECUTION"

                try:
                    import nacl.signing
                    verify_key = nacl.signing.VerifyKey(bytes.fromhex(rec["public_key_hex"]))
                    verify_key.verify(payload_bytes, bytes.fromhex(sig_hex))
                    return True, "OK"
                except Exception as ex:
                    return False, f"SIG_VERIFY_FAILED: {ex}"

            # 2. CREATE TEMPORARY TABLES FOR DISK-BACKED AGGREGATIONS
            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_records (
                    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id INTEGER NOT NULL,
                    receipt_id TEXT UNIQUE NOT NULL,
                    capability TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    is_current_version INTEGER NOT NULL,
                    outcome TEXT NOT NULL,
                    exit_code INTEGER NOT NULL,
                    latency_ms REAL,
                    started_at REAL NOT NULL,
                    completed_at REAL NOT NULL,
                    output_hash TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    env_fingerprint TEXT,
                    bound_version TEXT,
                    manifest_hash TEXT,
                    token_id TEXT,
                    token_hash TEXT,
                    has_complete_provenance INTEGER NOT NULL DEFAULT 0,
                    authoritative_worker INTEGER NOT NULL DEFAULT 0,
                    verified_activation INTEGER NOT NULL DEFAULT 0,
                    observed_transport TEXT,
                    tested_target TEXT,
                    is_conflicted INTEGER NOT NULL DEFAULT 0,
                    is_clean_success INTEGER NOT NULL,
                    is_defect_failure INTEGER NOT NULL,
                    is_operational_failure INTEGER NOT NULL,
                    is_partial INTEGER NOT NULL,
                    is_policy_blocked INTEGER NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_rec_cap ON _scan_records(capability, is_conflicted);")
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_rec_job_att ON _scan_records(job_id, attempt_number);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_seen_receipt_ids (
                    receipt_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    canonical_stmt_hash TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_seen_ids_rid ON _scan_seen_receipt_ids(receipt_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_seen_ids_att ON _scan_seen_receipt_ids(job_id, attempt_number);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_seen_tokens (
                    token_id TEXT,
                    token_hash TEXT,
                    job_id TEXT NOT NULL,
                    capability TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_seen_tok_tid ON _scan_seen_tokens(token_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_seen_tok_thash ON _scan_seen_tokens(token_hash);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_conflicts (
                    capability TEXT NOT NULL,
                    receipt_id TEXT,
                    job_id TEXT,
                    reason TEXT NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_conf_cap ON _scan_conflicts(capability);")
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_conf_rcpt ON _scan_conflicts(receipt_id);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_attempt_events (
                    event_id INTEGER,
                    job_id TEXT NOT NULL,
                    attempt_number INTEGER NOT NULL,
                    capability TEXT NOT NULL,
                    token_id TEXT,
                    token_hash TEXT,
                    manifest_version TEXT,
                    manifest_hash TEXT,
                    worker_id TEXT,
                    token_json TEXT
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_att_events_ja ON _scan_attempt_events(job_id, attempt_number);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_reconciled_jobs (
                    job_id TEXT PRIMARY KEY,
                    capability TEXT,
                    is_attributed INTEGER NOT NULL DEFAULT 0
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS _idx_rec_job_cap ON _scan_reconciled_jobs(capability);")

            conn.execute("""
                CREATE TEMP TABLE IF NOT EXISTS _scan_legacy_caps (
                    capability TEXT PRIMARY KEY
                );
            """)

            from ciph.workers.activation_evidence import SnapshotActivationVerifier
            activations = SnapshotActivationVerifier(conn, verify_ed25519_signature)

            # 3. SAMPLE SNAPSHOT BARRIER
            try:
                cursor = conn.execute("SELECT event_id, event_hash FROM ciph_event_store ORDER BY event_id DESC LIMIT 1;")
                barrier_row = cursor.fetchone()
            except (sqlite3.OperationalError, sqlite3.DatabaseError):
                checkpoint = LedgerScanCheckpoint(
                    attempted_barrier_id=0, attempted_barrier_hash="UNKNOWN",
                    last_verified_event_id=0, last_verified_event_hash="UNKNOWN",
                    verification_status="UNAVAILABLE", is_complete=False,
                    total_events_scanned=0, qualifying_receipts_count=0, duplicate_replays_count=0,
                    conflicting_receipts_count=0, reconciliation_events_count=0, reconciled_jobs_count=0,
                    unverifiable_receipts_count=0, scan_timestamp=now, unresolved_reconciled_jobs_count=0,
                    legacy_verified_receipts_count=0
                )
                profiles = self._build_profiles_from_db(conn, checkpoint, freshness_ttl_seconds, dependency_evidence_map, now, current_env)
                return profiles, checkpoint

            if not barrier_row:
                checkpoint = LedgerScanCheckpoint(
                    attempted_barrier_id=0, attempted_barrier_hash="GENESIS_BLOCK_CIPH_4.0",
                    last_verified_event_id=0, last_verified_event_hash="GENESIS_BLOCK_CIPH_4.0",
                    verification_status="VERIFIED_EMPTY", is_complete=True,
                    total_events_scanned=0, qualifying_receipts_count=0, duplicate_replays_count=0,
                    conflicting_receipts_count=0, reconciliation_events_count=0, reconciled_jobs_count=0,
                    unverifiable_receipts_count=0, scan_timestamp=now, unresolved_reconciled_jobs_count=0,
                    legacy_verified_receipts_count=0
                )
                profiles = self._build_profiles_from_db(conn, checkpoint, freshness_ttl_seconds, dependency_evidence_map, now, current_env)
                return profiles, checkpoint

            attempted_barrier_id = int(barrier_row["event_id"])
            attempted_barrier_hash = str(barrier_row["event_hash"])

            # 4. PAGINATED CURSOR SCAN WITH GENESIS RECOMPUTATION
            expected_prev_hash = "GENESIS_BLOCK_CIPH_4.0"
            cursor_id = 0
            page_size = 250

            total_scanned = 0
            qualifying_receipts_count = 0
            duplicate_replays_count = 0
            conflicting_receipts_count = 0
            reconciliation_events_count = 0
            unverifiable_receipts_count = 0
            legacy_verified_receipts_count = 0

            verification_status = "VERIFIED_COMPLETE"
            last_verified_id = 0
            last_verified_hash = "GENESIS_BLOCK_CIPH_4.0"

            while cursor_id < attempted_barrier_id:
                page_cursor = conn.execute("""
                    SELECT
                        event_id,
                        event_type,
                        aggregate_id,
                        LENGTH(CAST(payload AS BLOB)) AS payload_bytes,
                        CASE
                            WHEN LENGTH(CAST(payload AS BLOB)) > 1048576 THEN ''
                            ELSE payload
                        END AS payload,
                        timestamp,
                        previous_hash,
                        event_hash
                    FROM ciph_event_store
                    WHERE event_id > ? AND event_id <= ?
                    ORDER BY event_id ASC LIMIT ?;
                """, (cursor_id, attempted_barrier_id, page_size))
                rows = page_cursor.fetchall()
                if not rows:
                    break

                for row in rows:
                    ev_id = int(row["event_id"])
                    ev_type = str(row["event_type"])
                    agg_id = str(row["aggregate_id"])
                    payload_bytes = int(row["payload_bytes"] or 0)
                    raw_payload_str = str(row["payload"])
                    ev_time = float(row["timestamp"])
                    prev_hash = str(row["previous_hash"])
                    ev_hash = str(row["event_hash"])

                    total_scanned += 1

                    # Bound individual row payload size before parsing
                    if payload_bytes > MAX_EVENT_ROW_BYTES:
                        verification_status = "UNAVAILABLE"
                        break

                    # Cryptographic Hash-Chain Verification
                    computed_hash_input = f"{expected_prev_hash}|{ev_type}|{agg_id}|{raw_payload_str}|{ev_time}"
                    computed_hash = hashlib.sha256(computed_hash_input.encode('utf-8')).hexdigest()

                    if prev_hash != expected_prev_hash or ev_hash != computed_hash:
                        verification_status = "TAMPERED_EVENT_STORE"
                        break

                    expected_prev_hash = computed_hash
                    cursor_id = ev_id
                    last_verified_id = ev_id
                    last_verified_hash = computed_hash

                    # Parse JSON payload
                    try:
                        payload = json.loads(raw_payload_str)
                    except Exception:
                        if ev_type in ("ExecutionReceiptStoredEvent", "ExecutionAttemptStartedEvent"):
                            verification_status = "UNAVAILABLE"
                            break
                        unverifiable_receipts_count += 1
                        continue

                    if not isinstance(payload, dict):
                        if ev_type in ("ExecutionReceiptStoredEvent", "ExecutionAttemptStartedEvent"):
                            verification_status = "UNAVAILABLE"
                            break
                        continue

                    # --- Event Type A: ExecutionAttemptStartedEvent ---
                    if ev_type == "ExecutionAttemptStartedEvent":
                        job_id = payload.get("job_id")
                        att_num = payload.get("attempt_number", 1)
                        cap_name = payload.get("capability")
                        if job_id and cap_name:
                            try:
                                activation_ok, activation_reason = activations.record(payload, agg_id, ev_time)
                                if activation_reason == "ACTIVATION_TOKEN_OR_ATTEMPT_REUSED":
                                    conflicting_receipts_count += 1
                                    conn.execute("INSERT INTO _scan_conflicts (capability, job_id, reason) VALUES (?, ?, ?)",
                                                 (str(cap_name), str(job_id), activation_reason))
                                # Keep contradiction detection separate from authority:
                                # an unsigned statement never grants attribution, but
                                # cannot conceal disagreement with its signed token.
                                if payload.get("token"):
                                    asserted_token = ExecutionToken.from_dict(payload["token"])
                                    token_ok, _ = verify_ed25519_signature(
                                        asserted_token.kernel_key_id, KeyRole.KERNEL.value,
                                        asserted_token.compute_canonical_payload(), asserted_token.signature,
                                        asserted_token.issued_at)
                                    if token_ok and cap_name != asserted_token.capability:
                                        conflicting_receipts_count += 1
                                        for conflicted_cap in (str(cap_name), asserted_token.capability):
                                            conn.execute("INSERT INTO _scan_conflicts (capability, job_id, reason) VALUES (?, ?, ?)",
                                                (conflicted_cap, str(job_id), "ATTEMPT_TOKEN_CAPABILITY_MISMATCH"))
                                att_int = int(att_num)
                                att_tok_id = payload.get("token_id")
                                att_tok_hash = payload.get("token_hash")
                                att_ver = payload.get("manifest_version")
                                att_m_hash = payload.get("manifest_hash")
                                att_worker = payload.get("worker_id")

                                # Check token reuse across jobs at attempt time
                                if att_tok_id or att_tok_hash:
                                    seen_att_toks = conn.execute("""
                                        SELECT job_id, capability FROM _scan_seen_tokens
                                        WHERE ((token_id IS NOT NULL AND token_id = ?) OR (token_hash IS NOT NULL AND token_hash = ?)) AND job_id != ?;
                                    """, (att_tok_id, att_tok_hash, str(job_id))).fetchall()
                                    if seen_att_toks:
                                        conflicting_receipts_count += 1
                                        for sat in seen_att_toks:
                                            conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, NULL, ?, ?);",
                                                         (sat["capability"], str(job_id), f"Token {att_tok_id} reused across jobs {sat['job_id']} and {job_id}"))
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, NULL, ?, ?);",
                                                     (str(cap_name), str(job_id), f"Token {att_tok_id} reused across jobs"))
                                        conn.execute("UPDATE _scan_records SET is_conflicted = 1 WHERE job_id IN (?, ?);", (seen_att_toks[0]["job_id"], str(job_id)))
                                    conn.execute("INSERT INTO _scan_seen_tokens (token_id, token_hash, job_id, capability) VALUES (?, ?, ?, ?);",
                                                 (att_tok_id, att_tok_hash, str(job_id), str(cap_name)))

                                # Check for contradictory earlier attempt statements for same (job_id, attempt_number)
                                earlier_atts = conn.execute("""
                                    SELECT capability, token_id, token_hash, manifest_version, manifest_hash, worker_id
                                    FROM _scan_attempt_events WHERE job_id = ? AND attempt_number = ?;
                                """, (str(job_id), att_int)).fetchall()

                                for ea in earlier_atts:
                                    is_att_conflict = False
                                    reason = ""
                                    if ea["capability"] != str(cap_name):
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt capability: {ea['capability']} vs {cap_name}"
                                    elif ea["manifest_version"] and att_ver and ea["manifest_version"] != att_ver:
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt version: {ea['manifest_version']} vs {att_ver}"
                                    elif ea["manifest_hash"] and att_m_hash and ea["manifest_hash"] != att_m_hash:
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt manifest hash: {ea['manifest_hash']} vs {att_m_hash}"
                                    elif ea["token_id"] and att_tok_id and ea["token_id"] != att_tok_id:
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt token id: {ea['token_id']} vs {att_tok_id}"
                                    elif ea["token_hash"] and att_tok_hash and ea["token_hash"] != att_tok_hash:
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt token hash: {ea['token_hash']} vs {att_tok_hash}"
                                    elif ea["worker_id"] and att_worker and ea["worker_id"] != att_worker:
                                        is_att_conflict = True
                                        reason = f"Contradictory attempt worker id: {ea['worker_id']} vs {att_worker}"

                                    if is_att_conflict:
                                        conflicting_receipts_count += 1
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, NULL, ?, ?);",
                                                     (str(cap_name), str(job_id), reason))
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, NULL, ?, ?);",
                                                     (ea["capability"], str(job_id), reason))
                                        conn.execute("UPDATE _scan_records SET is_conflicted = 1 WHERE job_id = ? AND attempt_number = ?;", (str(job_id), att_int))

                                # Check for late attempt conflicting with an earlier receipt
                                existing_rcpts = conn.execute("""
                                    SELECT receipt_id, capability, bound_version, manifest_hash, token_id, token_hash, worker_id FROM _scan_records
                                    WHERE job_id = ? AND attempt_number = ?;
                                """, (str(job_id), att_int)).fetchall()
                                for er in existing_rcpts:
                                    is_conflict = False
                                    conflict_msg = ""
                                    if er["capability"] != str(cap_name):
                                        is_conflict = True
                                        conflict_msg = f"Late attempt capability {cap_name} differs from receipt capability {er['capability']}"
                                    elif att_ver and er["bound_version"] and att_ver != er["bound_version"]:
                                        is_conflict = True
                                        conflict_msg = "ATTEMPT_RECEIPT_VERSION_MISMATCH"
                                    elif att_m_hash and er["manifest_hash"] and att_m_hash != er["manifest_hash"]:
                                        is_conflict = True
                                        conflict_msg = f"Late attempt manifest hash {att_m_hash} differs from receipt manifest hash {er['manifest_hash']}"
                                    elif att_tok_id and er["token_id"] and att_tok_id != er["token_id"]:
                                        is_conflict = True
                                        conflict_msg = f"Late attempt token id {att_tok_id} differs from receipt token id {er['token_id']}"
                                    elif att_tok_hash and er["token_hash"] and att_tok_hash != er["token_hash"]:
                                        is_conflict = True
                                        conflict_msg = f"Late attempt token hash {att_tok_hash} differs from receipt token hash {er['token_hash']}"
                                    elif att_worker and er["worker_id"] and att_worker != er["worker_id"]:
                                        is_conflict = True
                                        conflict_msg = f"Late attempt worker {att_worker} differs from receipt worker {er['worker_id']}"

                                    if is_conflict:
                                        conflicting_receipts_count += 1
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);", (er["capability"], er["receipt_id"], str(job_id), conflict_msg))
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);", (str(cap_name), er["receipt_id"], str(job_id), conflict_msg))
                                        conn.execute("UPDATE _scan_records SET is_conflicted = 1 WHERE receipt_id = ?;", (er["receipt_id"],))

                                conn.execute("""
                                    INSERT INTO _scan_attempt_events
                                    (event_id, job_id, attempt_number, capability, token_id, token_hash, manifest_version, manifest_hash, worker_id, token_json)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                                """, (
                                    ev_id,
                                    str(job_id),
                                    att_int,
                                    str(cap_name),
                                    att_tok_id,
                                    att_tok_hash,
                                    att_ver,
                                    att_m_hash,
                                    att_worker,
                                    json.dumps(payload.get("token")) if payload.get("token") else None
                                ))
                            except sqlite3.Error:
                                raise
                            except Exception:
                                pass

                    # --- Event Type B: JobReconciledEvent ---
                    elif ev_type == "JobReconciledEvent":
                        job_id = payload.get("job_id")
                        target_state = str(payload.get("target_state", "")).strip()
                        notes = payload.get("resolution_notes")
                        op_id = payload.get("operator_id")
                        op_sig = payload.get("operator_signature")

                        # Strictly require: agg_id == job_id, terminal whitelisted state, notes >= 10 chars, operator signature
                        if (job_id and str(agg_id) == str(job_id) and
                            target_state in ("SUCCEEDED", "COMPLETED", "FAILED", "QUARANTINED") and
                            isinstance(notes, str) and len(notes.strip()) >= 10 and
                            op_id and op_sig and trust_snapshot):

                            notes_str = notes.strip()
                            res_dict = payload.get("result") or {}
                            res_str = json.dumps(res_dict, sort_keys=True)
                            res_digest = hashlib.sha256(res_str.encode('utf-8')).hexdigest()

                            recon_ipc_msg = f"RECONCILE:{job_id}:{target_state}:{res_digest}:{notes_str}".encode('utf-8')
                            recon_canon_msg = canonical_json({
                                "job_id": job_id,
                                "target_state": target_state,
                                "result": res_dict,
                                "resolution_notes": notes_str,
                                "timestamp": ev_time
                            }).encode("utf-8")

                            is_ok1, _ = verify_ed25519_signature(op_id, KeyRole.OPERATOR.value, recon_ipc_msg, op_sig, ev_time)
                            is_ok2 = False
                            if not is_ok1:
                                is_ok2, _ = verify_ed25519_signature(op_id, KeyRole.OPERATOR.value, recon_canon_msg, op_sig, ev_time)

                            if is_ok1 or is_ok2:
                                reconciliation_events_count += 1
                                conn.execute("INSERT OR IGNORE INTO _scan_reconciled_jobs (job_id, capability, is_attributed) VALUES (?, NULL, 0);", (job_id,))

                    # --- Event Type C: ExecutionReceiptStoredEvent ---
                    elif ev_type == "ExecutionReceiptStoredEvent":
                        rcpt_id_cand = payload.get("receipt_id")
                        if not rcpt_id_cand or str(agg_id) != str(rcpt_id_cand):
                            unverifiable_receipts_count += 1
                            cap_candidate = payload.get("capability")
                            if cap_candidate:
                                conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, 'EVENT_AGGREGATE_ID_MISMATCH');", (str(cap_candidate), str(rcpt_id_cand or agg_id), str(payload.get("job_id") or "UNKNOWN")))
                            continue

                        receipt, meta = StrictHistoricalReceiptParser.parse_raw_receipt(payload)
                        if receipt is None:
                            # A legacy row that predates current canonical rules is unverifiable
                            # evidence, not an integrity conflict and not a scan failure. Count it,
                            # skip it, and keep scanning: escalating here blanks the entire ledger
                            # (every capability degrades to UNAVAILABLE) on any vault with history.
                            unverifiable_receipts_count += 1
                            if meta and meta.get("legacy_hash_verified"):
                                legacy_verified_receipts_count += 1
                                legacy_cap = meta.get("capability") or payload.get("capability")
                                if legacy_cap:
                                    conn.execute("INSERT OR IGNORE INTO _scan_legacy_caps (capability) VALUES (?);", (str(legacy_cap),))
                            continue

                        cap_name = receipt.capability

                        # 1. Cryptographic Signature Verification (Ed25519)
                        key_id = receipt.worker_key_id or receipt.worker_id
                        try:
                            sig_bytes = receipt.compute_signature_payload().encode('utf-8')
                        except Exception:
                            # Same principle: an uncanonicalisable legacy receipt is unverifiable,
                            # never a global scan failure and never a capability conflict.
                            unverifiable_receipts_count += 1
                            continue

                        sig_valid = False
                        is_authoritative_worker = False

                        if trust_snapshot and key_id in trust_snapshot:
                            sig_valid, _ = verify_ed25519_signature(
                                key_id, KeyRole.WORKER.value, sig_bytes, receipt.worker_signature or "", receipt.completed_at
                            )
                            if sig_valid:
                                is_authoritative_worker = True
                        elif self.worker_secret_key:
                            # Direct key fallback for testing: verify signature cryptographically but NEVER confer authoritative active status
                            if len(self.worker_secret_key) == 32 and len(receipt.worker_signature or "") == 128:
                                try:
                                    import nacl.signing
                                    vk = nacl.signing.SigningKey(self.worker_secret_key).verify_key
                                    vk.verify(sig_bytes, bytes.fromhex(receipt.worker_signature or ""))
                                    sig_valid = True
                                except Exception:
                                    sig_valid = False
                            is_authoritative_worker = False

                        if not sig_valid:
                            unverifiable_receipts_count += 1
                            continue

                        # Reject future-dated receipts beyond 1.0s grace
                        if receipt.started_at > now + 1.0 or receipt.completed_at > now + 1.0:
                            is_authoritative_worker = False

                        raw_fingerprint = meta.get("raw_fingerprint")
                        token_hash = meta.get("execution_token_hash")
                        token_id = meta.get("token_id")
                        bound_manifest_ver = meta.get("bound_manifest_version")
                        manifest_hash = meta.get("manifest_hash")
                        parameters_hash = meta.get("parameters_hash")
                        plan_hash = meta.get("plan_hash")
                        step_id = meta.get("step_id")
                        canonical_stmt_hash = hashlib.sha256(sig_bytes).hexdigest()

                        # Check if receipt_id was already seen
                        seen_rcpts = conn.execute("""
                            SELECT capability, job_id, attempt_number, canonical_stmt_hash
                            FROM _scan_seen_receipt_ids
                            WHERE receipt_id = ?;
                        """, (receipt.receipt_id,)).fetchall()

                        if seen_rcpts:
                            # If exact identical replay (same capability, job, attempt, and signed payload hash), deduplicate
                            is_exact_replay = any(
                                sr["capability"] == cap_name and
                                sr["job_id"] == receipt.job_id and
                                sr["attempt_number"] == receipt.attempt_number and
                                sr["canonical_stmt_hash"] == canonical_stmt_hash
                                for sr in seen_rcpts
                            )
                            if is_exact_replay:
                                duplicate_replays_count += 1
                                continue

                            # Otherwise, receipt_id collision / reuse across executions or payloads!
                            conflicting_receipts_count += 1
                            for sr in seen_rcpts:
                                conn.execute("""
                                    INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason)
                                    VALUES (?, ?, ?, ?);
                                """, (sr["capability"], receipt.receipt_id, sr["job_id"], f"Receipt ID {receipt.receipt_id} reused across executions (by {cap_name})"))
                            conn.execute("""
                                INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason)
                                VALUES (?, ?, ?, ?);
                            """, (cap_name, receipt.receipt_id, receipt.job_id, f"Receipt ID {receipt.receipt_id} reused across executions"))

                            conn.execute("""
                                INSERT INTO _scan_seen_receipt_ids (receipt_id, capability, job_id, attempt_number, canonical_stmt_hash)
                                VALUES (?, ?, ?, ?, ?);
                            """, (receipt.receipt_id, cap_name, receipt.job_id, receipt.attempt_number, canonical_stmt_hash))
                            conn.execute("UPDATE _scan_records SET is_conflicted = 1 WHERE receipt_id = ?;", (receipt.receipt_id,))
                            continue

                        # First time seeing this receipt_id: register it
                        conn.execute("""
                            INSERT INTO _scan_seen_receipt_ids (receipt_id, capability, job_id, attempt_number, canonical_stmt_hash)
                            VALUES (?, ?, ?, ?, ?);
                        """, (receipt.receipt_id, cap_name, receipt.job_id, receipt.attempt_number, canonical_stmt_hash))

                        # Check for attempt payload conflicts (different receipt_id for same job and attempt)
                        seen_atts = conn.execute("""
                            SELECT capability, canonical_stmt_hash, receipt_id
                            FROM _scan_seen_receipt_ids
                            WHERE job_id = ? AND attempt_number = ? AND receipt_id != ?;
                        """, (receipt.job_id, receipt.attempt_number, receipt.receipt_id)).fetchall()

                        if seen_atts:
                            conflicting_receipts_count += 1
                            for sa in seen_atts:
                                conn.execute("""
                                    INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason)
                                    VALUES (?, ?, ?, ?);
                                """, (sa["capability"], sa["receipt_id"], receipt.job_id, f"Conflicting receipt payload for attempt {receipt.job_id}:{receipt.attempt_number}"))
                            conn.execute("""
                                INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason)
                                VALUES (?, ?, ?, ?);
                            """, (cap_name, receipt.receipt_id, receipt.job_id, f"Conflicting receipt payload for attempt {receipt.job_id}:{receipt.attempt_number}"))
                            conn.execute("UPDATE _scan_records SET is_conflicted = 1 WHERE job_id = ? AND attempt_number = ?;", (receipt.job_id, receipt.attempt_number))
                            continue

                        # 3. Authenticate Execution & Token Lineage
                        is_bound_attempt = False
                        bound_ver = bound_manifest_ver
                        bound_m_hash = manifest_hash
                        bound_tok_id = token_id
                        bound_tok_hash = token_hash

                        att_rows = conn.execute("""
                            SELECT capability, token_id, token_hash, manifest_version, manifest_hash, token_json, worker_id
                            FROM _scan_attempt_events WHERE job_id = ? AND attempt_number = ?;
                        """, (receipt.job_id, receipt.attempt_number)).fetchall()

                        for att_row in att_rows:
                            is_att_rcpt_conflict = False
                            conflict_reason = ""
                            if att_row["capability"] != cap_name:
                                is_att_rcpt_conflict = True
                                conflict_reason = f"Attempt capability {att_row['capability']} differs from receipt capability {cap_name}"
                            elif bound_manifest_ver and att_row["manifest_version"] and bound_manifest_ver != att_row["manifest_version"]:
                                is_att_rcpt_conflict = True
                                conflict_reason = "ATTEMPT_RECEIPT_VERSION_MISMATCH"
                            elif meta.get("manifest_hash") and att_row["manifest_hash"] and meta.get("manifest_hash") != att_row["manifest_hash"]:
                                is_att_rcpt_conflict = True
                                conflict_reason = f"Attempt manifest hash {att_row['manifest_hash']} differs from receipt manifest hash {meta.get('manifest_hash')}"
                            elif meta.get("token_id") and att_row["token_id"] and meta.get("token_id") != att_row["token_id"]:
                                is_att_rcpt_conflict = True
                                conflict_reason = f"Attempt token id {att_row['token_id']} differs from receipt token id {meta.get('token_id')}"
                            elif token_hash and att_row["token_hash"] and token_hash != att_row["token_hash"]:
                                is_att_rcpt_conflict = True
                                conflict_reason = f"Attempt token hash {att_row['token_hash']} differs from receipt token hash {token_hash}"
                            elif att_row["worker_id"] and receipt.worker_id and att_row["worker_id"] != receipt.worker_id:
                                is_att_rcpt_conflict = True
                                conflict_reason = f"Attempt worker {att_row['worker_id']} differs from receipt worker {receipt.worker_id}"

                            if is_att_rcpt_conflict:
                                conflicting_receipts_count += 1
                                conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);",
                                             (cap_name, receipt.receipt_id, receipt.job_id, conflict_reason))
                                conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);",
                                             (att_row["capability"], receipt.receipt_id, receipt.job_id, conflict_reason))

                        if is_authoritative_worker and token_hash:
                            token_to_verify = None
                            for att_row in att_rows:
                                if att_row["token_json"]:
                                    try:
                                        token_to_verify = ExecutionToken.from_dict(json.loads(att_row["token_json"]))
                                        break
                                    except Exception:
                                        token_to_verify = None

                            if not token_to_verify:
                                try:
                                    if receipt.attempt_number > 1:
                                        t_row = conn.execute("SELECT token FROM ciph_retry_tokens WHERE job_id = ? AND attempt_number = ?;", (receipt.job_id, receipt.attempt_number)).fetchone()
                                        if t_row and t_row[0]:
                                            token_to_verify = ExecutionToken.from_dict(json.loads(t_row[0]))
                                    else:
                                        j_row = conn.execute("SELECT execution_token FROM ciph_ipc_jobs WHERE job_id = ?;", (receipt.job_id,)).fetchone()
                                        if j_row and j_row[0]:
                                            token_to_verify = ExecutionToken.from_dict(json.loads(j_row[0]))
                                except Exception:
                                    token_to_verify = None

                            if token_to_verify is not None:
                                token_sig_ok, _ = verify_ed25519_signature(
                                    token_to_verify.kernel_key_id,
                                    KeyRole.KERNEL.value,
                                    token_to_verify.compute_canonical_payload(),
                                    token_to_verify.signature,
                                    receipt.completed_at
                                )

                                token_time_ok = (
                                    token_to_verify.issued_at <= receipt.started_at + 1.0 and
                                    receipt.started_at <= token_to_verify.expires_at + 1.0
                                )

                                receipt_time_ok = (
                                    receipt.started_at <= now + 1.0 and
                                    receipt.completed_at <= now + 1.0
                                )

                                # Attempt budget enforcement
                                budget_ok = (1 <= receipt.attempt_number <= token_to_verify.max_attempts)
                                if not budget_ok:
                                    conflicting_receipts_count += 1
                                    conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);",
                                                 (cap_name, receipt.receipt_id, receipt.job_id, f"Attempt number {receipt.attempt_number} exceeds token max_attempts {token_to_verify.max_attempts}"))

                                # Cross-job token reuse check
                                seen_toks = conn.execute("""
                                    SELECT job_id, capability FROM _scan_seen_tokens
                                    WHERE ((token_id IS NOT NULL AND token_id = ?) OR (token_hash IS NOT NULL AND token_hash = ?)) AND job_id != ?;
                                """, (token_to_verify.token_id, token_to_verify.token_hash(), str(receipt.job_id))).fetchall()
                                token_reuse_ok = True
                                if seen_toks:
                                    token_reuse_ok = False
                                    conflicting_receipts_count += 1
                                    for st in seen_toks:
                                        conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);",
                                                     (st["capability"], receipt.receipt_id, receipt.job_id, f"Token reused across jobs {st['job_id']} and {receipt.job_id}"))
                                    conn.execute("INSERT INTO _scan_conflicts (capability, receipt_id, job_id, reason) VALUES (?, ?, ?, ?);",
                                                 (cap_name, receipt.receipt_id, receipt.job_id, f"Token reused across jobs"))

                                conn.execute("INSERT INTO _scan_seen_tokens (token_id, token_hash, job_id, capability) VALUES (?, ?, ?, ?);",
                                             (token_to_verify.token_id, token_to_verify.token_hash(), str(receipt.job_id), str(cap_name)))

                                bindings_ok = (
                                    token_to_verify.capability == receipt.capability and
                                    token_to_verify.token_hash() == token_hash and
                                    receipt.input_hash == token_to_verify.parameters_hash
                                )
                                if token_id is not None and token_id != token_to_verify.token_id:
                                    bindings_ok = False
                                if manifest_hash is not None and manifest_hash != token_to_verify.manifest_hash:
                                    bindings_ok = False
                                if bound_manifest_ver is not None and bound_manifest_ver != token_to_verify.manifest_version:
                                    bindings_ok = False
                                if parameters_hash is not None and parameters_hash != token_to_verify.parameters_hash:
                                    bindings_ok = False
                                if plan_hash is not None and plan_hash != token_to_verify.plan_hash:
                                    bindings_ok = False
                                if step_id is not None and step_id != token_to_verify.step_id:
                                    bindings_ok = False

                                if token_to_verify.authorized_worker_class not in ("ALL", None, ""):
                                    if token_to_verify.authorized_worker_class != receipt.worker_id:
                                        bindings_ok = False

                                for att_row in att_rows:
                                    if att_row["capability"] != receipt.capability or att_row["token_hash"] != token_hash:
                                        bindings_ok = False
                                    if att_row["worker_id"] and receipt.worker_id and att_row["worker_id"] != receipt.worker_id:
                                        bindings_ok = False
                                    if bound_manifest_ver and att_row["manifest_version"] and bound_manifest_ver != att_row["manifest_version"]:
                                        bindings_ok = False
                                    if manifest_hash and att_row["manifest_hash"] and manifest_hash != att_row["manifest_hash"]:
                                        bindings_ok = False
                                    if token_id and att_row["token_id"] and token_id != att_row["token_id"]:
                                        bindings_ok = False

                                if token_sig_ok and token_time_ok and receipt_time_ok and budget_ok and token_reuse_ok and bindings_ok:
                                    is_bound_attempt = True
                                    bound_ver = bound_manifest_ver or token_to_verify.manifest_version
                                    bound_m_hash = manifest_hash or token_to_verify.manifest_hash
                                    bound_tok_id = token_id or token_to_verify.token_id
                                    bound_tok_hash = token_hash or token_to_verify.token_hash()

                        manifest = self._get_manifest(cap_name)
                        cur_ver = manifest.version if manifest else None
                        cur_m_hash = manifest.compute_manifest_hash() if manifest else None
                        has_explicit_fp = meta.get("has_explicit_fingerprint", False)
                        has_complete_provenance = meta.get("has_complete_provenance", False)

                        verified_activation = activations.matches_receipt(receipt)
                        is_env_compat = self._is_environment_compatible(raw_fingerprint, current_env, cap_name=cap_name)
                        is_cur = 1 if (
                            is_authoritative_worker and verified_activation and is_bound_attempt and
                            has_complete_provenance and
                            bound_ver is not None and bound_ver == cur_ver and
                            bound_m_hash is not None and bound_m_hash == cur_m_hash and
                            has_explicit_fp and is_env_compat
                        ) else 0
                        is_clean = 1 if (receipt.exit_code == 0 and receipt.outcome == OutcomeCategory.SUCCESS) else 0
                        is_op = 1 if (receipt.outcome in (OutcomeCategory.TIMEOUT, OutcomeCategory.TARGET_UNREACHABLE, OutcomeCategory.RESOURCE_EXHAUSTED)) else 0
                        is_part = 1 if (receipt.outcome == OutcomeCategory.PARTIAL_SUCCESS) else 0
                        is_pol = 1 if (receipt.outcome in (OutcomeCategory.POLICY_BLOCKED, OutcomeCategory.AUTH_REQUIRED, OutcomeCategory.CANCELLED)) else 0
                        is_defect = 1 if (receipt.outcome in (OutcomeCategory.EXECUTION_ERROR, OutcomeCategory.DEPENDENCY_FAILURE, OutcomeCategory.SANDBOX_VIOLATION) or (receipt.exit_code != 0 and not (is_clean or is_op or is_part or is_pol))) else 0

                        lat_ms = (receipt.completed_at - receipt.started_at) * 1000.0 if receipt.completed_at >= receipt.started_at else None

                        conn.execute("""
                            INSERT INTO _scan_records (
                                event_id, receipt_id, capability, job_id, attempt_number, is_current_version,
                                outcome, exit_code, latency_ms, started_at, completed_at,
                                output_hash, worker_id, env_fingerprint, bound_version,
                                manifest_hash, token_id, token_hash, has_complete_provenance,
                                observed_transport, tested_target, is_conflicted, is_clean_success,
                                is_defect_failure, is_operational_failure, is_partial, is_policy_blocked
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?);
                        """, (
                            ev_id, receipt.receipt_id, cap_name, receipt.job_id, receipt.attempt_number, is_cur,
                            receipt.outcome.value if hasattr(receipt.outcome, "value") else str(receipt.outcome),
                            receipt.exit_code, lat_ms, receipt.started_at, receipt.completed_at,
                            receipt.output_hash, receipt.worker_id, raw_fingerprint, bound_ver,
                            bound_m_hash, bound_tok_id, bound_tok_hash, 1 if has_complete_provenance else 0,
                            receipt.actual_transport_used, receipt.target, is_clean, is_defect, is_op, is_part, is_pol
                        ))
                        conn.execute("UPDATE _scan_records SET authoritative_worker=?, verified_activation=? WHERE receipt_id=?",
                                     (int(is_authoritative_worker), int(verified_activation), receipt.receipt_id))
                        qualifying_receipts_count += 1

                if verification_status != "VERIFIED_COMPLETE":
                    break

            is_complete = (
                verification_status == "VERIFIED_COMPLETE" and
                cursor_id == attempted_barrier_id and
                expected_prev_hash == attempted_barrier_hash
            )
            if not is_complete and verification_status == "VERIFIED_COMPLETE":
                verification_status = "UNAVAILABLE"

            # Transitive conflict propagation across connected receipts, jobs, and capabilities
            while True:
                new_conflicts = conn.execute("""
                    INSERT OR IGNORE INTO _scan_conflicts (capability, receipt_id, job_id, reason)
                    SELECT DISTINCT sr.capability, sr.receipt_id, sr.job_id, 'TRANSITIVE_COLLISION'
                    FROM _scan_seen_receipt_ids sr
                    WHERE (
                        sr.receipt_id IN (SELECT receipt_id FROM _scan_conflicts WHERE receipt_id IS NOT NULL)
                        OR sr.job_id IN (SELECT job_id FROM _scan_conflicts WHERE job_id IS NOT NULL)
                        OR sr.capability IN (SELECT capability FROM _scan_conflicts)
                    )
                    AND sr.receipt_id NOT IN (SELECT receipt_id FROM _scan_conflicts WHERE receipt_id IS NOT NULL);
                """).rowcount
                if new_conflicts == 0:
                    break

            conn.execute("""
                UPDATE _scan_records
                SET is_conflicted = 1
                WHERE receipt_id IN (SELECT receipt_id FROM _scan_conflicts WHERE receipt_id IS NOT NULL)
                   OR capability IN (SELECT capability FROM _scan_conflicts);
            """)

            # Both receipt-based and receipt-less attribution require a signed,
            # consumed activation verified in this snapshot. Unsigned metadata and
            # direct-key fallback receipts cannot supply job authority.
            conn.execute("""
                UPDATE _scan_reconciled_jobs AS j SET
                    capability=(SELECT MIN(a.capability) FROM _scan_activations a WHERE a.job_id=j.job_id),
                    is_attributed=1
                WHERE (SELECT COUNT(DISTINCT a.capability) FROM _scan_activations a WHERE a.job_id=j.job_id)=1
                  AND NOT EXISTS (SELECT 1 FROM _scan_conflicts c WHERE c.job_id=j.job_id
                      OR c.capability IN (SELECT a.capability FROM _scan_activations a WHERE a.job_id=j.job_id));
            """)

            reconciled_count = conn.execute("SELECT COUNT(*) FROM _scan_reconciled_jobs;").fetchone()[0]
            unresolved_reconciled_count = conn.execute("SELECT COUNT(*) FROM _scan_reconciled_jobs WHERE is_attributed = 0;").fetchone()[0]

            checkpoint = LedgerScanCheckpoint(
                attempted_barrier_id=attempted_barrier_id,
                attempted_barrier_hash=attempted_barrier_hash,
                last_verified_event_id=last_verified_id,
                last_verified_event_hash=last_verified_hash,
                verification_status=verification_status,
                is_complete=is_complete,
                total_events_scanned=total_scanned,
                qualifying_receipts_count=qualifying_receipts_count,
                duplicate_replays_count=duplicate_replays_count,
                conflicting_receipts_count=conflicting_receipts_count,
                reconciliation_events_count=reconciliation_events_count,
                reconciled_jobs_count=reconciled_count,
                unverifiable_receipts_count=unverifiable_receipts_count,
                scan_timestamp=now,
                unresolved_reconciled_jobs_count=unresolved_reconciled_count,
                legacy_verified_receipts_count=legacy_verified_receipts_count
            )

            profiles = self._build_profiles_from_db(
                conn=conn,
                checkpoint=checkpoint,
                freshness_ttl_seconds=freshness_ttl_seconds,
                dependency_evidence_map=dependency_evidence_map,
                now=now,
                current_env=current_env
            )

            return profiles, checkpoint

        except Exception as scan_ex:
            checkpoint = LedgerScanCheckpoint(
                attempted_barrier_id=attempted_barrier_id if 'attempted_barrier_id' in locals() else 0,
                attempted_barrier_hash=attempted_barrier_hash if 'attempted_barrier_hash' in locals() else "UNKNOWN",
                last_verified_event_id=0,
                last_verified_event_hash="UNKNOWN",
                verification_status="UNAVAILABLE",
                is_complete=False,
                total_events_scanned=total_scanned if 'total_scanned' in locals() else 0,
                qualifying_receipts_count=0,
                duplicate_replays_count=0,
                conflicting_receipts_count=0,
                reconciliation_events_count=0,
                reconciled_jobs_count=0,
                unverifiable_receipts_count=unverifiable_receipts_count if 'unverifiable_receipts_count' in locals() else 0,
                scan_timestamp=now,
                unresolved_reconciled_jobs_count=0,
                legacy_verified_receipts_count=legacy_verified_receipts_count if 'legacy_verified_receipts_count' in locals() else 0
            )
            all_caps = {m.name for m in self.registry.list_manifests()}
            profiles = {
                cap_name: self._empty_unavailable_profile(cap_name, f"SCAN_FAILURE: {type(scan_ex).__name__}")
                for cap_name in sorted(all_caps)
            }
            return profiles, checkpoint

        finally:
            if conn:
                try:
                    conn.close()
                except Exception:
                    pass

    def _is_environment_compatible(self, receipt_fp: Optional[str], current_env: str, cap_name: Optional[str] = None) -> bool:
        """
        Evaluates whether a receipt's environment fingerprint is compatible with current execution environment.
        Ensures foreign/mock host fingerprints (e.g. other_host_env_999, WRONG_ENV_FP) are rejected,
        while intra-repo development edits to unrelated files do not invalidate verified active status.
        """
        if not receipt_fp or not isinstance(receipt_fp, str) or not receipt_fp.strip():
            return False
        if receipt_fp == current_env:
            return True
        # Synthetic / mock / non-hex environment strings are strictly rejected
        if len(receipt_fp) != 16 or not all(c in "0123456789abcdefABCDEF" for c in receipt_fp):
            return False

        # Host environment binding: OS, kernel release, Python version, CIPH_ENV
        from ciph.workers.receipts import get_host_fingerprint_prefix
        host_prefix = get_host_fingerprint_prefix()

        # Receipts produced under the same host environment prefix
        if receipt_fp.startswith(host_prefix):
            return True

        # Backwards-compatible allowance for legacy host receipts produced on this host
        if receipt_fp in LEGACY_HOST_FINGERPRINTS:
            return True

        return False

    def _get_manifest(self, cap_name: str) -> Optional[CapabilityManifest]:
        if hasattr(self.registry, "get_manifest"):
            return self.registry.get_manifest(cap_name)
        cap = self.registry.get(cap_name)
        return cap.manifest if cap else None

    def _empty_unavailable_profile(self, cap_name: str, reason: str = "SCAN_VERIFICATION_FAILED") -> EmpiricalCapabilityProfile:
        manifest = self._get_manifest(cap_name)
        is_registered = manifest is not None
        current_ver = manifest.version if manifest else None
        return EmpiricalCapabilityProfile(
            capability_name=cap_name,
            registered_in_manifest=is_registered,
            current_manifest_version=current_ver,
            evidence_state=CapabilityEvidenceState.NONE,
            health_status=CapabilityHealthStatus.UNAVAILABLE,
            current_version_attempts=0,
            current_version_clean_successes=0,
            current_version_defect_failures=0,
            current_version_operational_failures=0,
            current_version_policy_blocked=0,
            current_version_partial=0,
            defect_failure_rate=None,
            operational_failure_rate=None,
            overall_success_rate=None,
            last_qualifying_success_at=None,
            last_attempt_at=None,
            clean_success_latency_p50_ms=None,
            clean_success_latency_p95_ms=None,
            clean_success_latency_avg_ms=None,
            lifetime_total_attempts=0,
            lifetime_reconciled_jobs=0,
            declared_network_policy=manifest.network_policy.value if manifest else None,
            observed_transports=(),
            tested_targets=(),
            recent_evidence_anchors=(),
            conflict_reasons=(reason,)
        )

    def _build_profiles_from_db(
        self,
        conn: sqlite3.Connection,
        checkpoint: LedgerScanCheckpoint,
        freshness_ttl_seconds: float,
        dependency_evidence_map: Optional[Dict[str, DependencyHealthEvidence]],
        now: float,
        current_env: str
    ) -> Dict[str, EmpiricalCapabilityProfile]:
        """Synthesizes empirical capability profiles from surviving temp-table records."""
        all_caps = {m.name for m in self.registry.list_manifests()}
        legacy_caps = set()
        try:
            for r in conn.execute("SELECT DISTINCT capability FROM _scan_records;").fetchall():
                all_caps.add(r[0])
            for r in conn.execute("SELECT DISTINCT capability FROM _scan_conflicts;").fetchall():
                all_caps.add(r[0])
            for r in conn.execute("SELECT DISTINCT capability FROM _scan_legacy_caps;").fetchall():
                all_caps.add(r[0])
                legacy_caps.add(r[0])
        except Exception:
            pass

        dep_map = dependency_evidence_map or {}
        profiles: Dict[str, EmpiricalCapabilityProfile] = {}

        for cap_name in sorted(all_caps):
            manifest = self._get_manifest(cap_name)
            is_registered = manifest is not None
            current_ver = manifest.version if manifest else None

            # Fail closed to UNAVAILABLE if checkpoint failed
            if checkpoint.verification_status != "VERIFIED_COMPLETE" and checkpoint.verification_status != "VERIFIED_EMPTY":
                profiles[cap_name] = self._empty_unavailable_profile(cap_name, "SCAN_VERIFICATION_FAILED")
                continue

            conflicts = tuple(r[0] for r in conn.execute("SELECT reason FROM _scan_conflicts WHERE capability = ? LIMIT ?;", (cap_name, MAX_RETAINED_CONFLICTS)).fetchall())

            # Finalize metrics strictly from non-conflicted surviving records
            cur_attempts = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1;", (cap_name,)).fetchone()[0]
            clean_successes = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1;", (cap_name,)).fetchone()[0]
            defect_failures = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_defect_failure = 1;", (cap_name,)).fetchone()[0]
            operational_failures = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_operational_failure = 1;", (cap_name,)).fetchone()[0]
            policy_blocked = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_policy_blocked = 1;", (cap_name,)).fetchone()[0]
            partial_runs = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_partial = 1;", (cap_name,)).fetchone()[0]
            lifetime_attempts = conn.execute("SELECT COUNT(*) FROM _scan_records WHERE capability = ? AND is_conflicted = 0;", (cap_name,)).fetchone()[0]

            last_clean_success_at = conn.execute("SELECT MAX(completed_at) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1;", (cap_name,)).fetchone()[0]
            last_attempt_at = conn.execute("SELECT MAX(completed_at) FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1;", (cap_name,)).fetchone()[0]
            cap_reconciled = conn.execute("SELECT COUNT(*) FROM _scan_reconciled_jobs WHERE capability = ? AND is_attributed = 1;", (cap_name,)).fetchone()[0]

            # Metric Calculations
            defect_denom = clean_successes + defect_failures
            defect_failure_rate = round(defect_failures / defect_denom, 4) if defect_denom > 0 else None

            op_denom = clean_successes + operational_failures
            operational_failure_rate = round(operational_failures / op_denom, 4) if op_denom > 0 else None

            overall_denom = cur_attempts
            overall_success_rate = round(clean_successes / overall_denom, 4) if overall_denom > 0 else None

            # Disk-backed exact percentiles directly in SQLite without Python memory arrays
            lat_cnt = conn.execute("""
                SELECT COUNT(*) FROM _scan_records
                WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1 AND latency_ms IS NOT NULL AND latency_ms >= 0;
            """, (cap_name,)).fetchone()[0]

            if lat_cnt > 0:
                lat_avg = conn.execute("""
                    SELECT ROUND(AVG(latency_ms), 2) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1 AND latency_ms IS NOT NULL AND latency_ms >= 0;
                """, (cap_name,)).fetchone()[0]
                off_50 = int(0.50 * (lat_cnt - 1))
                lat_p50 = conn.execute("""
                    SELECT ROUND(latency_ms, 2) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1 AND latency_ms IS NOT NULL AND latency_ms >= 0
                    ORDER BY latency_ms ASC LIMIT 1 OFFSET ?;
                """, (cap_name, off_50)).fetchone()[0]
                off_95 = int(0.95 * (lat_cnt - 1))
                lat_p95 = conn.execute("""
                    SELECT ROUND(latency_ms, 2) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0 AND is_current_version = 1 AND is_clean_success = 1 AND latency_ms IS NOT NULL AND latency_ms >= 0
                    ORDER BY latency_ms ASC LIMIT 1 OFFSET ?;
                """, (cap_name, off_95)).fetchone()[0]
            else:
                lat_avg = None
                lat_p50 = None
                lat_p95 = None

            # Determine EvidenceState
            if lifetime_attempts == 0:
                evidence_state = CapabilityEvidenceState.NONE
            elif clean_successes > 0:
                is_fresh = (last_clean_success_at is not None and (now - last_clean_success_at) <= freshness_ttl_seconds)
                evidence_state = CapabilityEvidenceState.CURRENT_VERSION_PROVEN if is_fresh else CapabilityEvidenceState.HISTORICAL_STALE
            elif cur_attempts > 0:
                evidence_state = CapabilityEvidenceState.CURRENT_VERSION_OBSERVED_UNPROVEN
            else:
                cur_m_hash = manifest.compute_manifest_hash() if manifest else None

                unbound_count = conn.execute("""
                    SELECT COUNT(*) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0
                      AND (bound_version IS NULL OR env_fingerprint IS NULL OR env_fingerprint = '' OR has_complete_provenance = 0 OR verified_activation = 0 OR authoritative_worker = 0);
                """, (cap_name,)).fetchone()[0]

                ver_mismatch_count = conn.execute("""
                    SELECT COUNT(*) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0
                      AND (
                          (bound_version IS NOT NULL AND bound_version != ?) OR
                          (manifest_hash IS NOT NULL AND manifest_hash != ?)
                      );
                """, (cap_name, current_ver or "", cur_m_hash or "")).fetchone()[0]

                env_mismatch_count = conn.execute("""
                    SELECT COUNT(*) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0
                      AND bound_version = ? AND (manifest_hash IS NULL OR manifest_hash = ?)
                      AND is_current_version = 0 AND env_fingerprint IS NOT NULL;
                """, (cap_name, current_ver or "", cur_m_hash or "")).fetchone()[0]

                stale_count = conn.execute("""
                    SELECT COUNT(*) FROM _scan_records
                    WHERE capability = ? AND is_conflicted = 0
                      AND bound_version = ? AND (manifest_hash IS NULL OR manifest_hash = ?)
                      AND is_current_version = 1 AND is_clean_success = 1;
                """, (cap_name, current_ver or "", cur_m_hash or "")).fetchone()[0]

                if unbound_count > 0:
                    evidence_state = CapabilityEvidenceState.HISTORICAL_UNBOUND
                elif ver_mismatch_count > 0:
                    evidence_state = CapabilityEvidenceState.HISTORICAL_VERSION_MISMATCH
                elif env_mismatch_count > 0:
                    evidence_state = CapabilityEvidenceState.HISTORICAL_ENVIRONMENT_MISMATCH
                elif stale_count > 0:
                    evidence_state = CapabilityEvidenceState.HISTORICAL_STALE
                else:
                    evidence_state = CapabilityEvidenceState.HISTORICAL_UNBOUND

            # Check Dependency Health Evidence (All 4 conditions + coverage)
            dep_evidence = dep_map.get(cap_name)
            dep_status = DependencyCheckResult.UNKNOWN
            if dep_evidence:
                is_cap_match = (dep_evidence.capability_name == cap_name)
                is_env_match = self._is_environment_compatible(dep_evidence.environment_fingerprint, current_env, cap_name=cap_name)
                is_fresh = dep_evidence.is_fresh(now)
                has_no_missing = (len(dep_evidence.missing_modules) == 0)

                manifest_declared = getattr(manifest, "declared_modules", ()) if manifest else ()
                covers_manifest = set(manifest_declared).issubset(set(dep_evidence.declared_modules)) if manifest_declared else True

                if dep_evidence.status == DependencyCheckResult.FAIL or len(dep_evidence.missing_modules) > 0:
                    dep_status = DependencyCheckResult.FAIL
                elif (dep_evidence.status == DependencyCheckResult.PASS and is_cap_match and is_env_match and is_fresh and has_no_missing and covers_manifest):
                    dep_status = DependencyCheckResult.PASS
                else:
                    dep_status = DependencyCheckResult.UNKNOWN

            # Evaluate HealthStatus (Exhaustive Precedence Table)
            if not is_registered:
                health_status = CapabilityHealthStatus.UNREGISTERED
            elif conflicts:
                health_status = CapabilityHealthStatus.INTEGRITY_CONFLICT
            elif cur_attempts == 0 and evidence_state == CapabilityEvidenceState.NONE:
                if cap_name in legacy_caps:
                    health_status = CapabilityHealthStatus.LEGACY_UNVERIFIED
                else:
                    health_status = CapabilityHealthStatus.UNTESTED
            elif cur_attempts == 0 and evidence_state != CapabilityEvidenceState.NONE:
                health_status = CapabilityHealthStatus.HISTORICAL_ONLY
            elif dep_status == DependencyCheckResult.FAIL:
                health_status = CapabilityHealthStatus.DEPENDENCY_FAILED
            elif dep_status == DependencyCheckResult.UNKNOWN:
                health_status = CapabilityHealthStatus.DEPENDENCY_UNVERIFIED
            elif cur_attempts > 0 and policy_blocked == cur_attempts:
                health_status = CapabilityHealthStatus.POLICY_RESTRICTED_ONLY
            elif cur_attempts > 0 and partial_runs > 0 and clean_successes == 0 and defect_failures == 0 and operational_failures == 0:
                health_status = CapabilityHealthStatus.PARTIAL_ONLY
            elif clean_successes == 0 and (defect_failures > 0 or operational_failures > 0):
                health_status = CapabilityHealthStatus.FAILING
            elif evidence_state == CapabilityEvidenceState.HISTORICAL_STALE and (last_clean_success_at is None or (now - last_clean_success_at) > freshness_ttl_seconds):
                health_status = CapabilityHealthStatus.HISTORICAL_ONLY
            elif (operational_failures > 0 and operational_failure_rate is not None and operational_failure_rate >= 0.20):
                health_status = CapabilityHealthStatus.OPERATIONAL_DEGRADED
            elif (defect_failures > 0 and defect_denom >= 3 and defect_failure_rate is not None and defect_failure_rate >= 0.20):
                health_status = CapabilityHealthStatus.DEGRADED
            elif (defect_failures > 0 and defect_denom < 3 and defect_failure_rate is not None and defect_failure_rate >= 0.20 and clean_successes > 0):
                health_status = CapabilityHealthStatus.INCONCLUSIVE_SAMPLE
            elif (evidence_state == CapabilityEvidenceState.CURRENT_VERSION_PROVEN and
                  (defect_failure_rate is None or defect_failure_rate < 0.20) and
                  (operational_failure_rate is None or operational_failure_rate < 0.20)):
                health_status = CapabilityHealthStatus.VERIFIED_ACTIVE
            else:
                health_status = CapabilityHealthStatus.HISTORICAL_ONLY

            # Recent Anchors (Bounded up to MAX_RETAINED_ANCHORS)
            anchor_rows = conn.execute("""
                SELECT receipt_id, event_id, job_id, attempt_number, completed_at, outcome, exit_code, latency_ms, output_hash, worker_id, env_fingerprint, bound_version, observed_transport, tested_target
                FROM _scan_records WHERE capability = ? AND is_conflicted = 0 ORDER BY completed_at DESC LIMIT ?;
            """, (cap_name, MAX_RETAINED_ANCHORS)).fetchall()

            anchors = [
                ExecutionEvidenceAnchor(
                    receipt_id=ar["receipt_id"],
                    event_id=ar["event_id"],
                    job_id=ar["job_id"],
                    attempt_number=ar["attempt_number"],
                    executed_at=ar["completed_at"],
                    outcome=OutcomeCategory(ar["outcome"]) if ar["outcome"] in [o.value for o in OutcomeCategory] else OutcomeCategory.EXECUTION_ERROR,
                    exit_code=ar["exit_code"],
                    latency_ms=ar["latency_ms"],
                    output_hash=ar["output_hash"],
                    worker_id=ar["worker_id"],
                    environment_fingerprint=ar["env_fingerprint"],
                    bound_manifest_version=ar["bound_version"],
                    observed_transport=ar["observed_transport"] or "UNKNOWN",
                    tested_target=ar["tested_target"]
                ) for ar in anchor_rows
            ]

            observed_transports = tuple(sorted([r[0] for r in conn.execute("SELECT DISTINCT observed_transport FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND observed_transport IS NOT NULL LIMIT 10;", (cap_name,)).fetchall()]))
            tested_targets = tuple(sorted([r[0] for r in conn.execute("SELECT DISTINCT tested_target FROM _scan_records WHERE capability = ? AND is_conflicted = 0 AND tested_target IS NOT NULL LIMIT 25;", (cap_name,)).fetchall()]))

            profiles[cap_name] = EmpiricalCapabilityProfile(
                capability_name=cap_name,
                registered_in_manifest=is_registered,
                current_manifest_version=current_ver,
                evidence_state=evidence_state,
                health_status=health_status,
                current_version_attempts=cur_attempts,
                current_version_clean_successes=clean_successes,
                current_version_defect_failures=defect_failures,
                current_version_operational_failures=operational_failures,
                current_version_policy_blocked=policy_blocked,
                current_version_partial=partial_runs,
                defect_failure_rate=defect_failure_rate,
                operational_failure_rate=operational_failure_rate,
                overall_success_rate=overall_success_rate,
                last_qualifying_success_at=last_clean_success_at,
                last_attempt_at=last_attempt_at,
                clean_success_latency_p50_ms=lat_p50,
                clean_success_latency_p95_ms=lat_p95,
                clean_success_latency_avg_ms=lat_avg,
                lifetime_total_attempts=lifetime_attempts,
                lifetime_reconciled_jobs=cap_reconciled,
                declared_network_policy=manifest.network_policy.value if manifest else None,
                observed_transports=observed_transports,
                tested_targets=tested_targets,
                recent_evidence_anchors=tuple(anchors),
                conflict_reasons=conflicts
            )

        return profiles

    @staticmethod
    def format_capability_card(
        profile: EmpiricalCapabilityProfile,
        manifest_hash: Optional[str] = None
    ) -> str:
        """
        Renders the authoritative Blueprint Section 19 empirical card body line-by-line.
        Does not emit the tagged header; the dialogue/formatter layer prepends the header.
        """
        reg_str = "yes" if profile.registered_in_manifest else "no"

        if profile.health_status == CapabilityHealthStatus.VERIFIED_ACTIVE:
            avail_str = "yes (VERIFIED_ACTIVE)"
        elif profile.health_status == CapabilityHealthStatus.HISTORICAL_ONLY:
            avail_str = "no (HISTORICAL_ONLY - verified evidence expired)"
        elif profile.health_status == CapabilityHealthStatus.UNTESTED:
            avail_str = "no (UNTESTED - declared in manifest; 0 verified executions)"
        elif profile.health_status == CapabilityHealthStatus.LEGACY_UNVERIFIED:
            avail_str = "no (LEGACY_UNVERIFIED - historical receipts unverified under current canonical rules)"
        else:
            avail_str = f"no ({profile.health_status.value})"

        if profile.last_qualifying_success_at:
            last_ver_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(profile.last_qualifying_success_at))
        else:
            last_ver_str = "N/A"

        failures = profile.current_version_defect_failures + profile.current_version_operational_failures
        targets_str = ", ".join(profile.tested_targets) if profile.tested_targets else "None"
        transports_str = ", ".join(profile.observed_transports) if profile.observed_transports else "None"

        env_str = "N/A"
        if profile.recent_evidence_anchors:
            for a in profile.recent_evidence_anchors:
                if a.environment_fingerprint:
                    env_str = a.environment_fingerprint
                    break

        if profile.recent_evidence_anchors:
            rcpt_ids = [a.receipt_id for a in profile.recent_evidence_anchors[:5]]
            receipts_str = f"[{', '.join(rcpt_ids)}]"
        else:
            receipts_str = "[]"

        lines = [
            f"Capability: {profile.capability_name}",
            f"Registered: {reg_str}",
            f"Available now: {avail_str}",
            f"Provider version: {profile.current_manifest_version or 'N/A'}",
            f"Manifest hash: {manifest_hash or 'N/A'}",
            f"Last verified: {last_ver_str}",
            f"Recent attempts: {profile.current_version_attempts}",
            f"Successful: {profile.current_version_clean_successes}",
            f"Partial: {profile.current_version_partial}",
            f"Execution failures: {failures}",
            f"Policy-blocked: {profile.current_version_policy_blocked}",
            f"Tested targets: {targets_str}",
            f"Verified transport: {transports_str}",
            f"Environment: {env_str}",
            f"Evidence receipts: {receipts_str}",
        ]
        return "\n".join(lines)

    def generate_self_knowledge_report(
        self,
        freshness_ttl_seconds: float = 14 * 86400.0,
        dependency_evidence_map: Optional[Dict[str, DependencyHealthEvidence]] = None,
        current_time: Optional[float] = None
    ) -> Dict[str, Any]:
        """Generate structured empirical self-knowledge summary."""
        profiles, checkpoint = self.compile_empirical_ledger(
            freshness_ttl_seconds=freshness_ttl_seconds,
            dependency_evidence_map=dependency_evidence_map,
            current_time=current_time
        )
        verified_active, untested, warning = [], [], []
        warning_status: Dict[str, str] = {}
        for p in profiles.values():
            status_value = str(getattr(p.health_status, "value", p.health_status))
            name = p.capability_name
            if status_value == "VERIFIED_ACTIVE":
                verified_active.append(name)
            elif status_value == "UNTESTED":
                untested.append(name)
            else:
                # Never silently drop a capability: anything not verified or untested is surfaced.
                warning.append(name)
                warning_status[name] = status_value

        historical_only = [n for n in warning if warning_status.get(n) == "HISTORICAL_ONLY"]
        degraded = [n for n in warning if warning_status.get(n) in ("DEGRADED", "OPERATIONAL_DEGRADED", "FAILING")]
        conflicted = [n for n in warning if warning_status.get(n) == "INTEGRITY_CONFLICT"]

        manifest_hashes = {}
        for name in profiles.keys():
            try:
                m = self._get_manifest(name)
                if m is not None and hasattr(m, "compute_manifest_hash"):
                    manifest_hashes[name] = m.compute_manifest_hash()
            except (AttributeError, TypeError, ValueError):
                continue

        return {
            "checkpoint": {
                "verification_status": checkpoint.verification_status,
                "is_complete": checkpoint.is_complete,
                "total_events_scanned": checkpoint.total_events_scanned,
                "duplicate_replays_count": checkpoint.duplicate_replays_count,
                "conflicting_receipts_count": checkpoint.conflicting_receipts_count,
                "reconciled_jobs_count": checkpoint.reconciled_jobs_count,
                "unverifiable_receipts_count": checkpoint.unverifiable_receipts_count,
                "legacy_verified_receipts_count": checkpoint.legacy_verified_receipts_count,
                "scan_timestamp": checkpoint.scan_timestamp,
            },
            "summary": {
                "total_capabilities_tracked": len(profiles),
                "verified_active_count": len(verified_active),
                "untested_count": len(untested),
                "warning_count": len(warning),
                "historical_only_count": len(historical_only),
                "degraded_count": len(degraded),
                "conflicted_count": len(conflicted),
                "verified_active_capabilities": sorted(verified_active),
                "untested_capabilities": sorted(untested),
                "warning_capabilities": sorted(warning),
                "warning_status_by_name": warning_status,
                "historical_only_capabilities": sorted(historical_only),
                "degraded_capabilities": sorted(degraded),
                "conflicted_capabilities": sorted(conflicted),
            },
            "empirically_verified_capabilities": sorted(verified_active),
            "profiles": profiles,
            "manifest_hashes": manifest_hashes
        }


# =====================================================================
# 6. MAINTENANCE LEASE MANAGER (RETIRED & REWIRED TO SHARED EXCLUSION)
# =====================================================================

from ciph.maintenance.exclusion import SharedExclusionCoordinator, MaintenanceInProgressError

class MaintenanceLeaseManager(SharedExclusionCoordinator):
    """
    Compatibility wrapper around SharedExclusionCoordinator.
    The unauthenticated acquire_lease and TRUNCATE-based run_idle_maintenance_cycle
    methods have been permanently retired.
    """
    pass
