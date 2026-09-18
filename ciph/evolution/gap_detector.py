"""
ciph.evolution.gap_detector - Automated Engineering Gap Detection & Failure Classification (Phase 8).
Distinguishes operational failures (external network, timeouts, auth, resources, sandbox) from
genuine engineering defects (unhandled exceptions, logic errors, missing telemetry/behavior).
Requires >= 2 distinct execution receipts demonstrating reproducible conditions.
"""

import os
import json
import time
import uuid
import sqlite3
import hashlib
from enum import Enum
from typing import Dict, Any, List, Optional, Tuple, Sequence

from ciph.contracts.enums import OutcomeCategory, RiskTier
from ciph.contracts.evolution import (
    EngineeringGapCandidate,
    GapCategory,
    EvolutionEvaluationGrant,
)
from ciph.contracts.base import ContractValidationError
from ciph.workers.receipts import ExecutionReceipt
from ciph.kernel.crypto_identity import TrustRegistry, KeyRole, KeyStatus


class FailureClassification(str, Enum):
    OPERATIONAL = "OPERATIONAL"
    ENGINEERING_DEFECT = "ENGINEERING_DEFECT"
    TELEMETRY_GAP = "TELEMETRY_GAP"
    BEHAVIOR_GAP = "BEHAVIOR_GAP"
    UNKNOWN = "UNKNOWN"


class EngineeringGapDetector:
    """
    Automated Engineering Gap Detector for CIPH self-evolution.
    Ingests execution receipts and telemetry anomalies, classifies failures,
    and formulates validated EngineeringGapCandidate contracts.
    """

    OPERATIONAL_OUTCOMES = {
        OutcomeCategory.TARGET_UNREACHABLE,
        OutcomeCategory.AUTH_REQUIRED,
        OutcomeCategory.RESOURCE_EXHAUSTED,
        OutcomeCategory.POLICY_BLOCKED,
        OutcomeCategory.SANDBOX_VIOLATION,
        OutcomeCategory.CANCELLED,
    }

    OPERATIONAL_ERROR_KEYWORDS = (
        "sandbox_unavailable",
        "connectionrefused",
        "timeout",
        "network unreachable",
        "rate limit",
        "credentials missing",
        "tor_offline",
        "circuit failed",
        "budget exhausted",
        "host unreachable",
        "permission denied",
        "storage full",
        "disk full",
    )

    def __init__(self, db_path: Optional[str] = None, required_failure_count: int = 2, trust_registry=None):
        self.db_path = db_path or ":memory:"
        self.required_failure_count = max(2, required_failure_count)
        self.trust_registry = trust_registry or TrustRegistry(self.db_path)
        from ciph.evolution.evidence import EvolutionEvidenceStore
        self.evidence = EvolutionEvidenceStore(self.trust_registry)
        self._init_db()
        # In-memory failure buffer: key -> list of ExecutionReceipt
        self._failure_buffer: Dict[str, List[ExecutionReceipt]] = {}

    def _get_connection(self, calling_holder_id: Optional[str] = None) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        from ciph.maintenance.exclusion import ExcludedConnection
        return ExcludedConnection(conn, calling_holder_id=calling_holder_id, db_path=self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_engineering_gaps (
                    gap_id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    target_capability TEXT NOT NULL,
                    affected_revision TEXT NOT NULL,
                    reproducible_conditions TEXT NOT NULL,
                    failure_evidence_hashes TEXT NOT NULL,
                    measured_impact TEXT NOT NULL,
                    testable_improvement_criterion TEXT NOT NULL,
                    risk_tier TEXT NOT NULL,
                    proposed_owner TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    evaluation_grant_id TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_operational_incidents (
                    incident_id TEXT PRIMARY KEY,
                    receipt_id TEXT NOT NULL,
                    capability TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
            """)
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_gap_failure_inputs (receipt_id TEXT PRIMARY KEY, signature TEXT, payload TEXT)')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_gap_evidence (gap_id TEXT PRIMARY KEY, evidence_hash TEXT)')
            conn.commit()

    def classify_failure(self, receipt: ExecutionReceipt) -> Tuple[FailureClassification, str, Dict[str, Any]]:
        """
        Classifies an execution receipt's failure into operational issue vs genuine software defect.
        Returns (classification, reason_summary, detail_dict).
        """
        outcome = receipt.outcome
        err_msg = (receipt.error_message or "").lower()
        err_class = (receipt.error_class or "").lower()

        # 1. Operational outcome checks
        if outcome in self.OPERATIONAL_OUTCOMES or outcome == OutcomeCategory.DEPENDENCY_FAILURE:
            return (
                FailureClassification.OPERATIONAL,
                f"Operational outcome {outcome.value}: external or environmental block",
                {"outcome": outcome.value, "error_message": receipt.error_message}
            )

        # 2. Operational keywords in error message or error class
        for kw in self.OPERATIONAL_ERROR_KEYWORDS:
            if kw in err_msg or kw in err_class:
                return (
                    FailureClassification.OPERATIONAL,
                    f"Operational error pattern detected ('{kw}')",
                    {"error_class": receipt.error_class, "error_message": receipt.error_message}
                )

        # 3. Clean runs (exit_code == 0) with empty results or missing telemetry
        if receipt.exit_code == 0 and outcome == OutcomeCategory.SUCCESS:
            if not receipt.results or (isinstance(receipt.results, dict) and len(receipt.results) == 0):
                return (
                    FailureClassification.TELEMETRY_GAP,
                    "Execution succeeded but produced zero telemetry results",
                    {"results": receipt.results}
                )
            return (FailureClassification.UNKNOWN, "Clean successful execution", {})

        # 4. Genuine software/logic defects: EXECUTION_ERROR or non-zero exit_code without operational cause
        if outcome in (OutcomeCategory.EXECUTION_ERROR, OutcomeCategory.DEPENDENCY_FAILURE) or receipt.exit_code != 0:
            return (
                FailureClassification.ENGINEERING_DEFECT,
                f"Repeatable code defect: {receipt.error_class or 'ExecutionError'} ({receipt.error_message or 'non-zero exit code'})",
                {
                    "error_class": receipt.error_class,
                    "error_message": receipt.error_message,
                    "exit_code": receipt.exit_code,
                    "backtrace": receipt.backtrace
                }
            )

        return (FailureClassification.UNKNOWN, f"Unclassified outcome {outcome}", {})

    def ingest_receipt(
        self,
        receipt: ExecutionReceipt,
        affected_revision: str = "rev_unknown",
        risk_tier: RiskTier = RiskTier.LOW
    ) -> Optional[EngineeringGapCandidate]:
        """
        Ingests an execution receipt.
        If the receipt represents an operational failure, logs it as an incident and returns None.
        If it represents a code defect, records in the failure buffer.
        When >= required_failure_count distinct receipts accumulate under the same signature,
        formulates and returns an EngineeringGapCandidate.
        """
        self.evidence.authenticate_execution(receipt)
        actual_revision = receipt.provenance.get('source_revision') or receipt.environment_fingerprint
        if affected_revision == 'rev_unknown':
            affected_revision = actual_revision
        if not actual_revision or affected_revision != actual_revision:
            raise ContractValidationError('AFFECTED_REVISION_NOT_BOUND_TO_RECEIPT')
        classification, reason, details = self.classify_failure(receipt)

        if classification != FailureClassification.ENGINEERING_DEFECT:
            self.evidence.record('NO_RELEVANCE_FOUND',{'receipt_id':receipt.receipt_id,'reason':reason})

        if classification == FailureClassification.OPERATIONAL:
            # Record operational incident without creating a code defect gap
            self._record_operational_incident(receipt, reason, details)
            return None

        if classification != FailureClassification.ENGINEERING_DEFECT:
            return None

        # Build reproducible signature
        sig = hashlib.sha256(json.dumps([receipt.capability, receipt.error_class, receipt.input_hash,
            receipt.environment_fingerprint, affected_revision, receipt.target],sort_keys=True).encode()).hexdigest()
        with self._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            found=conn.execute('SELECT 1 FROM ciph_gap_failure_inputs WHERE receipt_id=?',(receipt.receipt_id,)).fetchone()
            if found:return None
            conn.execute('INSERT INTO ciph_gap_failure_inputs VALUES (?,?,?)',(receipt.receipt_id,sig,json.dumps(receipt.to_dict())))
            rows=conn.execute('SELECT payload FROM ciph_gap_failure_inputs WHERE signature=? ORDER BY receipt_id LIMIT 100',(sig,)).fetchall()
        existing=[ExecutionReceipt.from_dict(json.loads(row[0])) for row in rows]
        for previous in existing:
            self.evidence.authenticate_execution(previous)
            previous_revision=previous.provenance.get('source_revision') or previous.environment_fingerprint
            previous_sig=hashlib.sha256(json.dumps([previous.capability,previous.error_class,previous.input_hash,
                previous.environment_fingerprint,previous_revision,previous.target],sort_keys=True).encode()).hexdigest()
            if previous_sig!=sig or self.classify_failure(previous)[0]!=FailureClassification.ENGINEERING_DEFECT:
                raise ContractValidationError('FAILURE_GROUP_TAMPERED')
        # Check threshold
        if len(existing) >= self.required_failure_count:
            # Extract distinct failure evidence hashes
            ev_hashes = []
            for r in existing:
                # Compute canonical receipt payload hash
                h = hashlib.sha256(r.compute_signature_payload().encode("utf-8")).hexdigest()
                if h not in ev_hashes:
                    ev_hashes.append(h)

            if len(ev_hashes) < self.required_failure_count:
                # Need distinct evidence hashes
                return None

            gap_id = 'GAP-'+sig
            if self.get_gap(gap_id):return None
            candidate = EngineeringGapCandidate(
                gap_id=gap_id,
                category=GapCategory.DEFECT,
                target_capability=receipt.capability,
                affected_revision=affected_revision,
                reproducible_conditions={
                    "error_class": receipt.error_class or "UnknownError",
                    "input_hash": receipt.input_hash,
                    "environment_fingerprint": receipt.environment_fingerprint,
                    "required_failures_observed": len(existing)
                },
                failure_evidence_hashes=ev_hashes,
                measured_impact={
                    "total_failures": len(existing),
                    "first_failure_time": existing[0].started_at,
                    "last_failure_time": existing[-1].completed_at,
                    "sample_error_message": receipt.error_message or ""
                },
                testable_improvement_criterion=f"Capability '{receipt.capability}' completes with exit_code=0 without raising {receipt.error_class or 'exception'}",
                risk_tier=risk_tier,
                proposed_owner="ciph.evolution"
            )

            # Persist to SQLite
            self._persist_gap(candidate)
            # Clear buffer for this signature to prevent duplicate gap creation
            self._failure_buffer[sig] = []
            return candidate

        return None

    def detect_missing_telemetry_gap(
        self,
        capability: str,
        receipts: Sequence[ExecutionReceipt],
        missing_fields: Sequence[str],
        affected_revision: str = "rev_unknown",
        risk_tier: RiskTier = RiskTier.LOW
    ) -> Optional[EngineeringGapCandidate]:
        """Formulates an EngineeringGapCandidate for missing telemetry from >= 2 distinct receipts."""
        if not missing_fields or len(receipts) < self.required_failure_count:
            return None
        if len(receipts) > 100:raise ContractValidationError('TELEMETRY_WORK_BUDGET_EXCEEDED')
        for receipt in receipts:self.evidence.authenticate_execution(receipt)
        first=receipts[0]
        revision=first.provenance.get('source_revision') or first.environment_fingerprint
        if affected_revision == 'rev_unknown':affected_revision=revision
        if not revision or affected_revision != revision:
            raise ContractValidationError('AFFECTED_REVISION_NOT_BOUND_TO_RECEIPT')
        for receipt in receipts:
            if (receipt.capability != capability or receipt.exit_code != 0 or receipt.outcome != OutcomeCategory.SUCCESS
                    or receipt.environment_fingerprint != first.environment_fingerprint
                    or receipt.input_hash != first.input_hash
                    or (receipt.provenance.get('source_revision') or receipt.environment_fingerprint) != revision
                    or not isinstance(receipt.results,dict)
                    or any(field in receipt.results for field in missing_fields)):
                raise ContractValidationError('UNPROVEN_TELEMETRY_GAP')

        ev_hashes = []
        for r in receipts:
            h = hashlib.sha256(r.compute_signature_payload().encode("utf-8")).hexdigest()
            if h not in ev_hashes:
                ev_hashes.append(h)

        if len(ev_hashes) < self.required_failure_count:
            return None

        gap_id = 'GAP-TEL-'+hashlib.sha256(json.dumps([capability,revision,sorted(missing_fields),sorted(ev_hashes)],sort_keys=True).encode()).hexdigest()
        if self.get_gap(gap_id):return None
        candidate = EngineeringGapCandidate(
            gap_id=gap_id,
            category=GapCategory.MISSING_TELEMETRY,
            target_capability=capability,
            affected_revision=affected_revision,
            reproducible_conditions={
                "missing_telemetry_fields": list(missing_fields),
                "inspected_receipt_count": len(receipts)
            },
            failure_evidence_hashes=ev_hashes,
            measured_impact={
                "receipts_evaluated": len(receipts),
                "telemetry_deficit": list(missing_fields)
            },
            testable_improvement_criterion=f"Capability '{capability}' results contain all expected keys: {', '.join(missing_fields)}",
            risk_tier=risk_tier,
            proposed_owner="ciph.evolution"
        )
        self._persist_gap(candidate)
        return candidate

    def detect_behavior_gap(self, capability, receipts, expected, source_question_ids=()):
        """Repeated successful executions violating an explicit independent oracle."""
        from ciph.contracts.base import canonical_json
        if not isinstance(expected,dict) or not expected or not self.required_failure_count<=len(receipts)<=100:
            raise ContractValidationError('BOUNDED_BEHAVIOR_ORACLE_REQUIRED')
        for receipt in receipts:self.evidence.authenticate_execution(receipt)
        first=receipts[0]
        revision=first.provenance.get('source_revision') or first.environment_fingerprint
        hashes=[]
        for receipt in receipts:
            if (receipt.capability!=capability or receipt.exit_code!=0 or receipt.outcome!=OutcomeCategory.SUCCESS
                    or receipt.input_hash!=first.input_hash or receipt.environment_fingerprint!=first.environment_fingerprint
                    or (receipt.provenance.get('source_revision') or receipt.environment_fingerprint)!=revision
                    or all(k in receipt.results and canonical_json(receipt.results[k])==canonical_json(value) for k,value in expected.items())):
                raise ContractValidationError('UNPROVEN_BEHAVIOR_GAP')
            hashes.append(hashlib.sha256(receipt.compute_signature_payload().encode()).hexdigest())
        if len(set(hashes))<self.required_failure_count:raise ContractValidationError('DISTINCT_BEHAVIOR_EVIDENCE_REQUIRED')
        # Question provenance must come from the signed receipt, never caller labels.
        linked=set(q for receipt in receipts for q in receipt.provenance.get('source_question_ids',()))
        if set(source_question_ids)-linked:raise ContractValidationError('UNBOUND_SOURCE_QUESTIONS')
        gap_id='GAP-BEH-'+hashlib.sha256(canonical_json([capability,revision,expected,sorted(hashes)]).encode()).hexdigest()
        existing=self.get_gap(gap_id)
        if existing:return existing
        gap=EngineeringGapCandidate(gap_id,GapCategory.MISSING_BEHAVIOR,capability,revision,
            {'input_hash':first.input_hash,'environment_fingerprint':first.environment_fingerprint,'expected':expected},
            hashes,{'violations':len(receipts),'reproduction_rate':1.0},'Results satisfy '+canonical_json(expected),
            RiskTier.LOW,'ciph.evolution',source_question_ids=source_question_ids)
        self._persist_gap(gap)
        return gap

    def _record_operational_incident(self, receipt: ExecutionReceipt, reason: str, details: Dict[str, Any]):
        incident_id = f"INC-{uuid.uuid4().hex[:8]}"
        with self._get_connection() as conn:
            conn.execute("""
                INSERT INTO ciph_operational_incidents (
                    incident_id, receipt_id, capability, reason, details, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                receipt.receipt_id,
                receipt.capability,
                reason,
                json.dumps(details),
                time.time()
            ))
            conn.commit()

    def _persist_gap(self, candidate: EngineeringGapCandidate):
        identity=self.evidence.record('ENGINEERING_GAP',candidate.to_dict())
        with self._get_connection() as conn:
            conn.execute('INSERT OR REPLACE INTO ciph_gap_evidence VALUES (?,?)',(candidate.gap_id,identity))
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO ciph_engineering_gaps (
                    gap_id, category, target_capability, affected_revision,
                    reproducible_conditions, failure_evidence_hashes,
                    measured_impact, testable_improvement_criterion,
                    risk_tier, proposed_owner, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'DETECTED', ?)
            """, (
                candidate.gap_id,
                candidate.category.value,
                candidate.target_capability,
                candidate.affected_revision,
                json.dumps(candidate.reproducible_conditions.to_dict()),
                json.dumps(list(candidate.failure_evidence_hashes)),
                json.dumps(candidate.measured_impact.to_dict()),
                candidate.testable_improvement_criterion,
                candidate.risk_tier.value,
                candidate.proposed_owner,
                candidate.created_at
            ))
            conn.commit()

    def get_gap(self, gap_id: str) -> Optional[EngineeringGapCandidate]:
        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM ciph_engineering_gaps WHERE gap_id = ?", (gap_id,)).fetchone()
            if not row:
                return None
            reference=conn.execute('SELECT evidence_hash FROM ciph_gap_evidence WHERE gap_id=?',(gap_id,)).fetchone()
            if not reference:raise ContractValidationError('UNVERIFIED_LEGACY_GAP')
            verified=self.evidence.verify(reference[0],'ENGINEERING_GAP')
            if verified['gap_id'] != gap_id:raise ContractValidationError('GAP_ID_MISMATCH')
            return EngineeringGapCandidate.from_dict(verified)
    def list_gaps(self, status: Optional[str] = None) -> List[EngineeringGapCandidate]:
        with self._get_connection() as conn:
            if status:
                cursor = conn.execute("SELECT * FROM ciph_engineering_gaps WHERE status = ? ORDER BY created_at DESC", (status,))
            else:
                cursor = conn.execute("SELECT * FROM ciph_engineering_gaps ORDER BY created_at DESC")
            return [self.get_gap(row['gap_id']) for row in cursor.fetchall()]

    def bind_evaluation_grant(
        self,
        gap_id: str,
        grant: EvolutionEvaluationGrant,
        trust_registry: TrustRegistry
    ) -> Tuple[bool, str]:
        """
        Cryptographically validates and binds an operator's EvolutionEvaluationGrant to a detected gap.
        Updates gap status to EVALUATION_GRANTED.
        """
        valid, err = grant.verify_signature(trust_registry)
        if not valid:
            return False, f"Invalid operator signature on EvolutionEvaluationGrant: {err}"

        if grant.gap_id != gap_id:
            return False, f"Grant gap_id '{grant.gap_id}' does not match target gap '{gap_id}'"

        gap = self.get_gap(gap_id)
        if not gap:
            return False, f"Gap '{gap_id}' not found in registry"

        if grant.target_capability != gap.target_capability:
            return False, 'GAP_CAPABILITY_MISMATCH'
        with self._get_connection() as conn:
            conn.execute("""
                UPDATE ciph_engineering_gaps
                SET status = 'EVALUATION_GRANTED', evaluation_grant_id = ?
                WHERE gap_id = ?
            """, (grant.grant_id, gap_id))
            conn.commit()

        return True, f"EvolutionEvaluationGrant '{grant.grant_id}' bound to gap '{gap_id}'"
