"""Signed, durable evolution evidence. Candidate output never signs these events."""
import hashlib
import json
import math
import time
from ciph.contracts.base import canonical_json, ContractValidationError
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.memory.event_store import EventStore
from ciph.workers.receipts import ExecutionReceipt


def digest(data):
    return hashlib.sha256(canonical_json(data).encode()).hexdigest()


class EvolutionEvidenceStore:
    def __init__(self, trust_registry):
        if trust_registry is None or not trust_registry.pinned_operator_pub_hex:
            raise ContractValidationError("PINNED_TRUST_REGISTRY_REQUIRED")
        self.trust = trust_registry
        self.events = EventStore(trust_registry.db_path)

    def record(self, kind, data):
        body = {"kind": kind, "data": data, "timestamp": time.time()}
        # Dedicated trusted supervisor authority. Never use the operator's consent key.
        key_id = "worker_primary"
        pair = self.trust.get_keypair(key_id)
        key = self.trust.get_key(key_id)
        if not pair or not key or key['role'] != 'WORKER' or key['status'] != 'ACTIVE':
            raise ContractValidationError("EVOLUTION_VERIFIER_KEY_UNAVAILABLE")
        body["signer_id"] = key_id
        identity = digest(body)
        body["signature"] = Ed25519KeyManager.sign(pair[0], canonical_json(body).encode())
        self.events.append_event("EvolutionEvidenceEvent", identity, body)
        return identity

    def verify(self, identity, kind):
        rows = self.events.get_events(aggregate_id=identity, event_type="EvolutionEvidenceEvent", limit=2)
        if len(rows) != 1 or not self.events.verify_integrity()[0]:
            raise ContractValidationError("UNVERIFIABLE_EVOLUTION_EVIDENCE")
        body = dict(rows[0]["payload"])
        signature = body.pop("signature", "")
        if digest(body) != identity or body.get("kind") != kind:
            raise ContractValidationError("EVOLUTION_EVIDENCE_BINDING_MISMATCH")
        key = self.trust.get_key(body.get("signer_id"))
        if not key or key['role'] != 'WORKER':
            raise ContractValidationError("INVALID_EVOLUTION_VERIFIER")
        valid, _ = self.trust.verify_signature_at_time(body['signer_id'], canonical_json(body).encode(), signature, body['timestamp'])
        if not valid:
            raise ContractValidationError("INVALID_EVOLUTION_SIGNATURE")
        return body['data']

    def validate_deployment(self, grant):
        valid, reason = grant.verify_signature(self.trust)
        if not valid:
            raise ContractValidationError(reason)
        for identity in grant.verification_evidence_hashes:
            data = self.verify(identity, "BENCHMARK_VERIFIED")
            from ciph.evolution.workflow import validate_chain
            validate_chain(self,data)
            proposal=self.verify(data['operator_review_id'],'EVOLUTION_OPERATOR_PROPOSAL')
            if proposal != {k:v for k,v in data.items() if k!='operator_review_id'}:
                raise ContractValidationError('OPERATOR_REVIEW_MISMATCH')
            from ciph.contracts.base import _unfreeze
            if (list(grant.dependency_changes)!=data['change_review']['dependency_changes']
                    or _unfreeze(grant.manifest_changes)!=data['change_review']['manifest_changes']):
                raise ContractValidationError('UNAPPROVED_DEPENDENCY_OR_MANIFEST_MIGRATION')
            if (data.get('candidate_hash') != grant.candidate_hash
                    or data.get('base_file_hash') != grant.base_file_hash
                    or data.get('target_capability') != grant.target_capability
                    or data.get('gap_id') != grant.gap_id or data.get('passed') is not True
                    or data.get('tests_run', 0) < 1):
                raise ContractValidationError("DEPLOYMENT_EVIDENCE_MISMATCH")
        return True

    def authenticate_execution(self, receipt):
        if not isinstance(receipt, ExecutionReceipt) or not receipt.verify_signature(trust_registry=self.trust):
            raise ContractValidationError("UNAUTHENTICATED_EXECUTION_RECEIPT")
        if (not all(math.isfinite(v) for v in (receipt.started_at, receipt.completed_at))
                or not 0 <= receipt.started_at <= receipt.completed_at <= time.time()+5):
            raise ContractValidationError("INVALID_RECEIPT_TIME")
        events = self.events.get_events(aggregate_id=receipt.receipt_id, event_type='ExecutionReceiptStoredEvent', limit=2)
        if len(events)!=1 or events[0]['payload'] != receipt.to_dict() or not self.events.verify_integrity()[0]:
            raise ContractValidationError("COMMITTED_EXECUTION_RECEIPT_REQUIRED")
        with self.events._get_connection() as conn:
            row = conn.execute('SELECT * FROM ciph_ipc_jobs WHERE job_id=?', (receipt.job_id,)).fetchone()
        if (not row or row['receipt_id'] != receipt.receipt_id
                or row['capability'] != receipt.capability
                or row['attempt_number'] != receipt.attempt_number
                or row['worker_signature'] != receipt.worker_signature
                or ExecutionReceipt.hash_payload(json.loads(row['params'])) != receipt.input_hash):
            raise ContractValidationError("EXECUTION_JOB_BINDING_MISMATCH")
        return receipt
