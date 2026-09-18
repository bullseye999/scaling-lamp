"""Signed activation evidence shared by queue ingress and snapshot ledger scans."""
import json
import math
import sqlite3
from ciph.contracts.base import canonical_json
from ciph.kernel.crypto_identity import ExecutionToken, retry_nonce
from ciph.workers.receipts import ExecutionReceipt


def activation_message(payload):
    """Domain-separated statement; adding/removing any payload field changes it."""
    statement = {k: v for k, v in payload.items() if k != 'activation_signature'}
    return canonical_json({'domain': 'ciph.execution_activation.v1', 'payload': statement}).encode('utf-8')


def _finite(value):
    return type(value) in (int, float) and math.isfinite(value)


class SnapshotActivationVerifier:
    """Verify only against the caller's read transaction and frozen public keys.

    Mutable job/consumption rows are consistency checks, never signing authority.
    A signed activation plus the consumed nonce and original retry authorization
    are required. Legacy unsigned attempt events remain historical evidence.
    """
    def __init__(self, conn, verify_signature):
        self.conn = conn
        self.verify_signature = verify_signature
        self.tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.execute('''CREATE TEMP TABLE _scan_activations (
            job_id TEXT NOT NULL, attempt_number INTEGER NOT NULL,
            capability TEXT NOT NULL, worker_id TEXT NOT NULL,
            token_id TEXT NOT NULL, token_hash TEXT NOT NULL,
            parameters_hash TEXT NOT NULL, idempotency_key TEXT,
            activated_at REAL NOT NULL, statement_hash TEXT NOT NULL,
            PRIMARY KEY (job_id, attempt_number), UNIQUE(token_id)
        )''')

    def record(self, payload, aggregate_id, event_time):
        """Return (valid, reason); propagate real database failures to the scanner."""
        if not {'ciph_ipc_jobs', 'ciph_consumed_tokens', 'ciph_retry_tokens'} <= self.tables:
            return False, 'ACTIVATION_STORAGE_MISSING'
        if not payload.get('activation_signature'):
            return False, 'UNSIGNED_ACTIVATION'
        try:
            token = ExecutionToken.from_dict(payload['token'])
            job_id, number = payload['job_id'], payload['attempt_number']
            worker, at = payload['worker_id'], payload['started_at']
            if (not isinstance(job_id, str) or not job_id or
                type(number) is not int or not 1 <= number <= token.max_attempts or
                not isinstance(worker, str) or not worker or not _finite(at) or
                not _finite(event_time) or abs(at - event_time) > 1e-6 or
                aggregate_id != f'attempt:{job_id}:{number}'):
                return False, 'ACTIVATION_CONTEXT_MISMATCH'
            if not all(_finite(x) for x in (token.issued_at, token.expires_at, payload['lease_expires_at'])):
                return False, 'ACTIVATION_INVALID_TIME'
            if not token.issued_at <= at <= token.expires_at or not at < payload['lease_expires_at']:
                return False, 'ACTIVATION_EXPIRED'
            if payload['activation_key_id'] != token.kernel_key_id:
                return False, 'ACTIVATION_SIGNER_MISMATCH'
            pairs = {
                'capability': token.capability, 'token_id': token.token_id,
                'token_hash': token.token_hash(), 'manifest_version': token.manifest_version,
                'manifest_hash': token.manifest_hash, 'parameters_hash': token.parameters_hash,
                'plan_hash': token.plan_hash, 'step_id': token.step_id,
            }
            if any(payload.get(k) != v for k, v in pairs.items()):
                return False, 'ACTIVATION_TOKEN_BINDING_MISMATCH'
            for message, sig, at_time in (
                (token.compute_canonical_payload(), token.signature, at),
                (activation_message(payload), payload['activation_signature'], at),
            ):
                if not self.verify_signature(token.kernel_key_id, 'KERNEL', message, sig, at_time)[0]:
                    return False, 'INVALID_ACTIVATION_SIGNATURE'
            job = self.conn.execute('SELECT * FROM ciph_ipc_jobs WHERE job_id=?', (job_id,)).fetchone()
            consumed = self.conn.execute('SELECT * FROM ciph_consumed_tokens WHERE token_id=? AND nonce=?',
                                         (token.token_id, token.nonce)).fetchone()
            if (not job or not consumed or consumed['job_id'] != job_id or
                consumed['worker_id'] != worker or not _finite(consumed['consumed_at']) or
                abs(consumed['consumed_at'] - at) > 1e-6):
                return False, 'ACTIVATION_CONSUMPTION_MISSING_OR_MISMATCHED'
            if (job['capability'] != token.capability or job['step_id'] != token.step_id or
                job['idempotency_key'] != payload['idempotency_key'] or
                job['plan_id'] != payload['plan_id'] or job['attempt_number'] < number or
                job['max_retries'] < number or job['created_at'] > at or
                ExecutionReceipt.hash_payload(json.loads(job['params'])) != token.parameters_hash):
                return False, 'ACTIVATION_JOB_MISMATCH'

            # A retry token must be bound to the authenticated parent's executed
            # failure, this job, and the attempt for which renewal was authorized.
            lineage = self.conn.execute('SELECT * FROM ciph_retry_tokens WHERE token_id=?',
                                        (token.token_id,)).fetchone()
            if lineage:
                parent = ExecutionToken.from_dict(json.loads(lineage['parent_token']))
                renewal_attempt = lineage['attempt_number']
                if (lineage['job_id'] != job_id or type(renewal_attempt) is not int or
                    not 1 < renewal_attempt <= number or lineage['parent_token_id'] != parent.token_id or
                    json.loads(lineage['token']) != token.to_dict() or
                    token.nonce != retry_nonce(parent, job_id, renewal_attempt)):
                    return False, 'INVALID_RETRY_LINEAGE'
                parent_fields = parent.to_dict(); child_fields = token.to_dict()
                for name in ('token_id', 'nonce', 'signature'):
                    parent_fields.pop(name); child_fields.pop(name)
                if parent_fields != child_fields:
                    return False, 'RETRY_AUTHORITY_CHANGED'
                if not self.verify_signature(parent.kernel_key_id, 'KERNEL',
                        parent.compute_canonical_payload(), parent.signature, at)[0]:
                    return False, 'INVALID_RETRY_PARENT_SIGNATURE'
                previous = self.conn.execute('''SELECT 1 FROM _scan_records r
                    JOIN _scan_activations a ON a.job_id=r.job_id AND a.attempt_number=r.attempt_number
                    WHERE r.job_id=? AND a.token_hash=? AND r.token_hash=?
                      AND r.attempt_number < ? AND r.exit_code != 0
                      AND r.authoritative_worker=1 AND r.verified_activation=1
                      AND r.is_conflicted=0 AND r.completed_at <= ? LIMIT 1''',
                    (job_id, parent.token_hash(), parent.token_hash(), renewal_attempt, at)).fetchone()
                if not previous:
                    return False, 'RETRY_PARENT_EXECUTION_MISSING'
            elif token.token_id.startswith('tok_retry_'):
                return False, 'RETRY_LINEAGE_MISSING'

            import hashlib
            statement_hash = hashlib.sha256(activation_message(payload)).hexdigest()
            prior = self.conn.execute('''SELECT job_id,attempt_number,statement_hash FROM _scan_activations
                                        WHERE token_id=? OR (job_id=? AND attempt_number=?)''',
                                     (token.token_id, job_id, number)).fetchall()
            if prior:
                if len(prior) == 1 and tuple(prior[0]) == (job_id, number, statement_hash):
                    return True, 'IDENTICAL_ACTIVATION_REPLAY'
                return False, 'ACTIVATION_TOKEN_OR_ATTEMPT_REUSED'
            self.conn.execute('INSERT INTO _scan_activations VALUES (?,?,?,?,?,?,?,?,?,?)',
                (job_id, number, token.capability, worker, token.token_id, token.token_hash(),
                 token.parameters_hash, payload['idempotency_key'], at, statement_hash))
            return True, 'VERIFIED_ACTIVATION'
        except (KeyError, TypeError, ValueError, OverflowError):
            return False, 'MALFORMED_ACTIVATION'

    def matches_receipt(self, receipt):
        row = self.conn.execute('SELECT * FROM _scan_activations WHERE job_id=? AND attempt_number=?',
                                (receipt.job_id, receipt.attempt_number)).fetchone()
        return bool(row and row['capability'] == receipt.capability and
                    row['worker_id'] == receipt.worker_id and
                    row['token_id'] == receipt.provenance.get('token_id') and
                    row['token_hash'] == receipt.provenance.get('execution_token_hash') and
                    row['parameters_hash'] == receipt.input_hash and
                    row['idempotency_key'] == receipt.idempotency_key and
                    row['activated_at'] <= receipt.started_at and
                    row['activated_at'] <= receipt.completed_at)
