"""Receipt-gated, event-backed epistemic projection. Public writes fail closed.

Signed revisions are the source of truth; SQLite view rows are disposable indexes.
All view changes, dependency edges and transition records share one transaction.
"""
import time
import math
from contextlib import contextmanager
from collections import deque
from ciph.contracts.base import canonical_json, _unfreeze
from ciph.kernel.crypto_identity import Ed25519KeyManager
from ciph.workers.receipts import ExecutionReceipt, generate_environment_fingerprint
import json
import sqlite3
import uuid
import hashlib
from typing import List, Dict, Any, Optional, Union, Tuple
from ciph.kernel.transmutation_dag import TransmutationNode, EpistemicCategory
from ciph.perception.observation import ReliabilityClass
from ciph.contracts.enums import (
    DecayProfile,
    DECAY_DURATIONS_SECONDS,
    EpistemicState,
    LifecycleState,
    OutcomeCategory,
)
from ciph.contracts.base import canonical_json, ContractValidationError, freeze_value
from ciph.contracts.epistemic import Claim, Observation, EpistemicAdmissionError, _ClaimTupleBase


def compute_normalized_context_hash(subject, predicate, condition=None, scope_id=None,
                                    environment_fingerprint="", authority_fingerprint="",
                                    input_hash="", network_policy=""):
    """Context comes from verified provenance; free-form conditions grant no isolation."""
    return hashlib.sha256(canonical_json([subject, predicate, scope_id, environment_fingerprint,
        authority_fingerprint, input_hash, network_policy]).encode()).hexdigest()


def derive_predicate_class(predicate, capability=None):
    if predicate in ("model_prediction", "forecast_yield", "forecast", "projected_pnl"):
        return "FORECAST"
    if predicate in ("stored_record", "retrieval_report", "execution_report", "source_reported"):
        return "HISTORICAL_RECORD"
    if predicate in ("status", "circuit_established", "connected", "is_active", "armed", "enabled", "ledger_balance", "balance_usd"):
        return "POINT_IN_TIME_STATE"
    return "HISTORICAL_RECORD"


class MaterializedWorldview:
    """
    Maintains high-performance materialized views of active claims in SQLite WAL.
    Updated strictly via append-only events, verified admissions, and authenticated transitions.
    Includes the Tabu Graveyard, Observation store, Dependency edges, and Transition log.
    """

    def __init__(
        self,
        db_path: str = "ciph_vault.db",
        event_store: Optional[Any] = None,
        receipt_verifier: Optional[Any] = None
    ):
        self.db_path = db_path
        self.event_store = event_store
        self.receipt_verifier = receipt_verifier
        self._runtime = None
        self._init_db()
        self._upgrade_projection_schema()

    def _get_connection(self, calling_holder_id: Optional[str] = None) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        conn.row_factory = sqlite3.Row

        from ciph.maintenance.exclusion import ExcludedConnection
        return ExcludedConnection(conn, calling_holder_id=calling_holder_id, db_path=self.db_path)

    def _init_db(self):
        with sqlite3.connect(self.db_path, timeout=5.0) as conn:
            conn.row_factory = sqlite3.Row
            # 1. Active Claims Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_active_claims (
                    claim_id TEXT PRIMARY KEY,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value TEXT NOT NULL,
                    condition TEXT,
                    state TEXT NOT NULL,
                    reliability TEXT NOT NULL,
                    assurance_score REAL NOT NULL,
                    evidence_receipt_ids TEXT NOT NULL,
                    observation_ids TEXT DEFAULT '[]',
                    parent_claim_ids TEXT NOT NULL,
                    superseded_by TEXT,
                    freshness_deadline REAL,
                    valid_from REAL,
                    valid_until REAL,
                    predicate_class TEXT,
                    normalized_context_hash TEXT,
                    verifier_provenance TEXT,
                    migration_status TEXT NOT NULL DEFAULT 'CANONICAL',
                    lifecycle_state TEXT NOT NULL DEFAULT 'ACTIVE',
                    decay_profile TEXT DEFAULT 'SOFTWARE_BEHAVIOR',
                    invalidation_barrier INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL,
                    updated_at REAL NOT NULL
                );
            """)

            # Schema migration for existing databases
            existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(ciph_active_claims);").fetchall()}
            migrations = [
                ("observation_ids", "TEXT DEFAULT '[]'"),
                ("valid_from", "REAL"),
                ("valid_until", "REAL"),
                ("predicate_class", "TEXT"),
                ("normalized_context_hash", "TEXT"),
                ("verifier_provenance", "TEXT"),
                ("migration_status", "TEXT NOT NULL DEFAULT 'CANONICAL'"),
                ("lifecycle_state", "TEXT NOT NULL DEFAULT 'ACTIVE'"),
                ("decay_profile", "TEXT DEFAULT 'SOFTWARE_BEHAVIOR'"),
                ("invalidation_barrier", "INTEGER NOT NULL DEFAULT 0"),
            ]
            for col_name, col_type in migrations:
                if col_name not in existing_cols:
                    conn.execute(f"ALTER TABLE ciph_active_claims ADD COLUMN {col_name} {col_type};")

            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_subject ON ciph_active_claims(subject);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_state ON ciph_active_claims(state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_lifecycle ON ciph_active_claims(lifecycle_state);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_migration ON ciph_active_claims(migration_status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_barrier ON ciph_active_claims(invalidation_barrier);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claims_context_hash ON ciph_active_claims(normalized_context_hash);")

            # 2. Tabu Graveyard Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_tabu_graveyard (
                    grave_id TEXT PRIMARY KEY,
                    claim_id TEXT,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    refuted_value TEXT,
                    reason TEXT NOT NULL,
                    negative_evidence TEXT,
                    buried_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_graveyard_subj ON ciph_tabu_graveyard(subject, predicate);")

            # 3. Observations Store Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_observations (
                    observation_id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    predicate TEXT NOT NULL,
                    value TEXT NOT NULL,
                    raw_evidence_digest TEXT NOT NULL,
                    raw_evidence_ref TEXT,
                    content_hash TEXT NOT NULL,
                    reliability TEXT NOT NULL,
                    observed_at REAL NOT NULL,
                    collected_at REAL NOT NULL,
                    ingested_at REAL NOT NULL,
                    expires_at REAL,
                    scope_id TEXT,
                    uncertain_source_time INTEGER NOT NULL DEFAULT 0,
                    created_at REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_subj_pred ON ciph_observations(subject, predicate);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_source ON ciph_observations(source);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_obs_content_hash ON ciph_observations(content_hash);")

            # 4. Claim Dependencies Table (DAG Edges)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_claim_dependencies (
                    parent_claim_id TEXT NOT NULL,
                    child_claim_id TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    PRIMARY KEY (parent_claim_id, child_claim_id)
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claim_dep_parent ON ciph_claim_dependencies(parent_claim_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_claim_dep_child ON ciph_claim_dependencies(child_claim_id);")

            # 5. Claim Transitions Audit Table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ciph_claim_transitions (
                    transition_id TEXT PRIMARY KEY,
                    claim_id TEXT NOT NULL,
                    from_epistemic_state TEXT,
                    to_epistemic_state TEXT,
                    from_lifecycle_state TEXT,
                    to_lifecycle_state TEXT,
                    reason TEXT NOT NULL,
                    actor TEXT,
                    invalidation_barrier INTEGER NOT NULL DEFAULT 0,
                    timestamp REAL NOT NULL
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_transitions_claim ON ciph_claim_transitions(claim_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_transitions_ts ON ciph_claim_transitions(timestamp);")
            conn.commit()

    def _upgrade_projection_schema(self):
        additions = {
            'ciph_active_claims': {'canonical_payload': 'TEXT', 'revision_event_id': 'INTEGER',
                'scope_id': 'TEXT', 'environment_fingerprint': 'TEXT', 'authority_fingerprint': 'TEXT'},
            'ciph_observations': {'canonical_payload': 'TEXT', 'revision_event_id': 'INTEGER'},
            'ciph_claim_dependencies': {'dependency_type': "TEXT NOT NULL DEFAULT 'REQUIRED_PREMISE'"},
            'ciph_tabu_graveyard': {'reopened_at': 'REAL', 'reopen_reason': 'TEXT',
                'reopen_evidence': 'TEXT', 'context_hash': 'TEXT'},
        }
        with self._get_connection() as conn:
            for table, columns in additions.items():
                existing = {r['name'] for r in conn.execute(f'PRAGMA table_info({table})')}
                for name, spec in columns.items():
                    if name not in existing:
                        conn.execute(f'ALTER TABLE {table} ADD COLUMN {name} {spec}')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_legacy_claims (claim_id TEXT PRIMARY KEY, original_row TEXT NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_legacy_projection (table_name TEXT NOT NULL, row_id TEXT NOT NULL, original_row TEXT NOT NULL, PRIMARY KEY(table_name,row_id))')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_cascade_checkpoints (root_id TEXT PRIMARY KEY, payload TEXT NOT NULL)')
            # Old default CANONICAL did not mean the row passed an evidence gate.
            for row in conn.execute('SELECT * FROM ciph_active_claims WHERE revision_event_id IS NULL'):
                conn.execute('INSERT OR IGNORE INTO ciph_legacy_claims VALUES (?,?)', (row['claim_id'], canonical_json(dict(row))))
            conn.execute("UPDATE ciph_active_claims SET migration_status='LEGACY_QUARANTINE', lifecycle_state='ARCHIVED' WHERE revision_event_id IS NULL")

    def _bind_runtime(self, runtime):
        if str(runtime.db_path) != str(self.db_path):
            raise EpistemicAdmissionError('EVIDENCE_DATABASE_MISMATCH')
        self._runtime = runtime
        self.event_store = runtime.event_store
        # Replay checks signatures and restores views without creating new claims.
        self.replay_from_event_store()

    def _authority(self):
        if self._runtime is None:
            raise EpistemicAdmissionError('RUNTIME_EVIDENCE_AUTHORITY_REQUIRED')
        return self._runtime

    @contextmanager
    def _transaction(self):
        self._authority()
        with self._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            yield conn

    def _receipt(self, receipt_id):
        runtime = self._authority()
        events = runtime.event_store.get_events(aggregate_id=receipt_id, event_type='ExecutionReceiptStoredEvent', limit=2)
        if len(events) != 1:
            raise EpistemicAdmissionError('COMMITTED_RECEIPT_REQUIRED')
        receipt = ExecutionReceipt.from_dict(events[0]['payload'])
        job = runtime.queue.get_job(receipt.job_id)
        cap = runtime.registry.get(receipt.capability)
        if not job or not cap:
            raise EpistemicAdmissionError('COMMITTED_JOB_REQUIRED')
        proof = runtime._authenticated_terminal_replay(job, cap.manifest, receipt.input_hash, receipt.idempotency_key)
        if proof.get('status') != 'SUCCESS' or proof.get('receipt') != receipt:
            raise EpistemicAdmissionError('UNVERIFIABLE_COMMITTED_EVIDENCE')
        return receipt

    def _event(self, conn, event_type, aggregate_id, changes):
        runtime = self._authority()
        timestamp = time.time()
        previous = runtime.event_store._get_latest_hash(conn)
        payload = {'version': 1, 'kind': event_type, 'aggregate_id': aggregate_id,
                   'timestamp': timestamp, 'previous_hash': previous,
                   'changes': changes, 'key_id': runtime.kernel_key_id}
        payload['signature'] = Ed25519KeyManager.sign(runtime.kernel_priv_bytes, canonical_json(payload).encode())
        body = json.dumps(payload, sort_keys=True)
        digest = hashlib.sha256(f'{previous}|{event_type}|{aggregate_id}|{body}|{timestamp}'.encode()).hexdigest()
        cur = conn.execute('INSERT INTO ciph_event_store (event_type,aggregate_id,payload,timestamp,previous_hash,event_hash) VALUES (?,?,?,?,?,?)',
                           (event_type, aggregate_id, body, timestamp, previous, digest))
        self._apply_changes(conn, changes, cur.lastrowid)
        return cur.lastrowid

    def _verified_event(self, row):
        runtime = self._authority()
        payload = json.loads(row['payload']) if isinstance(row['payload'], str) else row['payload']
        unsigned = dict(payload); signature = unsigned.pop('signature', '')
        if unsigned.get('version') != 1 or unsigned.get('kind') != row['event_type'] or unsigned.get('aggregate_id') != row['aggregate_id'] or unsigned.get('timestamp') != row['timestamp'] or unsigned.get('previous_hash') != row['previous_hash']:
            raise EpistemicAdmissionError('INVALID_EPISTEMIC_EVENT')
        key = runtime.trust_registry.get_key(unsigned.get('key_id'))
        if not key or str(getattr(key.get('role'), 'value', key.get('role'))) != 'KERNEL':
            raise EpistemicAdmissionError('INVALID_EPISTEMIC_EVENT_SIGNER')
        # Signature verification uses registry history at the original event time.
        valid, reason = runtime.trust_registry.verify_signature_at_time(unsigned['key_id'], canonical_json(unsigned).encode(), signature, row['timestamp'])
        if not valid:
            raise EpistemicAdmissionError(f'INVALID_EPISTEMIC_EVENT_SIGNATURE: {reason}')
        return unsigned['changes']

    @staticmethod
    def _insert_row(conn, table, row):
        names = list(row)
        conn.execute(f"INSERT OR REPLACE INTO {table} ({','.join(names)}) VALUES ({','.join('?' for _ in names)})", [row[n] for n in names])

    def _apply_changes(self, conn, changes, event_id):
        for kind, row in changes:
            row = dict(row)
            if kind == 'claim':
                row['revision_event_id'] = event_id
                self._insert_row(conn, 'ciph_active_claims', row)
                conn.execute('DELETE FROM ciph_claim_dependencies WHERE child_claim_id=?', (row['claim_id'],))
                for pid in json.loads(row['parent_claim_ids']):
                    self._insert_row(conn, 'ciph_claim_dependencies', {'parent_claim_id':pid, 'child_claim_id':row['claim_id'], 'created_at':row['created_at'], 'dependency_type':'REQUIRED_PREMISE'})
            elif kind == 'observation':
                row['revision_event_id'] = event_id
                self._insert_row(conn, 'ciph_observations', row)
            elif kind in ('grave', 'transition', 'checkpoint'):
                self._insert_row(conn, {'grave':'ciph_tabu_graveyard', 'transition':'ciph_claim_transitions', 'checkpoint':'ciph_cascade_checkpoints'}[kind], row)
            else:
                raise EpistemicAdmissionError('UNKNOWN_PROJECTION_EVENT')

    def _checked_row(self, conn, claim_id):
        row = conn.execute("SELECT * FROM ciph_active_claims WHERE claim_id=? AND migration_status='CANONICAL'", (claim_id,)).fetchone()
        if row is None:
            return None
        event = conn.execute('SELECT * FROM ciph_event_store WHERE event_id=?', (row['revision_event_id'],)).fetchone()
        if event is None:
            raise EpistemicAdmissionError('UNATTESTED_PROJECTION_ROW')
        latest = conn.execute("SELECT MAX(event_id) FROM ciph_event_store WHERE aggregate_id=? AND event_type IN ('EpistemicClaimAdmitted','EpistemicClaimTransitioned')", (claim_id,)).fetchone()[0]
        if latest != row['revision_event_id']:
            raise EpistemicAdmissionError('REPLAYED_PROJECTION_REVISION')
        changes = self._verified_event(event)
        expected = next((r for k, r in changes if k == 'claim' and r['claim_id'] == claim_id), None)
        actual = dict(row); actual.pop('revision_event_id', None)
        if expected != actual:
            raise EpistemicAdmissionError('TAMPERED_PROJECTION_ROW')
        return actual

    @staticmethod
    def get_decay_deadline(profile, from_time=None):
        duration = DECAY_DURATIONS_SECONDS[DecayProfile(profile)]
        return None if duration is None else (time.time() if from_time is None else from_time) + duration

    @staticmethod
    def _external_observation_policy(receipt):
        policy = receipt.provenance.get('external_source_policy')
        if not policy:
            return ReliabilityClass.THIRD_PARTY_FEED, None
        from ciph.perception.external_sources import SOURCE_POLICIES
        reliability = ReliabilityClass(policy['reliability'])
        if reliability not in SOURCE_POLICIES or not receipt.capability.startswith('external.observe.'):
            raise EpistemicAdmissionError('INVALID_EXTERNAL_SOURCE_POLICY')
        expected_ttl = SOURCE_POLICIES[reliability][2]
        if policy['ttl_seconds'] != expected_ttl or receipt.actual_transport_used != 'TOR_SOCKS5_REMOTE_DNS_PINNED':
            raise EpistemicAdmissionError('UNVERIFIED_EXTERNAL_TRANSPORT')
        raw = receipt.results.get('observation', {})
        if raw.get('source') != policy['url'] or raw.get('subject') != receipt.target:
            raise EpistemicAdmissionError('EXTERNAL_SOURCE_RETARGETING')
        from ciph.perception.external_sources import display_external_body
        display_external_body(raw['value'])  # validates immutable raw bytes, discards display
        return reliability, min(raw.get('observed_at', receipt.completed_at), receipt.completed_at) + expected_ttl

    def ingest_observation(self, receipt_id):
        """Intake only telemetry bound to an authenticated committed worker result.

        A source report stays attributed to that source, even when collected locally.
        """
        receipt = self._receipt(receipt_id)
        raw = receipt.results.get('observation') if isinstance(receipt.results, dict) else None
        if not isinstance(raw, dict):
            raw = {'source': 'worker:' + receipt.capability, 'subject':receipt.target or receipt.capability,
                   'predicate':'execution_report', 'value':receipt.results}
        reliability, policy_expiry = self._external_observation_policy(receipt)
        observation = Observation(
            observation_id='OBS-' + hashlib.sha256(receipt_id.encode()).hexdigest()[:32],
            source=raw['source'], subject=raw['subject'], predicate=raw['predicate'], value=raw['value'],
            observed_at=raw.get('observed_at', receipt.completed_at), collected_at=receipt.completed_at,
            expires_at=policy_expiry if policy_expiry is not None else raw.get('expires_at'), raw_evidence_ref='receipt:' + receipt_id,
            raw_evidence_digest=receipt.output_hash, reliability_class=reliability,
            scope_id=receipt.target, environment={'fingerprint':receipt.environment_fingerprint},
            uncertain_source_time='observed_at' not in raw)
        self.store_observation(observation)
        return self.get_observation(observation.observation_id)

    def _validate_observation(self, observation):
        if not isinstance(observation, Observation) or not observation.raw_evidence_ref.startswith('receipt:'):
            raise EpistemicAdmissionError('AUTHENTIC_OBSERVATION_PROVENANCE_REQUIRED')
        receipt = self._receipt(observation.raw_evidence_ref[len('receipt:'):])
        raw = receipt.results.get('observation') if isinstance(receipt.results, dict) else None
        if not isinstance(raw, dict):
            raw = {'source':'worker:' + receipt.capability, 'subject':receipt.target or receipt.capability, 'predicate':'execution_report', 'value':receipt.results}
        reliability, policy_expiry = self._external_observation_policy(receipt)
        expected = [raw['source'], raw['subject'], raw['predicate'], raw['value'], raw.get('observed_at', receipt.completed_at),
                    receipt.completed_at, policy_expiry if policy_expiry is not None else raw.get('expires_at'), receipt.target, {'fingerprint':receipt.environment_fingerprint}]
        actual = [observation.source, observation.subject, observation.predicate, observation.value, observation.observed_at,
                  observation.collected_at, observation.expires_at, observation.scope_id, dict(observation.environment)]
        if canonical_json(expected) != canonical_json(actual) or observation.raw_evidence_digest != receipt.output_hash or observation.reliability_class != reliability:
            raise EpistemicAdmissionError('UNBOUND_OBSERVATION_OR_FORGED_RELIABILITY')

    def store_observation(self, observation):
        self._validate_observation(observation)
        d = observation.to_dict()
        row = {k:d[k] for k in ('observation_id','source','subject','predicate','raw_evidence_digest','raw_evidence_ref',
                               'observed_at','collected_at','ingested_at','expires_at','scope_id')}
        row.update(value=canonical_json(d['value']), content_hash=observation.content_hash,
                   reliability=observation.reliability_class.value, uncertain_source_time=int(observation.uncertain_source_time),
                   created_at=observation.ingested_at, canonical_payload=canonical_json(d))
        with self._transaction() as conn:
            previous = conn.execute('SELECT * FROM ciph_observations WHERE observation_id=?', (observation.observation_id,)).fetchone()
            if previous:
                if previous['content_hash'] != observation.content_hash:
                    raise EpistemicAdmissionError('OBSERVATION_ID_COLLISION')
                return observation.observation_id
            self._event(conn, 'EpistemicObservationAdmitted', observation.observation_id, [('observation',row)])
        return observation.observation_id

    def get_observation(self, observation_id):
        with self._get_connection() as conn:
            row = conn.execute('SELECT * FROM ciph_observations WHERE observation_id=?', (observation_id,)).fetchone()
            if not row or not row['canonical_payload'] or not row['revision_event_id']:
                return None
            event = conn.execute('SELECT * FROM ciph_event_store WHERE event_id=?', (row['revision_event_id'],)).fetchone()
            expected = next((r for k,r in self._verified_event(event) if k == 'observation'), None)
            actual=dict(row);actual.pop('revision_event_id')
            if actual != expected:
                raise EpistemicAdmissionError('TAMPERED_OBSERVATION')
            observation=Observation.from_dict(json.loads(row['canonical_payload']))
            if observation.content_hash != row['content_hash']:
                raise EpistemicAdmissionError('OBSERVATION_INTEGRITY_MISMATCH')
            return observation

    def query_observations(self, subject=None, predicate=None, source=None, include_expired=False, limit=100):
        with self._get_connection() as conn:
            ids=[r[0] for r in conn.execute('SELECT observation_id FROM ciph_observations ORDER BY created_at DESC')]
        result=[]
        for oid in ids:
            obs=self.get_observation(oid)
            if obs and (not subject or obs.subject == subject) and (not predicate or obs.predicate == predicate) and (not source or obs.source == source) and (include_expired or not obs.is_expired()):
                result.append(obs)
                if len(result)>=limit:break
        return result

    def _canonicalize(self, candidate, conn):
        if not isinstance(candidate, (Claim, TransmutationNode)):
            raise EpistemicAdmissionError('CANONICAL_CLAIM_REQUIRED')
        state = EpistemicState(candidate.epistemic_state if isinstance(candidate, Claim) else candidate.state)
        receipts = tuple(candidate.evidence_receipt_ids)
        observations = tuple(getattr(candidate, 'observation_ids', ()))
        parents = tuple(candidate.parent_claim_ids)
        if len(parents)>256:
            raise EpistemicAdmissionError('PARENT_COUNT_EXCEEDED')
        if len(set(parents)) != len(parents):
            raise EpistemicAdmissionError('DUPLICATE_PARENT')
        if receipts and observations:
            raise EpistemicAdmissionError('AMBIGUOUS_EVIDENCE_PROJECTION')
        projector=self._authority().claim_projector
        if len(receipts)==1:
            receipt=self._receipt(receipts[0])
            expected=projector.project_claim(receipt, claim_id=candidate.claim_id, subject=candidate.subject,
                        predicate=candidate.predicate, value=candidate.value, parent_claim_ids=parents,
                        decay_profile=candidate.decay_profile)
        elif len(observations)==1 and not receipts:
            obs=self.get_observation(observations[0])
            if obs is None:raise EpistemicAdmissionError('AUTHENTIC_OBSERVATION_REQUIRED')
            self._validate_observation(obs)
            expected=projector.project_from_observation(obs, claim_id=candidate.claim_id, parent_claim_ids=parents, decay_profile=candidate.decay_profile)
        else:
            raise EpistemicAdmissionError('VERIFIABLE_EVIDENCE_REQUIRED')
        if state != expected.epistemic_state or canonical_json(candidate.value)!=canonical_json(expected.value) or candidate.subject!=expected.subject or candidate.predicate!=expected.predicate:
            raise EpistemicAdmissionError('UNBOUND_CLAIM_PROPOSITION_OR_STATE')
        if isinstance(candidate, Claim) and (candidate.scope_id != expected.scope_id or candidate.environment_fingerprint != expected.environment_fingerprint or candidate.authority_fingerprint != expected.authority_fingerprint):
            raise EpistemicAdmissionError('UNBOUND_CLAIM_CONTEXT')
        data=expected.to_dict()
        score=float(candidate.assurance_score)
        if not math.isfinite(score) or score<0 or score>expected.assurance_score:
            raise EpistemicAdmissionError('ASSURANCE_CEILING_EXCEEDED')
        deadline=expected.freshness_deadline
        if candidate.freshness_deadline is not None:
            if not math.isfinite(candidate.freshness_deadline) or candidate.freshness_deadline<0:
                raise EpistemicAdmissionError('INVALID_FRESHNESS_DEADLINE')
            deadline=min(deadline, candidate.freshness_deadline) if deadline is not None else candidate.freshness_deadline
        for pid in parents:
            parent=self._checked_row(conn,pid)
            if not parent or not self._usable(conn,parent,time.time()):
                raise EpistemicAdmissionError('INACTIVE_OR_MISSING_PARENT')
            score=min(score,parent['assurance_score'])
            pd=parent['freshness_deadline']
            if pd is not None:deadline=min(deadline,pd) if deadline is not None else pd
        data.update(assurance_score=score,freshness_deadline=deadline)
        # A caller cannot extend lifetime by changing created_at or choose ACTIVE on expired evidence.
        if deadline is not None and deadline<=time.time():data['lifecycle_state']='DORMANT'
        return data

    @staticmethod
    def _claim_row(data):
        context=hashlib.sha256(canonical_json({'scope_id':data['scope_id'], 'environment_fingerprint':data['environment_fingerprint'], 'authority_fingerprint':data['authority_fingerprint']}).encode()).hexdigest()
        return dict(claim_id=data['claim_id'], subject=data['subject'], predicate=data['predicate'], value=canonical_json(data['value']),
            condition=None,state=data['epistemic_state'], reliability='DIRECT_SENSOR',assurance_score=data['assurance_score'],
            evidence_receipt_ids=canonical_json(data['evidence_receipt_ids']), observation_ids=canonical_json(data['observation_ids']),
            parent_claim_ids=canonical_json(data['parent_claim_ids']), superseded_by=None,freshness_deadline=data['freshness_deadline'],
            valid_from=data['created_at'],valid_until=data['freshness_deadline'],predicate_class=derive_predicate_class(data['predicate']),
            normalized_context_hash=context,verifier_provenance=canonical_json({'verifier_id':'ciph.predicate', 'verifier_version':2,'authority_fingerprint':data['authority_fingerprint']}),
            migration_status='CANONICAL',lifecycle_state=data['lifecycle_state'],decay_profile=data['decay_profile'],invalidation_barrier=0,
            created_at=data['created_at'],updated_at=data['updated_at'],canonical_payload=canonical_json(data),scope_id=data['scope_id'],
            environment_fingerprint=data['environment_fingerprint'],authority_fingerprint=data['authority_fingerprint'])

    def _validate_graph(self, conn, candidate):
        graph={r['claim_id']:json.loads(r['parent_claim_ids']) for r in conn.execute("SELECT claim_id,parent_claim_ids FROM ciph_active_claims WHERE migration_status='CANONICAL'")}
        graph[candidate['claim_id']]=json.loads(candidate['parent_claim_ids'])
        children={};depths={};visiting=set()
        for child,parents in graph.items():
            for parent in parents:
                if parent not in graph:raise ValueError('DANGLING_PARENT')
                children.setdefault(parent,set()).add(child)
                if len(children[parent])>256:raise ValueError('GRAPH_WIDTH_EXCEEDED')
        def depth(cid):
            if cid in visiting:raise ValueError('DEPENDENCY_CYCLE')
            if cid in depths:return depths[cid]
            visiting.add(cid)
            if len(visiting)>17:raise ValueError('GRAPH_DEPTH_EXCEEDED')
            result=max((depth(pid)+1 for pid in graph[cid]),default=0)
            visiting.remove(cid);depths[cid]=result
            if result>16:raise ValueError('GRAPH_DEPTH_EXCEEDED')
            return result
        for cid in graph:depth(cid)

    def record_transition(self, claim_id, from_epistemic_state=None, to_epistemic_state=None, from_lifecycle_state=None,
                          to_lifecycle_state=None, reason='', actor=None, invalidation_barrier=0, conn=None):
        if conn is None:
            raise EpistemicAdmissionError('TRANSITIONS_REQUIRE_ATOMIC_STATE_CHANGE')
        return dict(transition_id='TRN-'+uuid.uuid4().hex,claim_id=claim_id,from_epistemic_state=from_epistemic_state,
                    to_epistemic_state=to_epistemic_state,from_lifecycle_state=from_lifecycle_state,to_lifecycle_state=to_lifecycle_state,
                    reason=reason,actor=actor or 'worldview',invalidation_barrier=invalidation_barrier,timestamp=time.time())

    def _revision(self, conn, row, reason, state=None, lifecycle=None, barrier=None, superseded_by=None):
        old=dict(row);row=dict(row)
        if state is not None:row['state']=str(getattr(state,'value',state))
        if lifecycle is not None:row['lifecycle_state']=str(getattr(lifecycle,'value',lifecycle))
        if barrier is not None:row['invalidation_barrier']=barrier
        if superseded_by:row['superseded_by']=superseded_by
        row['updated_at']=time.time()
        data=json.loads(row['canonical_payload']);data.update(epistemic_state=row['state'],lifecycle_state=row['lifecycle_state'],updated_at=row['updated_at'])
        row['canonical_payload']=canonical_json(data)
        transition=self.record_transition(row['claim_id'],old['state'],row['state'],old['lifecycle_state'],row['lifecycle_state'],reason=reason,invalidation_barrier=row['invalidation_barrier'],conn=conn)
        self._event(conn,'EpistemicClaimTransitioned',row['claim_id'],[('claim',row),('transition',transition)])
        return row

    def admit_claim(self, claim, event_store=None, **kwargs):
        if event_store is not None and event_store is not self._authority().event_store:
            raise EpistemicAdmissionError('CALLER_CONTROLLED_EVIDENCE_STORE')
        with self._transaction() as conn:
            data=self._canonicalize(claim,conn)
            row=self._claim_row(data)
            if data['evidence_receipt_ids']:
                receipt=self._receipt(data['evidence_receipt_ids'][0])
                job=self._authority().queue.get_job(receipt.job_id)
                token=json.loads(job['execution_token'])
                row['normalized_context_hash']=hashlib.sha256(canonical_json([row['normalized_context_hash'],receipt.input_hash,receipt.requested_network_policy,token['scope_grant_id']]).encode()).hexdigest()
            existing=self._checked_row(conn,claim.claim_id)
            if existing:
                original=json.loads(existing['canonical_payload'])
                identity=('subject','predicate','value','evidence_receipt_ids','observation_ids','parent_claim_ids','scope_id','environment_fingerprint','created_at','decay_profile')
                if any(canonical_json(original[k])!=canonical_json(data[k]) for k in identity):
                    raise EpistemicAdmissionError('IMMUTABLE_CLAIM_ID_COLLISION')
                return claim.claim_id  # replay never restores a demoted state or resets its clock
            if conn.execute('SELECT 1 FROM ciph_active_claims WHERE claim_id=?',(claim.claim_id,)).fetchone():
                raise EpistemicAdmissionError('LEGACY_CLAIM_ID_COLLISION')
            self._validate_graph(conn,row)
            transition=self.record_transition(row['claim_id'],to_epistemic_state=row['state'],to_lifecycle_state=row['lifecycle_state'],reason='ADMISSION',conn=conn)
            self._event(conn,'EpistemicClaimAdmitted',row['claim_id'],[('claim',row),('transition',transition)])
            self._contradictions(conn,row)
        return claim.claim_id

    def upsert_claim(self,node):
        """Compatibility adapter: exactly the same admission gate, never an escape hatch."""
        return self.admit_claim(node)

    def _usable(self,conn,row,now,visited=None,memo=None,budget=None):
        visited=set() if visited is None else visited
        memo={} if memo is None else memo
        budget=[1024] if budget is None else budget
        if row['claim_id'] in memo:return memo[row['claim_id']]
        if budget[0]<=0 or row['claim_id'] in visited:return False
        budget[0]-=1
        if row['invalidation_barrier'] or row['lifecycle_state']!='ACTIVE' or row['state'] in ('REFUTED','DISPUTED','SUPERSEDED','STALE') or row['superseded_by']:
            return False
        if row['freshness_deadline'] is not None and row['freshness_deadline']<=now:return False
        if row['decay_profile']=='SOFTWARE_BEHAVIOR' and row['environment_fingerprint'] and row['environment_fingerprint']!=generate_environment_fingerprint():return False
        visited.add(row['claim_id'])
        for pid in json.loads(row['parent_claim_ids']):
            parent=self._checked_row(conn,pid)
            if not parent or not self._usable(conn,parent,now,visited,memo,budget):return False
        visited.remove(row['claim_id'])
        memo[row['claim_id']]=True
        return True

    def get_usable_claim(self, claim_id):
        """Return an authenticated, currently usable canonical proposition."""
        with self._get_connection() as conn:
            row = self._checked_row(conn, claim_id)
            if not row or not self._usable(conn, row, time.time()):
                return None
            return self._row_to_claim(row)

    def find_internal_claim_ids(self, subject, predicate, limit=100):
        """Bounded candidate lookup; callers must still authenticate each result."""
        with self._get_connection() as conn:
            return [r[0] for r in conn.execute(
                "SELECT claim_id FROM ciph_active_claims WHERE subject=? AND predicate=? "
                "AND migration_status='CANONICAL' ORDER BY updated_at DESC,claim_id LIMIT ?",
                (subject, predicate, min(max(limit, 1), 100)))]

    def get_canonical_claim(self,claim_id):
        with self._get_connection() as conn:
            row=self._checked_row(conn,claim_id)
            return self._row_to_claim(row) if row else None

    @staticmethod
    def _row_to_claim(row):
        d=json.loads(row['canonical_payload'])
        d['value']=freeze_value(d['value'])
        for key,enum in (('epistemic_state',EpistemicState),('lifecycle_state',LifecycleState),('decay_profile',DecayProfile)):d[key]=enum(d[key])
        for key in ('evidence_receipt_ids','observation_ids','parent_claim_ids'):d[key]=tuple(d[key])
        return _ClaimTupleBase.__new__(Claim,**d)

    def _row_to_node(self,row):
        claim=self._row_to_claim(row)
        node=TransmutationNode(claim_id=claim.claim_id,subject=claim.subject,predicate=claim.predicate,value=_unfreeze(claim.value),
            state=claim.epistemic_state,assurance_score=claim.assurance_score,evidence_receipt_ids=list(claim.evidence_receipt_ids),
            parent_claim_ids=list(claim.parent_claim_ids),freshness_deadline=claim.freshness_deadline,lifecycle_state=claim.lifecycle_state,
            decay_profile=claim.decay_profile,created_at=claim.created_at,updated_at=claim.updated_at,
            superseded_by=row['superseded_by'],valid_from=row['valid_from'],valid_until=row['valid_until'],
            normalized_context_hash=row['normalized_context_hash'],predicate_class=row['predicate_class'],invalidation_barrier=row['invalidation_barrier'])
        node.observation_ids=list(claim.observation_ids)
        return node

    def get_claim(self,claim_id):
        with self._get_connection() as conn:
            row=self._checked_row(conn,claim_id)
            return self._row_to_node(row) if row else None

    def query_active_claims(self,subject=None,predicate=None,states=None,include_expired=False,include_quarantined=False,include_archived=False,limit=50):
        result=[];now=time.time()
        with self._get_connection() as conn:
            ids=[r[0] for r in conn.execute("SELECT claim_id FROM ciph_active_claims WHERE migration_status='CANONICAL' ORDER BY assurance_score DESC,updated_at DESC")]
            for cid in ids:
                row=self._checked_row(conn,cid)
                if subject and row['subject']!=subject or predicate and row['predicate']!=predicate:continue
                if states and row['state'] not in states:continue
                if include_expired and include_archived:
                    # Explicit maintenance view, never used as an active premise.
                    pass
                elif not self._usable(conn,row,now):continue
                result.append(self._row_to_node(row))
                if len(result)>=limit:break
        return result

    def get_dependencies(self,claim_id):
        with self._get_connection() as conn:
            row=self._checked_row(conn,claim_id)
            return json.loads(row['parent_claim_ids']) if row else []

    def get_downstream_dependents(self,claim_id):
        with self._get_connection() as conn:
            return [r['claim_id'] for r in conn.execute("SELECT claim_id,parent_claim_ids FROM ciph_active_claims WHERE migration_status='CANONICAL'") if claim_id in json.loads(r['parent_claim_ids'])]

    def link_dependency(self,parent_claim_id,child_claim_id,dependency_type='REQUIRED_PREMISE'):
        # Dependencies are immutable provenance, supplied when a new claim is admitted.
        with self._transaction() as conn:
            parent=self._checked_row(conn,parent_claim_id);child=self._checked_row(conn,child_claim_id)
            if not parent or not child:raise ValueError('DANGLING_PARENT')
            proposed=dict(child);proposed['parent_claim_ids']=canonical_json(json.loads(child['parent_claim_ids'])+[parent_claim_id])
            self._validate_graph(conn,proposed)
            if parent_claim_id in json.loads(child['parent_claim_ids']) and dependency_type=='REQUIRED_PREMISE':return
            raise EpistemicAdmissionError('IMMUTABLE_DEPENDENCIES: admit a newly evidenced claim with its parent links')

    def get_transitions(self,claim_id=None,limit=100):
        with self._get_connection() as conn:
            rows=conn.execute('SELECT * FROM ciph_claim_transitions WHERE (? IS NULL OR claim_id=?) ORDER BY timestamp DESC LIMIT ?', (claim_id,claim_id,limit))
            return [dict(r) for r in rows]

    def _cascade(self,conn,claim_id,reason,max_depth=16,max_children=256,max_budget=1024):
        if not 1<=max_depth<=16 or not 1<=max_children<=256 or not 1<=max_budget<=1024:raise ValueError('INVALID_CASCADE_BUDGET')
        root=self._checked_row(conn,claim_id)
        if root is None:raise ValueError('MISSING_CLAIM')
        root=self._revision(conn,root,reason,barrier=1)
        queue=deque([(claim_id,0)]);visited=set();incomplete=False
        while queue and len(visited)<max_budget:
            cid,depth=queue.popleft()
            if cid in visited:continue
            visited.add(cid)
            child_ids=[r[0] for r in conn.execute('SELECT child_claim_id FROM ciph_claim_dependencies WHERE parent_claim_id=? ORDER BY child_claim_id LIMIT ?', (cid,max_children+1))]
            if depth>=max_depth:
                incomplete |= bool(child_ids);continue
            if len(child_ids)>max_children:incomplete=True
            for child_id in child_ids[:max_children]:
                if child_id in visited:continue
                if len(visited)+len(queue)>=max_budget:incomplete=True;break
                child=self._checked_row(conn,child_id)
                state='DISPUTED' if root['state'] in ('DISPUTED','REFUTED') and child['state'] not in ('REFUTED','SUPERSEDED') else None
                self._revision(conn,child,reason,state=state,lifecycle='DORMANT',barrier=1)
                queue.append((child_id,depth+1))
        incomplete |= bool(queue)
        checkpoint={'root_id':claim_id,'payload':canonical_json({'incomplete':incomplete,'frontier':list(queue),'visited':sorted(visited),'reason':reason})}
        self._event(conn,'EpistemicCascadeCheckpoint',claim_id,[('checkpoint',checkpoint)])
        return {'visited':len(visited),'invalidated_count':max(0,len(visited)-1),'budget_exhausted':incomplete,'barrier_set':True}

    def propagate_invalidation_cascade(self,claim_id,reason='PARENT_INVALIDATED',max_depth=16,max_children=256,max_budget=1024,**kwargs):
        with self._transaction() as conn:return self._cascade(conn,claim_id,reason,max_depth,max_children,max_budget)

    def clear_invalidation_barrier(self,claim_id,reason='',**kwargs):
        raise EpistemicAdmissionError('FRESH_EVIDENCE_REQUIRED: admit a new claim; old evidence cannot clear a barrier')

    def reap_expired_claims(self,current_time=None,**kwargs):
        now=time.time() if current_time is None else float(current_time)
        if not math.isfinite(now):raise ValueError('INVALID_TIME')
        count=0
        with self._transaction() as conn:
            ids=[r[0] for r in conn.execute("SELECT claim_id FROM ciph_active_claims WHERE migration_status='CANONICAL' AND lifecycle_state='ACTIVE'")]
            for cid in ids:
                row=self._checked_row(conn,cid)
                expired=row['freshness_deadline'] is not None and row['freshness_deadline']<=now
                drift=row['decay_profile']=='SOFTWARE_BEHAVIOR' and row['environment_fingerprint'] and row['environment_fingerprint']!=generate_environment_fingerprint()
                if expired or drift:
                    self._revision(conn,row,'ENVIRONMENT_CHANGED' if drift else 'TTL_EXPIRED',lifecycle='DORMANT',barrier=1)
                    self._cascade(conn,cid,'PARENT_FRESHNESS_LAPSED');count+=1
        return count

    def reap_dormant_claims(self,current_time=None):return self.reap_expired_claims(current_time)

    def _contradictions(self,conn,new):
        # Only declared single-valued, time-varying local measurements participate.
        # Whole reports, forecasts and sets are not equality-based truth propositions.
        if new['predicate'] not in ('status','circuit_established','connected','is_active','armed','enabled','ledger_balance','balance_usd'):return
        rows=list(conn.execute("SELECT claim_id FROM ciph_active_claims WHERE subject=? AND predicate=? AND normalized_context_hash=? AND claim_id<>? AND migration_status='CANONICAL' AND lifecycle_state IN ('ACTIVE','DORMANT') AND state NOT IN ('REFUTED','SUPERSEDED','DISPUTED')",(new['subject'],new['predicate'],new['normalized_context_hash'],new['claim_id'])))
        for found in rows:
            old=self._checked_row(conn,found['claim_id'])
            if old['value']==new['value']:continue
            if old['valid_until'] is not None and new['valid_from']>=old['valid_until']:
                self._revision(conn,old,'TEMPORAL_SUPERSESSION',state='SUPERSEDED',lifecycle='DORMANT',barrier=1,superseded_by=new['claim_id'])
                self._cascade(conn,old['claim_id'],'PARENT_SUPERSEDED')
            elif new['valid_until'] is None or old['valid_from']<new['valid_until']:
                self._revision(conn,old,'CONTRADICTION_DISPUTED',state='DISPUTED',barrier=1)
                new=self._revision(conn,new,'CONTRADICTION_DISPUTED',state='DISPUTED',barrier=1)
                self._cascade(conn,old['claim_id'],'CONTRADICTION_DISPUTED');self._cascade(conn,new['claim_id'],'CONTRADICTION_DISPUTED')

    def detect_and_handle_contradiction(self,new_node,**kwargs):
        self.admit_claim(new_node)
        node=self.get_claim(new_node.claim_id)
        return {'claim_id':node.claim_id,'status':node.state.value,'contradiction':node.state==EpistemicState.DISPUTED, 'contradiction_detected':node.state==EpistemicState.DISPUTED, 'disputed_claim_ids':[c.claim_id for c in self.query_active_claims(subject=node.subject,predicate=node.predicate,states=['DISPUTED'],include_archived=True,include_expired=True)]}

    def bury_in_graveyard(self,subject,predicate,reason,claim_id=None,refuted_value=None,negative_evidence=None):
        if not claim_id or not reason:raise EpistemicAdmissionError('EXISTING_CLAIM_AND_REASON_REQUIRED')
        with self._transaction() as conn:
            row=self._checked_row(conn,claim_id)
            if not row or (subject,predicate)!=(row['subject'],row['predicate']):raise EpistemicAdmissionError('GRAVE_CONTEXT_MISMATCH')
            # Suppression does not prove refutation. Preserve the established epistemic judgment.
            grave=dict(grave_id='GRV-'+uuid.uuid4().hex,claim_id=claim_id,subject=subject,predicate=predicate,refuted_value=canonical_json(refuted_value),
                reason=reason,negative_evidence=canonical_json(negative_evidence or {}),buried_at=time.time(),reopened_at=None,reopen_reason=None,reopen_evidence=None,context_hash=row['normalized_context_hash'])
            self._revision(conn,row,'BURIED: '+reason,lifecycle='ARCHIVED',barrier=1)
            self._event(conn,'EpistemicGraveBuried',grave['grave_id'],[('grave',grave)])
            self._cascade(conn,claim_id,'PREMISE_BURIED')
        return grave['grave_id']

    def is_in_graveyard(self,subject,predicate):
        with self._get_connection() as conn:
            return conn.execute('SELECT 1 FROM ciph_tabu_graveyard WHERE subject=? AND predicate=? AND reopened_at IS NULL LIMIT 1',(subject,predicate)).fetchone() is not None

    def query_graveyard(self,limit=50):
        with self._get_connection() as conn:return [dict(r) for r in conn.execute('SELECT * FROM ciph_tabu_graveyard ORDER BY buried_at DESC LIMIT ?',(limit,))]

    def reopen_claim(self,claim_id,reason='',actor=None,evidence_id=None,operator_signature=None,**kwargs):
        if not reason:raise EpistemicAdmissionError('REOPEN_REASON_REQUIRED')
        runtime=self._authority()
        with self._transaction() as conn:
            row=self._checked_row(conn,claim_id)
            grave=conn.execute('SELECT * FROM ciph_tabu_graveyard WHERE claim_id=? AND reopened_at IS NULL ORDER BY buried_at DESC LIMIT 1',(claim_id,)).fetchone()
            if not row or not grave:raise EpistemicAdmissionError('ACTIVE_GRAVE_REQUIRED')
            directive=canonical_json(['REOPEN',grave['grave_id'],claim_id,reason]).encode()
            authorized=bool(operator_signature) and Ed25519KeyManager.verify(runtime.operator_pub_bytes,directive,operator_signature)
            if evidence_id and evidence_id.startswith('OBS-'):
                observation=self.get_observation(evidence_id)
                if observation is None:raise EpistemicAdmissionError('AUTHENTIC_OBSERVATION_REQUIRED')
                self._validate_observation(observation)
                fresh=runtime.claim_projector.project_from_observation(observation)
                old_value=json.loads(row['value'])
                same_proposition=isinstance(old_value,dict) and old_value.get('subject')==observation.subject and old_value.get('predicate')==observation.predicate
                authorized |= same_proposition and fresh.subject==row['subject'] and fresh.scope_id==row['scope_id'] and min(observation.observed_at,observation.collected_at)>grave['buried_at'] and evidence_id not in json.loads(row['observation_ids'])
            elif evidence_id:
                receipt=self._receipt(evidence_id)
                fresh=runtime.claim_projector.project_claim(receipt,predicate=row['predicate'])
                authorized |= fresh.subject==row['subject'] and fresh.scope_id==row['scope_id'] and receipt.completed_at>grave['buried_at'] and evidence_id not in json.loads(row['evidence_receipt_ids'])
            if not authorized:raise EpistemicAdmissionError('AUTHENTIC_REOPEN_TRIGGER_REQUIRED')
            updated=dict(grave);updated.update(reopened_at=time.time(),reopen_reason=reason,reopen_evidence=evidence_id or 'authenticated_operator')
            self._revision(conn,row,'INVESTIGATION_REOPENED',lifecycle='REOPENED',barrier=1)
            self._event(conn,'EpistemicGraveReopened',grave['grave_id'],[('grave',updated)])
        return {'success':True,'claim_id':claim_id,'lifecycle_state':'REOPENED','truth_restored':False}

    def quarantine_unverified_claims(self,event_store=None):
        self._upgrade_projection_schema()
        with self._get_connection() as conn:return conn.execute("SELECT COUNT(*) FROM ciph_active_claims WHERE migration_status='LEGACY_QUARANTINE'").fetchone()[0]

    def replay_from_event_store(self,event_store=None,projector=None):
        runtime=self._authority()
        if event_store is not None and event_store is not runtime.event_store:raise EpistemicAdmissionError('EVIDENCE_DATABASE_MISMATCH')
        valid,broken=runtime.event_store.verify_integrity()
        if not valid:raise EpistemicAdmissionError(f'EVENT_CHAIN_CORRUPT:{broken}')
        with self._transaction() as conn:
            if conn.execute('PRAGMA integrity_check').fetchone()[0]!='ok':raise EpistemicAdmissionError('SQLITE_INTEGRITY_FAILED')
            events=list(conn.execute("SELECT * FROM ciph_event_store WHERE event_type LIKE 'Epistemic%' ORDER BY event_id"))
            verified=[(event['event_id'],self._verified_event(event)) for event in events]
            conn.execute("DELETE FROM ciph_active_claims WHERE migration_status='CANONICAL'")
            for table in ('ciph_claim_dependencies','ciph_claim_transitions','ciph_cascade_checkpoints','ciph_observations','ciph_tabu_graveyard'):
                for row in (conn.execute(f'SELECT rowid AS legacy_row_id, * FROM {table}') if not verified else ()):
                    conn.execute('INSERT OR IGNORE INTO ciph_legacy_projection VALUES (?,?,?)', (table,str(row['legacy_row_id']),canonical_json(dict(row))))
                conn.execute(f'DELETE FROM {table}')
            for event_id,changes in verified:self._apply_changes(conn,changes,event_id)
            return conn.execute("SELECT COUNT(*) FROM ciph_active_claims WHERE migration_status='CANONICAL'").fetchone()[0]
