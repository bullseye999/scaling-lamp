"""Durable curiosity projections and atomic, signed scheduling reservations.

Questions are suggestions, never propositions. Answer authority remains in the
Phase 5 worldview. Uncertain attempts are retained for reconciliation, not retried.
"""
import hashlib
import json
import time
import uuid
from contextlib import contextmanager

from ciph.contracts.base import ContractValidationError
from ciph.contracts.epistemic import canonical_json
from ciph.kernel.crypto_identity import Ed25519KeyManager


class CuriosityStore:
    TABLES = {'question': 'ciph_curiosity_questions',
              'budget': 'ciph_curiosity_budget', 'attempt': 'ciph_curiosity_attempts'}

    def __init__(self, runtime):
        self.runtime = runtime
        with self.transaction() as conn:
            for table in self.TABLES.values():
                conn.execute(f'CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, payload TEXT NOT NULL, revision INTEGER NOT NULL)')
            conn.execute('CREATE TABLE IF NOT EXISTS ciph_curiosity_dependencies '
                         '(child_id TEXT NOT NULL, parent_id TEXT NOT NULL, PRIMARY KEY(child_id,parent_id))')
        self.replay()

    @contextmanager
    def transaction(self):
        with self.runtime.event_store._get_connection() as conn:
            conn.execute('BEGIN IMMEDIATE')
            yield conn

    def _verify(self, row):
        body = json.loads(row['payload'])
        signature = body.pop('signature', '')
        if (body.get('version') != 1 or body.get('kind') not in self.TABLES
                or body.get('aggregate_id') != row['aggregate_id']
                or row['event_type'] != 'CuriosityStateChangedEvent'
                or body.get('timestamp') != row['timestamp']
                or body.get('previous_hash') != row['previous_hash']):
            raise ContractValidationError('INVALID_CURIOSITY_EVENT')
        key = self.runtime.trust_registry.get_key(body.get('key_id'))
        if not key or str(getattr(key.get('role'), 'value', key.get('role'))) != 'KERNEL':
            raise ContractValidationError('INVALID_CURIOSITY_SIGNER')
        valid, reason = self.runtime.trust_registry.verify_signature_at_time(
            body['key_id'], canonical_json(body).encode(), signature, row['timestamp'])
        if not valid:
            raise ContractValidationError(f'INVALID_CURIOSITY_SIGNATURE: {reason}')
        if row['aggregate_id'] != f"curiosity:{body['kind']}:{body['id']}":
            raise ContractValidationError('CURIOSITY_EVENT_RETARGETED')
        return body

    def _apply(self, conn, kind, identity, data, revision):
        conn.execute(f'INSERT OR REPLACE INTO {self.TABLES[kind]} VALUES (?,?,?)',
                     (identity, canonical_json(data), revision))
        if kind == 'question':
            conn.execute('DELETE FROM ciph_curiosity_dependencies WHERE child_id=?', (identity,))
            conn.executemany('INSERT INTO ciph_curiosity_dependencies VALUES (?,?)',
                             [(identity, parent) for parent in data['depends_on']])

    def put(self, conn, kind, identity, data, reason):
        aggregate = f'curiosity:{kind}:{identity}'
        now = time.time()
        previous = self.runtime.event_store._get_latest_hash(conn)
        body = {'version': 1, 'kind': kind, 'id': identity, 'data': data,
                'reason': reason, 'aggregate_id': aggregate, 'timestamp': now,
                'previous_hash': previous, 'key_id': self.runtime.kernel_key_id}
        body['signature'] = Ed25519KeyManager.sign(self.runtime.kernel_priv_bytes, canonical_json(body).encode())
        payload = json.dumps(body, sort_keys=True, allow_nan=False)
        digest = hashlib.sha256(f'{previous}|CuriosityStateChangedEvent|{aggregate}|{payload}|{now}'.encode()).hexdigest()
        cursor = conn.execute('INSERT INTO ciph_event_store '
            '(event_type,aggregate_id,payload,timestamp,previous_hash,event_hash) VALUES (?,?,?,?,?,?)',
            ('CuriosityStateChangedEvent', aggregate, payload, now, previous, digest))
        self._apply(conn, kind, identity, data, cursor.lastrowid)

    def get(self, conn, kind, identity):
        row = conn.execute(f'SELECT * FROM {self.TABLES[kind]} WHERE id=?', (identity,)).fetchone()
        event = conn.execute('SELECT * FROM ciph_event_store WHERE aggregate_id=? '
            'AND event_type=? ORDER BY event_id DESC LIMIT 1',
            (f'curiosity:{kind}:{identity}', 'CuriosityStateChangedEvent')).fetchone()
        if not row and not event:
            if kind == 'budget' and identity == 'global':
                return {'paused': False, 'reason': None, 'failure_streak': 0,
                        'paused_at': None, 'last_error': None}
            return None
        if not row or not event:
            raise ContractValidationError('CURIOSITY_PROJECTION_MISSING')
        body = self._verify(event)
        if row['revision'] != event['event_id'] or row['payload'] != canonical_json(body['data']):
            raise ContractValidationError('CURIOSITY_PROJECTION_TAMPERED')
        return body['data']

    def all(self, conn, kind, limit=1024):
        prefix = f'curiosity:{kind}:'
        ids = [row[0] for row in conn.execute(
            f"SELECT id FROM {self.TABLES[kind]} UNION SELECT substr(aggregate_id, ?) "
            "FROM ciph_event_store WHERE event_type='CuriosityStateChangedEvent' "
            "AND substr(aggregate_id,1,?)=? ORDER BY 1 LIMIT ?",
            (len(prefix)+1, len(prefix), prefix, limit+1))]
        if len(ids) > limit:
            raise ContractValidationError('CURIOSITY_WORK_BUDGET_EXCEEDED')
        return [self.get(conn, kind, identity) for identity in ids]

    def replay(self):
        if not self.runtime.event_store.verify_integrity()[0]:
            raise ContractValidationError('CORRUPT_EVENT_STORE')
        with self.transaction() as conn:
            # Verify before changing projections; failure rolls back the entire rebuild.
            for table in self.TABLES.values():
                conn.execute(f'DELETE FROM {table}')
            conn.execute('DELETE FROM ciph_curiosity_dependencies')
            for row in conn.execute("SELECT * FROM ciph_event_store WHERE event_type='CuriosityStateChangedEvent' ORDER BY event_id").fetchall():
                event = self._verify(row)
                self._apply(conn, event['kind'], event['id'], event['data'], row['event_id'])

    def state(self):
        with self.transaction() as conn:
            return self.get(conn, 'budget', 'global')

    def pause(self, reason, failure=False):
        with self.transaction() as conn:
            state = self.get(conn, 'budget', 'global')
            state.update(paused=True, reason=reason, paused_at=time.time(), last_error=reason)
            if failure:
                state['failure_streak'] += 1
            self.put(conn, 'budget', 'global', state, reason)

    def resume(self, reason):
        """Trusted runtime/operator control; no caller field on a question can resume."""
        if not isinstance(reason, str) or not reason.strip():
            raise ContractValidationError('RESUME_REASON_REQUIRED')
        with self.transaction() as conn:
            state = self.get(conn, 'budget', 'global')
            state.update(paused=False, reason=None, paused_at=None, failure_streak=0)
            self.put(conn, 'budget', 'global', state, 'RUNTIME_RESUMED: '+reason)
            for question in self.all(conn, 'question'):
                if question['status'] == 'PAUSED' and not question.get('attempt_id'):
                    question['status'] = 'OPEN'
                    self.put(conn, 'question', question['question_id'], question, 'RESUMED')

    def reserve(self, question_id, max_count, max_cost):
        """The quota and question owner commit before execution. No refunds on uncertainty."""
        with self.transaction() as conn:
            q = self.get(conn, 'question', question_id)
            budget = self.get(conn, 'budget', 'global')
            if q['status'] != 'OPEN' or budget['paused']:
                return None
            from ciph.perception.curiosity_question import CuriosityQuestion
            questions = {d['question_id']: CuriosityQuestion.from_dict(d) for d in self.all(conn, 'question')} if q['depends_on'] else {}
            for identity in q['depends_on']:
                parent = questions[identity]
                if not self.runtime.question_dag.answer_is_current(parent, questions):
                    return None
            if self.runtime.worldview.is_in_graveyard(q['target_subject'], q['target_predicate']):
                return None
            now = time.time()
            attempts = self.all(conn, 'attempt', limit=10000)
            uncertain = next((a for a in attempts if a['question_id'] == question_id
                and a['status'] in ('RESERVED', 'RECONCILIATION_REQUIRED')), None)
            if uncertain:
                q.update(status='PAUSED', attempt_id=uncertain['attempt_id'], pause_reason='RECONCILIATION_REQUIRED')
                self.put(conn, 'question', question_id, q, 'RECONCILIATION_REQUIRED')
                return None
            recent = [a for a in attempts if a['reserved_at'] > now-3600]
            cost = max(1.0, q['estimated_cost_score'])
            if len(recent) >= max_count or sum(a['cost'] for a in recent)+cost > max_cost:
                budget.update(paused=True, reason='BUDGET_EXHAUSTED', paused_at=now)
                q.update(status='PAUSED', pause_reason='BUDGET_EXHAUSTED')
                self.put(conn, 'budget', 'global', budget, 'BUDGET_EXHAUSTED')
                self.put(conn, 'question', question_id, q, 'BUDGET_EXHAUSTED')
                return None
            attempt_id = 'INQ-'+uuid.uuid4().hex
            attempt = {'attempt_id': attempt_id, 'question_id': question_id,
                       'proposal_id': 'cmd_curiosity_'+attempt_id, 'reserved_at': now,
                       'cost': cost, 'status': 'RESERVED',
                       'receipt_id': None, 'job_id': None}
            q.update(status='SEARCHING', attempt_id=attempt_id)
            self.put(conn, 'attempt', attempt_id, attempt, 'RESERVED')
            self.put(conn, 'question', question_id, q, 'SEARCHING')
            if len(recent)+1 >= max_count or sum(a['cost'] for a in recent)+cost >= max_cost:
                budget.update(paused=True, reason='BUDGET_EXHAUSTED', paused_at=now)
                self.put(conn, 'budget', 'global', budget, 'BUDGET_EXHAUSTED')
            return attempt

    def finish(self, question_id, attempt_id, result, answered, threshold):
        with self.transaction() as conn:
            q = self.get(conn, 'question', question_id)
            attempt = self.get(conn, 'attempt', attempt_id)
            if q['attempt_id'] != attempt_id or attempt['status'] != 'RESERVED':
                return
            answered = answered or q['status'] == 'ANSWERED'
            receipt = result.get('receipt')
            uncertain = result.get('status') in ('RECONCILIATION_REQUIRED', 'INQUIRY_EXCEPTION', 'IN_FLIGHT')
            attempt.update(status='RECONCILIATION_REQUIRED' if uncertain else ('ANSWERED' if answered else 'UNRESOLVED'),
                receipt_id=receipt.receipt_id if receipt else None,
                job_id=receipt.job_id if receipt else result.get('job_id'))
            if not answered:
                q.update(status='PAUSED' if uncertain else 'UNRESOLVED', pause_reason=result.get('status'))
            budget = self.get(conn, 'budget', 'global')
            if answered:
                budget['failure_streak'] = 0
            else:
                budget['failure_streak'] += 1
                budget['last_error'] = result.get('status')
                if uncertain or budget['failure_streak'] >= threshold:
                    budget.update(paused=True, reason='RECONCILIATION_REQUIRED' if uncertain else 'CONSECUTIVE_FAILURES', paused_at=time.time())
            self.put(conn, 'attempt', attempt_id, attempt, attempt['status'])
            self.put(conn, 'question', question_id, q, q['status'])
            self.put(conn, 'budget', 'global', budget, 'ATTEMPT_COMPLETED')
