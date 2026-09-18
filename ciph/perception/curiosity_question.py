"""Typed, contextual curiosity questions. Evidence authority belongs to Phase 5."""
import copy
import hashlib
import math
import json
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Optional

from ciph.contracts.base import ContractValidationError
from ciph.contracts.epistemic import canonical_json
from ciph.workers.receipts import ExecutionReceipt


class QuestionPriority(str, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'


class QuestionStatus(str, Enum):
    OPEN = 'OPEN'
    SEARCHING = 'SEARCHING'
    ANSWERED = 'ANSWERED'
    BLOCKED = 'BLOCKED'
    UNRESOLVED = 'UNRESOLVED'
    PAUSED = 'PAUSED'


@dataclass
class CuriosityQuestion:
    question_id: str
    target_subject: str
    target_predicate: str
    question_text: str
    priority: QuestionPriority = QuestionPriority.MEDIUM
    status: QuestionStatus = QuestionStatus.OPEN
    estimated_cost_score: float = 1.0
    impact_score: float = 5.0
    relevance_score: float = 1.0
    risk_score: float = 0.0
    depends_on: list = field(default_factory=list)
    evidence_found: list = field(default_factory=list)
    answer_value: Any = None
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    dedup_hash: str = ''
    capability: Optional[str] = None
    parameters: dict = field(default_factory=dict)
    normalized_context_hash: Optional[str] = None
    environment_fingerprint: Optional[str] = None
    scope_id: Optional[str] = None
    answer_claim_id: Optional[str] = None
    attempt_id: Optional[str] = None
    pause_reason: Optional[str] = None
    search_internal_first: bool = True
    score_policy: str = 'PHASE6_FOUR_FACTOR_V1'

    def __post_init__(self):
        self.status = QuestionStatus(self.status)
        self.priority = QuestionPriority(self.priority)
        for key in ('question_id', 'target_subject', 'target_predicate', 'question_text'):
            value = getattr(self, key)
            if not isinstance(value, str) or not value.strip() or len(value) > 4096:
                raise ContractValidationError('INVALID_QUESTION_'+key.upper())
        for key, low, high in (('impact_score', 0, 10), ('relevance_score', 0, 1),
                               ('risk_score', 0, 1), ('estimated_cost_score', 0, 1000)):
            value = getattr(self, key)
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not low <= value <= high:
                raise ContractValidationError('INVALID_QUESTION_SCORE')
        if self.estimated_cost_score <= 0 or self.search_internal_first is not True:
            raise ContractValidationError('INVALID_INQUIRY_POLICY')
        if not math.isfinite(self.created_at) or self.created_at < 0 or self.created_at > time.time()+5:
            raise ContractValidationError('INVALID_QUESTION_TIME')
        if len(self.depends_on) > 256 or len(set(self.depends_on)) != len(self.depends_on):
            raise ContractValidationError('INVALID_QUESTION_DEPENDENCIES')
        identity = [self.target_subject, self.target_predicate, self.capability,
                    self.parameters, self.normalized_context_hash,
                    self.environment_fingerprint, self.scope_id]
        self.dedup_hash = hashlib.sha256(canonical_json(identity).encode()).hexdigest()
        if not isinstance(self.parameters, dict) or len(json.dumps(self.parameters, sort_keys=True, allow_nan=False)) > 65536:
            raise ContractValidationError('QUESTION_PARAMETERS_TOO_LARGE')

    def compute_priority_score(self):
        return (self.impact_score * self.relevance_score) / (self.estimated_cost_score * (1+self.risk_score))

    def to_dict(self):
        result = asdict(self)
        result.update(status=self.status.value, priority=self.priority.value)
        return result

    @classmethod
    def from_dict(cls, value):
        return cls(**copy.deepcopy(value))


class CuriosityQuestionDAG:
    MAX_QUESTIONS = 1024

    def __init__(self, runtime=None):
        self.runtime = runtime
        self.store = None
        self._memory = {}
        if runtime is not None:
            from ciph.perception.curiosity_store import CuriosityStore
            self.store = CuriosityStore(runtime)

    @property
    def _questions(self):
        """Compatibility snapshot; callers cannot mutate durable question state."""
        if self.store:
            with self.runtime.event_store._get_connection() as conn:
                conn.execute('BEGIN')
                return {q['question_id']: CuriosityQuestion.from_dict(q) for q in self.store.all(conn, 'question')}
        return copy.deepcopy(self._memory)

    def get_question(self, identity):
        return self._questions.get(identity)

    def propose_question(self, target_subject, target_predicate, question_text,
                         priority=QuestionPriority.MEDIUM, impact_score=5.0,
                         estimated_cost_score=1.0, depends_on=None, **requirements):
        permitted = {'relevance_score', 'risk_score', 'capability', 'parameters',
                     'normalized_context_hash', 'environment_fingerprint', 'scope_id', 'search_internal_first'}
        if set(requirements)-permitted:
            raise ContractValidationError('CALLER_QUESTION_STATE_REJECTED')
        if self.runtime and requirements.get('capability'):
            from ciph.workers.receipts import generate_environment_fingerprint
            requirements.setdefault('environment_fingerprint', generate_environment_fingerprint())
            parameters = requirements.get('parameters', {})
            if isinstance(parameters, dict):
                requirements.setdefault('scope_id', parameters.get('target'))
        q = CuriosityQuestion('pending', target_subject, target_predicate, question_text,
            priority=priority, impact_score=impact_score, estimated_cost_score=estimated_cost_score,
            depends_on=list(depends_on or ()), **requirements)
        q.question_id = 'QST-'+q.dedup_hash
        if self.store:
            with self.store.transaction() as conn:
                current = {v['question_id']: CuriosityQuestion.from_dict(v) for v in self.store.all(conn, 'question')}
                if q.question_id in current:
                    if current[q.question_id].depends_on != q.depends_on:
                        raise ContractValidationError('QUESTION_DEPENDENCIES_IMMUTABLE')
                    return None
                self._validate_new(q, current)
                self.store.put(conn, 'question', q.question_id, q.to_dict(), 'PROPOSED')
        else:
            if q.question_id in self._memory:
                if self._memory[q.question_id].depends_on != q.depends_on:
                    raise ContractValidationError('QUESTION_DEPENDENCIES_IMMUTABLE')
                return None
            self._validate_new(q, self._memory)
            self._memory[q.question_id] = copy.deepcopy(q)
        return q

    def _validate_new(self, q, current):
        if len(current) >= self.MAX_QUESTIONS:
            raise ContractValidationError('QUESTION_CAPACITY_EXCEEDED')
        visits = [0]
        def depth(identity, path):
            visits[0] += 1
            if visits[0] > 1024 or len(path) >= 16:
                raise ValueError('QUESTION_GRAPH_BUDGET_EXCEEDED')
            if identity == q.question_id or identity in path:
                raise ValueError('QUESTION_DEPENDENCY_CYCLE')
            if identity not in current:
                raise ValueError('QUESTION_PARENT_MISSING')
            for parent in current[identity].depends_on:
                depth(parent, path | {identity})
        for parent in q.depends_on:
            depth(parent, set())
            if sum(parent in node.depends_on for node in current.values()) >= 256:
                raise ValueError('QUESTION_WIDTH_EXCEEDED')
        if q.depends_on:
            q.status = QuestionStatus.BLOCKED

    def matching_claim(self, q, claim_id):
        """Authenticate current projection, context and exact receipt input binding."""
        if not self.runtime or (not q.capability and not q.normalized_context_hash):
            return None
        worldview = self.runtime.worldview
        claim = worldview.get_usable_claim(claim_id)
        if not claim or claim.subject != q.target_subject or claim.predicate != q.target_predicate:
            return None
        node = worldview.get_claim(claim_id)
        if q.normalized_context_hash and node.normalized_context_hash != q.normalized_context_hash:
            return None
        if q.scope_id and claim.scope_id != q.scope_id:
            return None
        if q.environment_fingerprint and claim.environment_fingerprint != q.environment_fingerprint:
            return None
        if node.valid_from is not None and node.valid_from > time.time():
            return None
        if claim.observation_ids:
            for identity in claim.observation_ids:
                observation = worldview.get_observation(identity)
                if observation is None:
                    return None
                worldview._validate_observation(observation)
        if q.capability:
            if len(claim.evidence_receipt_ids) != 1:
                return None
            receipt = worldview._receipt(claim.evidence_receipt_ids[0])
            if receipt.capability != q.capability or receipt.input_hash != ExecutionReceipt.hash_payload(q.parameters):
                return None
            # Failed application-level lookups are not answers about the stored record.
            if isinstance(receipt.results, dict) and receipt.results.get('success') is False:
                return None
            if q.target_predicate in ('stored_record', 'value') and isinstance(receipt.results, dict) and receipt.results.get('found') is False:
                return None
        return claim

    def answer_is_current(self, q, questions=None, visited=None, budget=None):
        """Question prerequisites also remain current through the complete DAG."""
        questions = self._questions if questions is None else questions
        visited = set() if visited is None else visited
        budget = [1024] if budget is None else budget
        if not q or q.status != QuestionStatus.ANSWERED or q.question_id in visited or len(visited) > 16 or budget[0] <= 0:
            return False
        budget[0] -= 1
        if not self.matching_claim(q, q.answer_claim_id):
            return False
        path = visited | {q.question_id}
        return all(self.answer_is_current(questions.get(parent), questions, path, budget) for parent in q.depends_on)

    def get_ready_unanswered_questions(self):
        current = self._questions
        # ANSWERED is a cached resolution, not perpetual permission for dependents.
        for q in current.values():
            if q.status == QuestionStatus.ANSWERED and not self.answer_is_current(q, current):
                self.set_status(q.question_id, QuestionStatus.OPEN, 'ANSWER_EVIDENCE_EXPIRED', clear_attempt=True)
                q.status = QuestionStatus.OPEN
        ready = []
        for q in current.values():
            if q.status not in (QuestionStatus.OPEN, QuestionStatus.BLOCKED):
                continue
            met = all(current[p].status == QuestionStatus.ANSWERED for p in q.depends_on)
            status = QuestionStatus.OPEN if met else QuestionStatus.BLOCKED
            if q.status != status:
                self.set_status(q.question_id, status, 'DEPENDENCIES_CHECKED')
                q.status = status
            if met:
                ready.append(q)
        return sorted(ready, key=lambda q: (-q.compute_priority_score(), q.created_at, q.question_id))

    def set_status(self, identity, status, reason, clear_attempt=False):
        if status == QuestionStatus.ANSWERED:
            raise ContractValidationError('VERIFIED_ANSWER_REQUIRED')
        if self.store:
            with self.store.transaction() as conn:
                q = self.store.get(conn, 'question', identity)
                # A concurrently owned investigation cannot be reset by a stale scheduler.
                if q['status'] == 'SEARCHING':
                    return
                q.update(status=status.value, pause_reason=reason)
                if clear_attempt:
                    q.update(attempt_id=None, answer_claim_id=None, answer_value=None, evidence_found=[])
                self.store.put(conn, 'question', identity, q, reason)
        else:
            self._memory[identity].status = status

    def resolve_question_with_evidence(self, question_id, answer_value=None, receipt_ids=None, *, claim_id=None):
        if not self.store or not claim_id:
            raise ContractValidationError('VERIFIED_ANSWER_CLAIM_REQUIRED')
        with self.store.transaction() as conn:
            data = self.store.get(conn, 'question', question_id)
            if data is None:
                return False
            q = CuriosityQuestion.from_dict(data)
            if self.runtime.worldview.is_in_graveyard(q.target_subject, q.target_predicate):
                return False
            questions = {d['question_id']: CuriosityQuestion.from_dict(d) for d in self.store.all(conn, 'question')} if q.depends_on else {}
            for parent in q.depends_on:
                p = questions[parent]
                if not self.answer_is_current(p, questions):
                    return False
            claim = self.matching_claim(q, claim_id)
            if not claim:
                return False
            value = claim.to_dict()['value']
            if answer_value is not None and canonical_json(answer_value) != canonical_json(value):
                raise ContractValidationError('UNBOUND_QUESTION_ANSWER')
            if receipt_ids is not None and list(receipt_ids) != list(claim.evidence_receipt_ids):
                raise ContractValidationError('UNBOUND_QUESTION_RECEIPTS')
            q.status = QuestionStatus.ANSWERED
            q.answer_claim_id = claim_id
            q.answer_value = value
            q.evidence_found = list(claim.evidence_receipt_ids)+list(claim.observation_ids)
            q.resolved_at = time.time()
            self.store.put(conn, 'question', question_id, q.to_dict(), 'EVIDENCE_RESOLVED')
            return True
