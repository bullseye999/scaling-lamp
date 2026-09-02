"""
ciph.perception.curiosity_question - Governed Curiosity Question DAG (CIPH 4.0 Blueprint Phase 6).
Represents epistemic questions with topological dependencies, prioritized by impact/relevance/cost/risk,
searching internal evidence first.
"""

import time
import uuid
import hashlib
from enum import Enum
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, field, asdict


class QuestionPriority(str, Enum):
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class QuestionStatus(str, Enum):
    OPEN        = "OPEN"
    SEARCHING   = "SEARCHING"
    ANSWERED    = "ANSWERED"
    BLOCKED     = "BLOCKED"
    UNRESOLVED  = "UNRESOLVED"
    PAUSED      = "PAUSED"


@dataclass
class CuriosityQuestion:
    question_id: str
    target_subject: str
    target_predicate: str
    question_text: str
    priority: QuestionPriority = QuestionPriority.MEDIUM
    status: QuestionStatus = QuestionStatus.OPEN
    estimated_cost_score: float = 1.0     # 1.0 = offline internal query, 10.0 = expensive probe
    impact_score: float = 5.0             # 1.0 to 10.0
    depends_on: List[str] = field(default_factory=list)
    evidence_found: List[str] = field(default_factory=list)
    answer_value: Any = None
    created_at: float = field(default_factory=time.time)
    resolved_at: Optional[float] = None
    dedup_hash: str = ""

    def __post_init__(self):
        if not self.dedup_hash:
            self.dedup_hash = hashlib.sha256(f"{self.target_subject}:{self.target_predicate}".encode()).hexdigest()

    def compute_priority_score(self) -> float:
        """Deterministic priority formula: (Impact * 2.0) / EstimatedCost."""
        return round((self.impact_score * 2.0) / max(self.estimated_cost_score, 0.1), 3)


class CuriosityQuestionDAG:
    """
    Manages active curiosity question DAG, topological dependency resolution,
    deduplication, and internal evidence linking.
    """

    def __init__(self):
        self._questions: Dict[str, CuriosityQuestion] = {}
        self._hash_to_qid: Dict[str, str] = {}
        self._children: Dict[str, List[str]] = {}

    def propose_question(
        self,
        target_subject: str,
        target_predicate: str,
        question_text: str,
        priority: QuestionPriority = QuestionPriority.MEDIUM,
        impact_score: float = 5.0,
        estimated_cost_score: float = 1.0,
        depends_on: Optional[List[str]] = None
    ) -> Optional[CuriosityQuestion]:
        """Propose a new curiosity question with automatic deduplication and dependency edges."""
        dedup_hash = hashlib.sha256(f"{target_subject}:{target_predicate}".encode()).hexdigest()
        if dedup_hash in self._hash_to_qid:
            existing_id = self._hash_to_qid[dedup_hash]
            existing = self._questions.get(existing_id)
            if existing and existing.status in (QuestionStatus.OPEN, QuestionStatus.SEARCHING, QuestionStatus.BLOCKED):
                return None  # Deduplicated

        deps = depends_on or []
        for dep in deps:
            if dep not in self._questions:
                raise ValueError(f"Dependency question '{dep}' does not exist in Question DAG.")

        qid = f"QST-{uuid.uuid4().hex[:8].upper()}"
        initial_status = QuestionStatus.BLOCKED if any(self._questions[d].status != QuestionStatus.ANSWERED for d in deps) else QuestionStatus.OPEN

        q = CuriosityQuestion(
            question_id=qid,
            target_subject=target_subject,
            target_predicate=target_predicate,
            question_text=question_text,
            priority=priority,
            status=initial_status,
            estimated_cost_score=estimated_cost_score,
            impact_score=impact_score,
            depends_on=deps,
            dedup_hash=dedup_hash
        )
        self._questions[qid] = q
        self._hash_to_qid[dedup_hash] = qid

        for dep in deps:
            if dep not in self._children:
                self._children[dep] = []
            self._children[dep].append(qid)

        return q

    def get_ready_unanswered_questions(self) -> List[CuriosityQuestion]:
        """Return actionable open questions whose dependencies have all been ANSWERED, ordered by priority."""
        ready = []
        for q in self._questions.values():
            if q.status in (QuestionStatus.OPEN, QuestionStatus.BLOCKED):
                all_deps_met = all(
                    dep in self._questions and self._questions[dep].status == QuestionStatus.ANSWERED
                    for dep in q.depends_on
                )
                if all_deps_met:
                    q.status = QuestionStatus.OPEN
                    ready.append(q)
                else:
                    q.status = QuestionStatus.BLOCKED

        ready.sort(key=lambda q: q.compute_priority_score(), reverse=True)
        return ready

    def resolve_question_with_evidence(
        self,
        question_id: str,
        answer_value: Any,
        receipt_ids: List[str]
    ) -> bool:
        """Mark question as answered with linked evidence receipts and unblock dependent child questions."""
        q = self._questions.get(question_id)
        if not q:
            return False
        q.status = QuestionStatus.ANSWERED
        q.answer_value = answer_value
        q.evidence_found = receipt_ids
        q.resolved_at = time.time()

        # Check and unblock children
        for child_id in self._children.get(question_id, []):
            child = self._questions.get(child_id)
            if child and child.status == QuestionStatus.BLOCKED:
                if all(self._questions[d].status == QuestionStatus.ANSWERED for d in child.depends_on):
                    child.status = QuestionStatus.OPEN

        return True
