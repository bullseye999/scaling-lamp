"""Phase 6: evidence-first, offline, bounded internal investigation."""
import math
import json
import hashlib
import threading
import time

from ciph.contracts.base import ContractValidationError
from ciph.contracts.enums import AuthorizationTier, NetworkPolicy, ReversibilityClass, RiskTier, ScopeType
from ciph.workers.receipts import generate_environment_fingerprint, compute_idempotency_key
from ciph.kernel.policy_engine import ScopeGrant
from ciph.kernel.network_sandbox import enforce_network_policy
from ciph.planner.schemas import IntentProposal
from ciph.perception.curiosity_question import QuestionStatus


class CuriosityDaemon:
    OFFLINE_CAPABILITIES = frozenset({'memory.retrieve', 'code.audit_dependencies', 'pentest.cvss_calculate'})

    def __init__(self, max_inquiries_per_hour=12, inquiry_interval_seconds=5.0,
                 allowed_capabilities=None, max_cost_per_hour=12.0, failure_threshold=3):
        if not isinstance(max_inquiries_per_hour, int) or max_inquiries_per_hour < 1:
            raise ValueError('INVALID_INQUIRY_QUOTA')
        if not isinstance(failure_threshold, int) or failure_threshold < 1:
            raise ValueError('INVALID_FAILURE_THRESHOLD')
        if not math.isfinite(max_cost_per_hour) or max_cost_per_hour <= 0:
            raise ValueError('INVALID_COST_QUOTA')
        if not math.isfinite(inquiry_interval_seconds) or inquiry_interval_seconds <= 0:
            raise ValueError('INVALID_INQUIRY_INTERVAL')
        self.max_inquiries_per_hour = max_inquiries_per_hour
        self.max_cost_per_hour = max_cost_per_hour
        self.failure_threshold = failure_threshold
        self.inquiry_interval_seconds = inquiry_interval_seconds
        self.allowed_capabilities = frozenset(self.OFFLINE_CAPABILITIES if allowed_capabilities is None else allowed_capabilities)
        self.inquiry_history = []  # Legacy diagnostic API, never dispatch authority.
        self.running = False
        self._thread = None
        self._stop = threading.Event()

    def can_inquire_under_budget(self, now=None):
        now = time.time() if now is None else now
        self.inquiry_history = [t for t in self.inquiry_history if t > now-3600]
        return len(self.inquiry_history) < self.max_inquiries_per_hour

    def record_inquiry(self, timestamp=None):
        self.inquiry_history.append(time.time() if timestamp is None else timestamp)

    def discover_epistemic_gaps(self, worldview):
        claims = worldview.query_active_claims(include_expired=True, include_archived=True, limit=100)
        gaps = [c for c in claims if c.lifecycle_state.value != 'ARCHIVED'
                and not worldview.is_in_graveyard(c.subject, c.predicate)
                and (not c.is_fresh() or c.lifecycle_state.value != 'ACTIVE' or c.state.value in ('DISPUTED', 'STALE'))]
        return sorted(gaps, key=lambda c: (c.assurance_score, c.claim_id))

    def _allowed(self, capability, runtime):
        cap = runtime.registry.get(capability) if capability else None
        if not cap or capability not in self.allowed_capabilities or capability not in self.OFFLINE_CAPABILITIES:
            return False
        manifest = cap.manifest
        return (manifest.network_policy == NetworkPolicy.OFFLINE_ONLY
                and manifest.reversibility == ReversibilityClass.READ_ONLY
                and manifest.authorization == AuthorizationTier.AUTO
                and manifest.risk_tier in (RiskTier.NONE, RiskTier.LOW))

    def _propose_gaps(self, runtime, gaps):
        for gap in gaps:
            canonical = runtime.worldview.get_canonical_claim(gap.claim_id)
            if not canonical or len(canonical.evidence_receipt_ids) != 1:
                continue
            proof = runtime.worldview._receipt(canonical.evidence_receipt_ids[0])
            job = runtime.queue.get_job(proof.job_id)
            # Re-investigate the actual recorded inputs. No text-to-capability guesses.
            runtime.question_dag.propose_question(gap.subject, gap.predicate,
                f'Recheck internal evidence for {gap.subject} [{gap.predicate}]',
                capability=proof.capability, parameters=job['params'],
                environment_fingerprint=generate_environment_fingerprint(),
                impact_score=max(1.0, 10.0-gap.assurance_score*10), relevance_score=1.0,
                risk_score=0.0, estimated_cost_score=1.0)

    def formulate_inquiry_proposal(self, gap_claim, runtime):
        """Compatibility method: only authenticated originating inputs may be repeated."""
        original = runtime.worldview.get_canonical_claim(gap_claim.claim_id)
        if not original or len(original.evidence_receipt_ids) != 1:
            return None
        proof = runtime.worldview._receipt(original.evidence_receipt_ids[0])
        if not self._allowed(proof.capability, runtime):
            return None
        job = runtime.queue.get_job(proof.job_id)
        return IntentProposal(proposal_id='curiosity_candidate_'+gap_claim.claim_id,
            objective=f'Recheck {gap_claim.subject}', proposed_capability=proof.capability,
            provided_parameters=job['params'], constraints={'source': 'curiosity_daemon'})

    def search_internal_evidence(self, q, runtime):
        """Search canonical claims then bounded committed receipts; never collect telemetry here."""
        dag = runtime.question_dag
        for identity in runtime.worldview.find_internal_claim_ids(q.target_subject, q.target_predicate):
            if dag.matching_claim(q, identity):
                return identity
        # Receipts may be durable before Phase 5 projection (e.g. interrupted coordinator).
        # Never re-project already represented evidence to undo its expiry/invalidation.
        with runtime.event_store._get_connection() as conn:
            rows = conn.execute("SELECT aggregate_id,payload FROM ciph_event_store WHERE event_type='ExecutionReceiptStoredEvent' "
                "AND json_extract(payload,'$.capability')=? AND json_extract(payload,'$.input_hash')=? "
                "ORDER BY event_id DESC LIMIT 100", (q.capability, self._input_hash(q.parameters))).fetchall()
        for row in rows:
            event = {'aggregate_id': row['aggregate_id'], 'payload': json.loads(row['payload'])}
            payload = event['payload']
            if not q.capability or payload.get('capability') != q.capability:
                continue
            if payload.get('input_hash') != self._input_hash(q.parameters):
                continue
            with runtime.worldview._get_connection() as conn:
                represented = conn.execute("SELECT claim_id,predicate FROM ciph_active_claims, json_each(evidence_receipt_ids) "
                    "WHERE json_each.value=? LIMIT 101", (event['aggregate_id'],)).fetchall()
            # A new registered predicate can be derived from an existing fresh report.
            # Its required parents preserve every original expiry and invalidation barrier.
            if len(represented) > 100 or any(row['predicate'] == q.target_predicate for row in represented):
                continue
            parents = [row['claim_id'] for row in represented]
            if any(runtime.worldview.get_usable_claim(identity) is None for identity in parents):
                continue
            try:
                receipt = runtime.worldview._receipt(event['aggregate_id'])
                candidate = runtime.claim_projector.project_claim(receipt, predicate=q.target_predicate, parent_claim_ids=parents)
                if candidate.subject != q.target_subject or not candidate.is_fresh():
                    continue
                runtime.worldview.admit_claim(candidate)
                if dag.matching_claim(q, candidate.claim_id):
                    return candidate.claim_id
            except ContractValidationError:
                continue
        return None

    @staticmethod
    def _input_hash(parameters):
        from ciph.workers.receipts import ExecutionReceipt
        return ExecutionReceipt.hash_payload(parameters)

    def run_inquiry_cycle(self, runtime):
        # This guard also covers evidence intake and adapter helper threads.
        with enforce_network_policy(NetworkPolicy.OFFLINE_ONLY):
            return self._run_cycle(runtime)

    def _run_cycle(self, runtime):
        results = []
        dag = runtime.question_dag
        store = dag.store
        runtime.worldview.reap_expired_claims()
        gaps = self.discover_epistemic_gaps(runtime.worldview)
        self._propose_gaps(runtime, gaps)
        ready = dag.get_ready_unanswered_questions()
        # Recover answers after a crash without retrying an uncertain invocation.
        recovering = [q for q in dag._questions.values() if q.status in (QuestionStatus.SEARCHING, QuestionStatus.UNRESOLVED, QuestionStatus.PAUSED)]
        candidates = (ready+recovering)[:100]
        dispatched = 0
        for q in candidates:
            if runtime.worldview.is_in_graveyard(q.target_subject, q.target_predicate):
                continue
            identity = self.search_internal_evidence(q, runtime)
            if identity and dag.resolve_question_with_evidence(q.question_id, claim_id=identity):
                results.append({'status': 'ANSWERED_INTERNAL', 'question_id': q.question_id,
                    'claim_id': identity, 'dispatched': False, 'answered': True})
                if q.attempt_id:
                    with store.transaction() as conn:
                        attempt = store.get(conn, 'attempt', q.attempt_id)
                    if attempt and attempt['status'] == 'RESERVED':
                        proof_ids = runtime.worldview.get_canonical_claim(identity).evidence_receipt_ids
                        proof = runtime.worldview._receipt(proof_ids[0]) if proof_ids else None
                        digest = hashlib.sha256(attempt['proposal_id'].encode()).hexdigest()
                        expected_key = compute_idempotency_key('plan_'+digest, 'step_'+digest, self._input_hash(q.parameters))
                        if proof and proof.idempotency_key == expected_key:
                            store.finish(q.question_id, q.attempt_id, {'status': 'SUCCESS', 'receipt': proof}, True, self.failure_threshold)
                        # A different execution may answer the question, but cannot
                        # establish the outcome of this reserved attempt.

                continue
            if q.status != QuestionStatus.OPEN:
                if q.status == QuestionStatus.SEARCHING:
                    results.append({'status': 'RECONCILIATION_REQUIRED', 'question_id': q.question_id, 'dispatched': False, 'answered': False})
                continue
            if not self._allowed(q.capability, runtime):
                dag.set_status(q.question_id, QuestionStatus.UNRESOLVED, 'OFFLINE_POLICY_BLOCKED')
                results.append({'status': 'SAFETY_BLOCKED_REQUIRES_OPERATOR', 'question_id': q.question_id,
                                'dispatched': False, 'answered': False})
                continue
            if dispatched >= 3 or store.state()['paused']:
                continue
            # Check dependency evidence again immediately before reserving work.
            if any(not dag.matching_claim(dag.get_question(p), dag.get_question(p).answer_claim_id) for p in q.depends_on):
                continue
            attempt = store.reserve(q.question_id, self.max_inquiries_per_hour, self.max_cost_per_hour)
            if not attempt:
                continue
            proposal = IntentProposal(proposal_id=attempt['proposal_id'],
                objective=q.question_text, proposed_capability=q.capability, provided_parameters=q.parameters,
                constraints={'source': 'curiosity_daemon', 'question_id': q.question_id,
                             'offline_only': True, 'attempt_id': attempt['attempt_id']})
            scope = ScopeGrant(scope_id='scope_curiosity_ro', scope_type=ScopeType.LOCAL_SYSTEM,
                allowed_targets=[q.target_subject], valid_until=time.time()+60)
            dispatched += 1
            try:
                # Recheck policies and burial after reservation, before any worker lease.
                if not self._allowed(q.capability, runtime) or runtime.worldview.is_in_graveyard(q.target_subject, q.target_predicate):
                    result = {'status': 'OFFLINE_POLICY_BLOCKED'}
                else:
                    result = runtime.execute_reference_loop(proposal, scope_grant=scope, claim_predicate=q.target_predicate)
                candidate = result.get('claim')
                answered = bool(candidate and dag.resolve_question_with_evidence(q.question_id, claim_id=candidate.claim_id))
            except Exception as error:
                result = {'status': 'INQUIRY_EXCEPTION', 'error': f'{type(error).__name__}: {error}'}
                answered = False
            store.finish(q.question_id, attempt['attempt_id'], result, answered, self.failure_threshold)
            receipt = result.get('receipt')
            results.append({'status': result['status'], 'question_id': q.question_id,
                'proposal_id': proposal.proposal_id, 'receipt_id': receipt.receipt_id if receipt else None,
                'claim_id': result['claim'].claim_id if result.get('claim') else None,
                'dispatched': True, 'answered': answered})
        return results

    def start(self, runtime):
        if self.running:
            return
        self.running = True
        self._stop.clear()
        def loop():
            while not self._stop.is_set():
                try:
                    self.run_inquiry_cycle(runtime)
                except Exception as error:
                    runtime.question_dag.store.pause(f'CYCLE_ERROR: {type(error).__name__}: {error}', failure=True)
                self._stop.wait(self.inquiry_interval_seconds)
        self._thread = threading.Thread(target=loop, name='CIPH-CuriosityDaemon', daemon=True)
        self._thread.start()

    def stop(self):
        self.running = False
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
