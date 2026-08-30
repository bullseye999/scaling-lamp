"""
ciph.planner.skill_registry - Procedural Skill Registry & 5-Stage Promotion Engine.
Caches validated DAG templates with environment drift hashes and confidence decay TTLs.
"""

import time
import hashlib
from typing import Dict, Any, List, Optional
from ciph.planner.schemas import SkillTemplate, SkillPromotionTier, ExecutionDAG, PlanStep


class SkillRegistry:
    """
    Manages reusable, parameterized procedural DAG skills.
    Enforces a strict 5-stage promotion lifecycle and checks environment hashes against drift.
    """

    def __init__(self):
        self._templates: Dict[str, SkillTemplate] = {}

    def register_candidate(
        self,
        signature: str,
        parameter_slots: List[str],
        dag_nodes: List[PlanStep],
        precondition_hash: str,
        confidence_decay_ttl: int = 604800
    ) -> SkillTemplate:
        """Register a new candidate template from a successfully executed DAG."""
        template_id = f"skill_{signature}_{hashlib.sha256(signature.encode()).hexdigest()[:8]}"
        template = SkillTemplate(
            template_id=template_id,
            signature=signature,
            parameter_slots=parameter_slots,
            dag_nodes=dag_nodes,
            precondition_hash=precondition_hash,
            confidence_decay_ttl=confidence_decay_ttl,
            promotion_tier=SkillPromotionTier.CANDIDATE,
            flawless_runs_count=1,
            created_at=time.time()
        )
        self._templates[signature] = template
        return template

    def record_run(self, signature: str, success: bool) -> None:
        """Record execution result for promotion/revocation tracking."""
        template = self._templates.get(signature)
        if not template:
            return

        if success:
            template.flawless_runs_count += 1
            # Auto-promote from CANDIDATE to VALIDATED after >= 3 clean runs
            if template.flawless_runs_count >= 3 and template.promotion_tier == SkillPromotionTier.CANDIDATE:
                template.promotion_tier = SkillPromotionTier.VALIDATED
        else:
            # Demote on execution failure
            template.promotion_tier = SkillPromotionTier.REVOKED

    def approve_skill(self, signature: str, auto_activate: bool = False) -> bool:
        """Operator sign-off promoting skill from VALIDATED/CANDIDATE to APPROVED (or ACTIVE if auto_activate)."""
        template = self._templates.get(signature)
        if template and template.promotion_tier in (SkillPromotionTier.VALIDATED, SkillPromotionTier.CANDIDATE):
            template.promotion_tier = SkillPromotionTier.ACTIVE if auto_activate else SkillPromotionTier.APPROVED
            return True
        return False

    def activate_skill(self, signature: str) -> bool:
        """Promote an APPROVED skill to ACTIVE fast-path."""
        template = self._templates.get(signature)
        if template and template.promotion_tier == SkillPromotionTier.APPROVED:
            template.promotion_tier = SkillPromotionTier.ACTIVE
            return True
        return False

    def match_and_instantiate(
        self,
        signature: str,
        runtime_params: Dict[str, Any],
        current_env_hash: str
    ) -> Optional[ExecutionDAG]:
        """
        Attempts to match a fast-path template.
        Returns instantiated ExecutionDAG if active and environment matches, or None on Cache Miss / Drift.
        """
        template = self._templates.get(signature)
        if not template:
            return None

        # 1. Tier check: Must be ACTIVE
        if template.promotion_tier != SkillPromotionTier.ACTIVE:
            return None

        # 2. TTL check: Check confidence decay
        if template.is_expired(time.time()):
            template.promotion_tier = SkillPromotionTier.REVOKED
            return None

        # 3. Drift check: Compare precondition hash
        if template.precondition_hash != current_env_hash:
            return None  # Environment drifted -> Force slow-path planning

        # 4. Instantiate parameterized DAG steps
        instantiated_steps = []
        for node in template.dag_nodes:
            step_params = dict(node.parameters)
            for slot in template.parameter_slots:
                if slot in runtime_params:
                    # Substitute parameter slot
                    for k, v in list(step_params.items()):
                        if v == f"${slot}":
                            step_params[k] = runtime_params[slot]

            instantiated_steps.append(
                PlanStep(
                    step_id=node.step_id,
                    capability=node.capability,
                    parameters=step_params,
                    depends_on=list(node.depends_on),
                    reversibility=node.reversibility,
                    compensation_action=node.compensation_action,
                    compensation_params=node.compensation_params,
                    success_condition=node.success_condition,
                    timeout_seconds=node.timeout_seconds,
                    authorization_tier=node.authorization_tier
                )
            )

        return ExecutionDAG(
            plan_id=f"DAG-{signature}-{int(time.time())}",
            objective=f"Fast-path execution of {signature}",
            steps=instantiated_steps,
            is_parameterized_template=True,
            template_signature=signature
        )
