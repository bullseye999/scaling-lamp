"""
ciph/kernel/crucible_types - the shared vocabulary of the Crucible.

4.5. The Crucible is the courtroom and the proving ground: it answers *given a candidate, is it
actually better than what we run now*, and it never answers *should we change ourselves*.

Frozen policy identities. A historical Crucible decision must stay true even if a later version of a
policy would judge it differently:

    CRUCIBLE_CANDIDATE_ID_V1     Gate Zero
    CRUCIBLE_PROTOCOL_V1         Gate One
    CRUCIBLE_METRICS_V1          Gate Three
    CRUCIBLE_PARETO_V1           Gate Three
    CRUCIBLE_PROMOTION_V1        Gate Four
    CRUCIBLE_POST_PROMOTION_V1   Gate Five
    CRUCIBLE_DEPLOYMENT_V1       R6 (governed deployment)
"""

import hashlib
import json
from typing import Any

CRUCIBLE_CANDIDATE_ID_V1 = "CRUCIBLE_CANDIDATE_ID_V1"
CRUCIBLE_PROTOCOL_V1 = "CRUCIBLE_PROTOCOL_V1"
CRUCIBLE_METRICS_V1 = "CRUCIBLE_METRICS_V1"
CRUCIBLE_PARETO_V1 = "CRUCIBLE_PARETO_V1"
CRUCIBLE_PROMOTION_V1 = "CRUCIBLE_PROMOTION_V1"
CRUCIBLE_POST_PROMOTION_V1 = "CRUCIBLE_POST_PROMOTION_V1"
CRUCIBLE_DEPLOYMENT_V1 = "CRUCIBLE_DEPLOYMENT_V1"

KIND_PLANNER_STRATEGY = "PLANNER_STRATEGY"
KIND_REASONING_POLICY = "REASONING_POLICY"
KIND_MODEL_CONFIGURATION = "MODEL_CONFIGURATION"
KIND_CAPABILITY_IMPLEMENTATION = "CAPABILITY_IMPLEMENTATION"
KIND_TOOL_STRATEGY = "TOOL_STRATEGY"
KIND_PROMPT_POLICY = "PROMPT_POLICY"
VALID_KINDS = (KIND_PLANNER_STRATEGY, KIND_REASONING_POLICY, KIND_MODEL_CONFIGURATION,
               KIND_CAPABILITY_IMPLEMENTATION, KIND_TOOL_STRATEGY, KIND_PROMPT_POLICY)

DIRECTION_HIGHER_BETTER = "HIGHER_BETTER"
DIRECTION_LOWER_BETTER = "LOWER_BETTER"
VALID_DIRECTIONS = (DIRECTION_HIGHER_BETTER, DIRECTION_LOWER_BETTER)


class CrucibleError(Exception):
    """A Crucible operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


def digest(payload: Any) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def short(digest_value: str) -> str:
    return str(digest_value)[:16]
