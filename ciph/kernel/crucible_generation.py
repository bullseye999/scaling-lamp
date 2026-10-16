"""
ciph/kernel/crucible_generation - 4.5 Gate Six: the candidate-generation boundary.

The Crucible answers "is this candidate better?". It must not quietly become "generate arbitrary
self-modifications". A generator may only PROPOSE an artifact; identity freeze, evaluation and
promotion belong to other layers, and none of them is reachable from here.

    CandidateGenerator -> proposes CandidateArtifact
    CandidateRegistry  -> freezes identity
    Crucible           -> evaluates
    Governance         -> promotes
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Sequence, Tuple

from ciph.kernel.crucible_types import CrucibleError, VALID_KINDS, digest

SOURCE_OPERATOR = "OPERATOR"
SOURCE_CODEX = "CODEX"
SOURCE_AGY = "AGY"
SOURCE_CIPH_PLANNER = "CIPH_PLANNER"
SOURCE_LLM_PATCH = "LLM_PATCH"
SOURCE_ALTERNATE = "ALTERNATE_IMPLEMENTATION"
VALID_SOURCES = (SOURCE_OPERATOR, SOURCE_CODEX, SOURCE_AGY, SOURCE_CIPH_PLANNER, SOURCE_LLM_PATCH,
                 SOURCE_ALTERNATE)


@dataclass(frozen=True)
class CandidateProposal:
    """An untrusted suggestion. It has no candidate identity and grants nothing."""

    kind: str
    artifact_digest: str
    configuration_digest: str
    source: str
    rationale: Optional[str] = None
    parent_candidate_id: Optional[str] = None
    baseline_candidate_id: Optional[str] = None
    environment_requirements: Tuple[str, ...] = ()
    proposal_id: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {"proposal_id": self.proposal_id, "kind": self.kind,
                "artifact_digest": self.artifact_digest,
                "configuration_digest": self.configuration_digest, "source": self.source,
                "rationale": self.rationale, "parent_candidate_id": self.parent_candidate_id,
                "baseline_candidate_id": self.baseline_candidate_id,
                "environment_requirements": list(self.environment_requirements)}


def propose_candidate(*, kind: str, artifact_digest: str, configuration_digest: str, source: str,
                      rationale: Optional[str] = None, parent_candidate_id: Optional[str] = None,
                      baseline_candidate_id: Optional[str] = None,
                      environment_requirements: Sequence[str] = ()) -> CandidateProposal:
    """
    Propose an artifact for evaluation. Every source is untrusted - including Ciph's own planner.

    This function writes nothing anywhere. Registration is a separate, explicit act performed by the
    registry, so a generator cannot smuggle a candidate into evaluation by proposing it.
    """
    if kind not in VALID_KINDS:
        raise CrucibleError("INVALID_CANDIDATE_KIND", str(kind))
    if source not in VALID_SOURCES:
        raise CrucibleError("INVALID_CANDIDATE_SOURCE", str(source))
    if not artifact_digest or not configuration_digest:
        raise CrucibleError("PROPOSAL_REQUIRES_ARTIFACT_AND_CONFIGURATION",
                            f"{artifact_digest!r}/{configuration_digest!r}")
    proposal_id = "CPP-" + digest({"kind": kind, "artifact": artifact_digest,
                                   "configuration": configuration_digest, "source": source,
                                   "parent": parent_candidate_id,
                                   "baseline": baseline_candidate_id})[:16].upper()
    return CandidateProposal(kind=kind, artifact_digest=str(artifact_digest),
                             configuration_digest=str(configuration_digest), source=source,
                             rationale=rationale, parent_candidate_id=parent_candidate_id,
                             baseline_candidate_id=baseline_candidate_id,
                             environment_requirements=tuple(sorted(
                                 str(item) for item in environment_requirements)),
                             proposal_id=proposal_id)
