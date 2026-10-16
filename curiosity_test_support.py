"""
curiosity_test_support - canonical state builders shared by the 4.4 specimens.

Fixtures may bypass product UX and workflow layers; they may NOT bypass the epistemic constitution, so
every helper here writes real observations, real evidence links and real provenance - the same records
production writes.
"""

from ciph.kernel.epistemic_ledger import (
    RELATION_CONTRADICTS,
    RELATION_SUPPORTS,
    canonical_proposition,
    record_evidence,
    record_observation,
)
from ciph.kernel.source_dependence import RELATION_PRIMARY_OBSERVATION, record_provenance
from ciph.kernel.world_model import canonical_scope


def add_evidence(db, proposition, *, relation=RELATION_SUPPORTS, source_ref='s', at,
                 independent=True) -> str:
    """One observation plus one evidence link, optionally grounded as a primary observation."""
    observation = record_observation(db, source_ref=source_ref, raw_text='report', now=at)
    evidence = record_evidence(db, proposition, relation=relation, source_ref=source_ref,
                               observation_ref=observation['observation_id'], evidence_time=at,
                               now=at)
    if independent:
        record_provenance(db, from_evidence=evidence, relation=RELATION_PRIMARY_OBSERVATION, now=at)
    return evidence


def proposition(subject, predicate, value, *, at):
    return canonical_proposition(subject, predicate, value,
                                 temporal_scope=canonical_scope(at))


def converge(db, subject, predicate, value, *, at, relation=RELATION_SUPPORTS, sources=2):
    """Two (or more) grounded supports: enough for CONVERGENCE_V1 to reach a definite state."""
    prop = proposition(subject, predicate, value, at=at)
    refs = tuple(add_evidence(db, prop, relation=relation, source_ref=f'{predicate}-{index}', at=at)
                 for index in range(sources))
    return prop, refs


def unconverged(db, subject, predicate, value, *, at):
    """Evidence EXISTS but has not converged: exactly the `EPISTEMIC_UNRESOLVED` shape."""
    prop = proposition(subject, predicate, value, at=at)
    add_evidence(db, prop, source_ref=f'{predicate}-lone', at=at)
    return prop


def contested(db, subject, predicate, value, *, at):
    """Proven independent support AND proven independent contradiction: the `CONTESTED` shape."""
    prop = proposition(subject, predicate, value, at=at)
    for index in range(2):
        add_evidence(db, prop, relation=RELATION_SUPPORTS, source_ref=f'sup-{index}', at=at)
    for index in range(2):
        add_evidence(db, prop, relation=RELATION_CONTRADICTS, source_ref=f'con-{index}', at=at)
    return prop


def refute(db, subject, predicate, value, *, at, sources=2):
    """Grounded contradiction only: the claim is CONVERGED_REFUTED, so its world state is ABSENT."""
    prop = proposition(subject, predicate, value, at=at)
    refs = tuple(add_evidence(db, prop, relation=RELATION_CONTRADICTS,
                              source_ref=f'refute-{index}', at=at) for index in range(sources))
    return prop, refs
