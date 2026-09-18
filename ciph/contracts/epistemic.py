"""
ciph.contracts.epistemic - First-Class Observation and Claim Contracts.
Enforces that VERIFIED_REAL claims can only be minted via verified receipt attestation.
"""

import time
import hmac
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, List, Tuple, Sequence
from collections import namedtuple
from collections.abc import Mapping

from ciph.contracts.enums import (
    ReliabilityClass,
    EpistemicState,
    LifecycleState,
    DecayProfile,
    DECAY_DURATIONS_SECONDS,
    RELIABILITY_BASE_WEIGHTS,
    OutcomeCategory,
)
from ciph.contracts.base import ContractValidationError, canonical_json, freeze_value, _unfreeze
 
class EpistemicAdmissionError(ContractValidationError):
    """Raised when a claim fails strict admission gates into MaterializedWorldview."""
    pass

def _get_receipt_class():
    from ciph.workers.receipts import ExecutionReceipt
    return ExecutionReceipt


class _RuntimeReceiptVerifier:
    """Narrow, runtime-bound receipt verification facade."""

    __slots__ = ("__registry", "authority_fingerprint")

    def __init__(self, *args: Any, **kwargs: Any):
        raise ContractValidationError(
            "CALLER_CONTROLLED_AUTHORITY_REJECTED: Receipt verifiers are created only by CiphRuntime."
        )

    @classmethod
    def _from_runtime(cls, registry: Any, operator_public_key: bytes) -> "_RuntimeReceiptVerifier":
        obj = object.__new__(cls)
        object.__setattr__(obj, "_RuntimeReceiptVerifier__registry", registry)
        fingerprint = hashlib.sha256(bytes(operator_public_key)).hexdigest()
        object.__setattr__(obj, "authority_fingerprint", fingerprint)
        return obj

    def verify(self, receipt: Any, current_time: float) -> Tuple[bool, str]:
        return receipt.verify(self.__registry, current_time=current_time)

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        record = self.__registry.get_key(key_id)
        return dict(record) if record is not None else None


SUPPORTED_EPISTEMIC_VERSIONS = {"1.0"}


import math

def _validate_timestamp(ts: Any, name: str, allow_none: bool = False, allow_future: bool = False, max_future_skew: float = 5.0) -> Optional[float]:
    """Validate that a timestamp is a finite, non-negative float within clock-skew bounds."""
    if ts is None:
        if allow_none:
            return None
        raise ContractValidationError(f"TIMESTAMP_REQUIRED: '{name}' cannot be None.")
    try:
        val = float(ts)
    except (TypeError, ValueError):
        raise ContractValidationError(f"MALFORMED_TIMESTAMP: '{name}' must be a finite float, got {ts!r}")
    if not math.isfinite(val) or val < 0.0:
        raise ContractValidationError(f"NON_FINITE_TIMESTAMP: '{name}' must be finite and non-negative, got {val}")
    now = time.time()
    if not allow_future and val > now + max_future_skew:
        raise ContractValidationError(
            f"FUTURE_TIMESTAMP_REJECTED (FUTURE_TIMESTAMP_SKEW_EXCEEDED): '{name}' ({val}) cannot be in the future (now: {now}, max skew: {max_future_skew}s)"
        )
    return val


@dataclass(frozen=True)
class Observation:
    """
    Untrusted external telemetry intake.
    Observations never represent accepted belief until passed through epistemic projection.
    Deeply immutable.
    """
    observation_id: str
    source: str
    subject: str
    predicate: str
    value: Any
    observed_at: float = field(default_factory=time.time)
    collected_at: float = field(default_factory=time.time)
    ingested_at: float = field(default_factory=time.time)
    expires_at: Optional[float] = None
    raw_evidence_ref: str = ""
    raw_evidence_digest: str = ""
    reliability_class: ReliabilityClass = ReliabilityClass.DIRECT_SENSOR
    scope_id: Optional[str] = None
    environment: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)
    uncertain_source_time: bool = False
    schema_version: str = "1.0"

    def __init__(
        self,
        observation_id: str,
        source: str,
        subject: str,
        predicate: str,
        value: Any,
        observed_at: Optional[float] = None,
        collected_at: Optional[float] = None,
        ingested_at: Optional[float] = None,
        expires_at: Optional[float] = None,
        raw_evidence_ref: str = "",
        raw_evidence_digest: str = "",
        reliability_class: ReliabilityClass = ReliabilityClass.DIRECT_SENSOR,
        scope_id: Optional[str] = None,
        environment: Optional[Any] = None,
        uncertain_source_time: bool = False,
        schema_version: str = "1.0"
    ):
        if schema_version not in SUPPORTED_EPISTEMIC_VERSIONS:
            raise ContractValidationError(f"Unsupported Observation schema_version: {schema_version}")

        now = time.time()
        obs_time = _validate_timestamp(observed_at, "observed_at", allow_none=True)
        if obs_time is None:
            obs_time = now
            uncertain_source_time = True

        coll_time = _validate_timestamp(collected_at, "collected_at", allow_none=True)
        if coll_time is None:
            coll_time = obs_time

        ing_time = _validate_timestamp(ingested_at, "ingested_at", allow_none=True)
        if ing_time is None:
            ing_time = now

        exp_time = _validate_timestamp(expires_at, "expires_at", allow_none=True, allow_future=True)

        object.__setattr__(self, "observation_id", str(observation_id))
        object.__setattr__(self, "source", str(source))
        object.__setattr__(self, "subject", str(subject))
        object.__setattr__(self, "predicate", str(predicate))
        object.__setattr__(self, "value", freeze_value(value))
        object.__setattr__(self, "observed_at", obs_time)
        object.__setattr__(self, "collected_at", coll_time)
        object.__setattr__(self, "ingested_at", ing_time)
        object.__setattr__(self, "expires_at", exp_time)
        object.__setattr__(self, "raw_evidence_ref", str(raw_evidence_ref))
        object.__setattr__(self, "raw_evidence_digest", str(raw_evidence_digest))
        object.__setattr__(self, "scope_id", str(scope_id) if scope_id is not None else None)
        object.__setattr__(self, "uncertain_source_time", bool(uncertain_source_time))

        rc = reliability_class if isinstance(reliability_class, ReliabilityClass) else ReliabilityClass(reliability_class)
        object.__setattr__(self, "reliability_class", rc)

        # Freeze environment dictionary deeply into tuple of sorted key-value pairs
        env_raw = dict(environment) if isinstance(environment, Mapping) else dict(environment or {})
        env_tuple = tuple(sorted((str(k), freeze_value(v)) for k, v in env_raw.items()))
        object.__setattr__(self, "environment", env_tuple)
        object.__setattr__(self, "schema_version", schema_version)

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if observation has passed its freshness deadline (anchored to collection/observation time)."""
        if self.expires_at is None:
            return False
        now = current_time if current_time is not None else time.time()
        return now > self.expires_at

    def compute_content_hash(self) -> str:
        """Compute versioned canonical SHA-256 fingerprint of the observation and its provenance metadata."""
        payload = {
            "schema_version": self.schema_version,
            "source": self.source,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": self.value,
            "observed_at": self.observed_at,
            "collected_at": self.collected_at,
            "expires_at": self.expires_at,
            "scope_id": self.scope_id,
            "raw_evidence_ref": self.raw_evidence_ref,
            "raw_evidence_digest": self.raw_evidence_digest,
            "reliability_class": self.reliability_class.value,
            "uncertain_source_time": self.uncertain_source_time,
            "environment": self.environment,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    @property
    def content_hash(self) -> str:
        """Convenience property for canonical content hash."""
        return self.compute_content_hash()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "source": self.source,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": _unfreeze(self.value),
            "observed_at": self.observed_at,
            "collected_at": self.collected_at,
            "ingested_at": self.ingested_at,
            "expires_at": self.expires_at,
            "raw_evidence_ref": self.raw_evidence_ref,
            "raw_evidence_digest": self.raw_evidence_digest,
            "reliability_class": self.reliability_class.value,
            "scope_id": self.scope_id,
            "uncertain_source_time": self.uncertain_source_time,
            "environment": {k: _unfreeze(v) for k, v in self.environment},
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Observation":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_EPISTEMIC_VERSIONS:
            raise ContractValidationError(f"Unsupported Observation schema_version: {ver}")
        rc = d.get("reliability_class", ReliabilityClass.DIRECT_SENSOR)
        if isinstance(rc, str):
            rc = ReliabilityClass(rc)
        return cls(
            observation_id=d["observation_id"],
            source=d["source"],
            subject=d["subject"],
            predicate=d["predicate"],
            value=d["value"],
            observed_at=d.get("observed_at"),
            collected_at=d.get("collected_at"),
            ingested_at=d.get("ingested_at"),
            expires_at=d.get("expires_at"),
            raw_evidence_ref=d.get("raw_evidence_ref", ""),
            raw_evidence_digest=d.get("raw_evidence_digest", ""),
            reliability_class=rc,
            scope_id=d.get("scope_id"),
            environment=d.get("environment", {}),
            uncertain_source_time=d.get("uncertain_source_time", False),
            schema_version=ver
        )


class ObservationIngestor:
    """
    Controlled intake pipeline for external and internal observations.
    Enforces payload integrity, source attribution, timestamp validation,
    policy-bounded reliability, and anti-forgery validation.
    """
    EXTERNAL_PREFIXES = ("http://", "https://", "feed://", "external:", "untrusted:", "webhook:", "rss:")

    @classmethod
    def ingest(
        cls,
        source: str,
        subject: str,
        predicate: str,
        value: Any,
        raw_evidence_ref: str = "",
        raw_payload: Optional[bytes] = None,
        expected_content_hash: Optional[str] = None,
        reliability_class: Optional[ReliabilityClass] = None,
        observed_at: Optional[float] = None,
        collected_at: Optional[float] = None,
        expires_at: Optional[float] = None,
        scope_id: Optional[str] = None,
        environment: Optional[Any] = None,
        ingress_receipt: Optional[Any] = None,
        uncertain_source_time: bool = False,
        schema_version: str = "1.0",
    ) -> Observation:
        import uuid
        now = time.time()

        # Timestamp validations (finite, non-negative, bounded skew)
        obs_time = _validate_timestamp(observed_at, "observed_at", allow_none=True)
        if obs_time is None:
            obs_time = now
            uncertain_source_time = True

        coll_time = _validate_timestamp(collected_at, "collected_at", allow_none=True)
        if coll_time is None:
            coll_time = obs_time

        exp_time = _validate_timestamp(expires_at, "expires_at", allow_none=True, allow_future=True)

        # Raw evidence digest calculation and verification
        raw_digest = ""
        if raw_payload is not None:
            raw_digest = hashlib.sha256(raw_payload).hexdigest()
            if expected_content_hash and not hmac.compare_digest(raw_digest, expected_content_hash):
                raise ContractValidationError(
                    f"OBSERVATION_PAYLOAD_INTEGRITY_MISMATCH: expected hash {expected_content_hash}, got {raw_digest}"
                )

        rc = ReliabilityClass(reliability_class) if reliability_class is not None else ReliabilityClass.UNVERIFIED_INCOMING
        if rc not in (ReliabilityClass.THIRD_PARTY_FEED, ReliabilityClass.UNVERIFIED_INCOMING):
            raise ContractValidationError("FORGED_RELIABILITY_REJECTED: source labels do not establish authority")
        if ingress_receipt is not None:
            raise ContractValidationError("Use runtime.worldview.ingest_observation for receipt-bound intake")
        if expected_content_hash and raw_payload is None:
            raise ContractValidationError("OBSERVATION_PAYLOAD_REQUIRED")

        obs_id = f"OBS-{uuid.uuid4().hex[:8].upper()}"
        return Observation(
            observation_id=obs_id,
            source=source,
            subject=subject,
            predicate=predicate,
            value=value,
            observed_at=obs_time,
            collected_at=coll_time,
            ingested_at=now,
            expires_at=exp_time,
            raw_evidence_ref=raw_evidence_ref,
            raw_evidence_digest=raw_digest,
            reliability_class=rc,
            scope_id=scope_id,
            environment=environment,
            uncertain_source_time=uncertain_source_time,
            schema_version=schema_version,
        )


_ClaimTupleBase = namedtuple(
    "_ClaimTupleBase",
    (
        "claim_id",
        "subject",
        "predicate",
        "value",
        "epistemic_state",
        "lifecycle_state",
        "decay_profile",
        "assurance_score",
        "evidence_receipt_ids",
        "observation_ids",
        "parent_claim_ids",
        "freshness_deadline",
        "scope_id",
        "environment_fingerprint",
        "authority_fingerprint",
        "created_at",
        "updated_at",
        "schema_version",
    ),
)


class Claim(_ClaimTupleBase):
    """
    Atomic unit of accepted truth in the MaterializedWorldview.
    Deeply immutable: evidence and parent links are frozen tuples.
    Security Invariant: VERIFIED_REAL cannot be instantiated arbitrarily via from_dict() or constructor.
    It requires verified receipt attestation and content binding via a runtime ClaimProjector.
    """
    __slots__ = ()

    @classmethod
    def _make(cls, iterable: Any) -> "Claim":
        raise ContractValidationError(
            "UNAUTHORIZED_CLAIM_CONSTRUCTION: Claim._make() is disabled; use the validated constructor."
        )

    def _replace(self, **kwargs: Any) -> "Claim":
        raise ContractValidationError(
            "UNAUTHORIZED_CLAIM_CONSTRUCTION: Claim._replace() is disabled; create a newly validated claim."
        )

    def __new__(
        cls,
        claim_id: str,
        subject: str,
        predicate: str,
        value: Any,
        epistemic_state: EpistemicState,
        lifecycle_state: LifecycleState = LifecycleState.ACTIVE,
        decay_profile: DecayProfile = DecayProfile.SOFTWARE_BEHAVIOR,
        assurance_score: float = 0.5,
        evidence_receipt_ids: Any = (),
        observation_ids: Any = (),
        parent_claim_ids: Any = (),
        freshness_deadline: Optional[float] = None,
        scope_id: Optional[str] = None,
        environment_fingerprint: str = "",
        authority_fingerprint: str = "",
        created_at: Optional[float] = None,
        updated_at: Optional[float] = None,
        schema_version: str = "1.0",
        receipt: Optional[Any] = None,
        _receipt_verifier: Optional[Any] = None,
        **kwargs
    ):
        if "trust_registry" in kwargs or "secret_key" in kwargs:
            raise ContractValidationError(
                "CALLER_CONTROLLED_AUTHORITY_REJECTED: Verification authority (trust_registry / secret_key) "
                "cannot be provided by caller. Authoritative registry must be managed internally."
            )

        if schema_version not in SUPPORTED_EPISTEMIC_VERSIONS:
            raise ContractValidationError(f"Unsupported Claim schema_version: {schema_version}")

        es = epistemic_state if isinstance(epistemic_state, EpistemicState) else EpistemicState(epistemic_state)

        # Constitutional Invariant: Observations are external intakes and cannot assert VERIFIED_REAL
        if es == EpistemicState.VERIFIED_REAL and (observation_ids or kwargs.get("observation") is not None):
            raise ContractValidationError(
                "OBSERVATION_CANNOT_MINT_VERIFIED_REAL: Observations are external intakes and cannot assert VERIFIED_REAL."
            )

        # Constitutional Invariant: Arbitrary callers cannot instantiate VERIFIED_REAL without authentic ExecutionReceipt attestation
        if es == EpistemicState.VERIFIED_REAL:
            ExecutionReceipt = _get_receipt_class()
            if receipt is None or not isinstance(receipt, ExecutionReceipt):
                raise ContractValidationError(
                    "UNAUTHORIZED_VERIFIED_REAL: Claims cannot be directly instantiated as VERIFIED_REAL "
                    "without an authentic ExecutionReceipt. Use runtime.claim_projector."
                )
            if receipt.exit_code != 0 or receipt.outcome != OutcomeCategory.SUCCESS:
                raise ContractValidationError(
                    f"Cannot mint VERIFIED_REAL from non-successful receipt (exit_code={receipt.exit_code}, outcome={receipt.outcome})"
                )
            if not receipt.receipt_id:
                raise ContractValidationError("ExecutionReceipt must have a non-empty receipt_id")

            # Predicate-specific & capability-class bounds (Receipt != Ground Truth)
            PROHIBITED_VERIFIED_REAL_CAPABILITIES = {
                "sports.predict_match",
                "pentest.cvss_calculate",
                "osint.find_monetizable_threats",
            }
            if receipt.capability in PROHIBITED_VERIFIED_REAL_CAPABILITIES:
                raise ContractValidationError(
                    f"CAPABILITY_CANNOT_MINT_VERIFIED_REAL: Capability '{receipt.capability}' is predictive or inferential. "
                    f"Receipt authenticity does not establish domain truth. Admissible only as INFERRED or HYPOTHESIZED."
                )

            # trading.portfolio_check separates ledger balance from forecast yield
            if receipt.capability == "trading.portfolio_check":
                if predicate in ("forecast", "forecast_yield", "projected_pnl", "risk_projection", "model_forecast"):
                    raise ContractValidationError(
                        f"PREDICATE_NOT_VERIFIABLE_AS_REAL: Capability '{receipt.capability}' predicate '{predicate}' "
                        f"is a forward-looking forecast and cannot assert VERIFIED_REAL. Admissible only as INFERRED or HYPOTHESIZED."
                    )

            # memory.retrieve verifies what was stored in memory, not external domain propositions
            if receipt.capability == "memory.retrieve":
                ALLOWED_MEMORY_PREDICATES = {
                    "stored_record", "memory_value", "record", "content", "value", "result",
                    "success", "key", "found"
                }
                if predicate not in ALLOWED_MEMORY_PREDICATES:
                    raise ContractValidationError(
                        f"PREDICATE_NOT_VERIFIABLE_AS_REAL: Capability 'memory.retrieve' can only verify stored memory records "
                        f"({sorted(ALLOWED_MEMORY_PREDICATES)}), not external ground-truth proposition '{predicate}'."
                    )

            # Verify output payload hash integrity
            expected_output_hash = ExecutionReceipt.hash_payload(receipt.results)
            if not receipt.output_hash or not hmac.compare_digest(receipt.output_hash, expected_output_hash):
                raise ContractValidationError(
                    f"ExecutionReceipt output_hash mismatch: expected {expected_output_hash}, got {receipt.output_hash}"
                )

            # Cryptographic verification against internal authoritative TrustRegistry ONLY
            if not receipt.worker_signature:
                raise ContractValidationError("ExecutionReceipt is unsigned; cannot mint VERIFIED_REAL without valid signature")

            if not isinstance(_receipt_verifier, _RuntimeReceiptVerifier):
                raise ContractValidationError(
                    "UNAUTHORIZED_VERIFIED_REAL: VERIFIED_REAL admission requires a runtime-bound ClaimProjector."
                )

            valid, reason = _receipt_verifier.verify(receipt, current_time=time.time())
            if not valid:
                raise ContractValidationError(f"ExecutionReceipt cryptographic verification rejected by authoritative TrustRegistry: {reason}")

            # Enforce WORKER role on receipt signer
            receipt_key_id = getattr(receipt, "worker_key_id", None) or receipt.worker_id
            signer_rec = _receipt_verifier.get_key(receipt_key_id)
            if signer_rec is not None:
                signer_role = getattr(signer_rec.get("role"), "value", signer_rec.get("role"))
                if str(signer_role).upper() != "WORKER":
                    raise ContractValidationError(
                        f"ROLE_MISMATCH: ExecutionReceipt signer '{receipt_key_id}' has role '{signer_role}', expected 'WORKER'"
                    )

            # Anti-retargeting bindings (Finding 2)
            expected_target = str(receipt.target) if receipt.target else str(receipt.capability)
            # 1. Subject binding: Claim subject must match receipt target (or capability if untargeted)
            if str(subject) != expected_target:
                raise ContractValidationError(
                    f"RETARGETING_DETECTED: Claim subject '{subject}' does not match receipt target '{expected_target}'"
                )

            # 2. Scope binding: Claim scope_id must match receipt target if specified
            if scope_id is not None and str(scope_id) != expected_target:
                raise ContractValidationError(
                    f"RETARGETING_DETECTED: Claim scope_id '{scope_id}' does not match receipt target '{expected_target}'"
                )

            # 3. Capability binding: if caller passed capability in kwargs, verify it matches receipt
            if kwargs.get("capability") is not None and kwargs["capability"] != receipt.capability:
                raise ContractValidationError(
                    f"RETARGETING_DETECTED: Capability mismatch: expected '{receipt.capability}', got '{kwargs['capability']}'"
                )

            # 4. Predicate & Value binding: strictly bound to receipt.results
            if isinstance(receipt.results, Mapping):
                if predicate not in receipt.results:
                    if len(receipt.results) == 1 and predicate in ("result", "results", "status", "finding"):
                        expected_val = receipt.results[next(iter(receipt.results))]
                    else:
                        raise ContractValidationError(
                            f"RETARGETING_DETECTED: Claim predicate '{predicate}' not found in receipt results: {list(receipt.results.keys())}"
                        )
                else:
                    expected_val = receipt.results[predicate]
            else:
                expected_val = receipt.results

            if freeze_value(value) != freeze_value(expected_val):
                raise ContractValidationError(
                    f"UNBOUND_CLAIM_VALUE: Claim value does not match authentic receipt results. "
                    f"Expected {expected_val!r} for predicate '{predicate}', got {value!r}"
                )

            allowed = VERIFIED_PREDICATES.get(receipt.capability, ())
            if predicate not in allowed:
                raise ContractValidationError("PREDICATE_NOT_VERIFIABLE_AS_REAL: no registered predicate verifier")

            # Enforce provenance and receipt-derived fields
            assurance_score = 1.0
            evidence_receipt_ids = (receipt.receipt_id,)
            environment_fingerprint = receipt.environment_fingerprint
            authority_fingerprint = _receipt_verifier.authority_fingerprint
            scope_id = receipt.target or scope_id
            created_at = float(receipt.completed_at)
            updated_at = float(receipt.completed_at)

        # Policy-ceiling enforcement on assurance score for inferential/predictive claims
        if es in (EpistemicState.HYPOTHESIZED, EpistemicState.INFERRED):
            cap = kwargs.get("capability") or (receipt.capability if receipt else None)
            if cap in ("sports.predict_match", "trading.portfolio_check"):
                assurance_score = min(assurance_score, 0.60)
            elif cap in ("pentest.cvss_calculate", "osint.find_monetizable_threats"):
                assurance_score = min(assurance_score, 0.80)

        # Observation provenance handling
        obs_obj = kwargs.get("observation")
        if obs_obj is not None:
            if es == EpistemicState.VERIFIED_REAL:
                raise ContractValidationError(
                    "OBSERVATION_CANNOT_MINT_VERIFIED_REAL: Observations are external intakes and cannot assert VERIFIED_REAL."
                )
            observation_ids = (obs_obj.observation_id,)
            created_at = min(float(obs_obj.observed_at), float(obs_obj.collected_at))
            updated_at = created_at
            if obs_obj.expires_at is not None:
                freshness_deadline = min(freshness_deadline, obs_obj.expires_at) if freshness_deadline is not None else obs_obj.expires_at
            base_limit = RELIABILITY_BASE_WEIGHTS.get(obs_obj.reliability_class, 0.40)
            policy_ceiling = 0.30 if obs_obj.reliability_class == ReliabilityClass.UNVERIFIED_INCOMING else 0.40
            assurance_score = min(assurance_score, base_limit, policy_ceiling)

        ls = lifecycle_state if isinstance(lifecycle_state, LifecycleState) else LifecycleState(lifecycle_state)
        dp = decay_profile if isinstance(decay_profile, DecayProfile) else DecayProfile(decay_profile)

        now = time.time()
        created = _validate_timestamp(created_at, "created_at") if created_at is not None else now
        updated = _validate_timestamp(updated_at, "updated_at") if updated_at is not None else created
        if freshness_deadline is not None:
            freshness_deadline = _validate_timestamp(freshness_deadline, "freshness_deadline", allow_future=True)
        if not math.isfinite(float(assurance_score)) or not 0 <= float(assurance_score) <= 1:
            raise ContractValidationError("INVALID_ASSURANCE_SCORE")

        # Freshness ceiling enforcement: anchored to evidence creation time, cannot exceed decay profile duration
        if dp in DECAY_DURATIONS_SECONDS and DECAY_DURATIONS_SECONDS[dp] is not None:
            duration = DECAY_DURATIONS_SECONDS[dp]
            max_ceiling = created + duration
            if freshness_deadline is None or freshness_deadline > max_ceiling:
                freshness_deadline = max_ceiling

        if receipt is not None:
            ceiling = 300.0 if receipt.capability in ("tor.check_status", "darknet.get_status", "security.deadman_status", "trading.portfolio_check") else 604800.0
            if receipt.capability == "sports.predict_match": ceiling = 2592000.0
            bound = float(receipt.completed_at) + ceiling
            freshness_deadline = min(freshness_deadline, bound) if freshness_deadline is not None else bound

        return super().__new__(
            cls,
            str(claim_id),
            str(subject),
            str(predicate),
            freeze_value(value),
            es,
            ls,
            dp,
            max(0.0, min(1.0, float(assurance_score))),
            tuple(str(x) for x in (evidence_receipt_ids or ())),
            tuple(str(x) for x in (observation_ids or ())),
            tuple(str(x) for x in (parent_claim_ids or ())),
            freshness_deadline,
            str(scope_id) if scope_id else None,
            str(environment_fingerprint),
            str(authority_fingerprint),
            created,
            updated,
            schema_version,
        )

    @classmethod
    def create_verified_real(
        cls,
        claim_id: str,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        value: Any = None,
        receipt: Optional[Any] = None,
        decay_profile: DecayProfile = DecayProfile.SOFTWARE_BEHAVIOR,
        scope_id: Optional[str] = None,
        parent_claim_ids: Any = (),
        **kwargs
    ) -> "Claim":
        """Fail closed: verified claims must be projected by a runtime-bound ClaimProjector."""
        raise ContractValidationError(
            "UNAUTHORIZED_VERIFIED_REAL: Direct verified-claim factories are disabled; "
            "use runtime.claim_projector.project_verified_real()."
        )

    @classmethod
    def _create_verified_real(
        cls,
        *,
        receipt_verifier: _RuntimeReceiptVerifier,
        claim_id: str,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        value: Any = None,
        receipt: Optional[Any] = None,
        decay_profile: DecayProfile = DecayProfile.SOFTWARE_BEHAVIOR,
        scope_id: Optional[str] = None,
        parent_claim_ids: Any = (),
        capability: Optional[str] = None,
    ) -> "Claim":
        ExecutionReceipt = _get_receipt_class()
        if receipt is None or not isinstance(receipt, ExecutionReceipt):
            raise ContractValidationError("Receipt must be an authentic ExecutionReceipt instance")

        # Auto-derive subject from receipt.target if not provided
        derived_subject = receipt.target if subject is None else subject
        if not derived_subject:
            derived_subject = receipt.capability

        # Auto-derive predicate if not provided
        if predicate is None:
            if isinstance(receipt.results, Mapping) and receipt.results:
                predicate = next(iter(receipt.results))
            else:
                predicate = "result"

        # Auto-derive value if not provided
        if value is None:
            if isinstance(receipt.results, Mapping) and predicate in receipt.results:
                value = receipt.results[predicate]
            else:
                value = receipt.results

        return cls(
            claim_id=claim_id,
            subject=derived_subject,
            predicate=predicate,
            value=value,
            epistemic_state=EpistemicState.VERIFIED_REAL,
            lifecycle_state=LifecycleState.ACTIVE,
            decay_profile=decay_profile,
            assurance_score=1.0,
            evidence_receipt_ids=(receipt.receipt_id,),
            observation_ids=(),
            parent_claim_ids=parent_claim_ids,
            scope_id=scope_id or receipt.target,
            environment_fingerprint=receipt.environment_fingerprint,
            created_at=receipt.completed_at,
            schema_version="1.0",
            receipt=receipt,
            _receipt_verifier=receipt_verifier,
            capability=capability,
        )

    def is_fresh(self, current_time: Optional[float] = None) -> bool:
        """Check if claim has not lapsed past its freshness deadline."""
        if self.freshness_deadline is None:
            return True
        now = current_time if current_time is not None else time.time()
        return now <= self.freshness_deadline

    def compute_claim_hash(self) -> str:
        """Compute canonical cryptographic hash of the claim state and evidence provenance."""
        payload = {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": self.value,
            "epistemic_state": self.epistemic_state.value,
            "lifecycle_state": self.lifecycle_state.value,
            "decay_profile": self.decay_profile.value,
            "assurance_score": self.assurance_score,
            "evidence_receipt_ids": sorted(self.evidence_receipt_ids),
            "observation_ids": sorted(self.observation_ids),
            "parent_claim_ids": sorted(self.parent_claim_ids),
            "freshness_deadline": self.freshness_deadline,
            "environment_fingerprint": self.environment_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
        }
        return hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "claim_id": self.claim_id,
            "subject": self.subject,
            "predicate": self.predicate,
            "value": _unfreeze(self.value),
            "epistemic_state": self.epistemic_state.value,
            "lifecycle_state": self.lifecycle_state.value,
            "decay_profile": self.decay_profile.value,
            "assurance_score": self.assurance_score,
            "evidence_receipt_ids": list(self.evidence_receipt_ids),
            "observation_ids": list(self.observation_ids),
            "parent_claim_ids": list(self.parent_claim_ids),
            "freshness_deadline": self.freshness_deadline,
            "scope_id": self.scope_id,
            "environment_fingerprint": self.environment_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Claim":
        d = dict(data)
        ver = d.get("schema_version", "1.0")
        if ver not in SUPPORTED_EPISTEMIC_VERSIONS:
            raise ContractValidationError(f"Unsupported Claim schema_version: {ver}")

        state_val = d.get("epistemic_state", EpistemicState.OBSERVED)
        es = EpistemicState(state_val) if isinstance(state_val, str) else state_val
        if es == EpistemicState.VERIFIED_REAL:
            # Reject untrusted serialized claims asserting VERIFIED_REAL
            raise ContractValidationError(
                "UNAUTHORIZED_VERIFIED_REAL: Claims loaded via from_dict() cannot assert VERIFIED_REAL. "
                "Must be projected again from a verified EventStore receipt."
            )

        ls = d.get("lifecycle_state", LifecycleState.ACTIVE)
        if isinstance(ls, str):
            ls = LifecycleState(ls)
        dp = d.get("decay_profile", DecayProfile.SOFTWARE_BEHAVIOR)
        if isinstance(dp, str):
            dp = DecayProfile(dp)

        return cls(
            claim_id=d["claim_id"],
            subject=d["subject"],
            predicate=d["predicate"],
            value=d["value"],
            epistemic_state=es,
            lifecycle_state=ls,
            decay_profile=dp,
            assurance_score=d.get("assurance_score", 0.5),
            evidence_receipt_ids=d.get("evidence_receipt_ids", ()),
            observation_ids=d.get("observation_ids", ()),
            parent_claim_ids=d.get("parent_claim_ids", ()),
            freshness_deadline=d.get("freshness_deadline"),
            scope_id=d.get("scope_id"),
            environment_fingerprint=d.get("environment_fingerprint", ""),
            authority_fingerprint=d.get("authority_fingerprint", ""),
            created_at=d.get("created_at"),
            updated_at=d.get("updated_at"),
            schema_version=ver,
        )


# These predicates concern local records or local measurements only. New predicates
# require an explicit verifier review; unknown outputs remain execution reports.
VERIFIED_PREDICATES = {
    "memory.retrieve": {"stored_record", "value", "found", "key"},
    "memory.store": {"stored", "key"},
    "tor.check_status": {"status", "circuit_established", "connected", "is_active"},
    "darknet.get_status": {"status", "active_feeds", "feed_count"},
    "security.deadman_status": {"status", "armed", "enabled"},
    "trading.portfolio_check": {"ledger_balance", "balance_usd"},
}

class ClaimProjector:
    """
    Trusted projector service responsible for admitting and projecting VERIFIED_REAL claims
    from cryptographically verified ExecutionReceipts using an authoritative TrustRegistry.
    Guarantees strict binding against retargeting of subject, scope, predicate, and value.
    Verification authority is strictly internal and cannot be caller-controlled.
    """
    __slots__ = ("__receipt_verifier",)

    def __init__(self, *args, **kwargs):
        raise ContractValidationError(
            "CALLER_CONTROLLED_AUTHORITY_REJECTED: ClaimProjector instances are created only by CiphRuntime."
        )

    @classmethod
    def _for_runtime(cls, registry: Any, operator_public_key: bytes) -> "ClaimProjector":
        projector = object.__new__(cls)
        verifier = _RuntimeReceiptVerifier._from_runtime(registry, operator_public_key)
        object.__setattr__(projector, "_ClaimProjector__receipt_verifier", verifier)
        return projector

    @property
    def authority_fingerprint(self) -> str:
        return self.__receipt_verifier.authority_fingerprint

    def project_verified_real(
        self,
        receipt: Any,
        claim_id: Optional[str] = None,
        predicate: Optional[str] = None,
        decay_profile: DecayProfile = DecayProfile.SOFTWARE_BEHAVIOR,
        parent_claim_ids: Sequence[str] = (),
        subject: Optional[str] = None,
        value: Any = None,
        scope_id: Optional[str] = None,
        capability: Optional[str] = None,
    ) -> Claim:
        """
        Derives and mints a VERIFIED_REAL claim strictly bound to receipt provenance.
        Fails closed on any retargeting or signature failure.
        """
        import uuid
        cid = claim_id or "CLM-" + hashlib.sha256(canonical_json([receipt.receipt_id, predicate, decay_profile]).encode()).hexdigest()[:32]
        return Claim._create_verified_real(
            receipt_verifier=self.__receipt_verifier,
            claim_id=cid,
            subject=subject if subject is not None else (receipt.target or receipt.capability),
            predicate=predicate,
            value=value,
            receipt=receipt,
            decay_profile=decay_profile,
            scope_id=scope_id if scope_id is not None else receipt.target,
            parent_claim_ids=parent_claim_ids,
            capability=capability,
        )

    def project_from_observation(
        self,
        observation: Observation,
        claim_id: Optional[str] = None,
        decay_profile: Optional[DecayProfile] = None,
        parent_claim_ids: Sequence[str] = (),
    ) -> Claim:
        """
        Projects an OBSERVED claim from an authentic Observation.
        Epistemic rule: An observation asserting 'Source reported X' admits
        the proposition that 'Source reported X', NOT that 'X is true'.
        Under no circumstances can an observation project VERIFIED_REAL.
        """
        import uuid
        cid = claim_id or "CLM-OBS-" + hashlib.sha256(canonical_json([observation.observation_id, decay_profile]).encode()).hexdigest()[:32]
        dp = decay_profile or (
            DecayProfile.LIVE_NETWORK_STATE if observation.reliability_class == ReliabilityClass.DIRECT_SENSOR
            else DecayProfile.SOFTWARE_BEHAVIOR
        )
        base_assurance = RELIABILITY_BASE_WEIGHTS.get(observation.reliability_class, 0.40)
        return Claim(
            claim_id=cid,
            subject=observation.source,
            predicate="source_reported",
            value={"subject": observation.subject, "predicate": observation.predicate, "value": _unfreeze(observation.value)},
            epistemic_state=EpistemicState.OBSERVED,
            lifecycle_state=LifecycleState.ACTIVE,
            decay_profile=dp,
            assurance_score=min(base_assurance, 0.30 if observation.reliability_class == ReliabilityClass.UNVERIFIED_INCOMING else 0.40),
            evidence_receipt_ids=(),
            observation_ids=(observation.observation_id,),
            parent_claim_ids=parent_claim_ids,
            freshness_deadline=observation.expires_at,
            scope_id=observation.scope_id,
            environment_fingerprint=dict(observation.environment).get("fingerprint", ""),
            authority_fingerprint=self.authority_fingerprint,
            created_at=min(observation.observed_at, observation.collected_at),
            observation=observation,
        )

    def project_claim(
        self,
        receipt: Any,
        manifest: Optional[Any] = None,
        claim_id: Optional[str] = None,
        subject: Optional[str] = None,
        predicate: Optional[str] = None,
        value: Any = None,
        parent_claim_ids: Sequence[str] = (),
        decay_profile: Optional[DecayProfile] = None,
    ) -> Claim:
        """
        Consolidated claim projection enforcing predicate-specific and capability-class rules.
        - Predictive capabilities project as HYPOTHESIZED (assurance <= 0.60, model prediction proposition).
        - Inferential capabilities project as INFERRED (assurance <= 0.80).
        - Direct sensor capabilities project as VERIFIED_REAL (or SUPPORTED).
        - Failed executions project as DISPUTED.
        """
        valid, reason = self.__receipt_verifier.verify(receipt, current_time=time.time())
        if not valid:
            raise ContractValidationError(f"INVALID_RECEIPT: {reason}")
        _validate_timestamp(receipt.started_at, "started_at")
        _validate_timestamp(receipt.completed_at, "completed_at")
        if receipt.started_at > receipt.completed_at:
            raise ContractValidationError("INVALID_EVIDENCE_INTERVAL")
        if receipt.exit_code != 0 or receipt.outcome != OutcomeCategory.SUCCESS:
            raise ContractValidationError("FAILED_EXECUTION_IS_NOT_DOMAIN_EVIDENCE")
        target = receipt.target or receipt.capability
        if subject is not None and subject != target:
            raise ContractValidationError("RETARGETING_DETECTED")
        results = receipt.results
        # A whole output is a report of execution, not a verified domain fact.
        if predicate is None:
            if receipt.capability == "sports.predict_match":
                predicate = "model_prediction"
            elif receipt.capability == "memory.retrieve":
                predicate = "retrieval_report"
            else:
                predicate = "execution_report"
        if predicate in ("model_prediction", "retrieval_report", "execution_report"):
            expected = results
        elif isinstance(results, Mapping) and predicate in results and (predicate in VERIFIED_PREDICATES.get(receipt.capability, ()) or receipt.capability in ("sports.predict_match", "trading.portfolio_check", "pentest.cvss_calculate", "osint.find_monetizable_threats")):
            expected = results[predicate]
        else:
            raise ContractValidationError("UNREGISTERED_PREDICATE")
        if value is not None and canonical_json(value) != canonical_json(expected):
            raise ContractValidationError("UNBOUND_CLAIM_VALUE")
        if predicate in VERIFIED_PREDICATES.get(receipt.capability, ()):
            return self.project_verified_real(receipt, claim_id=claim_id, predicate=predicate,
                subject=subject, value=expected, parent_claim_ids=parent_claim_ids,
                decay_profile=decay_profile or DecayProfile.LIVE_NETWORK_STATE)
        predictive = receipt.capability == "sports.predict_match" or (
            receipt.capability == "trading.portfolio_check" and predicate not in ("ledger_balance", "balance_usd"))
        inferential = receipt.capability in ("pentest.cvss_calculate", "osint.find_monetizable_threats")
        # Explicit output fields for algorithms; arbitrary fields never certify reality.
        state = EpistemicState.HYPOTHESIZED if predictive else (EpistemicState.INFERRED if inferential else EpistemicState.OBSERVED)
        score = 0.60 if predictive else (0.80 if inferential else 0.40)
        dp = decay_profile or (DecayProfile.STRATEGIC_HYPOTHESIS if predictive else DecayProfile.SOFTWARE_BEHAVIOR)
        cid = claim_id or "CLM-" + hashlib.sha256(canonical_json([receipt.receipt_id, predicate, dp]).encode()).hexdigest()[:32]
        return Claim(claim_id=cid, subject=target, predicate=predicate, value=expected,
            epistemic_state=state, assurance_score=score, decay_profile=dp,
            evidence_receipt_ids=(receipt.receipt_id,), parent_claim_ids=parent_claim_ids,
            scope_id=receipt.target, environment_fingerprint=receipt.environment_fingerprint,
            authority_fingerprint=self.authority_fingerprint, created_at=receipt.completed_at, receipt=receipt)
