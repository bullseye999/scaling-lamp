# 4.3 Gate Three — The Self Model

**Question:** *what does Ciph know about itself?*

**Module:** `ciph/kernel/self_model.py` — `test_gate_4_3_self_model.py`, 10 specimens.

## The central law

> **code presence != capability != permission != execution != successful effect.**

Each rung is a separate, independently recorded fact. The strongest claim Ciph may make is the
**highest rung whose whole ladder holds**, and the first missing rung is named:

```
UNKNOWN      nothing canonical is known about this capability     NO_INSTALLATION
INSTALLED    code exists somewhere, and that is all               NOT_AVAILABLE_IN_ENVIRONMENT
AVAILABLE    the code exists in THIS environment                  NOT_AUTHORIZED
AUTHORIZED   permission exists for this environment+manifest      NOT_EMPIRICALLY_VERIFIED
VERIFIED     a governed execution under this environment+manifest succeeded
```

## Shape

```
SelfModelProjection
    capability_id
    claim_level, installed, available, authorized, empirically_verified
    reason_codes, limitations, uncertainty
    environment_ref, manifest_identity
    performance_ref
    evidence_basis_digest

record_installation(...)      the weakest rung: code exists
record_authorization(...)     permission exists, separately
record_execution_evidence(...) the OUTCOME of a governed execution (success or a limitation)
```

## Laws

```
 1. Module installed != capability verified.
 2. Capability verified != currently available.
 3. Available != authorized.
 4. Authorized != executed.
 5. Execution attempt != successful effect (only a recorded success verifies).
 6. Self-reported model text is NOT self-model evidence.
 7. Performance comes from governed execution evidence, never self-assessment.
 8. Environment AND manifest identity matter: evidence under one proves nothing about another.
 9. Limitations are first-class.
10. UNKNOWN is a valid and honest answer.
11. Self-model history is append-only.
12. Restart reconstructs an identical self state from canonical evidence.
```

The manifest binding reuses `ManifestIdentity` from `ciph/kernel/manifest_identity.py`, so identity is
the same canonical object the rest of the system produces rather than a fresh string convention.

## Specimens that matter

**The hostile specimen.** `osint.py` exists and an LLM says *"I can perform OSINT"*. Result:
`installed = True`, `available = True`, `authorized = False`, `empirically_verified = False`,
claim level `AVAILABLE`. Ciph must not say "I can do this", and `assert_empirically_verified` refuses.

**The ladder climbs one rung at a time.** Install → `AVAILABLE`; authorize → `AUTHORIZED` (with
`NOT_EMPIRICALLY_VERIFIED`); a governed success → `VERIFIED` with no reason codes.

**Verified elsewhere is not available here.** The same capability queried in a different environment
reads `installed = True`, `available = False`, level `INSTALLED`.

**Manifest boundary (D11).** Verification recorded under `H1` does not verify `H2`: under `H2` the
capability is `AUTHORIZED` and not `VERIFIED`.

**A failed attempt is a limitation.** `succeeded = False` verifies nothing, appears in
`limitations`, and still supplies a `performance_ref`: performance is governed execution evidence,
never self-assessment.

**Prose never enters.** Three model outputs claiming authorization change no digest, add no
capabilities, and write no authorization or execution rows.

**UNKNOWN is valid.** A never-recorded capability reads `UNKNOWN` with `NO_INSTALLATION`, no
limitations and no performance reference.
