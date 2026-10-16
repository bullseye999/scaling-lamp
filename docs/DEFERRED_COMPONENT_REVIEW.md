# Deferred Component Review (post-Program 2)

Date: 2026-09-18 · Reviewer: Codex (independent assessment)

Phase 9 is the end of Program 2, so the deferred review recorded in `RESUME_WORK.md`
is now unblocked. Method: read each module, compare its docstring claims against what the
code actually does (imports, primitives), check overlap with phases already sealed, and
apply the Gate Zero precedent (fabricated ZK proofs, post-quantum signatures and hardware
attestation were previously accepted as genuine).

| Component | Claims | Reality (evidence) | Verdict |
| --- | --- | --- | --- |
| Epistemic Closed Loop (`ciph/epistemic/closed_loop.py`, 88 lines) | Curiosity → ingress → receipts → DAG → worldview loop | Thin wiring that overlaps what Phases 5–6 already implement (`materialized_views`, claim leases, `curiosity_daemon`) | **Archive** as design reference; fold anything still missing into the existing phases |
| Ghost Mesh (`ciph/federation/ghost_mesh.py`, 234 lines) | Distributed Tor P2P capability execution | Real Ed25519 peer enrolment (Gate Zero remediated), but no peer transport, no network policy integration, no operational need | **Defer** — keep the code, do not activate. Prerequisites: sandboxed transport, key distribution policy, cross-node receipt verification |
| Iron Crucible (`ciph/crucible/red_shadow.py`, 116 lines) | Autonomous adversarial falsification of capabilities | Encodes the project's own adversarial method; but "proactive penetration sweeps" need sandbox + scope enforcement first | **Candidate** — worth a scoped design after the Phase 0–9 sweep, not activation as-is |
| Sovereignty / Singularity (`ciph/sovereignty/singularity_engine.py`, 101 lines) | Solvency telemetry + perpetual self-maintenance + tethered evolution | The maintenance role is now genuinely delivered by Phase 9 Step 2 (idle maintenance engine + shared exclusion). The economic/telemetry part has no backing data | **Archive** — its useful half already exists and is better implemented |
| Zero-Knowledge Engine (`ciph/zk/zk_engine.py`, 100 lines) | "Non-interactive zero-knowledge proof generation" | SHA-256 commitments over JSON + receipts. This is not a ZK proof and proves no such statement | **Rename or archive** — must never be presented as ZK. If real ZK is wanted, that is a from-scratch cryptographic project |
| Byzantine Swarm / Council (`ciph/swarm/byzantine_consensus.py`, 161 lines) | BFT threshold voting across independent agent nodes | Uses real `nacl` Ed25519 signing/verification; correctness of the BFT properties is unproven at 161 lines | **Defer** — a concrete use (e.g. multi-agent review of high-risk changes) would justify hardening it |
| Silicon Sovereign (`ciph/silicon/hardware_root.py`, 172 lines) | HSM enclave sealing + NIST ML-DSA post-quantum resistance | Imports `hmac`/`hashlib`; no HSM binding, no PQ library, no attestation source | **Archive or rewrite** — real ML-DSA + real attestation is high-cost with no current need |

## Cross-cutting finding

Four of the seven components carry docstrings that claim capabilities the code does not
implement. That is prompt laundering applied to code — the same failure mode Step 3
removed from the conversation layer, and the same one Gate Zero found in these very
primitives.

**Recommended standing rule:** a module docstring may not claim a capability the code does
not implement. If a primitive is aspirational, it should say so explicitly (e.g.
"placeholder — no cryptographic backing").

## Recommended disposition summary

- **Archive:** epistemic closed loop, sovereignty/singularity, silicon sovereign, ZK-as-claimed
- **Defer (keep, do not activate):** ghost mesh, byzantine swarm
- **Candidate for a scoped design:** iron crucible

None of the seven should be activated before the Phase 0–9 sweep is sealed, and any
activation must satisfy the same adversarial bar as the rest of the system.
