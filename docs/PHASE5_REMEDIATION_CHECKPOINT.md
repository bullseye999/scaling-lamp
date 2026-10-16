# Phase 5 — Epistemic Convergence repair checkpoint

Updated: 2026-09-07

Status: **Phase 5 security repair verified in both environments.** The earlier claim that 357 passing tests established complete epistemic correctness is superseded by this checkpoint.

The operator explicitly authorized Codex to implement Phase 5 repairs. Changes are local and unstaged. Verification uses isolated source copies with fresh test databases and identities; it does not open the development vault.

## What was repaired

- **One admission gate.** `upsert_claim()` delegates to `admit_claim()`. Every accepted proposition is reconstructed from authenticated evidence and checked for exact subject, predicate, value, context, state, and assurance bounds. An unrelated event, phantom receipt ID, or caller-created observation cannot establish evidence. Receipt admission requires the corresponding successfully committed worker job, signed payload, request bindings, and intact event chain.
- **Execution and truth are separate.** All projection branches verify signatures, including predictions and algorithmic inferences. Explicit local predicates have narrowly registered verification rules. Predictions remain hypotheses, calculations remain inferences, memory output is a retrieval report, and unregistered domain predicates cannot mint verified claims. Assurance limits are policy bounds, not calibrated probabilities.
- **Authenticated observation intake.** `worldview.ingest_observation(receipt_id)` derives an observation from a committed collection result. Source labels such as `local:` cannot confer authority. Raw intake remains unverified until authenticated. Accepted external observations become `source_reported` propositions with a maximum assurance of 0.40. Full observation payloads retain JSON types and context; existing observation identities cannot be overwritten.
- **Atomic signed revisions.** Claim admission, parent edges, transitions, graves, and cascade checkpoints are projected through signed events in the same SQLite transaction. Revision signatures bind event type, aggregate identity, timestamp, previous chain hash, and the complete changes. Reads reject edited or replayed projection rows. Injected failures roll back both the event and its projection.
- **Deterministic replay.** Replay verifies the event chain and kernel signatures, then reapplies recorded revisions. It does not manufacture claims from arbitrary receipt-shaped events or mint new claim IDs. Repeated replay and process restart preserve claim identity, state, dependencies, transition history, and graveyard records.
- **Conservative migration.** Unattested legacy claims retain their original rows in quarantine and are excluded from canonical queries. Legacy observation, dependency, transition, and graveyard metadata is preserved separately when rebuilding an old projection. An existing quarantined claim ID cannot silently be reused.
- **Freshness and lifecycle.** Lifetime is anchored to evidence time, including the earlier of observation and collection timestamps. Receipt classes impose ceilings even when callers request a longer decay profile. Required parents bound both assurance and lifetime. Expiration makes claims dormant without changing epistemic judgments or resurrecting archived claims. Environment fingerprints include the OS, full Python version, and local package source bytes.
- **Dependency safety.** Cycles, missing parents, excessive depth, excessive fan-out, and excessive parent counts are rejected. Cascades use indexed, bounded work. An incomplete cascade leaves a durable root barrier and checkpoint; active queries check required ancestors, so unvisited descendants cannot remain usable. Shared-ancestor validation is memoized and budgeted. In-memory graph adapters return copied, bounded nodes.
- **Governed reopening.** A caller-supplied actor string or reason cannot clear a grave. New relevant receipt/observation evidence or an operator-signed directive is required. Reopening enables investigation while retaining the barrier and previous epistemic judgment. Manual commands bypass autonomous suppression while retaining command authorization, scope, and admission gates.
- **Queued inquiry suppression.** A question queued before burial is checked again against the graveyard immediately before autonomous dispatch. Queue history cannot bypass a subsequently created grave.
- **Runtime integration.** Reference-loop execution, DAG steps, curiosity refresh, and ActiveForgetting no longer fall back to unchecked insertion or raw `SUPPORTED` claims. Failed admission is reported explicitly as `EPISTEMIC_ADMISSION_REJECTED`; execution success does not hide that failure. Fresh investigations create new evidenced claims rather than rewriting old identities and clocks.

## Compatibility and scope

The canonical claim tuple remains the accepted representation. `TransmutationNode` remains an adapter and does not provide an alternate admission authority. The legacy SQL `state` column is retained as an index alongside the complete canonical payload.

Old tests that inserted invented claims, restored truth without evidence, accepted arbitrary audit assertions as verified facts, or expected freshness expiration to erase an epistemic judgment were updated to use the real worker/token/queue/receipt path. The fixture capability executes offline; assertions still exercise production admission and storage code.

Only required-premise edges are currently accepted by this repair. New dependency edits require a newly evidenced claim; an arbitrary parent-only inference is not sufficient evidence. Optional corroborating-edge scoring and domain-specific inference rules are not implemented. Unknown set or forecast predicates do not enter generic equality-based contradiction detection. Automatic background processing of incomplete cascade checkpoints is not implemented; their ancestor barriers keep affected claims unusable until explicit reconciliation or new evidence. These are conservative boundaries, not certified implementations of every optional extension in the earlier architectural proposal.

The 16-capability matrix is an isolated control-flow governance probe. It does not certify empirical truth, live services, OS containment, or every possible epistemic failure. Regression tests are executable checks, not formal proofs.

## Verification

Final results and exact source hashes are recorded in [PHASE5_VERIFICATION_RESULTS.json](PHASE5_VERIFICATION_RESULTS.json).

| Environment | Full discovery | Duration | Isolated governance matrix |
| --- | --- | --- | --- |
| venv | **368/368 PASS** | 234.544s | **16/16 PASS** |
| ciph-env | **368/368 PASS** | 201.568s | **16/16 PASS** |

- Full discovery includes 368 tests: the existing 320-test baseline plus 48 current Phase 5 tests.
- The Phase 5 suites contain 9 Stage 1, 8 Stage 2, 6 Stage 3, 3 Stage 4, and 22 adversarial regression tests.
- All 155 Python source files compile.
- The isolated governance matrix passed 16/16 in both environments on the final source; full-suite matrix tests also run with that source.
- The latest correction fixed a new test that used `/apply upgrade_id=...` instead of the declared `/apply proposal_id=...`. Both corrected authorization probes passed. Production command behavior was unchanged by that test correction.

Source-only pre-edit snapshot: `/tmp/ciph-p5-before-qs_1hkj7`.

Final verification copies:

- `.venv`: `/tmp/ciph-p5-queue-verification-venv-p5d070uq`
- `ciph_env`: `/tmp/ciph-p5-queue-verification-ciph-env-u8949d9d`

No changes have been staged or committed. The working tree contains existing modifications and untracked files as well as this repair; an empty index is not a clean working tree.
