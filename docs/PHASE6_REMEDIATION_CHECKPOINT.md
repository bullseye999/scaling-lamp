# Program 2, Phase 6 — Internal Governed Curiosity

Updated: 2026-09-07

Status: **Phase 6 implemented and verified locally in both environments.**

The operator authorized Option A: implement Phase 6 locally and verify it. This authorization does not start Phase 7 or activate the deferred experimental upgrade batch. Verification uses isolated source copies and fresh test databases. The development vault is not opened, and no persistent background service is started by this work.

## What CIPH now does

A curiosity question describes a specific missing piece of internal evidence. CIPH first looks for an authenticated, current answer in its worldview and committed execution history. If it finds one, it records the answer and its evidence without creating a worker job. Otherwise, an eligible local inquiry can reserve budget and execute through the existing governed runtime. The question becomes answered only when the resulting admitted proposition actually answers it.

A memory retrieval report answers what the memory lookup returned. It does not establish that the stored text is true about the outside world. A missing record can answer a question about whether a record was found; it cannot supply the missing record's value.

## Implementation

- `ciph/perception/curiosity_question.py`: validated question contracts, contextual identity, deterministic four-factor priority, immutable dependency definitions, bounded topology, and evidence-checked resolution. Question snapshots cannot mutate stored state. Caller fields cannot set answers or disable internal-first search.
- `ciph/perception/curiosity_store.py`: dedicated SQLite persistence for questions, normalized dependency edges, attempts, and shared budget/pause state. Signed `CuriosityStateChangedEvent` records and their projections commit together. Replay validates signatures and the event chain, then reconstructs questions, edges, attempts, and budgets. Projection edits and deleted attempt rows fail verification. An unused budget has an implicit default, preserving the existing zero-event behavior of an incomplete command.
- `ciph/perception/curiosity_daemon.py`: evidence-first scheduling, exact execution-input matching, vetted capability names and manifest restrictions, atomic reservations, persistent failure handling, and conservative recovery. Automatic gap proposals recover the original capability and parameters from authenticated execution history; subject text does not choose a capability.
- `ciph/memory/materialized_views.py`: explicit access to a usable canonical claim and a bounded subject/predicate candidate lookup. Phase 5 remains the authority for freshness, provenance, claim dependencies, and invalidation barriers.
- `ciph/runtime.py`: binds the durable question DAG after worldview initialization. An optional predicate request goes through the existing `ClaimProjector` and admission gate. `resume_curiosity(reason)` is an explicit trusted runtime/operator control that records the reason and retains spent quota.
- `ciph/epistemic/closed_loop.py`: the legacy autonomous refresh entry point delegates execution to the same curiosity scheduler. It cannot bypass offline restrictions, evidence matching, or budgets. Force-refresh requests a scan rather than synthesizing an external probe.
- `ciph/kernel/network_sandbox.py`: the inherited interpreter guard also rejects child-process launch/exec paths while offline restrictions are active.
- `ciph/capabilities/registry.py`: dependency inspection no longer constructs a staging manager and creates staging directories merely to perform a read-only audit.

## Evidence and scheduling invariants

Question identity binds subject, predicate, capability, parameters, environment, scope, and any explicit context requirement. Changing display text, priority, or dependency requests does not create another instance of the same inquiry. Existing dependency definitions cannot be rewritten, including into cycles. New graphs reject missing parents, depth beyond 16 hops, fan-out beyond 256, and traversal beyond 1,024 operations. Question storage is capped at 1,024 records.

Priority policy `PHASE6_FOUR_FACTOR_V1` computes `impact * relevance / (cost * (1 + risk))`. Inputs must be finite and within declared bounds, with positive cost. Ties use creation time and question ID. This implements Phase 6's four dimensions; it does not claim to implement every additional prioritization factor in the broader cognition blueprint.

Resolution authenticates a usable canonical claim, checks the exact subject and predicate, enforces specified context/environment/scope, and binds receipt capability and input hash to the question. Observation-backed answers retain source attribution. Dependency answers are rechecked through the question DAG before resolution and reservation; an old `ANSWERED` flag is insufficient.

Internal search checks matching canonical claims first, then up to 100 matching committed receipt candidates. Unrelated recent receipts cannot crowd a relevant receipt out of the search. A receipt committed before projection can be recovered through the Phase 5 gate. A fresh report can also support another registered predicate without new execution: existing projections become required parents, preserving their expiry and invalidation limits. Existing expired or invalidated evidence is not re-projected to reset its clock. Question-resolution events link existing proof; they do not create fake execution receipts.

The autonomous execution set is restricted to `memory.retrieve`, `code.audit_dependencies`, and `pentest.cvss_calculate`. A configured list can narrow this set. Every dispatch also requires `OFFLINE_ONLY`, `READ_ONLY`, automatic authorization, and NONE/LOW risk. Tor and other external probes are blocked. Policy and graveyard checks occur before dispatch; ordinary operator commands retain their existing separate authorization and scope rules.

Defaults are 12 inquiries and 12 logical cost units per rolling hour, with a minimum reserved cost of one unit per execution. These are scheduling units, not measured currency or CPU consumption. Reservations and question ownership commit atomically before dispatch, preventing concurrent schedulers from spending the same final slot or independently owning the same question. A cycle dispatches at most three inquiries.

Exhausted quota pauses execution durably. Three consecutive unanswered/failed inquiries pause it; an execution exception or uncertain outcome pauses it for reconciliation immediately. Resume retains charged attempts and does not blindly re-execute uncertain questions. Evidence search can still resolve questions while execution is paused. Failed or policy-blocked questions remain unresolved until fresh evidence or explicit maintenance changes their situation.

An interrupted reservation remains recorded with its stable proposal identity. Recovery searches for committed evidence and can complete its answer without another execution. If execution cannot be established, the attempt remains for reconciliation. A separate receipt can answer the question without reconciling that attempt; only a receipt carrying the reserved execution’s authenticated idempotency key establishes its completion. Expiry of the answer does not authorize another execution while the original attempt remains uncertain. This phase does not add an automatic retry/reconciliation daemon for those uncertain reservations.

## Compatibility and verification scope

Three older refresh tests used Tor/darknet-shaped fixtures. Their successful-refresh scenarios now use genuine offline memory receipts and keep the checks that old evidence identities and dormant claims are preserved. Dedicated tests separately require external and privileged inquiries to be blocked. The existing incomplete-command tests continue to require no execution events.

The dedicated Phase 6 suite contains 35 acceptance/adversarial tests covering evidence reuse, exact answer binding, observation attribution, context mismatch, expiry, DAG prerequisites and bounds, races, budget persistence, failures, interruption recovery, replay, row tampering, and offline execution attempts.

The network boundary here is an interpreter-level guard for the vetted local adapters, including inherited helper-thread restrictions and process-launch denial. OS/container containment and arbitrary hostile native-code isolation belong to Phase 7. The 16-capability matrix remains an isolated control-flow probe, not live-service or epistemic correctness certification.

## Final verification

[PHASE6_VERIFICATION_RESULTS.json](PHASE6_VERIFICATION_RESULTS.json) records the exact tested source hashes, counts, timings, and log paths. The current workspace was checked against both final source snapshots.

| Environment | Full discovery | Wall time | Isolated governance matrix |
| --- | --- | --- | --- |
| `.venv` | **403/403 PASS** | 272.432s | **16/16 PASS** |
| `ciph_env` | **403/403 PASS** | 234.583s | **16/16 PASS** |

- Full discovery includes the 368-test baseline and 35 dedicated Phase 6 tests.
- All 157 Python source files compile. The command inventory JSON is also included in the tested-source hashes.
- Final `.venv` copy: `/tmp/ciph-p6-verify-venv-tqtwhxvv`.
- Final `ciph_env` copy: `/tmp/ciph-p6-verify-ciph_env-dra3dg9x`.
- No changes have been staged or committed.

Source-only pre-edit snapshot: `/tmp/ciph-p6-before-vuza6kgg`.

All changes remain local. The working tree already contained modifications and untracked files; an empty staging index does not mean the working tree is clean.
