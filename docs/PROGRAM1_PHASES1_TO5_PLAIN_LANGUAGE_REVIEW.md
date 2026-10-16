**CIPH — Phases 1–5, explained as one connected system**

Prepared for your review on 7 September 2026.

Read the opening overview first. It gives you the main connection in about a minute. The rest explains each phase, follows one command through the system, and sets up the discussion for Program 2.

This describes the current combined implementation. Later repairs tightened earlier phases, so older checkpoint language is superseded where necessary.

---

**The one-minute overview**

Program 1 establishes a controlled journey from **a request**, to **an authorized action**, to **recorded evidence**, to **a carefully limited conclusion**.

| Phase | Its job in ordinary language | The question it answers |
| --- | --- | --- |
| 1 — Contracts | Give every component agreed, protected records to exchange. | What exactly is being requested, permitted, or reported? |
| 2 — Reference loop | Connect those components into one governed execution path. | How does an approved request become a recorded result? |
| 3 — Worker recovery | Handle interruptions, retries, ownership, and uncertain outcomes. | What happens when execution or storage breaks halfway through? |
| 4 — Command migration | Route supported commands through that governed path. | Does the command actually use the controls we built? |
| 5 — Epistemic convergence | Control which conclusions enter CIPH’s worldview and remain usable. | What does the evidence establish, and is it still relevant? |

The central distinction is:

**Permission to act, proof that an action ran, and permission to accept a conclusion are three separate decisions.**

For example, a sports prediction can execute successfully and produce a genuine signed receipt. That establishes that the model produced a prediction. It does not establish the future match result.

---

**Phase 1 — Give the whole system a shared language**

A contract is an agreed record format with validation rules. CIPH needs different components to mean the same thing when they say “plan,” “permission,” “receipt,” or “claim.”

The main records are:

| Record | Meaning |
| --- | --- |
| Intent and plan | The requested objective, proposed capability, parameters, and ordered steps. |
| Scope grant | The targets or systems an operation is permitted to touch. |
| Authorization grant | Approval for a particular operation, bound to its plan and parameters. |
| Job attempt and execution receipt | Which execution was attempted and what the worker reported. |
| Observation and claim | Collected information, followed by a proposition considered for acceptance. |

These records carry schema versions so changes to their formats can be recognized. The contracts protect important contents against silent changes. Claims are immutable: a caller cannot promote an existing claim simply by changing an attribute.

Hashes act as fingerprints of the relevant contents. Signatures associate those contents with an enrolled authority. Changing a signed request’s security-relevant fields must invalidate its approval.

Authority is tied to the runtime’s trusted identities. A caller saying “I am a worker” or supplying a different trust registry does not establish permission.

**How it connects:** every later phase uses these contracts. Without them, the planner could approve one action while the worker receives something materially different.

Reference: [Phase 1 checkpoint](PHASE1_REMEDIATION_CHECKPOINT.md), especially its final runtime-bound authority section.

---

**Phase 2 — Make the complete execution journey work**

Phase 2 connects the records to an actual execution path:

```text
Request → plan → permission checks → durable job
        → worker → signed receipt → committed history
        → evidence projection → response
```

“Durable” means a job is saved in the database instead of existing only in running program memory.

The runtime coordinates the work. The kernel’s checks control permission. An execution token tells the worker exactly what it may execute. The worker must validate that authority before invoking the capability.

The receipt must then be authenticated and committed with the job’s result. A successful-looking object in memory is insufficient. If the result cannot be safely recorded, CIPH must expose the failure or uncertainty instead of publishing verified success.

Retrieving an earlier result also requires evidence checks. CIPH cannot fabricate a fresh receipt from a database status field saying “completed.”

**How it connects:** Phase 1 defines the records; Phase 2 makes them travel through a working chain. Phase 5 later strengthens the decision about what conclusions may come out of that chain.

Reference: [Phase 2 history in the continuity log](RESUME_WORK.md) and [reference-loop tests](test_phase2_reference_loop.py). Historical references to HMAC receipts should be read alongside the current persistent Ed25519 worker identity and receipt implementation.

---

**Phase 3 — Keep that journey trustworthy when something fails**

A normal successful run is only part of the problem. Workers can stop, a lease can expire, or an operation can affect the outside world just before the process crashes.

A **lease** is a temporary reservation assigning work to a worker. A **heartbeat** helps show that the worker is still alive. An expired or foreign worker must not take over the right to complete someone else’s attempt.

An **idempotency key** identifies the same logical operation. It helps prevent duplicate execution and lets CIPH return authenticated evidence for work already completed. It does not magically make every possible side effect safe to repeat.

The crucial recovery distinction is:

| What happened? | Expected handling |
| --- | --- |
| The worker stopped before execution began. | Recover the job under the existing valid authority and lease rules. |
| An authenticated read-only attempt failed. | A bounded retry may be permitted, with verified token lineage. |
| The operation may already have changed something. | Require reconciliation before deciding what to do next. |

**Reconciliation** means establishing what actually happened before retrying or accepting an outcome. That protects against repeating a write merely because its success was never recorded.

Related database updates commit together or roll back together. For example, a job must not appear successfully completed while its required receipt evidence is missing.

**How it connects:** Phase 3 protects Phase 2’s execution chain during failures. Phase 5 depends on this: unreliable execution history would produce unreliable beliefs.

Reference: [Phase 3 checkpoint](PHASE3_REMEDIATION_CHECKPOINT.md).

---

**Phase 4 — Make supported commands use the governed journey**

Building a safe runtime is insufficient if a slash command can still call a module directly and bypass it.

Phase 4 introduced the command registry: a central mapping from supported command names and aliases to capabilities and validated arguments. Capability adapters connect the existing application modules to that interface.

A **capability** is a specific operation CIPH exposes, such as retrieving memory, calculating CVSS, or checking a service. Its **manifest** describes its requirements, including authorization and network policy.

The supported command path now goes through the runtime and worker controls. Argument parsing rejects ambiguous or invalid input before execution. Privileged commands require authentic approval; restricted operations require the right scope.

Independent command invocations receive fresh identities. Responding to an authorization challenge remains bound to that exact pending operation.

There is an important compatibility boundary: the migration exposes **18 primary commands and 53 names/aliases across 16 canonical capabilities**. Of the inventoried legacy names, **176 are explicitly unavailable**. They were not all migrated. `/help` is presentation-only and does not produce an execution receipt or worldview claim.

**How it connects:** Phase 4 is the user-facing entrance to the Phase 1–3 machinery. Its number reflects the build order; it often runs first when you type a command.

References: [Phase 4 checkpoint](PHASE4_REMEDIATION_CHECKPOINT.md) and [supported command inventory](COMMAND_MIGRATION.md).

---

**Phase 5 — Decide what CIPH may conclude and keep using**

“Epistemic” concerns knowledge: what evidence supports a proposition, how strongly it supports it, and whether it is still useful.

A **claim** is a specific proposition, such as a statement about a stored record or a measured status. The **worldview** is the organized collection of accepted claim records and their history of changes.

Phase 5 puts admission behind one evidence gate. An invented receipt ID, an unrelated event, an unsigned observation, or an unchecked insertion cannot establish an accepted claim.

These examples show the intended meaning, rather than literal response text:

| Evidence | Permitted interpretation |
| --- | --- |
| Memory returns some text. | That text was retrieved; its contents are not automatically true about the world. |
| A model returns a forecast. | The model produced a forecast; the future outcome remains uncertain. |
| An authenticated collection captures an external report. | That source reported the assertion; the assertion is not automatically verified reality. |

The system also keeps three questions separate:

- **Epistemic state:** what does the evidence establish—observed, inferred, disputed, and so on?
- **Lifecycle:** is the claim active, dormant, archived, or reopened for investigation?
- **Freshness:** has the applicable time horizon expired?

An expired claim becomes dormant without having its epistemic judgment erased. “Too old to rely on now” does not mean “proven false.” Replaying yesterday’s evidence cannot start a new freshness clock.

Claims can depend on other claims. A required premise limits a child’s assurance and useful lifetime. If that premise becomes unusable, downstream claims cannot quietly continue as active evidence. Bounded cascades and ancestor checks protect this even when a large update cannot finish in one pass.

For supported measurement predicates, context and time help distinguish conflicting evidence from an older status being superseded. Arbitrary differences between reports are not automatically treated as contradictions.

The **graveyard** suppresses repeated autonomous investigation of buried propositions. Reopening requires an authentic trigger and permits investigation; it does not restore truth. Even a question queued before burial is checked again before autonomous dispatch. Manual commands retain their execution and admission controls.

Finally, signed claim events allow CIPH to rebuild the same recorded worldview after restart. Rebuilds preserve identities, transitions, dependencies, and graves instead of generating new claims from old receipts. Unverified legacy records are preserved in quarantine outside canonical queries.

**How it connects:** Phase 5 turns Phase 2–3 evidence into controlled reasoning material, including results entered through Phase 4. It is the foundation that Program 2’s curiosity must respect.

Reference: [Phase 5 checkpoint](PHASE5_REMEDIATION_CHECKPOINT.md).

---

**One command, all five phases**

Suppose you enter:

```text
/memory key=operator_alias
```

The connected journey is:

1. **Phase 4** recognizes the command and parses `key=operator_alias`.
2. **Phase 1 contracts** express the intent, plan, permission context, and execution records consistently.
3. **Phase 2** checks the capability’s requirements, records the job, and sends it through the governed worker path.
4. **Phase 3** controls the worker’s lease and attempt, and protects the result if execution or storage is interrupted.
5. **The receipt and job outcome** are authenticated and committed.
6. **Phase 5** checks what that evidence supports before admitting a retrieval report into the worldview.
7. **The response** presents the recorded result. Missing data must remain missing; retrieved text must not silently become a verified external fact.

If the command executes but claim admission fails, the runtime exposes `EPISTEMIC_ADMISSION_REJECTED`. Execution and acceptance remain separate outcomes.

This is why the phases behave as one system: each handoff carries the previous phase’s guarantees forward.

---

**Where the information belongs**

These are the architectural ownership boundaries to keep in mind during review:

| Component | Responsibility |
| --- | --- |
| StateManager and runtime status | Operational information such as readiness, active work, and loaded components. |
| Durable job queue | Work to perform, attempts, leases, and outcomes. |
| EventStore | The durable history of recorded events and evidence. |
| MaterializedWorldview | Evidence-backed claim records and their current usability. |
| CipherVault | Private encrypted memory and sensitive configuration. |

Also distinguish the graphs: an **execution DAG** orders actions; a **claim dependency graph** connects premises and conclusions; a **question DAG** organizes investigations. They cooperate, but represent different things.

---

**Where we stand before Program 2**

The latest recorded verification passed **368/368 tests in both Python environments**, including **48 Phase 5 tests**. Both isolated governance matrices passed **16/16**, and all **155 Python source files** compiled. These are the recorded repair results, not a new test run performed for this writeup.

Three boundaries matter for tomorrow:

1. Phase 4 covers the supported slash-command surface. Full legacy feature parity and every natural-language orchestration path are not covered by that migration claim.
2. Phase 5 currently supports required-premise dependencies. Optional corroboration scoring, additional domain inference rules, and automatic background reconciliation scheduling remain extensions. Incomplete cascades retain barriers that keep affected claims unusable.
3. Passing tests and the isolated matrix do not certify all live services or containment of arbitrary hostile code. Strong process/container isolation and independent OS network enforcement belong to the planned Phase 7 work.

The development vault was not opened during the repair verification. Changes remain local and unstaged.

Detailed evidence: [verification results and source hashes](PHASE5_VERIFICATION_RESULTS.json).

---

**The connection to Program 2 tomorrow**

Program 2 begins at **Phase 6: Internal Governed Curiosity**. Its next question is: “Given the evidence already available, what useful internal uncertainty should CIPH investigate next?”

Existing curiosity and question structures provide starting points. Their existence does not establish that the full Phase 6 requirements have been completed.

A sensible first review is to follow one internal question through this proposed cycle:

```text
Notice an internal gap → check existing evidence → prioritize the question
→ check budget, duplication and suppression → perform permitted work
→ verify and commit evidence → update the worldview → resolve or retain the gap
```

Phase 6 should search internal evidence first, use deterministic priorities, respect investigation budgets, avoid duplicate questions, and pause when necessary. Its blueprint exit gate requires useful internal investigation **without external network calls**.

For tomorrow’s kickoff, we can review the existing curiosity code against that gate, choose one small internal investigation as the first complete example, and define its acceptance tests. We should keep the Phase 5 barriers intact while doing so.

The later Program 2 phases are **7: external evidence and sandboxing**, **8: evidence-driven self-evolution with operator review**, and **9: empirical capability self-knowledge**. They build on the same request → permission → execution → evidence → claim chain.

Roadmap reference: [Convergence Blueprint, implementation roadmap](CIPH_CONVERGENCE_BLUEPRINT.md#21-implementation-roadmap-two-program-structure).

**Your quick review prompts**

- Can I follow a command from its name to its worker receipt?
- Can I tell the difference between successful execution and an accepted proposition?
- Do uncertain side effects trigger reconciliation rather than an automatic repeat?
- Can I explain why old or invalid premises stop supporting active conclusions?
- Is tomorrow’s first curiosity example internal, bounded, and using this same evidence path?
