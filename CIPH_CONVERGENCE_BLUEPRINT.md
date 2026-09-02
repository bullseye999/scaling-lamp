# CIPH Convergence Blueprint

**Status:** Assessment draft  
**Date:** 2026-08-31  
**Implementation state:** Dialogue and architecture only

No implementation work, code transfer, or publication is authorized by this document. It records the architecture agreed during assessment mode.

## 1. Mission

CIPH's next phase is convergence rather than feature expansion.

The objective is to transform CIPH from a collection of powerful modules into one governed cognitive runtime where:

    Every intention becomes a validated plan.
    Every execution produces a receipt.
    Every accepted belief references evidence.
    Every uncertainty becomes a governed question.
    Every self-improvement begins with a demonstrated engineering gap.

Guiding instruction:

> Stop growing CIPH sideways. Make its existing organs share one nervous system.

## 2. Constitutional Rules

### Reality

- LLM output is never evidence.
- No execution claim is accepted without a valid receipt.
- No receipt means no verified state change.
- Failed and policy-blocked actions also produce receipts.
- External content enters as untrusted observations.
- Accepted truth lives in the worldview, not prompts or module flags.

### Authority

    LLM         proposes interpretations and actions
    Curiosity   prioritizes uncertainty
    Planner     compiles validated action graphs
    Kernel      authorizes actions and admits evidence
    Workers     execute actions
    Receipts    attest outcomes
    Worldview   represents accepted knowledge
    Operator    controls consequential actions and deployment

### Evolution

- CIPH never modifies itself merely because an LLM suggested an improvement.
- Self-relevance must be supported by an observable engineering gap.
- Candidate code never replaces a live implementation directly.
- Promotion requires isolation, tests, benchmarks, approval, canary observation, and rollback.
- CIPH cannot install LLM-inferred dependencies automatically.

## 3. Target Architecture

    USER / EVENT / SCHEDULE
              |
              v
    DETERMINISTIC COMMAND ROUTER
              |
       known command?
        /           \
      yes            no
       |              |
       |        CONTEXT ASSEMBLER
       |        verified state first
       |              |
       |              v
       |             LLM
       |        IntentProposal
       |              |
       +-------+------+
               v
        SCHEMA VALIDATION
          /           \
    incomplete       complete
        |               |
        v               v
    clarify          PLANNER
    with operator       |
                       v
                  ExecutionDAG
                       |
                       v
                     KERNEL
              scope / policy / risk
             authorization / budget
                       |
                  authorized?
                   /       \
                 no         yes
                 |           |
                 v           v
          Validation      PERSISTENT
            Result        JOB QUEUE
                               |
                               v
                            WORKER
                               |
                               v
                       EXECUTION RECEIPT
                               |
                               v
                           EVENT STORE
                               |
                               v
                       EPISTEMIC KERNEL
                               |
                               v
                    MATERIALIZED WORLDVIEW
                         /           \
                        v             v
                grounded reply   curiosity event

## 4. Canonical Existing Components

CIPH should extend its existing CIPH 4 contracts instead of creating another competing framework.

| Responsibility | Canonical destination |
|---|---|
| Application bootstrapping | Thin CiphCore or bootstrap layer |
| Capability interface | BaseCapability |
| Capability discovery | CapabilityRegistry |
| Static action policy | CapabilityManifest |
| Scope & boundary constraints | ScopeGrant |
| Explicit operator authorization | AuthorizationGrant |
| Plans & DAGs | PlanStep and ExecutionDAG |
| Persistent execution | IPCJobQueue, JobAttempt, and DurableWorkerDaemon |
| Execution evidence & receipts | ExecutionReceipt (HMAC-signed, hashed payloads) |
| Untrusted external intake | Observation (source, freshness, content hash) |
| Epistemic assertions | Claim and TransmutationDAG |
| Historical truth | EventStore |
| Current accepted truth | MaterializedWorldview |
| Operational status | StateManager |
| Private encrypted information | CipherVault |
| Attention and interaction rhythm | CadenceManager |
| Operator-facing epistemic language | DialogueFormatter |

Receipt gating, graveyard behavior, contradiction handling, and TTL behavior from CiphKernelV3 should migrate into the canonical kernel rather than creating a permanent second kernel.

## 5. State Ownership

CIPH must distinguish different forms of state.

### StateManager

Live operational status:

- Running workers
- Loaded capabilities
- Tor health
- Active jobs
- Current focus
- System readiness

### EventStore

Immutable historical events:

- Actions proposed
- Jobs leased
- Receipts stored
- Claims transitioned
- Questions opened

### MaterializedWorldview

Current accepted beliefs:

- Supported claims
- Disputed claims
- Stale claims
- Active evidence relationships

### CipherVault

Private encrypted information:

- Personal memories
- Credentials
- Operator configuration
- Sensitive histories
- Private context

StateManager must not become the universal database. It is the live operational projection.

Modules may keep temporary internal state, but authoritative changes must be emitted as events and reflected through their designated state owner.

## 6. Capability Architecture

Every executable operation becomes an action-level capability:

    memory.retrieve
    memory.store
    sports.predict_match
    bounty.passive_recon
    osint.collect_feed
    code.inspect
    telemetry.measure_transport

A provider can expose several capabilities, but every operation receives its own contract.

A complete manifest declares:

- Name and version
- Provider
- Description
- Input and output schemas
- Risk tier
- Network policy
- Reversibility
- Authorization tier
- Required scope type
- Timeout and resource limits
- Receipt schema
- Side-effect class
- Dependency requirements
- Health-check behavior
- Compatibility version

CiphCore must not know whether sports prediction uses Poisson modeling, an API, or a future implementation. It asks the registry for sports.predict_match.

### Provider lifecycle

    initialize
    health
    list capabilities
    execute
    drain
    shutdown

### External Policy & Transport Enforcement

Capability manifests declare policy requirements, but the capability code is **never trusted** to enforce them itself:
- `OFFLINE_ONLY`: Sockets are disabled at the runner/sandbox boundary. Any socket syscall is trapped or denied.
- `TOR_MANDATORY`: Non-Tor egress is blocked by network namespace/firewall/proxy rules. Transport fails closed if the Tor circuit is unavailable.
- `Actual transport`: The worker supervisor independently inspects and measures the network transport route; the capability's self-reported transport is not taken as fact.

### Replaceability

    Memory V1 active
          |
    Memory V2 staged
          |
    contract tests
          |
    shadow execution
          |
    benchmark
          |
    operator approval
          |
    canary activation
          |
    promote or rollback

## 7. Command and Intent System

### Deterministic path

Known slash commands use a declarative CommandRegistry rather than a giant if/elif chain.

Each command registration contains:

- Command and aliases
- Parameter schema
- Capability
- Authorization requirements
- Help text

### Natural-language path

Natural or ambiguous requests go to the LLM, which returns an IntentProposal. The proposal is not executable.

An IntentProposal contains:

- Objective
- Proposed capability
- Provided parameters
- Missing parameters
- Scope reference
- Constraints
- Requested outcome

If required data is missing:

- Use a default only if the capability explicitly declares it safe.
- Otherwise ask the operator.
- Never invent a target or authorization scope.
- Do not issue an ExecutionReceipt because nothing executed.
- Produce a PlanValidationResult or MissingParameterNotice.

### Authorization as a First-Class Object

Authorization is never a loose boolean flag (`authorized = True`). Operator or policy approvals generate an immutable, short-lived `AuthorizationGrant`:

```
AuthorizationGrant:
  grant_id: str (UUID)
  plan_hash: str (SHA-256 of compiled ExecutionDAG)
  step_id: str
  capability: str
  params_hash: str (SHA-256 of canonical params)
  scope_grant_id: str
  max_budget: Dict[str, float]
  expires_at: float (epoch timestamp, short TTL)
  signature: str (Kernel HMAC / Key)
```

`ScopeGrant` explicitly defines allowed targets:
```
ScopeGrant:
  scope_id: str
  scope_type: ScopeType (e.g. LOCAL_SYSTEM, TARGET_DOMAIN, TELEMETRY_ONLY)
  allowed_targets: List[str]
  denied_targets: List[str]
  network_policy_override: Optional[NetworkPolicy]
  valid_until: float
```

The kernel independently validates every completed proposal against active grants before generating job leases.

## 8. Planning and Execution

The LLM proposes actions. The deterministic planner constructs the executable DAG.

A plan includes:

- Plan ID and objective
- Steps (`PlanStep`) and dependency graph (`ExecutionDAG`)
- Preconditions and success conditions
- Budgets and timeouts
- Scope references (`ScopeGrant`)
- Required `AuthorizationGrant` specifications
- Reversibility
- Compensation actions
- Stop conditions

The kernel checks:

- Capability registration & version
- Parameter schemas & types
- Valid `ScopeGrant` and `AuthorizationGrant` matching `plan_hash` and `params_hash`
- Network policy (independently enforced)
- Resource budget & time boundaries
- Recursion limits
- Reversibility & sandbox tier requirements
- Idempotency key uniqueness
- Existing tabu and failure history

Workers, not the kernel, perform operations. The kernel authorizes execution and validates the resulting evidence.

## 9. Canonical Receipts & Trust Model

Every attempted action produces an `ExecutionReceipt`.

### Receipt Schema
- Receipt ID, Job ID, Plan ID, Step ID
- Worker ID & Worker signature (HMAC authenticated)
- Capability name and provider version
- Target and `ScopeGrant` reference
- Input parameters hash and output payload hash (SHA-256)
- Raw artifact reference (URI or artifact store hash for payloads > 64KB)
- Start and completion timestamps (epoch float)
- Exit code and structured outcome category
- Requested network policy and independently measured transport
- Side effects emitted
- Resource usage metrics (CPU, RAM, wall time)
- Attempt number and deterministic idempotency key:
  `idempotency_key = sha256(plan_id + ":" + step_id + ":" + params_hash)`
- Environment fingerprint (OS, Python version, Git commit hash)
- Error classification and backtrace (if failed)

### Receipt Trust Boundaries & Artifact Storage
1. **Integrity vs Honesty:** A payload hash guarantees byte-level integrity against corruption, but does not prove worker honesty. Receipts must carry an authenticated `worker_id` and cryptographic HMAC generated by the local worker runtime.
2. **Artifact Separation:** SQLite `EventStore` holds structured metadata, summary stats, and content hashes. Large execution payloads (PCAPs, full HTML dumps, AST trees) are persisted in an immutable artifact store (`ciph_vault/artifacts/`), referenced by content hash.
3. **Receipt Immutability:** Once written to `EventStore`, receipts cannot be updated or deleted.

Possible outcomes:

    SUCCESS
    PARTIAL_SUCCESS
    EXECUTION_ERROR
    POLICY_BLOCKED
    AUTHORIZATION_REQUIRED
    TIMEOUT
    RESOURCE_EXHAUSTED
    DEPENDENCY_FAILURE
    SANDBOX_VIOLATION
    CANCELLED

A receipt proves what happened during an execution attempt. It does not automatically prove every generalized conclusion inferred from the output.

## 10. Epistemic Governance

CIPH must separate epistemic state, lifecycle, and freshness.

### Epistemic state

    UNKNOWN
    HYPOTHESIZED
    OBSERVED
    CORROBORATED
    SUPPORTED
    DISPUTED
    REFUTED
    SUPERSEDED
    VERIFIED_REAL

> **Epistemic Principle on `VERIFIED_REAL`:**  
> `VERIFIED_REAL` does not represent absolute, timeless, or metaphysical truth. It means **empirically supported within the recorded scope, environment fingerprint, and freshness TTL**. Every claim retains its provenance, expiration horizon, and the possibility of future reopening or refutation upon contradictory evidence.

### Lifecycle

    ACTIVE
    DORMANT
    ARCHIVED
    REOPENED

### Freshness

Freshness is calculated from:

- Evidence age
- Subject volatility
- Source reliability
- Software or environment version
- Contradictions
- Corroboration
- Expiration rules

An old hypothesis does not become false. It becomes dormant and leaves normal reasoning context.

### Decay profiles

    Live network state      minutes or hours
    Operational anomaly     days
    Software behavior       until version or environment changes
    Strategic hypothesis    weeks or months
    Mathematical fact       no temporal decay

New relevant evidence can reopen dormant claims.

The graveyard contains refuted, superseded, abandoned, or repeatedly failed hypotheses, not everything merely unanswered.

## 11. Curiosity Engine

Curiosity begins from CIPH's worldview, goals, receipts, and failures.

### Six sources

    UNKNOWN       What is missing?
    DISPUTED      Why does evidence disagree?
    ANOMALY       Why did reality behave unexpectedly?
    GOAL_GAP      What must be learned to achieve the objective?
    SELF_GAP      What does CIPH not understand about itself?
    EXPLORATION   What potentially useful area remains unexplored?

### CuriosityQuestion

A governed question contains:

- Question ID, text, source, and subject
- Parent question
- Evidence that created it
- Known facts and unknowns
- Evidence requirements
- Permitted sources
- Scope and risk lane
- Impact, novelty, urgency, and goal relevance
- Estimated information gain and cost
- Budget and deadline
- Success and stop conditions
- Recursion depth
- Deduplication fingerprint
- Status

### Question lifecycle

    OPEN
    INVESTIGATING
    PARTIALLY_RESOLVED
    RESOLVED
    PAUSED_BUDGET
    BLOCKED_SCOPE
    BLOCKED_EVIDENCE
    EXPIRED
    ABANDONED

Budget exhaustion pauses a question. It does not make it false.

High-impact paused questions appear in /briefing. New evidence may reopen them.

### Priority

Priority is calculated deterministically:

    impact
    + goal relevance
    + urgency
    + anomaly severity
    + information value
    + approved operator focus
    - investigation cost
    - execution risk
    - redundancy

The LLM may propose factors but cannot assign the authoritative score.

## 12. Curiosity Cadence

Curiosity is primarily event-driven.

    Failed receipt
    Disputed claim
    Expired fact
    Missed prediction
    Unexpected latency
    New objective
    Repeated failure
    Missing capability
           |
           v
    Curiosity candidate

Recommended rhythm:

- Integrity-critical events create immediate candidates.
- Normal failed or disputed events are debounced and batched.
- Full worldview reconciliation runs at startup and periodically.
- Exploration runs only during idle windows.
- Duplicate anomalies form one parent question with grouped evidence.

The existing curiosity daemon becomes:

    CuriosityEngine
        +-- GapResolver
        +-- ContradictionResolver
        +-- AnomalyInvestigator
        +-- GoalResearcher
        +-- SelfInvestigator
        +-- ExploratoryResearcher

ExploratoryResearcher may produce questions and observations. It cannot directly generate deployable mutations.

## 13. Internal-First Investigation

Evidence order:

    Question
    -> MaterializedWorldview
    -> receipts
    -> telemetry
    -> verified memory
    -> previous observations
    -> previous questions and hypotheses
    -> LLM generates hypotheses
    -> determine the remaining information gap

DeepSeek's prior knowledge is useful for hypothesis generation. It is never evidence.

External acquisition occurs only when internal evidence cannot resolve the question.

External results become Observation objects containing:

- Source
- Retrieval time
- Collection method
- Reliability class
- Content hash
- Raw evidence reference
- Expiry
- Scope

External text is untrusted and cannot issue capability calls.

## 14. Experiment Isolation

RunPod is optional. CIPH is local-first.

### Isolation tiers

    SIMULATION
    DISPOSABLE_PROCESS
    ROOTLESS_CONTAINER
    LOCAL_VM
    REMOTE_EPHEMERAL_ENVIRONMENT
    AUTHORIZED_LIVE_CANARY

The kernel selects the minimum safe tier.

Sandbox defaults:

- No secrets
- No host directory mounts
- Read-only fixtures
- Network disabled
- Explicit egress allowlist
- No privileged mode
- CPU, memory, storage, and time limits
- No container socket
- Immutable environment manifest
- Kill switch
- Receipt exported before destruction
- Destruction receipt afterward

Network investigation order:

    passive telemetry
    -> synthetic experiment
    -> isolated VM
    -> authorized canary
    -> live change only when explicitly approved

RunPod is reserved for GPU-heavy or hardware-limited experiments. It is not required for networking, Python, memory, kernel, or Tor development.

## 15. Dependency Security

Automatic pip installation from generated imports (such as historical routines in `code_staging.py:114`) is an active security hazard and **must be removed immediately in Phase 0**.

Replacement process:

    candidate requests dependency
    -> package exists in allowlist?
    -> version pinned?
    -> hash verified?
    -> license and provenance known?
    -> vulnerability policy passed?
    -> operator approval if new?
    -> install inside isolated candidate environment

Candidate dependencies never install directly into CIPH's live host environment.

## 16. Operator Focus Context

CIPH may use operator attention to prioritize curiosity, but it must not surveil the operator.

Allowed signals:

- Explicit /focus
- Active CIPH objective
- Current dialogue
- Approved workspace activity
- Current task queue
- Operator-pinned priorities
- DEEP_FOCUS state

Avoid:

- Persisting raw shell history
- Monitoring unrelated directories
- Permanent behavioral profiling
- Reading sensitive content without consent

Store derived, expiring signals:

    focus_area: network_runtime
    strength: 0.82
    source: approved_workspace_activity
    expires_at: ...

Operator focus is one priority factor. It never suppresses critical security or integrity events.

## 17. Maintenance Mode

When CIPH is idle, it enters maintenance rather than unlimited curiosity.

Permitted tasks:

- Verify event-chain integrity
- Expire abandoned leases
- Deduplicate questions
- Refresh indexes
- Detect database growth
- Safely checkpoint WAL files
- Validate backups
- Audit capability health
- Run isolated AST and static checks
- Generate derived episodic summaries
- Identify stale configuration

Maintenance requires:

- A separate resource budget
- A global maintenance lease
- No conflicting database writers
- No automatic code modifications
- No outward network activity by default

Summaries never silently replace raw evidence. They are derived claims linked to source event IDs.

## 18. Evidence-Driven Evolution

Curiosity cannot promote directly into self-modification.

The transition requires an EngineeringGapCandidate containing:

- Gap ID
- Source questions
- Supporting receipts
- Repeated failure evidence
- Affected capability
- Measurable operational cost
- Missing telemetry or behavior
- Expected improvement
- Testable success metric
- Risk
- Proposed owner

Evolution chain:

    Verified engineering gap
            |
    Evolution Bridge
            |
    Self-Awareness inspection
            |
    Engineering hypothesis
            |
    Candidate design
            |
    Code staging
            |
    Dependency review
            |
    Isolated static checks
            |
    Contract tests
            |
    Behavioral tests
            |
    Security and invariant tests
            |
    Resource benchmark
            |
    Operator review
            |
    Shadow deployment
            |
    Canary activation
            |
    Promote or rollback
            |
    Evolution receipt

NO_RELEVANCE_FOUND becomes a durable outcome rather than a silent None.

No candidate applies itself.

## 19. Capability Self-Knowledge

CIPH answers "What can you do?" using a capability ledger rather than identity prompts.

Example:

    Capability: bounty.passive_recon
    Registered: yes
    Available now: yes
    Provider version: 4.1
    Last verified: 2026-08-30
    Recent attempts: 25
    Successful: 21
    Partial: 1
    Execution failures: 1
    Policy-blocked: 2
    Verified transport: Tor SOCKS5h
    Environment: ...
    Evidence receipts: [...]

Reliability considers:

- Sample size
- Recency
- Environment version
- Provider version
- Target class
- Transport
- Partial outcomes
- Policy blocks versus execution failures

CIPH never claims a capability merely because its prompt mentions it.

## 20. CiphCore Migration

CiphCore becomes a compatibility facade and composition root.

Its mature role:

    load configuration
    initialize private vault
    initialize event store
    initialize registries
    register capabilities
    initialize kernel
    initialize planner
    initialize workers
    initialize cognition
    start runtime
    shutdown cleanly

It does not understand sports, darknet, memory retrieval, bounty logic, or upgrade implementation details.

Migration follows a strangler pattern:

1. Register one existing operation as a canonical capability.
2. Route its command through the new path.
3. Verify the complete loop.
4. Keep the old path temporarily as a compatibility fallback.
5. Remove the fallback after behavioral parity is proven.
6. Repeat capability by capability.

There is no big-bang rewrite and no premature microservice conversion.

## 21. Implementation Roadmap (Two-Program Structure)

To prevent cognitive overload and premature complexity, implementation is partitioned into two distinct programs:

---

### PROGRAM 1: CORE HARDENED RUNTIME (Phases 0–5)

#### Phase 0: Freeze, Baseline & Urgent Safety Fixes
- Freeze major feature expansion.
- **Urgent Safety Gate:** Eliminate generated-dependency auto-installation (`pip install`) from `code_staging.py:114` and live execution paths.
- Record existing baseline behaviors and run contract tests.
- Identify personal versus public data boundaries for sanitization.

**Exit gate:** Auto-pip is eradicated, baseline tests pass, and scope boundaries are locked.

#### Phase 1: Canonical Versioned Contracts & Schemas
- Formally define strongly typed, versioned data contracts:
  - `ScopeGrant` & `AuthorizationGrant` (first-class immutable objects, HMAC-signed)
  - `IntentProposal` & `PlanStep` & `ExecutionDAG`
  - `JobAttempt` & `ExecutionReceipt`
  - `Observation` & `Claim`
- Remove duplicate conceptual ownership.
- Separate operational (`StateManager`), historical (`EventStore`), epistemic (`MaterializedWorldview`), and private (`CipherVault`) state.

**Exit gate:** Complete, versioned contract test suite passes.

#### Phase 2: Safe Reference Loop with Durable Persistent Queue
- Integrate a minimal durable `IPCJobQueue` with SQLite WAL transaction boundaries.
- Wire a low-risk offline capability (`memory.read` or `telemetry.transport_check`):
  ```
  intent -> plan -> kernel authorization -> durable job -> worker -> HMAC receipt -> EventStore -> Worldview -> response
  ```
- Establish the end-to-end receipt generation, hashing, and event emission path.

**Exit gate:** The complete offline loop passes integration, crash-interruption, and replay tests.

#### Phase 3: Robust Worker Daemons, Leases & Crash Recovery
- Implement durable worker daemon pool with heartbeat leasing.
- Enforce at-least-once delivery with deterministic idempotency keys:
  `idempotency_key = sha256(plan_id + ":" + step_id + ":" + params_hash)`
- Atomic `BEGIN IMMEDIATE` transaction boundaries between job state and receipt commit.
- Connect worker output directly to `EventStore`.

**Exit gate:** Simulated worker kills and retries leave zero corrupted state and produce zero duplicate side effects.

#### Phase 4: Command & Capability Strangler Migration
- Introduce declarative `CommandRegistry` (deprecating if/elif chains in `ciph_core.py`).
- Implement capability adapters for core modules (OSINT, Memory, Tor, Pentest, Sports).
- Migrate commands incrementally via shadow execution and parity tests.
- Shrink direct `CiphCore` orchestration dependencies.

**Exit gate:** All core slash commands route through the governed kernel without calling raw module implementations directly.

#### Phase 5: Epistemic Convergence
- Consolidate receipt-gated claim management in `MaterializedWorldview`.
- Implement decay profiles, TTL invalidation, and hypothesis graveyard.
- Implement contradiction detection and evidence linking (`TransmutationDAG`).
- Retire duplicate epistemic state paths.

**Exit gate:** No claim in `MaterializedWorldview` exists without a verifiable `ExecutionReceipt` or `Observation`.

---

### PROGRAM 2: GOVERNED COGNITION & EVOLUTION (Phases 6–9)

#### Phase 6: Internal Governed Curiosity
- Introduce `CuriosityQuestion` objects and DAG.
- Implement deterministic candidate prioritization (impact, relevance, cost, risk).
- Search internal evidence first (`MaterializedWorldview`, `EventStore`, telemetry).
- Enforce investigation budgets, question deduplication, and auto-pausing.

**Exit gate:** Curiosity investigates and resolves internal operational gaps without external network calls.

#### Phase 7: External Evidence & Multi-Tier Sandboxing
- Implement external evidence-source policies (`ReliabilityClass`).
- Build multi-tier local execution sandboxes (disposable process, rootless container).
- Independently enforce network policies (`OFFLINE_ONLY`, `TOR_MANDATORY`) at the OS/runner layer.
- Treat all external content as untrusted `Observation` objects.

**Exit gate:** Sandboxed execution cannot access host files, secrets, or unauthorized network interfaces.

#### Phase 8: Evidence-Driven Self-Evolution
- Gate all code modifications behind an `EngineeringGapCandidate`.
- Enforce mandatory pipeline: gap -> hypothesis -> staging -> isolated tests -> benchmarks -> operator review -> canary -> promote/rollback.
- Prohibit autonomous live code mutations or dependency installations.

**Exit gate:** Zero self-modifications can bypass explicit operator sign-off and regression rollback.

#### Phase 9: Capability Ledger & Empirical Self-Knowledge
- Derive CIPH's self-knowledge ("What can you do?") strictly from empirical receipt ledgers.
- Implement idle maintenance leases (integrity verification, WAL checkpointing, index refresh).
- Generate verifiable capability reports and operator briefings.

**Exit gate:** CIPH accurately reports its abilities based purely on verified execution history.

---

## 22. Required Invariant Tests

The unified system must formally verify and prove:

- **Epistemic Authority:** LLM output cannot directly mutate authoritative state or create accepted claims.
- **Execution Evidence:** Missing parameters or unexecuted actions never produce `ExecutionReceipt`s.
- **Deterministic Idempotency:** Re-executing a job with identical `idempotency_key = sha256(plan_id + ":" + step_id + ":" + params_hash)` re-uses the existing receipt or idempotently skips execution without duplicate side effects.
- **Crash Safety:** Worker crashes during execution preserve recoverable job leases; atomic transactions prevent orphan jobs or partial receipt commits.
- **Bounded Verification:** `VERIFIED_REAL` is bounded by freshness TTL, environment fingerprint, and scope; failed actions are permanently recorded as failures.
- **Evidence Dynamics:** Expired hypotheses transition to dormant (never falsely refuted); new evidence can reopen dormant questions.
- **Prompt Injection Defense:** External documents and untrusted observations cannot trigger capability execution or kernel policy bypasses.
- **External Policy Enforcement:** `OFFLINE_ONLY` capabilities are denied socket creation by the OS sandbox; `TOR_MANDATORY` capabilities fail closed if Tor is unreachable.
- **Dependency Isolation:** Generated imports cannot invoke `pip install` or modify the host environment.
- **Evolution Governance:** Failed code upgrades leave the active runtime intact; canary degradation triggers automatic rollback.
- **Sanitization Invariant:** No private operator secrets, keys, or personal memories can leak into public staging packages.

## 23. Private-to-Public Workflow

### Private workspace

ciph_project is the personal working version.

It may contain:

- Personal identity and preferences
- Private memory
- Credentials
- Local databases
- Logs
- Operator-specific behavior
- Sensitive reports
- Private books and artifacts
- Local machine paths

It never directly publishes anything.

### Sanitization gate

Before public transfer, review for:

- Names and identity
- Personal prompt rules
- API keys and credentials
- Environment files
- Encryption keys and salts
- Databases and WAL files
- Logs and PID files
- Reports and target information
- Private memory
- Local filesystem paths
- Operator profiles
- Personal contact information
- Books and licensed or private artifacts
- Generated predictions and histories

### Public staging workspace

Only sanitized source, safe configuration examples, tests, documentation, and public assets move into scaling-lamp.

Release workflow:

    Private implementation complete
            |
    privacy and secret audit
            |
    sanitized transfer proposal
            |
    operator review
            |
    explicit approval to transfer
            |
    tests inside scaling-lamp
            |
    release summary and final diff
            |
    explicit operator approval to push
            |
    push only after approval

Finishing code is never permission to transfer or push.

## 24. Explicitly Deferred

Until convergence is complete:

- No new mega-intelligence engine
- No voice system
- No GUI expansion
- No additional trading strategy
- No additional crawler merely for feature count
- No consciousness layer
- No microservice conversion
- No required RunPod dependency
- No autonomous dependency installation
- No automatic self-deployment
- No covert operator profiling
- No large directory reorganization before behavior is unified

## 25. Final Principle

    CIPH should not believe because an LLM said so.
    CIPH should not act because curiosity wanted to.
    CIPH should not evolve because a blueprint sounded clever.

    CIPH reasons through the LLM.
    CIPH investigates through governed curiosity.
    CIPH acts through authorized capabilities.
    CIPH remembers through validated evidence.
    CIPH evolves through measured improvement.
    CIPH remains under operator authority.

This blueprint remains an assessment artifact until the operator explicitly ends assessment mode and authorizes implementation.

