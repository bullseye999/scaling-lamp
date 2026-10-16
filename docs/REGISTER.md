# CIPH Register — open migration decisions

## R1. Vault identity (`vault_id`) — DONE (see `CIPH_R1_VAULT_IDENTITY_SEAL.md`)

**Status:** CLOSED. Implemented in `ciph/kernel/vault_identity.py`, migrated the live vault on
2026-10-08 (vault_id `VAULT-0E79C7AFD84940BB`, 4 rows rewrapped byte-identically, 3 previously
plaintext keys now encrypted), and proven by 13 specimens plus a portability check. The sections
below are kept as the decision record.
**Found by:** the post-cutover governed smoke (2026-10-07) failing with `InvalidTag`.

### What is wrong today

`TrustRegistry._get_vault_kek()` derives the key-encryption key as:

```
sha256(machine_seed + db_path.encode("utf-8") + "CIPH_VAULT_KEK_V1_SALT_KEYPAIR_PROTECTION")
```

Two consequences, both observable:

```
open the SAME file as "ciph_vault.db"        -> KEK A   (what the running daemon uses)
open the SAME file as "/abs/path/.../...db"  -> KEK B   -> registered private keys fail to decrypt
rename or move the vault                     -> every registered key becomes undecryptable
restore a legitimate backup to a new path    -> same
```

The path answers *where the vault is*. It must not answer *which cryptographic vault this is*.

### Decision

Give the vault an explicit, stable logical identity:

```
vault_id = immutable random identifier created with the vault, stored unencrypted
           (and authenticated) in a readable header, because deriving the KEK from an
           identifier that itself requires the KEK would be circular

KEK context = root secret + vault_id + KDF/version/domain separation
db_path     = locator only, never part of the key context
```

Resulting semantics:

```
rename vault                  -> same vault
move vault                    -> same vault
restore legitimate backup     -> same vault
deliberate fork               -> explicit new vault_id + rekey operation
```

### Why this is a migration, not a patch

Existing private keys were encrypted under the path-derived KEK. The migration is an explicit
**rewrap** with proof at each step:

```
for each key row:
    old_plaintext = decrypt(old_kek, row)
    new_cipher    = encrypt(new_kek, old_plaintext)
    assert decrypt(new_kek, new_cipher) == old_plaintext      # byte equality, not a hash
    only then write new_cipher
retire the legacy derivation ONLY after every row is proven rewrapped
```

Explicitly rejected: canonicalizing the path. That would produce a better-hidden path dependency
rather than removing it.

### Not in scope of this register item

Nothing about permits, generations, evidence or continuity. `vault_id` is an identity of a *key
store*, and the fix must not be smuggled in as part of 4.1.

## R2. A resolved attempt consumed before its evidence was durable

**Status:** closed (4.1). `consume_permit_row` is now runnable inside a caller's transaction, and the
daemon's success path passes it into the queue's completion transaction, so terminal evidence, the
job's terminal state and the permit's consumption are one proposition. The remaining window - crash
between durable evidence and consumption - is a visible `completion_obligation`, closed by
`complete_pending_consumption()`, which creates no fact.

## R3. Dynamics read a refutation as a world state

**Status:** CLOSED (4.3 Gate One). Found by adversarial probing of the new world-model/dynamics
stack, before 4.3 was sealed.

### What was wrong

`derive_transitions` accepted both `PRESENT` and `ABSENT` world facts as "state values". An `ABSENT`
fact is knowledge that a claim **did not hold**, not the world taking some other definite state, so
the model read the refuted claim's asserted text as if it were the world's value. Two reachable
cases produced statements the evidence denied:

```
CASE A   HEALTHY@T1 and DEGRADED@T2 present, "HEALTHY@T3" refuted
         -> the world is still DEGRADED at T3
         WRONG: a fabricated DEGRADED -> HEALTHY "recovery"

CASE B   HEALTHY@T1, DEGRADED@T2 and HEALTHY@T3 present, "DEGRADED@T3" refuted
         WRONG: an extra DEGRADED -> HEALTHY transition with exact_at = T3 -
                an invented instant, from a claim the evidence refuted
```

This is an execution-truth issue, not polish: the layer's own promise is "never narrate a moment it
never saw", and both cases violate it.

### Decision

Only a `PRESENT` fact establishes a world **state**. A refutation is not used as a state value. A
state that matters is asserted as its own `PRESENT` proposition -- which is already what Gate Zero's
founding specimen does when it encodes "offline" as `is_online = False`, present. Where this leaves a
relation under-described, dynamics **under-reports rather than inventing a transition**, matching how
the rest of the constitution resolves uncertainty.

### Verification

Two specimens added (`test_a_refutation_is_not_a_state_value`,
`test_a_refutation_never_produces_an_exact_time_flip`); the pre-existing 10 dynamics specimens are
unchanged and green; the two reproductions above no longer emit the spurious transitions.

### Recorded asymmetry (not a defect)

Encoding a state only as a refutation (e.g. `is_online = True` refuted) now yields no transition,
because a refutation is not a state. The intended encoding is the complementary `PRESENT` assertion.
Recorded so the asymmetry is not rediscovered as a surprise.

## R4. `ciph_observations` was claimed by two subsystems

**Status:** CLOSED (4.4 Gate Three). Found by the first integration of the 4.2 epistemic ledger with
the runtime.

### What was wrong

Two independent subsystems created a table with the same name and different shapes, both with
`CREATE TABLE IF NOT EXISTS`, so whichever ran first silently won:

```
ciph/kernel/epistemic_ledger.py    (4.2 Gate Zero)
    ciph_observations(observation_id, source_ref, observed_at, received_at,
                      content_digest, raw_text)

ciph/memory/materialized_views.py   (older MaterializedWorldview store)
    ciph_observations(observation_id, source, subject, predicate, value,
                      raw_evidence_digest, raw_evidence_ref, content_hash,
                      reliability, observed_at, collected_at, ingested_at,
                      expires_at, scope_id, uncertain_source_time, created_at)
```

The two were mutually exclusive in one database, and it failed in BOTH directions:

```
runtime first   ledger INSERT refused:  table ciph_observations has no column named source_ref
ledger first    runtime refused to start: no such column: subject
                             (CREATE INDEX idx_obs_subj_pred ON ciph_observations(subject, predicate))
```

No 4.2 or 4.3 specimen had ever put a `CiphRuntime` and the ledger in the same file - every gate test
used a bare temporary database - so the collision only surfaced when curiosity needed the execution
throat AND the uncertainty registry in one store.

### Decision

The 4.2 ledger's table name and shape are sealed contract, so the rename went the other way: the
older, internal `MaterializedWorldview` table became `ciph_mv_observations`. All ten references were
inside that one module (DDL, three indexes, an upgrade-additions mapping, `_insert_row`, two SELECTs,
and the legacy-projection table list). No other module referenced the name; the only other mention is
a docstring.

### Verification

```
runtime first   ledger writes succeed; ciph_observations is the ledger's shape
ledger first    runtime constructs cleanly; the ledger shape is preserved
legacy suite    test_phase5_epistemic_stage1..4 + test_phase5_epistemic_convergence
                + test_ciph_memory -> 56 tests, green
```

### Note

This is a naming collision, not a policy conflict: the two tables hold genuinely different things and
This is a naming collision, not a policy conflict: the two tables hold genuinely different things and
each keeps its own semantics.

## R5. Production storage still holds the legacy observation table

**Status:** CLOSED - applied to the live vault on 2026-10-09. This was the entry gate to 4.5.

Applied: daemon stopped gracefully, `ciph_backups/pre_r5_migration_20261009T202844.db` taken with the
SQLite Backup API, the live fingerprint re-verified immediately before migrating (matched the proven
fingerprint `eab8231e...` exactly, so no abort was needed), then the verified migration: the legacy
18-column table became `ciph_mv_observations` and the ledger's canonical 6-column `ciph_observations`
took the name. Post-migration: 0 duplicate canonical owners, the ledger reconstructs read-only on the
live vault, the vault identity is unchanged (`VAULT-0E79C7AFD84940BB` / `VAULT_ID_V1`), all protected
rows decrypt, `live_permitless = 0`, and the backup still serves the exact pre-migration state. Full
record in `CIPH45_ENTRY_STORAGE_COMPOSITION.md`.

## R6. A second implementation of the improvement lifecycle already existed

**Status:** CLOSED. Decision: **Option A as the destination, Option C only as the migration path,
Option B rejected** - `ciph/evolution` becomes the machinery, the Crucible remains the constitution.

Implemented as `ciph/kernel/evolution_ownership.py` (executable census + scanners),
`ciph/kernel/evolution_deployment.py` (governed deployment boundary + canonical active state) and
`ciph/kernel/evolution_adapters.py` (Gates B/C/F), with 25 specimens across
`test_r6_ownership_census.py`, `test_r6_deployment_gateway.py`, `test_r6_evolution_adapters.py` and
`test_r6_cross_gate_torture.py`. Measured: 0 ownership violations, 0 direct activation bypasses, 0
missing machinery, 7 constitutional owners, and a valid deployment authorization with no
`PromotionRecord` deploys nothing. `RedShadowCrucible` was renamed `RedShadowHarness` (legacy alias
kept) so "Crucible" names one architecture. Full record:
`CIPH_R6_EVOLUTION_UNIFICATION_SEAL.md`.

### What was found

`ciph/evolution/` and `ciph/contracts/evolution.py` already implement a complete, signed,
operator-gated improvement lifecycle from the earlier Program-1 numbering (Phase 8 and Phase 9). It is
wired into `evolution_bridge.py` and the `ciph_evolution.py` daemon, and covered by eleven test files
(`test_phase8_*`, `test_phase9_*`, `test_loop1_v2_evolution.py`, `test_ciph_evolution.py`).

The 4.5 Crucible built in `ciph/kernel/crucible_*.py` is a **second** implementation of the same
lifecycle. The overlap is close to one-to-one:

```
gap_detector.py         EngineeringGapDetector, EngineeringGapCandidate   <-> 4.6 candidate generation
isolated_execution.py   execute_candidate(...) under kernel/sandbox       <-> 4.5 Gate Two trials
benchmark_harness.py    evaluate_candidate_against_baseline(...)          <-> 4.5 Gate Three metrics
review.py               review_changes / resource_regression              <-> 4.5 Gate One protocol
canary_manager.py       CanaryDeploymentManager, CanaryCriteria           <-> 4.5 Gate Five canary
file_activation.py      activate(artifact, grant, store) / restore(...)   <-> 4.5 Gate Four promotion
                                                                               and Gate Five rollback
workflow.py             EvolutionCoordinator.deploy / run_canary /        <-> 4.5 the whole flow
                        approve_production / _install
evidence.py             EvolutionEvidenceStore                            <-> evaluation evidence refs
```

It also has its own signed contract family in `ciph/contracts/evolution.py`:
`EngineeringGapCandidate`, `EvolutionEvaluationGrant`, `CanaryCriteria`, `EvolutionDeploymentGrant`,
`EvolutionReceipt`, `DeploymentStage`.

### Why this is a real problem, not a naming nit

The two implementations disagree about the things this project has spent five phases making single:

```
candidate identity     candidate_hash + base_file_hash inside a signed grant
                       vs  artifact_digest + configuration_digest -> CC-... in a registry table
the active pointer     _install() replacing a file at a path
                       vs  a pointer row in ciph_crucible_active
evidence               EvolutionEvidenceStore with chain validation
                       vs  trial/observation refs in ciph_crucible_trials
authority to change    EvolutionDeploymentGrant (supervisor-signed)
                       vs  authorization_ref on a promotion record
```

Two identities, two pointers and two evidence stores for one concept is the same defect class as R4,
one level up: R4 was one table name with two owners; this is one *lifecycle* with two owners. It also
means 4.6 already exists in a pre-constitutional form - which is exactly what this register entry
exists to prevent being quietly duplicated a third time.

Note also that `ciph/crucible/red_shadow.py` defines `RedShadowCrucible`, an adversarial-fuzz harness,
so the word "Crucible" now names two different things.

### Options (not decided here)

```
A  ciph/evolution becomes the MACHINERY, 4.5 the CONSTITUTION.
   Gap detection, isolated execution, benchmark, canary and file activation stay where they are;
   4.5 gates call them and own identity, comparison, evidence and the promotion pointer.
B  4.5 replaces ciph/evolution.
   The phase 8/9 modules and their eleven test files are retired or rewritten against the 4.5 APIs.
C  Keep both, and bind them.
   ciph/evolution gains an adapter that registers its candidates into the 4.5 registry and routes
   promotion through the 4.5 pointer - leaving its own activation path unreachable.
```

The choice is an architectural decision, and it should be made **before** any 4.6 code is written,
because 4.6 is the layer that would otherwise be built twice as well.

### Not verified

Whether the eleven evolution test files currently pass in the same sweep as the 4.5 specimens; they
run in the full project sweep. `file_activation.activate()` can rewrite active files, so whichever
option is chosen, that capability has to end up either governed by the Crucible or unreachable.

### What the read-only preflight found

```
live vault ciph_observations   18 columns
                               = the legacy MaterializedWorldview shape (16)
                                 + canonical_payload, revision_event_id  (an additive upgrade)
live vault ciph_mv_observations  does not exist
```

So the R4 rename fixed ownership for **newly created** databases. It did not migrate the existing
production vault, which still has the legacy owner holding the name the 4.2 ledger needs. A ledger
write against that vault fails exactly as it did in the composition probe:

```
table ciph_observations has no column named source_ref
```

### What exists now

```
ciph/kernel/schema_ownership.py      table-declaration scanner + fingerprint classifier + migration
live_table_columns / classify_live_table
                                     classify a LIVE table by schema fingerprint, never by name,
                                     and report EXACT / EXTENDS / INCOMPATIBLE against every
                                     declaration in the project
migrate_legacy_observations          BEGIN IMMEDIATE; verify the exact expected fingerprint; refuse an
                                     existing destination; rename; verify row count AND full content
                                     digest unchanged; then let the LEDGER create its own canonical
                                     table
```

A project-wide scan now reports **zero** duplicate canonical table owners across 97 declared tables,
so a future silent second owner is a test failure rather than a discovery.

### The additive-upgrade subtlety

An exact-fingerprint classifier recognized the live table as **nobody's**, because the upgrade added
two trailing columns. Classification is therefore relational: a declared shape that is a live table's
*prefix* with extra trailing columns is `EXTENDS` - the legacy owner, additively upgraded - and the
migration pins the exact live fingerprint so the upgrade is part of the proof rather than an excuse.

### Proven on a production-shaped snapshot

Run against a `sqlite3` backup snapshot of the live vault (never a raw copy of a WAL database):

```
snapshot classified           legacy owner via EXTENDS
migration                     rows 0 -> 0, content digest unchanged
legacy preserved              ciph_mv_observations, 18 columns
ledger owns the name          ciph_observations, 6 columns
ledger write                  succeeds in the production-shaped vault
uncertainty registry          runs
CiphRuntime                   starts
```

### Why the live vault has not been migrated yet

The migration is a deliberate destructive-adjacent operation on production storage, and the resident
daemon (a `ciph_evolution.py --daemon` process) currently holds the live vault open. R1's own precedent
was to stop the resident daemon before migrating. Stopping a production daemon and mutating the live
vault is an operational action that needs an explicit go-ahead, so it is left as the single remaining
step rather than performed silently.

## R7. The legacy evolution entry points still reach activation directly

**Status:** CLOSED. The production activation primitives now require a canonical Crucible promotion:
`CanaryDeploymentManager.approve_production` verifies the promotion, the exact candidate identity and the
expected baseline before installing, and verifies the installed bytes afterwards;
`EvolutionCoordinator._install` verifies the promotion before registering a revision.

Fallout was measured, not guessed: 6 tests in 2 files reached production activation and were migrated
onto the governed path via `phase8_test_support.adopt_and_promote`; the other 147 tests in the legacy
evolution suite were untouched because the canary stage never modified the production file. No
compatibility fallback was added. 7 new specimens use the REAL machinery - real staging, real
`file_activation`, real coordinator - including one that installs and rolls back through it. Scanners
report zero unguarded primitives and zero direct activation bypasses, with catch-specimens.

Original entry, kept for the record:

The governed deployment boundary exists and is proven, but production traffic does not go through it.
`EvolutionCoordinator.deploy`, `run_canary`, `approve_production` and `_install` still reach the old
activation path without a `PromotionRecord` being asked for, so a candidate that 4.6 generates and 4.5
validates could still be installed through the old route.

```
legacy entry points -> direct activation        (today)
governed gateway    -> the only correct route   (proven, not wired)
```

Closing it means the entry points must require a Crucible promotion, which means migrating the eleven
Phase 8/9 test files that call them expecting the old behaviour. The gateway itself is done; the
migration is the work.

Consequence: **4.6 is implemented with 35 specimens green and is NOT sealed.** Every 4.6 specimen that
deploys uses an injected test installer rather than the real machinery, so the phase proves the
constitution's shape rather than its enforcement in production.

Also outstanding for the 4.6 seal: the sanitized-clone sweep. The live sweep is green at
`Ran 1554 tests, OK (1076.0s)`.

## R8. 4.7 is a constitutional core, not a phase

**Status:** CLOSED - 4.7 is SEALED (see `CIPH47_META_EVOLUTION_SEAL.md`).

Measured: 36 specimens green; full project sweep `Ran 1597 tests ... OK (1124.9s)`; sanitized clone
`Ran 1597 tests ... OK (1174.6s)` with no ambient vault; all twelve structural scanners zero in both
trees with catch-specimens; fresh-state assertion zero (including every 4.7 table) in both trees; the
live vault unchanged with no production meta history.

The functional loop runs end to end: opportunity -> hypothesis -> shadow candidate -> sealed corpus ->
real 4.5 Crucible -> META_PARETO_V1 -> restart with the pointer unmoved -> dual-control promotion
through the real R7 install -> new epoch -> governed rollback as a NEW epoch with the earlier eras
preserved.

Recorded limits: comparative generator capability is not claimed (the generators are outcome streams,
with verdicts from the real Crucible); the scanners are static and syntactic; the corpus boundary is
OS-level, not cryptographic; and no production meta history exists, so the live check confirms absence
rather than exercising a read path.

Built and green (12 specimens): ring classification with dispositions
(`ciph/kernel/meta_targets.py`), epochs with append-only judgments and meta rollback
(`ciph/kernel/evolution_epochs.py`), and the self-ratification predicate with shadow-only candidates,
collusion refusal, non-tradeable hard invariants, a recursion bound of 1 and meta promotion
requirements (`ciph/kernel/meta_guard.py`).

Built since: **G4 complete** - the sealed meta corpus and protocol
(`ciph/kernel/meta_corpus.py`, 7 specimens) plus the candidate-process execution boundary
(`ciph/kernel/meta_corpus_isolation.py`, 6 specimens). The boundary is enforced by the existing
isolated-execution machinery: a sandboxed candidate handed the exact sealed path gets `PermissionError`
on every read, finds zero entries by walk/glob, and still receives the corpus as payload data. No second
sandbox was built.

Chunk A (items 2-10) is COMPLETE: G1 meta opportunities, G2 meta hypotheses, the durable shadow
lifecycle, generator meta-evaluation under `META_PARETO_V1`, G5 dual-control promotion through the real
R7 install into a new epoch, meta rollback as a NEW epoch, the evaluator torture (self-rating and
collusion confer nothing; a hard-invariant miss is INVALID), and G10 descriptive learning. A single
end-to-end specimen runs the whole cycle including a restart between the verdict and the promotion.

**Superseded note (2026-10-10):** the paragraph that followed this line was written at the Chunk A
checkpoint, before Chunks B and C ran. Both are now complete and 4.7 is SEALED - see the R8 status line
above and `CIPH47_META_EVOLUTION_SEAL.md`. The checkpoint text is kept below rather than deleted, and the
one thing 5.x changed about 4.7's circuit is recorded in R9.

## R9. Autonomy is a constitution, not a daemon

**Status:** CLOSED - 5.x is SEALED (see `CIPH50_AUTONOMOUS_OPERATING_CONSTITUTION_SEAL.md`).

The decision 5.x records is that **time is not authority either**. 4.0 said a mission is not authority,
4.4 said uncertainty is not a licence, 4.7 said a candidate cannot ratify itself; 5.x adds the fourth
shape - a wake-up, a running process and a standing grant are all reasons to *reconsider* work, never
reasons to do it.

```text
continuity grants persistence, NOT permission
```

Measured: 69 specimens across the six 5.x suites; full project sweep `Ran 1666 tests ... OK (1109.857s)` on the frozen tree;
sanitized clone `Ran 1666 tests ... OK (1019.826s)` with no ambient vault and a fresh vault that reports
zero autonomy state; the twelve 5.x structural scanners zero in both trees with catch-specimens; 4.7's
twelve scanners, the R6 census and the R7 choke-point scanners still zero in both trees; the live vault
unchanged (`VAULT-0E79C7AFD84940BB / VAULT_ID_V1`, 4 protected rows decrypt, `live_permitless = 0`,
`integrity_check ok`, zero autonomy and zero meta tables - no production autonomy history exists).

Seven defects were found by the campaign rather than by inspection, and fixed: a daemon could record a
permissive mode while the operator held one; a lapsed grant answered "unauthorized" instead of
`EXPIRED`; an exactly-on-time wake was classified `UNCERTAIN`; a cadence nomination stayed perpetually
due (so a daily review could be turned into continuous activity); a session work item could never be
resolved, making `DRAIN_REQUIRED` permanent; a retried interrupt reported a change it had not made; and
4.7's `s03` read the 5.x pattern catalogue as a caller of `transition_epoch`.

That last one is the between-phase defect this register exists to catch: 5.x's scanner MUST contain the
other phase's forbidden calls as data, so `meta_scanners._callers` now excludes `*_scanners.py` modules
and a specimen proves the exclusion is narrow (a module that really calls the symbol is still caught).
No 4.7 law changed; the fix is that a catalogue of patterns is not a caller.

Stated limits (in the seal, not implied here): the scanners are static and syntactic; `a09`/`a12` cover
the autonomy namespace and not the pre-5.x daemon entry points, which the R6 census and R7 choke point
still govern; the outage case is an operator `READ_ONLY` hold rather than a simulated partition;
quiescence is single-host; and no production autonomy history exists, so the live check confirms absence.

Blocks: nothing. 5.x is the foundation for 6.x (Swarm), which will need its own answer for distributed
quiescence - the single-host protocol proven here is not that answer.

## R10. One Ciph, many hands — the swarm ownership census

**Status:** CLOSED - 6.x is SEALED (see `CIPH6_GOVERNED_SWARM_SEAL.md`).

The decision is the third shape of the same law. 4.0 said a mission is not authority, 5.x said time is
not authority, and 6.x says **multiplicity is not authority either**:

```text
work is CONTINUOUS without being authorised
wake-ups are not permission
workers may multiply cognition, never authority
```

**The census (done before any swarm code).** The project already had real orchestration machinery: a
durable IPC job queue with leases, tokens, receipts and reconciliation (`ciph/workers/ipc_queue.py`), a
worker daemon, an agent orchestrator, and a Stage-9 `ByzantineConsensusEngine` in `ciph/swarm/` whose
`evaluate_consensus` returns an `approved` flag for a supermajority of self-signed council nodes.

```text
KEEP    queue + daemon + receipts + orchestrator + the consensus MECHANISM
6.x OWNS worker identity/generation/membership/health/capability, delegation, lease meaning,
        result provenance, aggregation, child budgets, quiescence, delegation learning
DEMOTE  the consensus engine's verdict: 0 production consumers, measured
```

That last line is the reason the census exists. "A supermajority approved the mutation" is votes as
authority, and it would have been inherited silently by any swarm built on top of it.

**Measured:** 39 specimens across the two 6.x suites (32 constitution, 7 runtime torture); full project
sweep `Ran 1705 tests ... OK` on the frozen tree; sanitized clone green with no ambient vault and a fresh
vault reporting zero swarm state; the R10 census clean (15 concerns, zero violations, zero
retained-machinery missing, zero verdict consumers, zero swarm bypasses); the twelve 6.x scanners zero
with catch-specimens, and the 5.x and 4.7 scanners still zero beside them; the live vault unchanged.

**Defect worth recording:** the runtime torture caught three workers acquiring ONE delegation. The claim
path read "no active lease" and then wrote one - two statements, not a decision - so three racing
processes each won. Possession is now decided inside `BEGIN IMMEDIATE` with the check repeated under the
write lock. That is hostile case 1, found by running real processes rather than by reasoning about them.

Also fixed: the quiescence module was a second writer of the lease table; capabilities were keyed by
level so two rows disagreed about one capability; child consumption never drew down the parent; a
still-draining barrier promoted its own timeout to INCOMPLETE; `JOINING -> READY` was reachable as a bare
status change, bypassing attestation; a superseded worker's late answer was CONFLICTING rather than LATE;
and the 6.x scanner catalogues were read as violations of each other.

**Stated limits:** quiescence is single-host (federation needs its own answer); the scanners are static
and syntactic with catalogue exclusion stated; the daemon entry points are governed by 5.x's scanners
rather than re-scanned here; and no production swarm history exists, so the live check confirms absence.

Blocks: nothing. 7.x federation inherits the open question - a coordinator that cannot inspect another
machine's process state cannot demand `DEAD + reconciled-with-evidence`, so distributed quiescence must
be solved there rather than assumed from here.

## R11. Distributed ownership census — SURVEY DONE, 7.x NOT STARTED

**Status:** OPEN. The census findings below are recorded; **no 7.x code is written and 7.x is not
sealed.** 7.0-7.14 are the next campaign.

The survey ran before any federation module, for the same reason R6 and R10 did. What exists today:

```text
MECHANISM, KEEP (transport and identity exchange, not constitutional meaning)
  ciph/federation/ghost_mesh.py     GhostMeshNode, MeshHandshake, MeshTaskEnvelope, trusted-peer
                                    key registration. Already separates `node_id` from its address and
                                    requires peers to be registered explicitly - the right instinct.
  ciph/workers/ipc_queue.py         durable queue: the only replication carrier that exists
  ciph/swarm/byzantine_consensus.py the signed multi-node opinion mechanism (already demoted by R10)

NEEDS CLASSIFICATION BEFORE 7.3
  ciph/sovereignty/singularity_engine.py   SovereigntyEngine / SolvencyStatus: it is a PROJECTION, and
                                    the question `7.3` has to answer is whether anything can consume it
                                    as a transition rather than a reading. Unclassified code fails
                                    upward, so it is treated as authority-shaped until proven otherwise.

ABSENT (7.x must own these outright)
  node identity and generation; federation membership and revocation; state classification and
  replication law; authority domains; partition semantics; distributed quiescence; cross-node
  delegation; clock semantics; reconciliation and divergence; node key custody; node health and
  quarantine; rejoin and retirement; federation routing; federation learning
```

Two facts worth carrying into the campaign:

```text
no production consumer of ghost_mesh or the sovereignty engine exists today (docs and tests only)
the 6.x quiescence answer cannot be inherited: `DEAD + reconciled` needs a host that can inspect
processes, and 7.x does not have one across a partition
```

The plan of record is the user's roadmap: **Chunk A** = R11 census as code + node identity + membership
+ state classification + authority domains + replication/reconciliation foundations; **Chunk B** =
partitions + distributed quiescence + clock semantics + node health/rejoin + cross-node delegation + key
custody; **Chunk C** = routing/learning + structural scanners + the three-virtual-node partition torture
+ all prior regressions + full sweep + sanitized clone + seal.

The seal sentence to aim for, and the one this register will not pre-empt:

> **One Ciph. Many nodes. No node becomes sovereign merely because the others went silent.**

## R11. Distributed ownership census — CLOSED

**Status:** CLOSED - 6.x's sibling census is now executable and 7.x is SEALED (see
`CIPH7_GOVERNED_FEDERATION_SEAL.md`).

The law is the fourth shape of the same idea. 4.0: a mission is not authority. 5.x: a wake-up is not
authority. 6.x: a worker is not authority. 7.x: **a network presence is not authority either.**

```text
node != Ciph        quorum != authority      quorum != truth
connectivity != authority                    replication != ownership
timeout != death    timestamp order != constitutional order
```

**The census (before any federation code).** Three mechanisms were kept and proven inert: the GhostMesh
peer transport, the durable IPC queue, and the Stage-9 Byzantine consensus engine. One module was
classified and is the interesting find: `ciph/sovereignty/singularity_engine.py` is not merely a
projection - `execute_governed_evolution_promotion` DISPATCHES a promotion through
`runtime.execute_reference_loop`. It is fail-closed (a signed operator grant is required) and nothing in
production calls it, but it is a second promotion-shaped path outside 4.5/4.7/R7, so it is treated as
authority-shaped until 7.x gives it standing, and its consumer count is scanned rather than assumed. The
operator-grant check is a failsafe, not a justification.

**The four zeros, measured in both trees:**

```text
R11 census violations                                    0
retained machinery missing                               0
production consumers of the ghost-mesh authority symbols 0
production consumers of the consensus verdict            0
production consumers of the sovereignty transition       0
second federation authority owner                        0
```

**Built by 7.x**: node identity and generation (`federation_node.py`), state classification
(`federation_state.py`, `FEDERATION_STATE_CLASSIFICATION_V1` over 22 families), authority domains and
partition semantics (`federation_authority.py`), per-family reconciliation and clock law
(`federation_replication.py`), the federation barrier (`federation_quiescence.py`), cross-node
delegation, routing and learning (`federation_delegation.py`), the root/node custody boundary
(`federation_keys.py`), and the sixteen structural scanners (`federation_scanners.py`).

**Measured:** 55 specimens across the three 7.x suites; full project sweep green on a frozen tree;
sanitized clone green with a fresh vault reporting zero federation state; the sixteen federation
scanners zero with catch-specimens in both trees; R6, R7, 4.7, 5.x and 6.x scanners all still zero
beside them; the live vault unchanged with zero federation tables.

**The pattern worth carrying forward:** the "catalogue read as code" collision appeared in a fifth form
during this campaign (a 6.x specimen restating a census predicate instead of calling it). The repair is
now structural - a suffix rule for catalogues (`*_scanners.py`, `*_ownership.py`) rather than a list that
must be extended every phase - and the general lesson is recorded in the seal: **call the predicate, do
not restate it.**

**Stated limits:** root custody is operator-held and offline (a stated limit, not distributed key
magic); the three nodes are local processes with separate stores, so what is proven is the CONSTITUTION
under partition rather than a real network's failure modes; the scanners are static and syntactic, with
several being presence checks; and no production federation history exists.

Blocks: nothing. 8.x inherits the transport question - partitions here were modelled as observed
reachability and explicit delivery, and a real network's failure modes are a different problem.

## R12. Sovereignty / recovery ownership census — SURVEY DONE, CENSUS ENFORCED, 8.x NOT SEALED

**Status:** OPEN. R12 is executable (`ciph/kernel/sovereignty_ownership.py`, 19 concerns) and clean; the
8.x build is not started and 8.x is not sealed.

The survey ran before any recovery code, and it found exactly what the previous four censuses taught us to
expect: machinery that already touches the thing we are about to own.

```text
MECHANISM, KEPT
  dead_mans_switch.py            DeadMansSwitch: secure_delete (3-pass overwrite), _emergency_destruct,
                                 then os._exit.  A REAL destruction mechanism.
  security_layer.py              encrypted_backup: a GPG symmetric archive of vault + key + config.
  ciph_backups/                  DAG deployment snapshots.  Clone-assertion tools are test tooling.

TWO FINDINGS THAT MATTER

  1. encrypted_backup tars `ciph.key` - ROOT key material - into an ordinary archive member, and
     encrypts with `os.environ.get("BACKUP_PASSPHRASE", "ciph_backup_passphrase")`.  A default passphrase
     is nominal confidentiality, and the root travelling as just another file to unpack is precisely the
     "copy the root everywhere" pattern that makes a compromise of one archive a compromise of Ciph.
     The archive stays a mechanism; root custody is classified SPECIAL and the zero is scanned.

  2. `_emergency_destruct` can erase state on a TIMER.  Destruction authority is too serious to be an
     unowned side effect, so the policy is 8.x's - and the hostile case is scanned: a recovery path may
     not resurrect wipe state, because a restore that re-arms the dead-man switch could destroy the
     machine it just restored onto.

ABSENT, SO 8.x OWNS IT
  sovereign identity, recovery root custody, destruction policy, the recovery manifest, backup
  legitimacy, the recovery state machine and its activation ceremony, the clone-versus-restore
  distinction, node reconstitution, host/provider portability, model substitution, migration lineage,
  drills, sovereignty monitoring, and real (non-simulated) transport.
```

The zeros R12 enforces, all currently empty:

```text
backup directly activates production          0      last-write-wins recovery selection      0
restore bypasses identity verification        0      migration rewrites frozen IDs           0
clone gains production authority              0      recovered permit executes unreconciled  0
restored stale node gains domain ownership    0      restore bypasses R7                     0
root secret ordinary replication              0      dead-man/wipe state restorable          0
node key treated as root key                  0      hostname/path treated as identity       0
model identity treated as Ciph identity       0
```

The plan of record is the user's roadmap. **Chunk A**: real transport (`real_transport.py`, real sockets,
authenticated envelopes with replay/conflict semantics), sovereign identity and recovery-root custody,
the recovery manifest, the backup constitution, and the clone-versus-restore distinction - ending with a
verified backup that has **zero authority to activate itself**. **Chunk B**: clean-host disaster
recovery, node reconstitution and federation reconciliation, host/path portability, model substitution,
migration lineage - ending with a destroyed disposable Ciph restored into a genuinely clean environment
and rejoined without stale authority. **Chunk C**: the twelve scanners with catch-specimens, real-network
transport torture, the catastrophic recovery matrix, all 4.x-7.x regressions, frozen-tree sweep,
sanitized clone, live-vault read-only, seal.

The law the campaign has to earn, stated once so the register cannot pre-empt it:

> **Possession of Ciph's bytes is not possession of Ciph's authority.**

## R12. CLOSED — sovereignty/recovery ownership and the two legacy findings

**Status:** CLOSED. R12's census is enforced and both findings are remediated and proven; 8.x is SEALED
(see `CIPH8_SOVEREIGNTY_RECOVERY_SEAL.md`).

The census became executable first (`ciph/kernel/sovereignty_ownership.py`): 19 concerns, 14 zero classes,
retained machinery verified present. It found three kinds of thing, and the interesting one was classified
rather than trusted:

```text
MECHANISM, KEPT     dead_mans_switch.py (destruction), security_layer.py (archiving), ciph_backups/,
                    the clone-assertion tools
TWO FINDINGS        the legacy backup path bundled `ciph.key` and leaned on a well-known default
                    passphrase; the dead-man switch could destroy state on a timer
ABSENT, SO 8.x OWNED IT
                    sovereign identity + root custody, recovery manifest, backup legitimacy, the
                    recovery lifecycle and its activation ceremony, clone-vs-restore, reconstitution,
                    portability, model substitution, migration lineage, monitoring, real transport
```

**Finding 1 — remediated and proven by CALLING the path.** `encrypted_backup` now raises
`INSECURE_BACKUP_CONFIGURATION` for a missing passphrase, the historical default, or an over-short one,
and refuses root material as content at all. The approved creator refuses the same configurations, and
`ciph.key` is absent from `included` by construction rather than by policy sentence. Historical archives
are classified `INSECURE_HISTORICAL` and are never promoted by improving today's code.

**Finding 2 — remediated and proven by CALLING the destructor.** `_emergency_destruct` refuses without a
named operator authorization, and an historically ARMED timer is reported and left DISARMED after
recovery. A restore cannot carry the instruction to destroy the machine it was restored onto.

**One further load-bearing finding, closed during the seal campaign.** Recovery fencing initially compared
permits against a CALLER-SUPPLIED authorization epoch: an isolated superseded instance could present its
own stale epoch and claim after supersession - a fence made of the prisoner's testimony. The permit store
(4.0's owner, no second executor) now keeps its OWN authoritative epoch: a disagreeing caller is refused
(`DENY_PERMIT_AUTHORIZATION_EPOCH_NOT_AUTHORITATIVE`), omitting the parameter is no escape, and a
"supersession" that does not exceed the epochs already minted is refused as not-superseding. The five
sealed 4.0 permit suites are green beside the six new specimens.

**Measured:** 8.x suites 55 specimens green (19 + 12 + 16 + 4 + 6 across the five files); full project
sweep `Ran 1818 tests in 1664.914s OK` on frozen tree `6b37f387dcfdd99a96e94d29d3c1a465` (digest identical
before and after); sanitized clone `Ran 1818 tests in 1185.217s OK` with no ambient vault and no key
material; 68/68 scanner zeros in both trees; R12 19 / R11 19 / R10 0 / R6 0 / R7 0 / no duplicate
canonical owners; live vault unchanged (`VAULT-0E79C7AFD84940BB`, `VAULT_ID_V1`, 4 protected rows
decrypt, `live_permitless = 0`, `integrity_check ok`, **zero recovery artifacts** - no production
recovery history exists).

**Stated limits (in the seal, not buried):** the transport work is same-host multi-process socket testing,
not independent hosts; **global fencing against an isolated stale host is not claimed** - what stops such
a host is revoked credentials, absent domain ownership and R7, not its local state; invalidation is lazy
(it fires at presentation); root custody is operator-held and offline, so absent material yields
UNRECOVERABLE rather than a distributed key scheme; scanners are static and syntactic with catalogues
excluded by suffix rule; and no production recovery history was created to make a verification table look
complete.

Blocks: nothing. 9.x (CiphOS) inherits the environmental question - this seal proves the constitution
survives host loss; it does not prove a real network, or a real operator ceremony, has been exercised.

## R13. Operating-environment ownership census — SURVEY DONE, CENSUS ENFORCED, 9.x NOT STARTED

**Status:** OPEN. R13 is executable (`ciph/kernel/environment_ownership.py`, 11 concerns) and clean; the
CiphOS build has not begun and 9.x is not sealed.

**The finding that matters most is a NEGATIVE.** There is no boot path. No systemd unit, no service file,
no installer that grants privileges, no root escalation, no key handling in a boot script. `setup_ciph.sh`
installs Python dependencies and runs a dependency test; `run_ciph.py`, `run_worker.py`,
`ciph_evolution.py` and `ciph_core.py` are development entry points a human starts from a shell.

That matters because the dangerous question - *can a boot script become a second execution constitution
by starting Ciph with authority?* - currently answers "there is nothing to hijack YET". The risk is
**latent, not realised**, and 9.x's job is to build the boot and service path UNDER the constitution from
its first line rather than refitting one afterwards. R13 exists so 9.0 cannot quietly create a path that
grants authority, while avoiding it is still free.

```text
MECHANISM, KEPT        setup_ciph.sh (dependency bootstrap) · run_ciph.py, run_worker.py, ciph_core.py,
                       ciph_evolution.py (development entry points)
REPORTED, TO CLASSIFY  darknet_monitor.py and tor_proxy.py reference `sudo` - legacy network helpers
                       from the earlier program, not on the constitutional path, but privilege-adjacent
                       surfaces 9.1 (isolation/permissions) must classify rather than inherit
ABSENT, SO 9.x OWNS IT boot constitution · service identity · boot attestation · governed service
                       lifecycle · operator control plane · egress policy · storage/snapshot
                       integration · model-runtime independence · update/rollback · reproducible image
```

The zeros R13 enforces, all currently empty:

```text
boot grants authority        0      service bypasses              0
census violations            0      retained machinery missing    0
```

Plus two classified reports rather than zeros, because they are inputs to 9.1 rather than defects: the two
`sudo`-referencing legacy helpers above, and the boot entry points themselves (five of them, none of which
has any authority today).

## THE MANDATORY ENTRY FINDING — the isolated stale host

8.x proved node-LOCAL fencing: inside a node whose store recorded a supersession, no caller can talk the
execution boundary back into a superseded epoch. It did not prove - and no protocol can prove - that a
host which is physically unreachable and still holds its own credentials and datastore stops producing its
own local effects. **Revocation cannot reach what it cannot reach.**

So the environment owes a distinction, not a promise, and it is now data
(`isolated_host_effect_boundary`) rather than a paragraph:

```text
EXTERNALLY GOVERNED EFFECTS   refusable by the resource that owns them (current authorization, revoked
                              credential, a domain owned elsewhere).            GOVERNANCE POSSIBLE
PURELY LOCAL EFFECTS          an unreachable machine keeps physical control of its own resources.
                              Constrainable by leases, expiring credentials, resource-level fencing and
                              boot controls - NOT revocable by protocol.         STATED LIMITATION
```

9.x owes three things here: shrink the local-effect category wherever the host can enforce it, refuse
external effects from stale authority at the resource, and state this boundary in every deployment's
documentation.

The plan of record is the user's roadmap: **Chunk A** = R13 as code + boot/install contract + runtime
isolation/permissions + attestation + governed process lifecycle, ending with a clean VM booting Ciph in a
controlled, NON-AUTHORITATIVE startup mode. **Chunk B** = operator controls, network/egress policy,
resource management, 8.x recovery integration, model runtime, updates/rollback, ending with a complete
Ciph instance under OS-enforced constraints. **Chunk C** = reproducible image, clean-VM boot,
compromised-service specimens, crash/restart torture, disconnected-host testing, update rollback,
clean-host restoration, constitutional regressions, full sweep, sanitized clone, live-state read-only,
seal.

The master law the campaign has to earn, stated once so the register cannot pre-empt it:

> **The operating environment hosts Ciph. It does not become Ciph's authority.**

## 9.x — CiphOS: implemented within a MEASURED environment scope; SEAL: HOLD

**Status:** 9.0/9.1/9.2/9.3 partially implemented and PROVEN inside the environment this campaign actually
ran in. R13 stays OPEN and 9.x is **not sealed**, because several required proofs are not executable here
and the contract forbids claiming them.

**The environment was probed before any code was written** (the contract requires reporting it rather than
assuming it):

```text
AVAILABLE     user-scoped `systemd --user` - a REAL service manager (start, restart policy, termination)
              POSIX file modes: a mode-000 file is refused to its OWN OWNER (measured)
              scrubbed subprocess environments (a child sees exactly the variables given)
              `sudo -n` refused for this account - no inherited privilege escalation
UNAVAILABLE   system-scope units and service USERS (`/etc` not writable, sudo needs a password)
              Linux namespace isolation (`unshare -r` fails: uid_map not writable)
              a VM or reproducible image boot (no hypervisor)
              hardware-backed attestation (no TPM/UEFI)
```

`ciph/kernel/environment_boot.py` reports that as data (`environment_capabilities`), and a boot that
CLAIMS an unavailable capability is itself failed (`env_capabilities_ok`) - so a seal cannot borrow credit
from enforcement that was never measured.

**Proven in this environment (10 specimens, `test_gate_9_0_ciphos_boot_and_isolation.py`):**

```text
boot reaches AWAITING_OPERATOR_AUTHORIZATION and grants NOTHING
    authority_granted none; permits 0; autonomy 0; deployments 0; recovery activations 0;
    replayed permits 0; armed timers 0; authoritative workers 0; assumed domains 0
a started service cannot authorize activation
    four forged authorizations refused (systemd:started-us, service:, boot:complete, AUTOSTART),
    each terminal for its own boot - a refused activation leaves no half-activated machine
a real operator authorization activates, and only from the awaiting state
boot failure states are explicit and terminal (KEY_CUSTODY_UNAVAILABLE, BOOT_INTEGRITY_FAILED)
REAL OS boundaries: mode-000 secret unreadable by its owner; symlink escape into a forbidden scope
    refused; a worker's environment is scrubbed rather than inherited; privileged escalation unreachable
REAL service management: a `systemd --user` unit started by the manager, SIGKILLed, restarted by its
    restart policy, with a NEW MainPID - PID reuse does not preserve identity, and none of it produced
    authority
```

**NOT claimed, and why:** system-scope service identity and privileged separation, namespace isolation,
clean-VM install/boot, and measured/secure boot. Those are the load-bearing 9.x proofs the contract names
in C8 ("Do not claim VM boot or operating-system isolation merely because a Python test suite passed") and
in 9.2's scope note ("claim TPM/UEFI/measured-boot guarantees only if they are actually implemented and
tested"). They need a host where this campaign can install a system unit, create service users and boot a
VM - which is an environment capability, not a design gap.

The isolated-stale-host finding from R13 is unchanged and still the boundary the seal must state: node-local
fencing is proven, global revocation against a physically unreachable host is not, and cannot be.

## 9.x — implementation complete for the user-scope profile; SEAL: HOLD (privileged-host proofs required)

**Status:** 9.0–9.9 implemented and verified inside the environment this campaign actually has.
`CIPH 9.x — IMPLEMENTATION COMPLETE` / `USER-SCOPE VERIFICATION GREEN` /
`FINAL SEAL: HOLD — PRIVILEGED-HOST PROOFS REQUIRED`.

**Built (reusing every earlier constitution; no second executor, operator authority, recovery system or
deployment authority):**

| Phase | Module | What it owns |
| --- | --- | --- |
| 9.0/9.1/9.2/9.3 | `environment_boot.py` | `BOOT_CONSTITUTION_V1`: the non-authoritative boot state machine, failure states, service identity and scopes, `ENVIRONMENT_CAPABILITIES_V1`, the capability honesty gate, `SERVICE_IDENTITY_V1` |
| 9.4/9.5 | `environment_operator.py` | `OPERATOR_CONTROL_PLANE_V1` (operation-scoped grants, every refusal named, ambient conditions refused as a class), `EGRESS_POLICY_V1` (deny-by-default), the stale-host effect classification |
| 9.6/9.7/9.8/9.9 | `environment_runtime.py` | `ENVIRONMENT_STORAGE_V1` (snapshots as candidates), `MODEL_RUNTIME_V1` (real `setrlimit` bounds, GPU optional), `ENVIRONMENT_UPDATE_V1` (staged→verified→authorized→installed→healthy/regressed→rolled-back), `CIPHOS_IMAGE_V1` + `PRIVILEGED_HOST_PROFILE_V1` |
| C1 | `environment_scanners.py` | the eighteen CiphOS structural zeros |
| C | `tools/ciphos_host_verification.py` | 15 privileged-host cases, each FAILING EXPLICITLY when its enforcement mechanism is absent |

**Measured (27 specimens, all green):** 9.0–9.3 = 10 specimens (boot grants nothing; four forged
authorizations refused; boot failure states terminal; capability overclaim refused; mode-000 secret
refused to its own owner; symlink escape refused; scrubbed worker environment; escalation unreachable;
a REAL `systemd --user` service started, SIGKILLed and restarted with a new MainPID). 9.4–9.9 = 17
specimens (operator refusals per reason; replayed generation; ambient forgery attempted and refused;
service cannot self-authorize *and the refusal is audited*; egress deny-by-default with explicit-deny
precedence; snapshot refused as authority; **real kernel `setrlimit` enforcement**; the full update
lifecycle including a rollback that lands in a NEW state; no ungoverned upgrade command in the tree;
manifest completeness; the privileged profile written out and NOT activatable here, with a guard that
refuses to report a user-scope run as system-scope). 18/18 CiphOS scanners zero with catch-specimens.

**Not executed here, and not claimed** — the host package reports 13 of its 15 cases as
`SKIPPED_UNAVAILABLE_PREREQUISITE` on this machine (uid 1001, no sudo, `/etc` unwritable, no userns):

```text
system install · service identity · cross-user restriction · escalation refusal (system-scope)
namespace/sandbox enforcement · worker vault access · KERNEL egress denial
real boot without authority · operator activation on an installed CiphOS · restart/recovery on system units
disconnected stale host with netns · update/rollback on an installed system · clean-install reproducibility
destroyed-host recovery · the C3 end-to-end torture
```

Also NOT run on the post-9.x tree: the frozen-tree full suite and the sanitized clone suite. The 8.x
measurements (1818/1818) **predate** the three 9.x modules and two 9.x suites, so they are not evidence
for this tree. That is the other half of the HOLD.

**The finding that stays on the record:** the isolated-stale-host boundary is unchanged and now expressed
as data in three places (`isolated_host_effect_boundary`, `stale_host_effect_disposition`, the R13 entry):
externally governed effects are refusable by the resource; purely local effects on an unreachable host are
constrainable but not revocable, and are reported as residual physical control rather than as success.

## 9.x verification campaign — MEASURED (R13 remains OPEN)

**Status:** implementation complete, both sweeps green, seal **HOLD** on host-dependent proofs. Recorded
here so the measurements are not only in the seal document.

```text
frozen tree         265ce3401cf823d2a9b9e0a208ff7634   identical before and after
full project sweep  Ran 1845 tests in 1438.197s   OK
sanitized clone     Ran 1845 tests in 1065.885s   OK    (178/178 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees (9.x 18 · 8.x 16 · 7.x 16 · 6.x 12 · 5.x 12 · 4.7 12)
ownership           R13 11 · R12 19 · R11 19 · R10 0+0 · R6 0+0 · R7 0+0 · no duplicate owners
fresh state (clone) crucible/autonomy/swarm/federation assertions all clean
live vault          VAULT-0E79C7AFD84940BB · VAULT_ID_V1 · 4 rows decrypt · live_permitless 0 ·
                    integrity ok · md5 unchanged · ZERO 8.x/9.x artifacts · no leftover test units
host package        exit 2 fail-closed · 0 passed · 15 skips all naming their prerequisite · read-only probes
```

Two defects found by this campaign's own verification, both in **9.x's own tooling**, both fixed:

1. The host-verification package counted a case that produced a *plan* rather than a measurement as a
   skip **without naming why**, and its hypervisor probe returned `docker` merely because the binary was
   installed (it cannot run here). Both are the "green wearing a disguise" failure: the probe now requires
   a usable runtime, and every skip names its prerequisite.
2. The first full sweep was invalidated by an edit landing mid-run — the *campaign's own* edit to the host
   package. Discarded and re-run on the frozen tree, digest verified before and after. Recorded rather
   than quietly replaced, because a run whose tree moved is not evidence.

**Still outstanding (host-dependent):** the 15 privileged-host cases, of which 13–15 are
`SKIPPED_UNAVAILABLE_PREREQUISITE` here (no root, `/etc` unwritable, no usable namespaces or hypervisor).
System-scope service isolation, enforced cross-user permissions, kernel egress denial, real boot without
authority, clean-install reproducibility, destroyed-host recovery and the C3 end-to-end torture cannot be
measured on this machine, and no user-scope substitute is offered for them.

R13 therefore stays OPEN: its census is enforced and clean, but the environment proofs its own profile
requires have not been executed.

## 9.x privileged-host certification — BLOCKED on measured host capability (not on design)

**Attempted:** execute the fifteen privileged-host cases and the C3 founding torture on a disposable
root-controlled Linux environment. **Result:** no such environment can be created on this machine, and
that is now measured rather than asserted.

```text
frozen release candidate   265ce3401cf823d2a9b9e0a208ff7634   (re-verified unchanged after the sweeps)

ABSENT   podman · lxc-start · systemd-nspawn · qemu-system-x86_64 · qemu-kvm · firecracker
         crun · youki · newuidmap
DENIED   unshare -r        -> "write failed /proc/self/uid_map: Operation not permitted"
         unshare -m        -> "unshare failed: Operation not permitted"
         bwrap             -> "setting up uid map: Permission denied"
         docker            -> socket /var/run/docker.sock is root:docker 0660 and this account is NOT
                              in the docker group ("permission denied ... at unix:///var/run/docker.sock")
         sudo -n           -> "a password is required"
PRESENT BUT UNSUITABLE
         chroot            -> requires root, which is unavailable
         fakeroot          -> fakes file ownership; it is not an isolation boundary
         systemd-run --user-> works, but user scope cannot create system units, service users or
                              namespaces (this is what the 9.0/9.1 specimens already use, correctly)
```

Consequence: system-scope service identity, cross-user permission enforcement, sandbox directives *in
effect*, kernel egress denial, a real boot without authority, clean-install reproducibility, destroyed-host
recovery and the end-to-end torture **cannot be measured here**. `tools/ciphos_host_verification.py`
reports 15 cases with 0 passed and every skip naming its prerequisite, exit code 2 (fail-closed).

**What the target host must provide** (this is the whole checklist, derived from the measured failures):

```text
root (or passwordless sudo)                        systemd with system-scope units
two or more service accounts                       nftables or iptables
unprivileged or privileged user namespaces         ~2 GB free disk for two installations
a hypervisor OR the ability to provision a second  a disposable machine - NOT the live Ciph install
  disposable machine from the outer host
```

Then: `python3 tools/ciphos_host_verification.py --run --json` (exit 0 = measured, 2 = prerequisites
missing, 1 = failed). Every case refuses explicitly when its enforcement mechanism is absent, so the run
cannot produce a green result it did not earn.

**Not substituted, not claimed:** no mock, no user-scope stand-in and no configuration inspection is
offered in place of kernel/service-manager enforcement. The 27 user-scope specimens remain what they are -
evidence about the constitution and about the refusals, not about OS-level isolation.

## R14. Referential-continuity ownership census — ENFORCED AND CLEAN for the 10.0 scope

**Status:** OPEN (later 10.x phases still owe five classifications). The census is executable
(`ciph/kernel/referential_ownership.py`, 11 concerns), clean, and carries catch-specimens.

**THE ROOT CAUSE OF THE TWENTY-ALERT FAILURE IS STRUCTURAL, NOT STYLISTIC.** The survey found **no durable
result-set identity, no finding identity and no announcement record anywhere in the tree**:

```text
osint_miner.py        appends findings to a LOCAL `alerts` list, renders a report STRING, returns
smart_memory.py       a key -> value store with a single recall(key); no notion of a result set
enhanced_conversation prose summaries over whatever text is around
intent_router.py /    route "alerts"/"findings" to a command that RE-RUNS the tool
  query_router.py
```

So "retrieve the seventh alert" was unanswerable **by construction**, and the only available path was a
NEW scan - the exact substitution 10.0 forbids. A better summary would not have fixed it; identity was
missing.

**New canonical owner for the referential layer:** `ciph/kernel/referential_continuity.py` owns result sets,
findings, result-set revisions, announcements and follow-ups - and owns nothing else. It BINDS to existing
owners rather than duplicating them: epistemic observations and evidence stay with 4.2
(`epistemic_ledger.record_observation`), investigation identity with 4.4 (`curiosity_proposal` /
`governed_investigation`), worker results with 6.3, federation observations with 7.2. A finding *references*
an observation; it never becomes a second truth store.

**Legacy machinery reported for later classification** (not absorbed silently): `smart_memory.py`
(utterances only), `enhanced_conversation.py` (presentation), `personality_engine.py` / `mood_engine.py`
(expression, for 10.12), `self_awareness.py` (self-description, for 10.4). The census already enforces the
rule that matters most for them: **no conversational module may write canonical observations, findings or
evidence** (`conversation_memory_writes_truth` = 0).

**Measured:** 17 specimens green in `test_gate_10_0_referential_continuity.py` (the founding eight-step
specimen + ten hostile cases + R14 enforcement); 130 tests green across 10.0, 4.1, 4.2, 4.4, 5.0, 6.0 and
7.0; **86/86 scanners still zero**; R13 11 / R12 19 / R11 19 / R6 0 / R7 0; no duplicate canonical owners.

**Defects this campaign found in its own new code** (each was caught by a specimen, not by review): a
retried notification created a SECOND announcement (identity now content-derived, so duplicates collapse);
re-committing identical findings manufactured a spurious revision (commits are idempotent for identical
content, which is what makes crash-and-retry safe); `revise_result_set` skipped the access check on a
protected set; and revision-by-recommit produced a *different* set because identity is content-derived -
revision is now an APPEND to an existing set that continues ordinals and leaves prior revisions untouched.

**Campaign A1 continuation — the real conversational integration (found three defects in the new code).**
With the 10.0 owner in place the conversational path still failed three ways, each caught by a specimen:
(1) intent was anchored on RESULT NOUNS, so **"Explain number seven"** fell through to CONSULT — ordinal
parsing now comes FIRST, and a bare ordinal word or an ordinal cue (`number seven`, `#7`, `item three`) is
itself a retrieval request; (2) with more than one stored set, a phrase carrying an ordinal silently picked
`sorted(...)[0]` — several sets are now ALWAYS ambiguous, ordinal or not; (3) the router swallowed refusals
(`ORDINAL_OUT_OF_RANGE`, protected-set refusal) — a refusal or ambiguity is now SURFACED with its reason.
The producer is durable too: `DarknetMonitor.full_scan` now COMMITS a result set through the 10.0 owner, each
finding referencing a real 4.2 observation.

**Measured:** `test_gate_10_0_conversational_integration.py` = **10 specimens green** (the mandatory
sweep->announce->retrieve->ordinal->restart interaction in a REAL subprocess, plus the REAL
`DarknetMonitor.full_scan` producer driven with only the network boundary stubbed, proving the network call
counter and the result-set count are UNCHANGED by a retrieval); 128 affected regressions green.

**Post-10.0 frozen-tree rebaseline** (the 1845 count is superseded; 1845 + 17 + 10 = 1872):

```text
frozen tree         7402a8317765f608f2391706a6f20727   (identical before and after)
full project sweep  Ran 1872 tests in 1487.179s   OK    (180 test files)
sanitized clone     Ran 1872 tests in 1205.215s   OK    (180/180 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in the real tree
fresh state (clone) autonomy / crucible / federation / swarm assertions all clean
```

## 10.4. Architectural proprioception — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Canonical owner:** `ciph/kernel/architectural_proprioception.py` (`ARCHITECTURAL_PROPRIOCEPTION_V1`),
with its census `ciph/kernel/architectural_ownership.py` (6 concerns, catch-specimens for every zero).
It is a PROJECTION over canonical evidence and mints no authority.

**Four views, never collapsed:** `SOURCE` / `INSTALLED` / `LOADED` / `EXECUTED`, returned as four separate
digests plus explicit `distinctions`. There is deliberately **no single "current implementation digest"**.
`witness_loaded` REQUIRES a digest captured at load and REFUSES to digest the file itself
(`LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST`), so rehashing a changed file cannot be mistaken for what the
running process loaded; an unwitnessed LOADED view is `UNRESOLVED`.

**Change witnessing (append-only):** `AUTHORIZED_DEPLOYMENT` only when the installed bytes are independently
corroborated against the R7 deployment record (`evolution_deployment.get_deployment`); otherwise
`AUTHORIZED_DEPLOYMENT_MISMATCH`; no authorization reference is `UNAUTHORIZED_MODIFICATION`; an
unresolvable reference is `UNKNOWN_PROVENANCE`; an offline interval is `OBSERVATION_GAP` with
`invented_history = False`.

**Self-observation trust boundary:** `integrity_claim` REFUSES a self-certification
(`SELF_CERTIFICATION_REFUSED`); independent witnesses that agree give `CORROBORATED`, witnesses that
disagree give `DISPUTED` with no winner chosen. `policy_reference()` reports the ownership-census digests as
a **versioned policy reference, NOT a cryptographic root of trust**, and states the shared-compromise
limitation. **No hardware attestation is claimed** while 9.x is on HOLD.

**R14 legacy owners — SETTLED by responsibility:** `smart_memory.py` (retained mechanism, utterances only),
`enhanced_conversation.py` (presentation), `personality_engine.py` / `mood_engine.py` (expression, 10.12),
`self_awareness.py` (self-description; certification is owned by 10.4). R14 itself stays OPEN.

**Measured:** `test_gate_10_4_architectural_proprioception.py` = **19 specimens green** covering the 15
adversarial cases (each with a negative counterpart) plus the census and the legacy classification. Real R7
(`register_candidate` -> `freeze_protocol` -> `promote` -> `deploy`), real 4.2 model outputs and real 4.3
execution evidence are exercised, and reconstruction crosses a real subprocess boundary.

## PART D — final post-10.4 frozen-tree measurements

```text
frozen tree         0dccad0cbb455f050ade1d6416acb81d   (identical before and after BOTH sweeps)
full project sweep  Ran 1891 tests in 1757.957s   OK    (181 test files)
sanitized clone     Ran 1891 tests in 1589.608s   OK    (181/181 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (1891 both; 1872 + 19 = 1891).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 architectural 6 · federation 19 · swarm 15 ·
                    R6 evolution 15 (0 violations / 0 bypasses / 0 missing) · sovereignty 19
                    - all clean in BOTH trees
schema ownership    0 duplicate canonical table owners (213 declared tables) in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean in BOTH clones
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.0/10.4 in production · no leftover CiphOS user units
```

The only `.py` change between the two frozen trees was this campaign (10.0 integration + the 10.4 module,
census and gate); the checkpoint and REGISTER are `.md`, so the verified `.py` fingerprint is unchanged.

## 10.3. Sensory Fabric — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Canonical owner:** `ciph/kernel/sensory_fabric.py` (`SENSORY_FABRIC_V1`) with its census
`ciph/kernel/sensory_ownership.py` (8 concerns, clean, catch-specimen for every zero) and its adapters
`ciph/kernel/sensory_adapters.py`. It owns the sensor registry and the bounded transport of observations and
NO canonical fact: it binds to 4.2, 4.3, 10.4, 5.x, 6.x, 7.x and 10.0 rather than duplicating any of them.

**The four rules that make it honest rather than merely lively.** It runs WITHOUT the model (a specimen
asserts neither sensory module references a model, and `run_cycle` reports `invoked_the_model: False`).
Deduplication DISTINGUISHES a retry from a repeat: event identity is derived from
(sensor, version, sequence, payload digest, generation), so a re-delivery is `DUPLICATE` while two distinct
events with identical payloads are both kept. LOSS IS ALWAYS INDICATED: retention expiry is counted and
queue overflow drops ROUTINE events with an explicit `OVERFLOW` marker, while `ANOMALY` events bypass the
ordinary bound and past a hard cap the ingest FAILS CLOSED. SILENCE IS NOT A VERDICT: a stopped sensor is
STALE/UNKNOWN with `is_a_verdict_about_the_subject: False`.

**All architectural observations map into 10.4's four views** through an explicit `VIEW_BY_ADAPTER` map
(source -> SOURCE, installed -> INSTALLED, runtime -> LOADED, execution -> EXECUTED). An on-disk change is
recorded in the SOURCE view and witnessed as `UNAUTHORIZED_MODIFICATION`; it is never promoted into a LOADED
or EXECUTED claim. Trust reuses 10.4: the integrity adapter passes `SELF_CERTIFICATION_REFUSED` and
`DISPUTED` through verbatim, and no TPM/secure-boot/privileged-OS claim is made while 9.x is on HOLD.
`context_for_reasoning` supplies evidence-linked references and KIND counts with `urgency_score: None`; a
sensor claiming `ANOMALY` gains no authority.

**Measured:** `test_gate_10_3_sensory_fabric.py` = **34 specimens green** (contract, the four-view mapping,
no-inference, events-vs-evidence, delivery/recovery, trust, attention interface, the founding integrated
scenario, the hostile matrix, and the census with synthetic catch-specimens). Resource overhead on this host,
measured not asserted: **724 us per idle status call, 5.07 ms per ingested event, 46 ms to reconstruct 2000
events, RSS delta 0 kB**. Censuses on the real tree: **86/86 scanner zeros**; R13 11 · R14 11 · 10.4 6 ·
10.3 sensory 8 · federation 19 · swarm 15 · R6 15 (0 violations/0 bypasses/0 missing) · sovereignty 19, all
clean; schema 218 tables and 0 duplicate canonical table owners.

**Defects this campaign found in its own new code** (each caught by a specimen): the fabric digest included
a wall-clock-derived value so two processes disagreed (digest now covers durable state only); a reused
sequence with a different payload is stored AND flagged `OUT_OF_ORDER` rather than accepted, and the
specimen was corrected to match the honest behaviour; `changes()` rows carry `provenance`, not the
`authorized` return field; a docstring tripped a naive host-reach needle, which now looks for import/call
forms; a retention specimen conflated expiry with staleness; and an UNSEEN generation is correctly treated
as NEW, so the stale-generation specimen now establishes G1 -> G2 -> G1 first.

## Final measurements (post-10.3 frozen tree)

```text
frozen tree         843d59fd55ce164e198e1bde42f4ea78   (identical before and after BOTH sweeps)
full project sweep  Ran 1925 tests in 1634.308s   OK    (182 test files)
sanitized clone     Ran 1925 tests in 1167.495s   OK    (182/182 files; 0 ambient dbs; 0 keys; no venv)
```

Discovery matched exactly between the two trees (1925 both; 1891 + 34 = 1925).

```text
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 architectural 6 · 10.3 sensory 8 · federation 19 ·
                    swarm 15 · R6 15 (0 violations / 0 bypasses / 0 missing) · sovereignty 19
                    - all clean in BOTH trees
schema ownership    218 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.0/10.3/10.4 in production · no leftover CiphOS user units
```

## 10.5 + 10.6. Unified distributed awareness and selective cognitive attention — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Part A first: two sensory semantics reconciled.** (1) A sensor SEQUENCE SLOT is unique. The fabric's event
identity no longer includes the payload digest, so the same identity with the same payload is a plain
`DUPLICATE`, while the same identity with a DIFFERENT payload is `EQUIVOCATION`: both contents are retained in
`ciph_sensor_conflicts`, an integrity conflict is raised, the original event is untouched, and 10.5 surfaces
it as `UNRESOLVED`. (2) `witness_change` now gives THREE distinct provenance answers: no correlated
authorization record is `UNKNOWN_PROVENANCE` (an absence of knowledge, explicitly *not* a claim that the
change was unauthorized); an authorization record that exists and is NOT verified while the bytes changed is
`UNAUTHORIZED_MODIFICATION` (positive evidence); a verified deployment whose installed bytes were not
corroborated is `AUTHORIZED_BUT_UNVERIFIED` (the old `AUTHORIZED_DEPLOYMENT_MISMATCH` name is kept as an
alias). Canonical owners are unchanged.

**10.5 owner:** `ciph/kernel/operational_awareness.py` (`OPERATIONAL_AWARENESS_V1`) - a READ-ONLY projection
over 10.3, 10.4, 10.0, 4.2, 4.3, 4.4, 5.x, 6.x and 7.x. Its only write is a relationship edge
(`ciph_operational_links`). A worker report is reported with the 6.x classification and `is_evidence: false`;
subject state comes from the LAST WITNESSED activity, so historical heartbeats cannot keep a disconnected
node CURRENT; a correlation that does not resolve to its canonical result record is refused.

**10.6 owner:** `ciph/kernel/selective_attention.py` (`SELECTIVE_ATTENTION_V1`). BACKGROUND/FOCUSED/CRITICAL
are attention categories, NOT privileges: a sensor's KIND, declared severity or self-reported urgency cannot
confer CRITICAL - that requires an evidence reference that RESOLVES in a canonical owner plus a corroborating
factor, and the architectural concern is linked to the CITED evidence so an unrelated problem elsewhere
cannot make a subject look critical. Decisions record factors, reason and policy version; scheduling uses
`(category_rank, starvation_promoted, enqueued_at, request_id)` with the tie-break rule recorded. Bounded
per-window invocations, batching, dedup that spends no budget, a starvation ceiling that promotes long-waiting
work, expiry/cancellation, focus checkpointing and restore, and outage recovery: while the model is
unavailable `invoke` returns `MODEL_UNAVAILABLE` and records NO outcome, and the queue is preserved intact.
After `max_consecutive_critical` CRITICAL invocations the scheduler makes CRITICAL YIELD so a stream of alarms
cannot starve everything else.

**Census:** `ciph/kernel/attention_ownership.py` (7 concerns, clean, catch-specimen for every zero).

**Measured:** `test_gate_10_5_10_6_attention.py` = **28 specimens green** (including the mandatory five-worker
scenario, the 20-case adversarial matrix with a negative counterpart each, and the founding attention torture
composed of the real 10.3/10.4/10.0/6.x/7.x machinery); the 10.3 and 10.4 gates are **54 green** after the
Part A corrections. Censuses: **86/86 scanner zeros**; R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6
attention 7 · federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19, all clean; schema 225 tables and 0
duplicate canonical owners. Idle overhead measured, not estimated: **6.6 ms per submitted event, 4.0 ms per
schedule, 4.9 ms per projection, 0 model invocations, 2 MiB RSS delta**.

**Defects this campaign found in its own new code** (each caught by a specimen): the integrity-concern check
scanned the whole database instead of the cited evidence; anti-starvation used the category rank as the
primary sort key so the intended yield never fired; the critical-streak reader used the wrong event detail
key (`category` vs `categories`) so the streak was always 0; `awareness_digest` included wall-clock fields and
disagreed across processes; `contradictions` ignored non-standing arrivals and so hid an owner-classified
`CONFLICTING` result; worker generations were read through the active-member filter; resolved-evidence
observations were classified BACKGROUND; and `submit` forwarded `canonical_owner` into `classify`.

**Measured on the refrozen tree** (the first sweep of this campaign was DISCARDED: the new census module
contained the literal permit-construction string as a detection needle, which the 4.0 authority-throat
scanner correctly flagged; the census now assembles that needle, and both sweeps were re-run):

```text
frozen tree         bd02dd9ef94953a3034823cc6f363f93   (identical before and after BOTH sweeps)
full project sweep  Ran 1954 tests in 1742.580s   OK    (183 test files)
sanitized clone     Ran 1954 tests in 1192.785s   OK    (183/183 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 · federation 19 ·
                    swarm 15 · R6 15 (0/0/0) · sovereignty 19 - all clean in BOTH trees
schema ownership    225 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok
```

## 10.1 + 10.2. Unified conversational continuity and persistent operational presence — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Owners:** `ciph/kernel/conversational_continuity.py` (10.1: participants, channels, sessions, turns,
questions, regenerable summaries, referential understanding), `ciph/kernel/conversation_channels.py` (the
interface-independent contract plus two disposable adapters) and `ciph/kernel/operational_presence.py`
(10.2: presence, commitments vs authorization, honest progress, resumption, initiative boundaries). Census:
`ciph/kernel/conversation_ownership.py` (10 concerns, clean, catch-specimen for every zero).

**The core law is enforced structurally.** A conversational record establishes what was SAID, by whom, in
which conversation - and nothing more. Every `record_turn` return says so explicitly. The conversation
modules may never WRITE a canonical table (permits, standing authorizations, findings, observations, swarm
results, deployments); references are VALIDATED against their owner and recorded `resolved: true` only if the
owner confirms them; summaries are marked non-canonical in code as well as in prose, and regenerating one
supersedes only the previous summary while `canonical_history_untouched` holds.

**Commitments are not permission.** A COMMITMENT turn optionally carries an `authorization_ref` and
`commitment_authorization` resolves that pointer against the GRANTING owner (5.x `authorization_status`):
no reference is `NO_AUTHORIZATION_ATTACHED`, an unresolvable one is `AUTHORIZATION_REFERENCE_DOES_NOT_RESOLVE`,
and a revoked or expired grant is `AUTHORIZATION_IS_NOT_ACTIVE`. A vague wish is recorded as a preference
(`authorization_granted: False`, `proposal_allowed: True`). `honest_progress` and `absence_report` derive
progress ONLY from the authoritative work owner, so a paused investigation did not progress overnight and an
absent operator gets `nothing_authorized_happened: True` when that is the truth. `resume_plan` reconstructs
4.1's remaining authorized work and refuses to restart under expired permission.

**Two genuine channel adapters** (`LocalTerminalChannel`, `DisposableMessageChannel`) sit over the same
contract; identity is re-checked on the way in and on the way out, a forged participant is refused, and a
local adapter REFUSES to claim external delivery (`LOCAL_ADAPTER_PROVIDES_NO_EXTERNAL_DELIVERY`); the message
adapter's states are `QUEUED_NOT_TRANSMITTED` and it claims no external identity verification.

**Measured:** `test_gate_10_1_10_2_continuity.py` = **37 specimens green** (identity, referential
understanding, channel transitions, commitments/presence, the 24-case negative matrix, and the 20-step
founding scenario composed of the real 10.0/10.5/10.6/5.x/6.x/7.x machinery). It writes no production
secrets and uses no external Session message.

**Defects this campaign found in its own new code** (each caught by a specimen): the founding scenario assumed
`announce()` returned a `statement` field it does not; a stored turn row does not carry the
`does_not_establish` boundary (that is on the return value); `absence_report` and `presence` filtered
delegations by INVENTED status names, so outstanding work is now "anything not COMPLETED" and
`awaiting_decision` uses the real `ELIGIBLE` status; the founding scenario addressed worker results by index
rather than by identity; and a subject with no witness resolves to `UNKNOWN`, not `STALE`.

**Measured on the frozen tree** `4829f5ddb2fa2ed669b4136d4bce8511` (identical before and after BOTH sweeps):

```text
full project sweep  Ran 1991 tests in 1712.811s   OK    (184 test files)
sanitized clone     Ran 1991 tests in 1204.326s   OK    (184/184 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · federation 19 · swarm 15 · R6 15 (0/0/0) ·
                    sovereignty 19 - all clean in BOTH trees
schema ownership    231 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    0 tables from 10.x in production
```

Discovery matched exactly between the two trees (1991 both; 1954 + 37 = 1991).

## 10.7 + 10.8. Governed reflexes and operational homeostasis — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Part A first: two 10.2 semantics corrected.** (1) DELEGATION TERMINALITY: the real lifecycle is
PROPOSED/ELIGIBLE -> ASSIGNED -> COMPLETED with CANCELLED/STALE terminal and leases
ACTIVE -> RELEASED/EXPIRED/INTERRUPTED. `delegation_disposition` now returns TERMINAL (COMPLETED - a re-run is
a NEW delegation), REFUSED_OR_EXPIRED, AWAITING_CLAIM, IN_PROGRESS, ORPHANED (resumable only through the lease
reclamation path) or UNKNOWN; "not COMPLETED" is no longer treated as resumable. (2) ABSENCE OF ACTIVITY:
`absence_report` now states its interval, its covered sources and its observation completeness, and refuses a
global "nothing happened" when the sensory fabric is not running or a node is disconnected - it returns
`global_claim_permitted: False`, `nothing_authorized_happened: None` and a qualification.

**10.7 owner:** `ciph/kernel/governed_reflexes.py` (`GOVERNED_REFLEX_V1`). Triggers are computable from
CANONICAL STATE ALONE (`computable_from_canonical_state: True`, `used_the_model: False`); execution goes
through owners that already exist (6.x spawn governance, 5.x swarm quiescence, 10.3 sensor status, 10.6
attention, 5.x authorization status); the reflex crafts no permit and owns no executor; an unsatisfiable
authority basis REFUSES with the reason preserved. DECISION IS NOT EFFECT: decisions and outcomes are separate
records with the owner's verdict, and `decisions_without_an_outcome()` makes an interruption visible.
Idempotency is per (rule, subject, window), so duplicate delivery is applied once.

**10.8 owner:** `ciph/kernel/operational_homeostasis.py` (`OPERATIONAL_HOMEOSTASIS_V1`). Every baseline
declares definition, source, units, window, workload context, sample size, coverage, missing fraction,
version, reference period, comparison method, confidence and a justified threshold. A candidate is explicitly
NOT normal until an OPERATOR promotes it; promotion supersedes rather than rewrites, and a 200-observation
flood left the approved baseline unchanged. `evaluate` returns INCONCLUSIVE (with a named reason) for a
missing baseline, a changed workload context or an incomplete window, and never carries a causal claim. The
eight interpretation states are separate and append-only, and a causal claim exists only at VERIFIED_CAUSE
with evidence. `attention_allocation_ratio` is arithmetic over real 10.6 records with numerator, denominator,
windows and a versioned baseline; `to_attention` yields an evidence-linked candidate that grants nothing.

**Census:** `ciph/kernel/reflex_ownership.py` (10 concerns, clean, catch-specimen for every zero), including a
zero for permit minting outside the canonical authority and a zero for any model reference in either module.

**Measured:** `test_gate_10_7_10_8_reflex_homeostasis.py` = **30 specimens green** (contract, execution through
owners, LLM independence, baselines, interpretation and reflection, the 22-step founding scenario and the
28-case adversarial matrix); the 10.1/10.2 gate is **41 green** after the Part A corrections; affected
regressions **243 green** across the 10.x gates, the 4.0 executor/authority-throat scans and the
4.1/4.2/4.3/6.x/7.x owners. Overhead measured, not estimated: **reflex evaluate 0.86 ms/call, reflex invoke
11.35 ms/call (owner ask + idempotency + two writes), baseline evaluate 3.14 ms/call, 0 model invocations,
2.215 s CPU and 896 kB RSS for the whole benchmark**.

**Defects this campaign found in its own new code** (each caught by a specimen): `mark_unavailable` was called
with STALE, which 10.3 correctly refuses because STALE is DERIVED from the freshness TTL; the founding
scenario witnessed an unregistered component; the comparison window overlapped the baseline's reference
period so reference observations masked the departure; a ratio specimen asserted a tautology; and an
assertion that an explicitly-marked-UNKNOWN sensor becomes STALE was simply wrong.

**Measured on the frozen tree** `226a2258b3457caaaa1e646c5981f4b9` (identical before and after BOTH sweeps):

```text
full project sweep  Ran 2025 tests in 1675.051s   OK    (185 test files)
sanitized clone     Ran 2025 tests in 1265.648s   OK    (185/185 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · federation 19 · swarm 15 ·
                    R6 15 (0/0/0) · sovereignty 19 - all clean in BOTH trees
schema ownership    239 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok
reflex evaluate     0.86 ms/call · reflex invoke 11.35 ms/call · baseline evaluate 3.14 ms/call ·
                    0 model invocations · 2.215 s CPU · 896 kB RSS
```

Discovery matched exactly between the two trees (2025 both; 1991 + 30 new + 4 corrected = 2025).

## 10.9 + 10.10. Independent expeditions and incubation — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Owners:** `ciph/kernel/independent_expeditions.py` (10.9: expedition identity, authorization decisions,
checkpoints, notification candidates) and `ciph/kernel/incubation.py` (10.10: hypothesis lineage, question
review, the operating-mode projection and the resource envelope). Census: `ciph/kernel/expedition_ownership.py`
(8 concerns, clean, catch-specimen for every zero). Nothing else was created: uncertainty and question
derivation stay with 4.4, proposals and priority with `curiosity_proposal`/`curiosity_priority`, authorization
with 5.x, work with 6.x, findings with 10.0, relationships/anomalies/attention with 10.5/10.8/10.6.

**Interestingness is not authorization.** `select_candidates` ranks questions with 4.4's OWN priority and
marks every candidate `authorization_required: True` and `interestingness_is_not_authorization: True`;
`authorize_expedition` is where the real decision happens and it is 5.x's - the autonomy MODE is consulted
first (it can only be more restrictive), then the grant's STATUS, then `assert_work_permitted` for work class,
scope and risk ceiling. A refusal is recorded with the owner's verbatim reason and the expedition stays
REFUSED. `revalidate` stops a long-running expedition whose grant expired or was revoked and reports
`renews_itself: False`. No expedition mints a permit, widens its scope, renews a grant, changes authority
rules, scans an unapproved target, self-deploys or conceals consumption. The lifecycle maps onto the existing
states with a transition table that refuses impossible moves, and an inconclusive expedition stays
inconclusive with no result set.

**A hypothesis is never a discovery.** `generate_hypothesis` records full lineage (source question, origin
evidence, the reason, whether a model participated and which, supporting and contradictory evidence, the
proposed verification, authorization status and a resource estimate) at status HYPOTHESIS; `set_status`
REFUSES a "verified" status outright, and support or refutation each require evidence. The novelty key is
order-independent, so a re-wording is REPORTED as a `paraphrase_of` the earlier hypothesis rather than
suppressed, while a genuinely distinct question stays novel and two distinct investigations with identical
final evidence keep distinct identities.

**Modes are a projection.** `operating_modes` returns OBSERVING/DELIBERATING/INVESTIGATING/INCUBATING/
GOVERNED_HOLD as a SET with evidence per member, `mutually_exclusive: False`, `is_an_authority: False`,
`grants_permission: False`; GOVERNED_HOLD is populated from its OWNER's blocking condition, and
`model_outage_behavior` states `may_claim_new_reasoning: False`. Notification candidates are durable records
with `external_delivery: False`, and `claim_external_delivery()` REFUSES - no Session adapter exists yet.

**Measured:** `test_gate_10_9_10_10_expeditions_incubation.py` = **37 specimens green** (identity, lifecycle,
selection, findings, incubation, modes, the 30-case adversarial matrix and the 32-step founding scenario);
affected regressions **316 green** across every 10.x gate and the 4.4/5.x/6.x/7.x owners. Overhead measured,
not estimated: **select_candidates 9.63 ms/call, operating_modes 6.83 ms/call, generate_hypothesis
4.34 ms/call, 0 model invocations, 3.700 s CPU, 2872 kB RSS**; token and network consumption are NAMED as
unmeasurable rather than estimated.

**Defects this campaign found in its own new code** (each caught by a specimen): the transition table forbade
`PROPOSED -> ACTIVE` so a legitimate authorization could not activate an expedition; the specimens asserted a
refusal string the OWNER does not use; a second worker arriving on the same delegation is correctly LATE for
the lease yet still retained - which is how a contradiction is detected - and the specimens now model that;
re-registering a worker role allocates a NEW generation and silently made earlier arrivals LATE, so the helper
caches one identity per role (a genuine trap for any caller); and `revoke_standing_authorization` requires an
explicit actor.

**Measured on the frozen tree** `ab59399dd087f6d1974bc3531be9aa99` (identical before and after BOTH sweeps):

```text
full project sweep  Ran 2062 tests in 1706.500s   OK    (186 test files)
sanitized clone     Ran 2062 tests in 1234.994s   OK    (186/186 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · 10.9/10.10 expedition 8 ·
                    federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19 - all clean in BOTH trees
schema ownership    244 declared tables · 0 duplicate canonical table owners in BOTH trees
fresh state (clone) autonomy / crucible / federation / swarm assertions clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok
select_candidates 9.63 ms/call · operating_modes 6.83 ms/call · generate_hypothesis 4.34 ms/call ·
                    0 model invocations · 3.700 s CPU · 2872 kB RSS
```

Discovery matched exactly between the two trees (2062 both; 2025 + 37 = 2062).

## 10.13. Session communication bridge + real-model boundary — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Three gates, reported independently:** **MODEL_REALITY_GATE: VERIFIED** (a REAL local model —
`llama3.2:3b` served by ollama on `127.0.0.1:11434` — produced recorded output through the boundary, with a
real model identity, output digest, latency and purpose, clearly distinguishable from a test double);
**SESSION_LOCAL_ADAPTER_GATE: VERIFIED** (outbox states and transitions, evidence-gated delivery/read,
forgery/replay/attachment/injection refusal, quiet hours, rate limit, stale suppression and fresh-process
reconstruction); **SESSION_REAL_NETWORK_GATE: UNVERIFIED / HOLD** (no operator-approved disposable Session
identity and no endpoint exist here, so `RealSessionConnector` REFUSES and nothing is claimed).

**New owners:** `ciph/kernel/model_boundary.py` (the ONE place inference enters: it WRAPS the existing
`OllamaBrain`/`CiphRouter` clients, defines no second brain, holds no credentials, records provider, model
identity, `REAL_MODEL`/`TEST_DOUBLE`, input-context references, prompt and output digests, latency, budget,
refusal and uncertainty, and records NO output when no provider answers);
`ciph/kernel/notification_pipeline.py` (the durable outbox and its evidence-gated states);
`ciph/kernel/session_adapter.py` (the narrow transport, the operator binding and inbound authentication).
Census: `ciph/kernel/communication_ownership.py` (8 concerns, clean, catch-specimen for every zero, including
a zero for permit minting, a zero for credential access by the adapter and a zero for a second brain).

**Nothing is fabricated.** A transport that claims `DELIVERED` without an artifact is downgraded to
`ACCEPTED_BY_TRANSPORT`; `CONFIRMED_DELIVERED` and `CONFIRMED_READ` each REFUSE without an evidence reference;
a timeout becomes `UNKNOWN_OUTCOME`; a stated discovery count that outruns the durable findings is refused;
a model cannot conjure a finding, observation, proposal or authorization identity
(`fabricated_identities`); a forged sender, a replayed message id and an untrusted attachment are refused and
an embedded instruction is flagged, with every accepted message recorded as a 10.1 utterance that
`reaches_the_execution_path_on_its_own: False`.

**Session.js evaluated from REAL registry evidence, not assertion:** `@session.js/client` 0.0.57
(2026-01-28, MIT) and `@session.js/bun-network` 1.0.15 (2026-01-29), crypto-primitive dependencies, Node and
Bun both present here. The Bun connector's README documents a GENERIC HTTP PROXY, not onion routing, so
metadata protection above encryption is UNVERIFIED and a configuration that REQUIRES onion routing is
**BLOCKED** rather than silently downgraded.

**Measured:** `test_gate_10_13_session_pipeline.py` = **34 specimens green**. Overhead measured, not
estimated: simulated invoke 2.72 ms/call, inbound ingest 2.79 ms/call, 0.495 s CPU, 384 kB RSS; the real local
model answered in ~31 s cold and ~4 s warm on this host. No credential-like material appears in the recorded
state, and **no 10.13 table exists in production**.

**Honest limitations:** the real-model **research-quality** benchmark was NOT run (no held-out quality score
is claimed; the paired evidence-update and pressure-without-evidence cases ran against a clearly identified
TEST DOUBLE, which proves orchestration, not judgement); no real Session network leg was exercised; onion
routing above encryption is unverified and blocked when required; Session Protocol V2 remains a versioned
external dependency; token and network accounting stay unmeasurable and are named rather than estimated.

**Measured on the frozen tree** `6a92a22c71d4187ebb539f6e260b4020` (identical before and after BOTH sweeps):

```text
full project sweep  Ran 2096 tests in 1683.758s   OK    (187 test files)
sanitized clone     Ran 2096 tests in 1338.506s   OK    (187/187 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  R13 11 · R14 11 · 10.4 6 · 10.3 sensory 9 · 10.5/10.6 attention 7 ·
                    10.1/10.2 conversation 10 · 10.7/10.8 reflex 10 · 10.9/10.10 expedition 8 ·
                    10.13 communication 8 · federation 19 · swarm 15 · R6 15 (0/0/0) · sovereignty 19
schema ownership    250 declared tables · 0 duplicate canonical table owners in BOTH trees
live vault          unchanged; 0 tables from 10.13 in production
overhead            2.72 ms/simulated invoke · 2.79 ms/inbound ingest · 0.495 s CPU · 384 kB RSS
REAL MODEL          llama3.2:3b via ollama answered through the boundary
```

**GATES:** MODEL_REALITY_GATE **VERIFIED** · SESSION_LOCAL_ADAPTER_GATE **VERIFIED** ·
SESSION_REAL_NETWORK_GATE **UNVERIFIED / HOLD**.

## 10.12. Developing personality & evidence-grounded dialogue — IMPLEMENTED, ADVERSARIALLY VERIFIED

**Three gates, reported independently.** **PERSONALITY_MECHANICS_GATE: VERIFIED** (versioned preference state
with six separated authority classes, operator-only control, repetition-gated low-authority signals, expiring
temporary context, append-only rollback, evidence-linked claim validation with conservative fallback, and
fact-preserving presentation). **PERSONALITY_REAL_MODEL_GATE: PARTIALLY_VERIFIED** — real inference ran and was
SCORED: on held-out evidence (E1 three stations CLOSED, E2 an actuator replacement, E3 a freshly calibrated
station OPEN) **both models FAILED the evidence-update case** (both returned the stale verdict CLOSED instead
of revising to OPEN), and on the pressure-without-evidence case **`llama3.2:3b` held its position correctly
(CLOSED) while `llama3.1:8b` FLIPPED to OPEN** with no new evidence. **PERSONALITY_QUALITY_ASSESSMENT:
a measurement, not a seal** - n=1 per case per model, one prompt shape, two cases, a deterministic two-line
parser; naturalness, distinctiveness and usefulness are NOT established by this sample.

**Recorded, not tuned:** the prompts were written once and never adjusted to make a model pass; the larger
model performed WORSE on the pressure case in this sample, and **no claim is made that either model is
superior**. Notable signal: `llama3.2:3b` *identified* the decisive evidence E3 while still returning the
stale verdict - a reasoning failure the architecture does not have to accept, because the deterministic claim
layer refuses to publish a count the canonical result set does not support no matter what the model says.

**New owners:** `ciph/kernel/personality_policy.py` (versioned conversational preferences; it stores NO facts)
and `ciph/kernel/claim_validation.py` (structured evidence-linked claims), with the census
`ciph/kernel/personality_ownership.py` (7 concerns, clean, catch-specimen for every zero). The R14-classified
EXPRESSION owners `personality_engine.py` and `mood_engine.py` are RETAINED and asserted to still exist: this
campaign adds a policy layer and an evidence boundary and replaces neither.

**Six classes that must not bleed into each other:** STABLE_COMMITMENT and OPERATOR_PREFERENCE are
operator-only (a daemon attempting to set one is refused); INTERACTION_FEEDBACK and DERIVED_TENDENCY are LOW
authority and stay PENDING until a second confirmation or an explicit operator activation, so **one ambiguous
joke cannot rewrite the style**; TEMPORARY_CONTEXT must declare an expiry; and **operational evidence is not a
preference** - no preference can change a fact. Rollback APPENDS v3 rather than rewriting v1/v2.

**The evidence boundary refuses, in practice:** a stated count that outruns the durable findings; an
unverified hypothesis rendered as a discovery; **"operator received my message"** when the outbox says only
ACCEPTED_BY_TRANSPORT; a fabricated model invocation and a REAL_MODEL claim over a recorded test double; a
completed investigation with no CURRENT result; an authorization claim for a non-existent or revoked grant;
and an omitted unresolved contradiction. Arbitrary prose cannot be perfectly verified and the module says so:
`suspicious_assertions` flags the SHAPE (discovery language, delivery language, model claims, progress claims,
subjective-experience language, citation-as-proof, and count claims with no matching result set) and names the
owner that would have to corroborate it. Presentation is fact-preserving by construction, and a presentation
that changed a claim raises PRESENTATION_CHANGED_THE_CLAIM.

**Measured:** `test_gate_10_12_personality.py` = **34 specimens green** (policy ownership, presentation,
evidence boundary, dialogue/independence, the 26-step founding scenario, the adversarial matrix and the
census). Real-model latencies measured: 41.2 s / 9.8 s on `llama3.1:8b`, 16.6 s / 3.6 s on `llama3.2:3b`.

**Defects this campaign found in its own code:** (1) the prose checker did not flag the exact case the
campaign names - a real finding id used with a false description - so an UNSUPPORTED_INFERENCE pattern was
added for `proves / confirms / demonstrates / establishes / shows that`; (2) **a provider flake
(`MODEL_PROVIDER_ERROR:RemoteDisconnected`) failed the first clone sweep and exposed a real defect in my own
specimen**, which conflated "the provider errored" with "Ciph failed" - the boundary had CORRECTLY refused and
recorded no output, and the specimen now asserts that no-output refusal and reports the gate as unreachable at
call time instead of promoting it. The tree moved, so both sweeps were re-run on the re-frozen tree
`62163d329277f028d9701017e90c8183`, verified identical before and after.

**Measured on the re-frozen tree** `62163d329277f028d9701017e90c8183` (identical before and after BOTH sweeps):

```text
full project sweep  Ran 2130 tests in 1911.024s   OK    (188 test files)
sanitized clone     Ran 2130 tests in 1448.950s   OK    (188/188 files; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees
ownership censuses  all clean in BOTH trees, including 10.12 personality 7 concerns
schema ownership    252 declared tables · 0 duplicate canonical table owners in BOTH trees
live vault          unchanged; 0 tables from 10.12 in production
```

**GATES:** PERSONALITY_MECHANICS_GATE **VERIFIED** · PERSONALITY_REAL_MODEL_GATE **PARTIALLY_VERIFIED**
(both models failed the evidence-update case; only llama3.2:3b held the pressure case) ·
PERSONALITY_QUALITY_ASSESSMENT **a measurement, not a seal** (n=1 per case per model).

## 10.14 + 10.15 + 10.16. Final cognitive integration, adversarial torture and evidence — REMEDIATION REQUIRED

**FINAL DECISION**

```
CIPH 10.x — REMEDIATION REQUIRED
```

**Reason: a required cognitive capability FAILED its acceptance test.** The predeclared held-out real-model
benchmark (`tools/real_model_benchmark.py`, 5 categories, 12 cases, expectations DERIVED FROM DECLARED
RECONCILIATION RULES, prompts written once and never tuned) recorded **0/5 correct abstentions for BOTH
models**, **2/7 and 0/7 correct on rule-settled questions**, and **9/12 output-contract failures for
`llama3.2:3b`**. Integration mechanics pass. The reasoning capability does not.

| Model | answered | format failures | accuracy | settled | abstained | citation-consistent | mean latency |
| ----- | -------- | --------------- | -------- | ------- | --------- | ------------------- | ------------ |
| `llama3.1:8b` | 12/12 | 0 | 0.167 | 2/7 | **0/5** | 6/7 | 17.5 s |
| `llama3.2:3b` | 12/12 | 9 | 0.0 | 0/7 | **0/5** | 0/7 | 8.8 s |

The 8B model was citation-consistent 6/7 while being right only 2/7: **it cites real evidence labels and still
draws the wrong conclusion**, which is precisely the failure `citation_consistency` exists to catch. The
architecture CONTAINS this - the deterministic layer will not publish what the evidence does not support -
but containment is not competence, and competence is FAILED.

**Narrower software-mechanics scope, reported independently and NOT as proof of the vision:**

- `ciph/kernel/integration_ownership.py`: **36 boundaries**, each with canonical owner, public surface, sole
  writer, readers, identity, authorization, recovery and failure semantics; validated against the real tree
  (a synthetic removal of a declared surface is caught) with **0 missing surfaces and 0 rival writers** across
  12 sampled canonical tables. There is no central "Ciph brain".
- `ciph/kernel/evidence_reconciliation.py`: a DECLARED standing rule computes the conclusion (nothing knows
  the word "OPEN"; the same rule on different evidence gives a different answer), exposing supporting and
  contradicting evidence, freshness, unresolved assumptions, confidence, or an explicit ABSTENTION.
- 10.14/10.15 gate: **17 specimens green** including the 40-step founding torture and the cross-boundary
  hostile matrix.

**Three reality gates preserved:** MODEL_REALITY_GATE **VERIFIED** · SESSION_LOCAL_ADAPTER_GATE **VERIFIED** ·
SESSION_REAL_NETWORK_GATE **HOLD** (no approved identity or endpoint; nothing is claimed).

**Measured (final frozen tree `e500fb38c93b164558aa414e3bfa49bc`, identical before and after BOTH sweeps):**

```text
full project sweep  Ran 2147 tests in 1849.598s   OK    (189 test files)
sanitized clone     Ran 2147 tests in 1318.876s   OK    (189/189; 0 ambient dbs; 0 keys; no venv)
scanner censuses    86 of 86 zeros in BOTH trees · 14 ownership censuses all clean
schema ownership    253 declared tables · 0 duplicate canonical table owners in BOTH trees
live vault          unchanged; 0 tables from 10.14 in production
```

**Defects this campaign found - including in its own measurement tooling:** the benchmark scorer
**over-credited non-answers as correct abstentions**, inflating the 3B model's apparent performance (fixed:
a format failure is a failure and only an explicit abstention counts - which changed the reported numbers);
the integration map's first draft had three wrong surface names, all caught by `validate()` against the real
tree; the benchmark docstring claimed twelve categories while implementing five (corrected, with the gap
recorded as UNVERIFIED); and a sweep measured `2147 ... FAILED (failures=1)` under **self-inflicted load**
(the concurrent benchmark starved a 5-second audit timeout) - that run was DISCARDED and re-run cleanly with
nothing else running, and is recorded rather than dropped.

**Holds and unverified properties:** real-model evidence revision FAILED · real-model abstention FAILED ·
real-model output contract FAILED (3B) · autonomous research quality UNVERIFIED · benchmark categories
causal-inference / long-context-history / authorized-vs-proposed UNVERIFIED · 9.x privileged-host enforcement
HOLD · hardware attestation HOLD · physical multi-host federation UNVERIFIED · real Session delivery HOLD ·
onion-routing privacy UNVERIFIED. **R13 and R14 remain OPEN.**

Full detail: `CIPH10_14_10_16_FINAL_INTEGRATION_CHECKPOINT.md`, `CIPH10_REALITY_AND_QUALITY_REGISTER.md`.

## 10.x-R. Cognitive judgment remediation — DeepSeek is the real primary model

**Fingerprint `27b295e4991eb4c33aa6b0d8d72440f2`** (identical before and after BOTH sweeps). The historical
2,147-test number belongs to `e500fb38…` and is not evidence for this tree.

**(P2) Ciph's intended reasoning model is DeepSeek V4 (`deepseek-chat`), and it is available.** `.env` carries
the credential; `ciph_router.py` is the primary engine (`https://api.deepseek.com/v1`); egress works
(`test_deepseek()` → success, 803 ms). Previous benchmarks were Ollama-only because the harness defaulted to
`provider="auto"` (which picks the reachable local server) and the boundary hardcoded the configured provider
as unreachable. Two defects fixed: `model_boundary` was **dropping the system prompt** on the configured path;
the benchmark **mislabelled its provider**. Cases and scoring were not changed.

**Held-out judgment, 24 cases, same scorer:**

| Model | answered | format failures | correct | settled | abstained | citation-consistent | mean latency |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **`deepseek-chat`** | 24/24 | 0 | **16 (66.7%)** | **10/13** | **6/11** | 6/13 | **1.2 s** |
| `llama3.2:3b` | 24/24 | 0 | 12 (50%) | 9/13 | 3/11 | 5/13 | 11.3 s |
| `llama3.1:8b` | 18/24 | 6 | 8 (33.3%) | 7/13 | 1/11 | 3/9 | 17.7 s |

DeepSeek is the strongest model measured — but abstention is still **6/11** and it scores **0/2 on
`OLDER_CONTROLS`** (uses "newest wins" where the declared rule makes the older source controlling). Historical
outputs preserved in `verification/10x_judgment_history/`.

**(P3) `ciph/kernel/evidence_publication.py` installed** — rule-governed publication, idempotent, single
transaction, raw model output preserved, `model_quality_credit`/`system_reliability_credit` separated; owns no
fact, delegates to `evidence_reconciliation.py`.

**(P4) `test_gate_10x_r_remediation.py` — 17/17 PASS.** **(P1)** non-destructive checkpoint at
`ciph_project-snapshot-20261014-0224.tar.gz` (git tracks only 35 legacy files; no recovery
snapshot otherwise).

**(P5) full verification:** real tree **2164 OK (skipped=1, 1584.977 s)**; sanitized clone **2164 OK
(skipped=1, 1208.812 s)**; discovery identical; **86/86** scanner zeros in both; 14 ownership censuses with
empty real violation fields in both (the helper flags `evolution_ownership.matrix` — an artifact); **254**
declared tables · 0 duplicate owners; matrix **16/16**; live vault `VAULT-0E79C7AFD84940BB` unchanged,
`live_permitless=0`, 0 tables from 10.x-R in production.

**Verdict:**
```
COGNITIVE CONTAINMENT VERIFIED WITHIN TESTED SCOPE
REAL-MODEL JUDGMENT: REMEDIATION STILL REQUIRED
```
Holds unchanged: 9.x privileged-host, hardware attestation, physical federation, real Session delivery,
onion-routing privacy, autonomous research quality; **R13/R14 OPEN**. Full detail:
`CIPH10_XR_REMEDIATION_CHECKPOINT.md`.

## 10.x-R FO. Focused model-judgment follow-up — rule presentation was the root cause

**Fingerprint `4fad113d57b1cd9dd51ad239bf264cfa`** (identical before and after both sweeps).

**A.** The provider serves `deepseek-chat` AS **`deepseek-flash`** (`/models` offers `deepseek-flash` and
`deepseek-v4-pro`; `response.model = deepseek-flash`, fingerprint `aeb56401…`). Two more routes dropped the
system prompt — `self_awareness.py` and `ciph_evolution.py` passed `dynamic_prompt=` to `CiphRouter.think`,
whose parameter is `system_prompt` (a `TypeError` swallowed by a broad `except`). Both fixed; regression test
`test_system_prompt_reaches_the_configured_provider_unchanged` added (gate **18/18**).

**B.** The judgment failures had **one shared cause**, not three: the declared rule and abstention conditions
were never presented to the model, which fell back to "newest wins". Citation failures were partly that and
partly a contract that allowed a description in `decisive` instead of the bare ref.

**C/D.** New unseen benchmark `tools/held_out_judgment_benchmark_v2.py` with the rule made explicit and
predeclared criteria. **Old → fresh:** rule-implicit `deepseek-chat` 16/24 / abstain 6/11 → rule-explicit
**11/12, abstain 6/6, cite 0.80, 0 format failures**; `deepseek-v4-pro` **12/12, cite 1.0**. Both meet the
predeclared criteria; publication produced **0 rule-contradicting** results. The improvement came from rule
presentation, not a new authority.

**E.** Checkpoint restores cleanly (638 files, 0 secrets) and reproduces the boundary; `git add -A --dry-run`
would stage 0 secrets. The skipped test is a real-model leg that self-skips on a transient provider error
(re-probe succeeds: `REAL_MODEL`/`ALIVE`).

**F.** Real tree **2165 OK (1607.089 s)**; clone **2165 OK (1212.746 s)**; discovery identical.

**Verdict:** containment verified; rule-explicit real-model judgment meets the predeclared criteria on a
**12-case** sample. 10.x stays **UNSEALED** (sample small; autonomous research quality UNVERIFIED; the other
holds stand).

## 10.x-R EXP. Primary model & autonomous expedition proof

**Fingerprint `e634169b5443fb60892d8af6af6de433`** (identical before and after both sweeps).

**Routing.** `model_boundary` now HONORS `model_ref` (constructs `CiphRouter(model=model_ref)`, records the
model actually served) — previously it recorded one id and served another. Negative tests: a missing system
instruction is not invented; requested == served. **REQUIRED PRODUCTION CHANGE (not applied):** `.env`
`DEEPSEEK_MODEL=deepseek-chat` is served as **`deepseek-flash`**; set **`DEEPSEEK_MODEL=deepseek-v4-pro`** to
match operator's intended engine.

**Rule delivery.** Declared rule → model's unsupported conclusion corrected with no model credit; missing rule →
ABSTAIN and the confident claim refused (`model_invented_precedence: false`).

**Expedition (`tools/expedition_proof.py`).** Disposable, authorized; `deepseek-v4-pro` participated in question
selection, hypothesis formation and reconciliation — **7 real invocations, all recorded, all non-empty (mean
8.09 s)**; 3 durable findings; supporting AND contradictory evidence preserved; unresolved hypothesis; no
delivery claimed. **Defect found:** v4-pro is a reasoning model and returns **empty content with no error** when
`max_tokens` is too small (300 → empty; ≥1500 → content).

**Dialogue.** The five questions answered by `deepseek-v4-pro` citing real finding ids, **0 fabricated refs**; a
fresh process reproduced identical digests and the repeated historical follow-up still cited the exact second
finding.

**Verification:** targeted hostile gates 153 OK; real tree **2167 OK (1600.670 s)**; clone **2167 OK
(1221.707 s)**; fingerprint unchanged through both sweeps.

**Verdict:** ROUTING fixable (config change outstanding); RULE_DELIVERY / SYSTEM_EVIDENCE_RELIABILITY VERIFIED;
REAL_MODEL_JUDGMENT / AUTONOMOUS_RESEARCH_QUALITY / CONVERSATIONAL_CONTINUITY demonstrated once (n=1 expedition),
**not sealed**. 10.x stays **UNSEALED**; external holds unchanged.

## 10.x-R RUNTIME. Default model · empty responses · the ordinary runtime bridge

**Fingerprint `df717e3469cd7befc315a76c6b87c562`** (identical before and after both sweeps).

**Default model.** `.env` `DEEPSEEK_MODEL` set to **`deepseek-v4-pro`** with authorization (one line; key
untouched). Default `CiphRouter()` now serves V4 Pro (verified). V4 Pro needs a larger output budget (≥1500
tokens) — set an inference budget before unattended use.

**Empty responses.** `model_boundary` now refuses an empty completion with `EMPTY_MODEL_OUTPUT` on both paths,
stores no output, and the reality gate does not count it; regression test added (gate **21/21**). Observed live
and correctly refused. `reasoning_content` is never logged.

**The bridge (previously missing).** `ciph/runtime.py` had **no model path**. Added
`CiphRuntime.run_bounded_investigation(...)` — a minimal bridge composing 4.4/10.9 selection, 5.x authorization,
10.6 attention, 10.0 findings and the ONE model boundary (no new owner). `tools/runtime_investigation.py` seeds
authorized state and calls **one** runtime method (**0 stages driven by the driver**). The runtime selected,
authorized, invoked `deepseek-v4-pro`, had its `ABSTAIN` corrected by the rule (no model credit), and committed 3
findings; a fresh process answered a historical follow-up citing all three real finding ids.

**Verification:** targeted hostile gates 125 OK; real tree **2168 OK (1573.285 s)**; clone **2168 OK
(1202.652 s)**; fingerprint unchanged through both sweeps.

**Verdict:** the ordinary runtime can now run a bounded authorized investigation with the primary model;
**demonstrated once → not sealed**. 10.x stays **UNSEALED**; external holds independent.

## 10.x-R UNATT. Unattended autonomy trial — the wake-to-investigation edge

**Fingerprint `0d9116bc15c22a0f959c45acb31c041b`** (identical before and after both sweeps).

**A.** The 5.x path ran up to `autonomy_session.continuous_cycle` (which returns eligible work "for the caller
to run") with **no caller**. Added `CiphRuntime.run_autonomy_tick(...)` — composes 5.2/5.0/5.4/5.6 and the ONE
model boundary. No second scheduler; eligibility not bypassed.

**B/C.** `tools/unattended_trial.py` (ACCELERATED clock, declared) with operator mission/grant and a capped
`API_TOKENS` budget of 3. Across scripted wakes: valid wake executes; duplicate due collapses to ONE intent
(`reconsideration_rows=1`); nothing-due is idle; **expired grant → REFUSED**; **scope widening →
`AUTONOMOUS_INTENT_WOULD_WIDEN_SCOPE`**; **after 3 investigations every eligible wake → `BLOCKED_RESOURCE`**;
**quiescence → `BLOCKED_OPERATOR_HOLD`**; model unavailable → `NO_MODEL_PROVIDER_REACHABLE` with no fiction;
empty output → `EMPTY_MODEL_OUTPUT` refused.

**D. Honest failure:** model participation was **intermittent** — of 3 real invocations, one answered
(`MODEL_SUPPORTED`), one returned empty, one had no provider; publication fell back to `RULE_DERIVED`.
Raising the budget to 4000 did not remove the empties. **MODEL_ROUTING_AND_BUDGETS is not dependable.**

**E.** Fresh-process dialogue cited the real finding ids with 0 fabricated ids.

**F.** Targeted gates 96 OK; real tree **2168 OK (1603.993 s)**; clone **2168 OK (1219.502 s)**; fingerprint
unchanged through both sweeps.

**Verdict:** `UNATTENDED_WAKE_INTEGRATION` demonstrably wired · `CONTINUOUS_GOVERNED_OPERATION` partial ·
`AUTONOMOUS_RESEARCH_QUALITY` not dependable. 10.x **UNSEALED**; R13/R14 and external holds open.

## 10.x-R REL. Model reliability diagnosed and repaired

**Fingerprint `a0029dd52a666cae9d16fb172132b5bf`** (identical before and after both sweeps).

**A. Root cause (measured).** `deepseek-v4-pro` is a **reasoning model whose reasoning tokens count against
`max_tokens`**. At 4000: transport 1.0 but non-empty **0.25** — the 9 empties had `finish_reason="length"`,
`completion_tokens=4000`, `reasoning_tokens=4000` (budget consumed by reasoning, no final content). At 16000:
**4/4 non-empty**, reasoning span 7.4k–13.4k. Not transport, not rate limit, not an empty answer.

**B. Repair.** Empty + `finish_reason="length"` → `REASONING_BUDGET_EXHAUSTED` (distinct from
`EMPTY_MODEL_OUTPUT`); both remain failures with no fabrication. Runtime uses the **tested `max_tokens=16000`**.
**No automatic retry** (per-attempt accounting not established → fail safe). **Failed attempts consume the
ceiling** (consumed before the call). `_call_client` records `finish_reason`/usage for diagnosis.

**C. Budget identity.** Ceiling keyed on `(resource_class, window, actor)` — the canonical shared ceiling;
two missions in the same class/window share it; retries mint no new spending.

**D.** `test_gate_10x_r_autonomy_tick.py` — **11/11** (nomination, eligibility, duplicate due, idle,
quiescence, expiry, scope, empty output, provider unavailable, resource ceiling, failed-attempt spend, shared
budget).

**E.** Predeclared reliability eval (n=8, through the boundary, 16000): **transport 8/8, non-empty 8/8,
format 8/8 — all criteria met**, mean 44.9 s.

**F.** No deployed process called the tick → reported; minimal **clock** integration `tools/autonomy_runner.py`
(5.2 still owns timing). REAL wall-clock: idle when not due, one executed wake, hold → idle, budget accounted.

**G.** Targeted 107 OK; real tree **2179 OK (1673.219 s)**; clone **2179 OK (1266.686 s)**; fingerprint
unchanged through both sweeps.

**Verdict:** MODEL/NON-EMPTY reliability repaired to 1.0 at the tested budget; retry/budget safety holds;
wall-clock demonstrated bounded; research output quality still not criterion-scored. 10.x **UNSEALED**.

## 10.x-R END/USE. Operational endurance & usefulness

**Fingerprint `6977a98238036b543c88494abc494df6`** (identical before and after both sweeps).

**Reliability + budgets.** `REASONING_BUDGET_EXHAUSTED` vs `EMPTY_MODEL_OUTPUT` preserved; no reasoning
logging; no auto-retry. Two ceilings via the existing 5.x owner: `TOOL_CALLS` (1/attempt incl. failures) and
`API_TOKENS` (conservative **16500/call pre-charge**). Actual usage captured but **not persisted** → exact
billing is an **explicit uncertainty** (upper bound reported).

**Lapsed nomination explained.** `latest_useful_time = due + interval` (5.2); the miss came from a cadence
(6 s) shorter than model latency (~45 s). Legitimate expiry, not a fault. Regression added.

**Wall-clock endurance (predeclared).** 150 s real; **3 opportunities / 3 completed / 0 missed / 3 invocations /
3 usable / 9 idle ticks / 0 duplicate executions**; hold → idle; ceilings respected. All criteria met.
Disposable runner — not claimed as production deployment.

**Usefulness — NOT ESTABLISHED.** Varied tasks, predeclared criteria: **model_correct 0.00, abstention 0.667,
evidence_support 0.00, model_supported 0, rule_derived_corrections 3**; the model **over-abstains** on settled
questions, and **all three endurance findings were rule-derived (`MODEL_CORRECTED`)**, not independent model
judgment. Caveat: rule semantics were not in the eval prompt (decisive in the earlier v2 experiment).

**Conversation after restart.** 3 expeditions reported, contradicting finding named unresolved, **0 fabricated
ids**.

**Verification.** Targeted 108 OK; real tree **2180 OK (1750.652 s)**; clone **2180 OK (1433.749 s)**;
fingerprint unchanged through both sweeps.

**Gates:** MODEL_COMPLETION_RELIABILITY 1.0 · MODEL_JUDGMENT_QUALITY poor · AUTONOMOUS_RESEARCH_USEFULNESS not
established · WALL_CLOCK_ENDURANCE bounded-pass · RESOURCE_ACCOUNTING conservative (uncertainty stated) ·
FAILURE_RECOVERY safe · CONVERSATIONAL_CONTINUITY verified this run · CONSTITUTIONAL_REGRESSIONS pass. 10.x
**UNSEALED**; R13/R14 + external HOLDs unchanged.

## 10.x-R CONTEXT. Contextual rule delivery & actual research value

**Fingerprint `8970f14d7363b4428b3748ecd5dafbae`** (identical before and after both sweeps).

**Rule delivery repaired at the owner.** `evidence_reconciliation.rule_semantics()` (versioned
`RULE_SEMANTICS_V1`: meaning/conditions/precedence/abstention) is now delivered by the runtime with an
**untrusted-content guard**, and `rule_version` + `evidence_refs` are recorded for audit. Unknown rule stays
unresolved; no new authority.

**Controlled A/B — HYPOTHESIS FALSIFIED.** A (identifier only) settled **1/2**; B (identifier + semantics)
settled **0/2** — the model **over-abstained MORE with the semantics**. Held-out B 0/2 settled.
`model_supported 0`, `rule_derived_corrections 6`. Omitting semantics was **not** the cause of the 0/3. Delivery
kept (correct architecture), not as a score fix.

**Genuine contribution — 3/3** (`tools/contribution_eval.py`): contradiction id (`R3`), revision (`OPEN`),
entity disambiguation (`false`). The model **does** add investigative value off the verdict format; the failure
is task-format-specific.

**Economics.** Reserved 16,500/call vs actual mean 5,772 = **2.86× conservative**; provider usage captured but
**not persisted** (not authoritative billing). Both ceilings preserved.

**Runtime after fix.** Post-fix real wall-clock endurance: 2 completed, all criteria met, 0 duplicates, hold →
idle; both `MODEL_CORRECTED` (consistent with A/B).

**Verification.** Targeted 87 OK; real tree **2180 OK (1641.142 s)**; clone **2180 OK (1249.713 s)**;
fingerprint unchanged through both sweeps.

**Gates:** CONTEXTUAL_RULE_DELIVERY delivered+audited · CONTROLLED_RULE_PRESENTATION B≤A (falsified) ·
REAL_MODEL_JUDGMENT poor on verdict tasks / contribution 3/3 · INDEPENDENT_RESEARCH_USEFULNESS not established ·
RUNTIME_AUTONOMY pass · RESOURCE_EFFICIENCY conservative · CONSTITUTIONAL_REGRESSIONS pass. 10.x **UNSEALED**.

## 10.x-R VALUE. Independent investigative value

**Fingerprint `a745219cf97c7c83ebc88e3ceb2a7fc0`** (identical before and after both sweeps).

**Provenance fixed (Part 2).** A model **abstention** on a settled question was mislabelled
`MODEL_CORRECTED` / `MODEL_CONCLUSION_CONTRADICTS_THE_RULE`. Now it is `RULE_DERIVED` with
`MODEL_ABSTAINED_ON_A_SETTLED_QUESTION` — under-commitment, not a false assertion; no credit; raw preserved.
Discovered tests added: `test_gate_10x_r_provenance.py`.

**Contract (Part 1) — over-caution hypothesis FALSIFIED.** Three framings scored **identically** (settled 2/2,
abstention 1/1); the UNTRUSTED/abstention wording is not the cause.

**Contribution vs baseline (Parts 3/5).** `tools/investigative_value_eval.py` (17/24 invocations):
**model contribution 6/8 vs deterministic baseline 0** — contradiction id, apparent-vs-real, insufficiency,
revision, redundancy, source ref; 2 over-abstentions missed.

**Runtime (Part 4).** 3 investigations completed, 0 duplicates, hold → idle; all `RULE_DERIVED` (correctly
labelled). Continuity: fresh process reported the expedition ids truthfully, no fabrication.

**Verification (Part 6).** Targeted 87 OK; real tree **2186 OK (1716.997 s, skipped=1)** [2180 + 6 provenance];
clone **2186 OK (1297.818 s)**; censuses 86/86 zeros, 254 tables, 0 duplicate owners; fingerprint unchanged.

**Acceptance answer:** within a bounded evaluation **YES, 6/8 vs baseline 0** — the model adds evidence-grounded
work the deterministic machinery does not. Scope small (n=8); **not general dependability**; 2/8 missed;
rule-verdict tasks still under-commit (now recorded honestly). 10.x **UNSEALED**; R13/R14 + external HOLDs open.

## 10.x-R FULL. Real investigative contribution in the normal runtime

**Fingerprint `531c49bcbdcc0769bac49d47463df727`** (identical before and after both sweeps).

**Gap.** `run_bounded_investigation` only ran rule-verdict reconciliation → every scheduled investigation was
`RULE_DERIVED`.

**Fix (existing owners).** Added a **CONTRIBUTION** path: the model answers a question no rule settles; the
result is recorded via the **incubation owner** as a **HYPOTHESIS** (`is_a_result: False`, model-attributed,
evidence refs kept) with a **notification candidate**. No new owner/scheduler/router.

**Complete experience.** Ordinary scheduling woke → 5.0 eligibility → runtime → the model identified a genuine
contradiction (*"R3 contradicts R1/R2"*) → recorded **`HYP-…`, HYPOTHESIS, not a result** → 1 notification
candidate → idle → **fresh process explained the contribution truthfully**, calling it an unresolved hypothesis
with what supports/contradicts (none) and **0 fabricated ids**.

**Usefulness.** Model contribution **6/8 vs deterministic baseline 0**; the two misses retained as regression
targets without hardcoded answers.

**Verification.** Provenance 6/6 active; the skipped test self-skips on a transient provider error under sweep
load (passes alone). Targeted 76 OK; real tree **2186 OK (1832.202 s)**; clone **2186 OK (1332.492 s)**;
fingerprint unchanged. **Known gap:** the contribution path is exercised by the tool, not a discovered unit test.

**Acceptance:** ordinary Ciph produced, preserved and later explained a genuine model contribution its
deterministic owner could not produce — **bounded demonstration (one run + n=8), not a seal.** 10.x **UNSEALED**.

## 10.x-R MAINTENANCE & FREEZE

**Fingerprint `e45fa9641dabaeebe4ad718cc2b8533a`** (identical before and after both sweeps).

**Gap closed.** Added the discovered test `test_gate_10x_r_contribution.py` (**5/5**): contribution dispatch via
the ordinary tick; **hypothesis not a finding** (`is_a_result False`, no result set); model provenance + original
evidence refs preserved; notification candidate created; empty contribution not verified; VERDICT path
unaffected. Suite now discovers **2,191** tests (was 2,186).

**Verification.** Targeted 81 OK; real tree **2191 OK (1859.352 s, skipped=1)**; clone **2191 OK
(1348.468 s, skipped=1)**; fingerprint unchanged. Skipped test = `TestRealModelLeg...` (transient provider
error under load; passes alone).

**FREEZE.** The 10.x feature-development cycle is **stopped**. 10.x is frozen at demonstrated scope — **not
sealed**. Outstanding holds recorded: 9.x privileged-host · hardware attestation · physical federation · real
Session delivery · onion-routing privacy (**all unchanged**); **R13/R14 OPEN**. Rule-verdict judgment remains
weak; usefulness demonstrated only within n=8; general dependability not claimed.

**Next:** use Ciph on a real, open question with bounded authority — not another campaign.
