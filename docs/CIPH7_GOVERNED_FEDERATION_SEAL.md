# CIPH 7.x — GOVERNED FEDERATION

**Status:** SEALED, on measured evidence (2026-10-10).

```text
Distribution grants reach, not sovereignty.

node != Ciph      quorum != authority    quorum != truth
connectivity != authority                replication != ownership
timeout != death  timestamp order != constitutional order
silence from the authority owner does not manufacture a replacement owner
```

6.x proved one Ciph can divide work across many workers without creating many little sovereign Ciphers.
7.x asks the next question: **can Ciph exist coherently across multiple independently failing nodes
without letting topology, quorum, clocks or connectivity become authority?** The answer is a federation
whose authority is explicit DOMAIN OWNERSHIP, whose state families each carry their own replication law,
and whose answer to a silent machine is SAFE MODE - never a new owner.

## R11 — the census, made executable first

The survey ran before any federation code and is now enforced (`ciph/kernel/federation_ownership.py`, 19
concerns). Its verdict, carried forward exactly:

```text
KEEP AS MECHANISM (and prove they decide nothing)
  ciph/federation/ghost_mesh.py       handshakes, task envelopes, trusted-peer keys
  ciph/workers/ipc_queue.py           the only durable carrier
  ciph/swarm/byzantine_consensus.py   the signed multi-node opinion mechanism

CLASSIFIED BEFORE AUTHORITY
  ciph/sovereignty/singularity_engine.py

ABSENT, SO 7.x OWNS IT
  node identity/generation, membership, state classification, authority domains, partitions,
  distributed quiescence, clock law, reconciliation, key custody, node health, rejoin/retirement,
  routing, federation learning
```

The classification found something the survey could not: `SovereigntyEngine` is not merely a projection.
`execute_governed_evolution_promotion` DISPATCHES a production promotion through
`runtime.execute_reference_loop`. It is fail-closed - no signed operator grant, no transition - and
nothing in production calls it, but it is a second promotion-shaped path outside 4.5/4.7/R7. So it is
treated as authority-shaped until 7.x gives it standing, and its consumer count is scanned. The
operator-grant check is a FAILSAFE, not a justification.

```text
R11 zeros (real tree and clone)
  census violations                        0
  retained machinery missing               0
  production consumers of the ghost-mesh authority symbols      0
  production consumers of the consensus verdict                 0
  production consumers of the sovereignty transition             0
  second federation authority owner         0
  federation bypass patterns                0
```

## What was built

| Phase | Module | What it owns |
| --- | --- | --- |
| R11 | `federation_ownership.py` | 19 concerns, mechanisms, authority-shaped consumer zeros |
| 7.0/7.1/7.10/7.11 | `federation_node.py` | node identity, generation, membership, health, rejoin/retirement |
| 7.2 | `federation_state.py` | `FEDERATION_STATE_CLASSIFICATION_V1`: six classes over 22 families |
| 7.3/7.5 | `federation_authority.py` | authority domains, epochs, governed transfer, quorum refusal, partition views |
| 7.7/7.8 | `federation_replication.py` | per-family reconciliation, causal order, the wall-clock refusal |
| 7.6 | `federation_quiescence.py` | the federation barrier and swarm-wide emergency stop |
| 7.4/7.12/7.13 | `federation_delegation.py` | cross-node delegation, routing/placement, descriptive learning |
| 7.9 | `federation_keys.py` | the root -> node credential boundary |
| 7.x | `federation_scanners.py` | the sixteen structural zeros |

No new executor, no second permit authority, no second promotion path: distributed work is delegated by
these modules and any authoritative effect still crosses 4.0, 4.5, 4.7 and R7.

## Measured evidence

```text
7.x suites                     55 specimens, OK
  test_gate_7_0_...            25   (R11 census, node identity, classification, authority,
                                      replication, clocks, reconstruction)
  test_gate_7_5_...            19   (partitions, quiescence, keys, delegation, routing, learning)
  test_gate_7_9_...            11   (the three-node runtime torture)

full project sweep             Ran 1761 tests in 1212.530s   OK   (frozen tree)
sanitized clone sweep          Ran 1761 tests in 1049.801s   OK   (no ambient vault)
live vault                     VAULT-0E79C7AFD84940BB / VAULT_ID_V1, 4 protected rows all decrypt,
                               live_permitless = 0, integrity_check ok, zero federation tables
```

Scanner censuses, real tree and clone:

```text
federation scanners (7.x)      16 of 16 zero, each with its own catch-specimen
R11 census                     19 concerns, 0 violations, 0 missing machinery, 0 authority consumers
swarm scanners (6.x)           12 of 12 zero        autonomy scanners (5.x)   12 of 12 zero
meta scanners (4.7)            12 of 12 zero        R6 census / R7 choke point  0 / 0
duplicate canonical owners     0
```

## The three-node torture

Three real node processes, each with its own datastore, identity, key and runtime directory. Records
travel by an explicit delivery into the store that merges them, because that is what replication is - no
shared database pretending to be a network.

```text
quorum cannot seize authority    A owns D-1; A is unreachable from B and C; B and C reach each other
                                 and agree. Both are refused NOT_THE_AUTHORITY_OWNER, the quorum claim
                                 returns authority_effect "none", C's ownership claim for A's epoch is
                                 INTEGRITY_CONFLICT and is not adopted, and A still owns D-1 at epoch 1
evidence merges, authority not   A and B both observe OBS-1: ONE standing record (DUPLICATE second
                                 time), not two confirmations. B observes something else: both survive.
                                 B asserting canonical state for A's domain: INTEGRITY_CONFLICT, not
                                 stored, with the quorum claim attached
quiescence honesty               A and C acknowledge; N-B is observed UNREACHABLE from A. The barrier
                                 stays DRAINING with N-B@1 unresolved. Only revoking N-B's authority
                                 reaches QUIESCENT - a timeout is never an acknowledgement
stale rejoin                     B presents epoch 12 against epoch 26: STALE_AUTHORITY_EPOCH with
                                 authority_revived = False; a wrong generation: STALE_GENERATION; its
                                 EVIDENCE still merges, because evidence is not authority
clock attack                     B writes with a clock 9999s AHEAD and A 9999s behind; the higher epoch
                                 still orders first, and authority_winner_by_wall_clock raises rather
                                 than choosing
consensus attack                 the legacy engine returns approved=True for a unanimous council.
                                 B's transition is still refused and A still owns D-1
sovereignty attack               the solvency projection is favourable. Same refusal, same owner
emergency stop during partition  domains FROZEN (not transferred), zero acknowledgements fabricated,
                                 and the frozen domain refuses even its OWN owner
key revocation                   B's credential revoked; B cannot authenticate; A is untouched, and no
                                 node holds root authority
whole-federation reconstruction  every node's digests reproduce from fresh processes
```

## Defects found and fixed in this campaign

1. **The census caught my own ownership drift first.** `federation_delegation.py` claimed the learning
   concern and `federation_replication.py` claimed the clock law, because I consolidated those phases
   differently from the census I had just written. The census was pointing at the right problem - a
   concern with two possible owners - and the fix was to make the census match the implemented owner
   rather than to widen it.
2. **`ciph/federation/__init__.py` was read as a consumer of GhostMeshNode.** An `__init__` re-export is
   a declaration; the package that EXPORTS a mechanism is not a consumer of it.
3. **s13 fired on the quiescence module** for building member strings from `node_generation` without
   stating a currency rule. The barrier now filters to the current generation explicitly - the scanner
   was right that the rule belonged in the code.
4. **s10 could not see the wall-clock offence it was written for** (`sorted(..., key=lambda r:
   r.wall_time)` slips past a `sort(key=lambda...)` pattern). The pattern now names the ordering key,
   which is the actual signal.
5. **The R6 census read `federation_scanners.py` as an owner of the active candidate pointer.** Fourth
   phase, same collision: a scanner MUST contain other phases' forbidden table names as data, and a
   table-name-plus-`UPDATE ` heuristic reads that as a write. Repaired through the mechanism R6 already
   had (`SIGNAL_DECLARING_MODULES`), which is now the standing answer for this class.
6. **The 6.x specimen for the R10 dormant-authority zero re-implemented the census predicate instead
   of calling it.** When the census moved from a hand-maintained exclusion list to a suffix rule, the
   specimen kept testing the OLD list and passed for the wrong reason. It now calls the real predicate.
   That is the fifth time this class has appeared in this project (4.7's scanner, the swarm scanners, the
   R6 census, the R6 specimen, this one), and the lesson is now written where it belongs: **call the
   predicate, do not restate it** - a restated predicate is a second implementation of a rule, which is
   the exact failure mode this whole register exists to prevent.
7. **The three-node torture drove early specimens against the wrong store** - a peer asserting against
   its OWN empty store proved nothing about the federation. The specimens now deliver peer actions into
   the store that holds the lineage, which is both a sharper test and a more honest model of a message
   arriving.

## Stated limits (not implied absences)

- **Root custody is operator-held and offline.** That is the V1 answer, written down as a limit rather
  than dressed up as distributed key management: a node holds its OWN credential, membership never
  implies root authority, and how to distribute root custody safely is deliberately not solved here.
- **The three nodes are local processes with separate stores**, not three machines. The partition is
  modelled as observed reachability plus explicit message delivery, so what is proven is the
  CONSTITUTION under partition - not a real network's failure modes. 8.x is where transport, not law,
  becomes the interesting problem.
- The scanners are **static and syntactic**, with catalogue modules excluded by name (a file that
  declares a pattern is not a file that uses it). They narrow the bypass surface; the architectural
  review remains the root fallback.
- Several scanners are PRESENCE checks - the law has to be in the code (the lineage gate, the scope
  guard, the wall-clock refusal, the unreachable status) - and a presence check cannot see a
  semantically wrong implementation, only a missing one.
- **Federation learning is per-observer and descriptive.** There is no `FEDERATION_INTELLIGENCE_SCORE`,
  and historical placement success grants no authority.
- **No production federation history exists.** The live vault has zero federation tables, so the live
  check confirms absence rather than exercising a read path.
- Wall time remains first-class for scheduling, expiry and human audit. What is refused is using it to
  order constitutional events, and the refusal has an executable form.

## Seal criteria

```text
One sovereign Ciph identity maintained                        PROVEN
Node identity distinct from address/process/worker            PROVEN
Node generation explicit                                      PROVEN
Membership governed                                           PROVEN
Handshake != membership                                       PROVEN
State families explicitly classified                          PROVEN
SECRET_LOCAL state not ordinary-replicated                    PROVEN
Authority domains explicit                                    PROVEN
Quorum cannot mint authority                                  PROVEN
Connectivity loss cannot mint authority                       PROVEN
Owner silence cannot mint authority                           PROVEN
Cross-node delegation != authority transfer                   PROVEN
Remote result != evidence automatically                       PROVEN
Replicated evidence preserves provenance/source dependence    PROVEN
Last-write-wins not used for constitutional authority         PROVEN
Wall clock does not decide constitutional ordering            PROVEN
Partition semantics fail safe                                 PROVEN
Unreachable != dead                                           PROVEN
Timeout != quiescent acknowledgement                          PROVEN
Distributed quiescence honest                                 PROVEN
Joining/rejoining nodes cannot bypass the barrier             PROVEN
Stale node cannot revive stale authority                      PROVEN
Conflicting authoritative histories surface conflict          PROVEN
Node root/key boundaries explicit                             PROVEN
Node cannot self-ratify health                                PROVEN
Routing grants no authority                                   PROVEN
R7 remains sole production activation path                    PROVEN
4.7 remains sole meta-evolution promotion constitution        PROVEN
5.x autonomy remains above distributed work                   PROVEN
6.x worker authority remains subordinate                      PROVEN
Legacy ByzantineConsensus verdict has zero authority effect   PROVEN
GhostMesh transport has zero constitutional authority         PROVEN
SovereigntyEngine projection cannot silently become authority PROVEN
Federation reconstructs deterministically                     PROVEN
Three-node partition torture green                            PROVEN
All federation scanner invariants zero                        PROVEN
Previous programs regressions green                           PROVEN
Full project sweep green                                      PROVEN
Sanitized clone green                                         PROVEN
Live vault read-only invariants green                         PROVEN
```

```text
R11 CLOSED

CIPH 7.x — GOVERNED FEDERATION
SEALED
```

**One Ciph. Many nodes. No node becomes sovereign merely because the others went silent.**
