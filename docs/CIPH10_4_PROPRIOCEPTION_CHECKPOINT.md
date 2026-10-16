# CIPH 10.x — CAMPAIGN A1 / 10.0 INTEGRATION · FROZEN-TREE REBASELINE · 10.4 ARCHITECTURAL
# PROPRIOCEPTION

**Status:** 10.0 INTEGRATION COMPLETE · POST-10.0 BASELINE MEASURED · 10.4 IMPLEMENTED · ADVERSARIAL
SPECIMENS GREEN · **10.x NOT SEALED** (this is a checkpoint, not the program seal).

```text
The LLM may rest. Ciph's operational continuity does not.
Observation != authority.   Loaded code != source code currently on disk.
An observation is not evidence until it is durable and attributable.
Self-observation cannot independently certify its own integrity.
One observer is not enough.  Evidence before assertion.  Architecture before sensors.
```

---

## PART A — the REAL 10.0 conversational integration

### What was actually broken (found this campaign, in the new code)

The 10.0 owner (`ciph/kernel/referential_continuity.py`) and the router hook existed, but the
conversational path still had three defects, each found by a specimen rather than by review:

| # | Defect | Fix |
| - | ------ | --- |
| 1 | Intent was anchored on RESULT NOUNS (`alert`/`finding`/`result`/`idea`) plus the bare word `seventh`, so **"Explain number seven"** carried no noun and fell through to CONSULT - i.e. back to the model. | Ordinal parsing moved FIRST: a bare ordinal word (`seventh`) or an ordinal cue (`number seven`, `#7`, `item three`) is itself a retrieval request. |
| 2 | With **more than one** stored result set, a phrase WITH an ordinal silently picked `sorted(...)[0]`. | Several stored sets are ALWAYS ambiguous now, ordinal or not; the ambiguity is reported instead of being resolved by recency or sort order. |
| 3 | The router swallowed a refusal (`ORDINAL_OUT_OF_RANGE`, protected-set refusal) and returned `(CONSULT, None)`. | A refusal or ambiguity is SURFACED as `(CONSULT, payload-with-reason)`, so "I cannot retrieve that, and here is why" reaches the caller instead of silence the model can fill. |

### The producer is now durable (the real entry point)

The R14 survey named `darknet_monitor` as a producer that rendered findings into a **string**. It now
COMMITS a durable result set through the 10.0 owner at the end of `DarknetMonitor.full_scan`
(`_commit_scan_alerts`): each alert becomes a finding that REFERENCES a real 4.2 observation, committed as a
NEW result set (a scan is a genuine new observation of the world). A failure to persist is REPORTED, never
faked - the scan result stands, but the durable identity is marked unavailable.

### Specimens

```text
test_gate_10_0_conversational_integration.py   10 specimens green (was 9; +1 real entry point)
  - the mandatory interaction: sweep -> announce -> "Show me the twenty alerts" -> "Explain number seven"
    -> restart the runtime in a REAL subprocess -> "What happened with that seventh alert?"
    -> identical finding_id AND evidence_ref, and `scanned_again = False`
  - the real producer: DarknetMonitor.full_scan driven through its real orchestration (Tor check, feed
    scoring, tally, alert sync, durable commit); ONLY the network boundary is stubbed (`verify_tor` /
    `_tor_get`) because this host has no egress. 25 alerts -> 25 durable findings.
  - PROOF that retrieval never rescans: the network-boundary call counter and the result-set count are both
    UNCHANGED by answering the question, before and after the restart.
  - identity: a RETRY re-commits the same findings -> same set, idempotent, one revision; two different
    investigations with identical findings keep distinct identities; a revision appends and keeps identity;
    an announcement keeps its own historical revision; unauthorized retrieval is refused; missing evidence
    is reported, never replaced.
```

Scope, stated rather than implied: the network scanning tools cannot be run for real here (no egress), so
the egress-dependent half is stubbed at the network boundary and the finding/identity/persistence half is
production code.

---

## PART B — post-10.0 frozen-tree rebaseline

```text
frozen tree         7402a8317765f608f2391706a6f20727   (identical before and after the sweep)
full project sweep  Ran 1872 tests in 1487.179s   OK    (180 test files)
sanitized clone     Ran 1872 tests in 1205.215s   OK    (180/180 test files, 0 ambient dbs, 0 keys, no venv)
```

Discovery matched exactly between the two trees (1872 both), so there is no difference to explain. The
historical 1845 count is superseded - it was measured on a tree without the two 10.0 gate files
(1845 + 17 + 10 = 1872).

```text
scanner censuses    86 of 86 zeros      (9.x 18 · 8.x 16 · 7.x 16 · 6.x 12 · 5.x 12 · 4.7 12)
ownership censuses  R13 11 clean · R14 11 clean · federation 19 clean · swarm 15 clean
                    R6 evolution 15 clean (0 violations, 0 bypasses, 0 missing) · sovereignty 19 clean
schema ownership    213 declared tables · 0 duplicate canonical table owners
fresh state (clone) autonomy clean · crucible clean (no production-evolution import) ·
                    federation clean (0 nodes/domains/history, R11 clean, 16 scanners zero) · swarm clean
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · s3_gate_satisfied = True · integrity ok ·
                    zero 10.0/10.4 tables in production (no production activation of this program)
                    no leftover CiphOS systemd --user units
```

---

## PART C — 10.4 architectural proprioception

**Canonical owner:** `ciph/kernel/architectural_proprioception.py` (`ARCHITECTURAL_PROPRIOCEPTION_V1`).
It owns a PROJECTION over canonical evidence and mints no authority: observing a change never authorizes
installing, promoting, restarting or modifying anything.

### C2 — four views, never collapsed

```text
SOURCE     what source files and declared components/dependencies are present in the observed tree
INSTALLED  what artifact bytes and configuration are present in the selected installed environment
LOADED     what implementation a running process ACTUALLY LOADED, where a load-time witness exists
EXECUTED   what operations have attributable, AUTHORITATIVE execution evidence
```

There is deliberately **no single "current implementation digest"**. `project_component` returns the four
views plus explicit `distinctions` (`source_vs_installed`, `installed_vs_loaded`, `source_vs_loaded`,
`loaded_is_resolved`, `executed_is_resolved`).

**Rehashing is not loading.** `witness_loaded` REQUIRES a digest captured at load (see `load_time_digest`)
and refuses to digest the file itself
(`LOAD_WITNESS_REQUIRES_A_CAPTURED_DIGEST`). Without a witness the LOADED view is `UNRESOLVED` - never
"probably the source".

### C3 — change witnessing

Append-only `ciph_arch_changes`. An **authorization reference is not authorization**: an R7 deployment
record is evidence of an INTENDED action, and the change is `AUTHORIZED_DEPLOYMENT` only once the installed
bytes are independently corroborated (`verified_installed_digest == current_digest`); otherwise it is
`AUTHORIZED_DEPLOYMENT_MISMATCH`. A change with no authorization reference is
`UNAUTHORIZED_MODIFICATION`. An authorization reference that resolves to nothing is `UNKNOWN_PROVENANCE`.
An offline interval is `OBSERVATION_GAP` with `invented_history = False` (no digest, no modification time
is invented). Correlation reads the R7 owner's record (`evolution_deployment.get_deployment`); it never
asks the filesystem who authorized anything.

### C4 — the self-observation trust boundary

`integrity_claim` REFUSES a self-certification: evidence produced by the local observer alone returns
`SELF_CERTIFICATION_REFUSED`. Independent witnesses that agree return `CORROBORATED`; independent witnesses
that disagree return `DISPUTED` and **nothing is chosen between them**. `policy_reference()` reports the
ownership-census digests as a **versioned policy reference, not a cryptographic root of trust**, and states
the shared-compromise limitation explicitly: the observer and its policy share one trust domain, so an
attacker able to modify the observer can modify the policy. **No TPM/UEFI/measured-boot attestation is
claimed** while CiphOS 9.x certification remains on HOLD.

### C5 — integration with the self-model

Verified architectural observations carry a durable **4.2** observation/execution reference and are read
back through `explain()`, which answers from evidence: components with evidence, running implementation,
changed-on-disk, installed-but-not-loaded, operations that executed, authorized changes, dependent
components, and what remains uncertain. The reasoning model explains this projection; it does not
manufacture architectural state.

### R14 legacy dispositions — SETTLED by responsibility

| Module | Disposition |
| ------ | ----------- |
| `smart_memory.py` | RETAINED MECHANISM - conversation utterances only; never operational truth, never writes canonical tables |
| `enhanced_conversation.py` | PRESENTATION - prose over canonical evidence; owns nothing |
| `personality_engine.py` | EXPRESSION - shapes tone/wording (10.12); asserts no facts, owns no authority |
| `mood_engine.py` | EXPRESSION - internal tone state for wording (10.12); never truth |
| `self_awareness.py` | SELF_DESCRIPTION - describes over the code index; CERTIFICATION is owned by 10.4, so it cannot self-certify |

### Census

`ciph/kernel/architectural_ownership.py` - 6 concerns, clean, with synthetic catch-specimens for every
zero: rival architectural observer, rival epistemic/deployment owner, forbidden architectural patterns
(loaded-view-from-a-source-read, observation-grants-authority, self-certified integrity, second executor,
attestation overclaim, directly-asserted architectural fact), loaded-view-must-be-a-witness, and
attestation-overclaim. Documented limitation: these are SYNTACTIC checks and cannot catch obfuscation or a
rival introduced under an unrelated name - which is exactly why `integrity_claim` refuses self-certification
at RUNTIME instead of relying on a scanner to be complete.

---

## PART D — adversarial verification (15 specimens, each with a negative counterpart)

```text
 1  source changes while the running process keeps its earlier loaded version        + unwitnessed LOADED is UNRESOLVED
 2  installed artifact changes but no execution is proven                            + EXECUTED stays UNRESOLVED
 3  a new runtime loads the updated version after restart                            + the old witness is history, not overwritten
 4  an authorized R7 deployment correlates with observed installed bytes             + intent alone (bytes disagree) = MISMATCH
 5  an unauthorized modification has no authorization provenance                     + a dangling auth ref = UNKNOWN_PROVENANCE
 6  an offline observer records a gap, not an invented history                        + no digest is invented for the gap
 7  a forged architectural observation is refused                                     + a real captured digest / canonical ref is accepted
 8  two observers disagree -> DISPUTED                                                + agreeing independent witnesses -> CORROBORATED
 9  the local observer cannot certify itself                                          + a same-domain "witness" is still self-evidence
10  a restored instance keeps history and gets a new runtime generation               + the restored digest is the new generation
11  a disconnected node is STALE, not CURRENT                                          + a missing observation is UNKNOWN, not FRESH
12  a model statement cannot become execution evidence                                + real 4.3 execution evidence DOES resolve
13  protected introspection cannot expose secrets or held-out material               + the projection exposes digests only, no content
14  a fresh process reconstructs the same canonical projection                        + digests agree across the process boundary
15  the four distinctions survive restart and rollback                               + views stay distinct and resolved
```

Specimens exercise real machinery: the real R7 path (`register_candidate` -> `freeze_protocol` ->
`promote` -> `deploy` with a verified installer), the real 4.2 model-output path, the real 4.3
`record_execution_evidence`, and a real subprocess boundary for reconstruction.

---

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

## Honest limitations

- **No privileged-host proof is claimed.** No system users, namespaces, nftables, secure boot or VM boot
  were exercised here; 9.x remains SEAL HOLD and 10.4 asserts no hardware attestation.
- **No network scan was run.** The egress-dependent producer is stubbed at the network boundary only.
- **Syntactic censuses are not complete.** Stated above.
- **`classify_freshness`** is a small, local staleness classifier used by the projection; federation node
  staleness proper remains owned by 7.x and is not duplicated.
- **R14 stays OPEN** (its full scope is settled only when the 10.x program's conversation/personality work
  lands); the five legacy dispositions are now SETTLED by responsibility.

## Next

10.3 Sensory Fabric, using this architectural model as its shared representational foundation:
every sensor observation carries identity, source, method, scope, runtime generation, observed time,
evidence reference and freshness - the same shape 10.4 already uses.
