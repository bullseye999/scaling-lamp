# CIPH 8.x — SOVEREIGNTY & RECOVERY

**Status:** SEALED, on measured evidence (2026-10-12).

```text
Machine != Ciph.  Provider != Ciph.  Model != Ciph.  Database copy != Ciph.
Backup != authority.  Valid signature != current authorization.
Recovery != automatic activation.  Clone != restored sovereign identity.
```

> **Possession of Ciph's bytes is not possession of Ciph's authority.**

8.x answers the nastier question the earlier programs set up but deliberately did not settle: *if the
machines, provider, paths, processes, models and installation disappear, what exactly must survive for
the result to still legitimately BE Ciph?* The answer is a sovereign identity with a lineage, an
RE-ATTESTED runtime, a classified recovery manifest, integrity-bound backups that carry no authority, a
governed activation ceremony that requires ENFORCEABLE fencing, and one boundary that refuses a stale
instance's permit at the execution surface itself.

## Architecture and frozen identities

| Phase | Module | What it owns |
| --- | --- | --- |
| R12 | `sovereignty_ownership.py` | the census: 19 concerns, 14 zero classes, retained machinery |
| 8.1 | `sovereign_identity.py` | sovereign identity + lineage, operator-held root custody, destruction policy |
| 8.2 | `recovery_manifest.py` | `RECOVERY_MANIFEST_V1`: 28 families across six dispositions, integrity-bound |
| 8.3 | `backup_constitution.py` | `BACKUP_SET_V1`/`BACKUP_CONSISTENCY_V1`: created != verified != restorable != authorized |
| 8.4/8.5 | `recovery_engine.py` | `RECOVERY_STATE_V1`, `RECOVERY_ACTIVATION_V1`, structured authorization, enforceable fencing |
| 8.4/8.5 | `recovery_state.py` | the lifecycle, the activation ceremony, clone registry |
| 8.5 | `federation_reconstitution.py` | `NODE_RECONSTITUTION_V1`: new generation, stale authority refused, orphaned ownership |
| 8.6/8.7/8.8 | `sovereignty_portability.py` | host/path classification, `MODEL_SUBSTITUTION_V1`, `RECOVERY_MIGRATION_PLAN_V1` |
| 8.10 | `sovereignty_monitoring.py` | `SOVEREIGNTY_HEALTH_V1`: LAST_PROVEN_RESTORE, no score |
| 8.0 | `real_transport.py` | `REAL_TRANSPORT_SESSION_V1`, `FEDERATION_ENVELOPE_V1` |
| 8.x | `sovereignty_scanners.py` | the sixteen structural zeros |
| 8.0/PZ | `permit_store.py` (4.0's owner) | the AUTHORITATIVE EPOCH the execution boundary compares against |

## R12 — the two findings, remediated by execution

**Finding 1: the legacy backup path.** `security_layer.encrypted_backup` packaged `ciph.key` as an
ordinary archive member and fell back to a well-known default passphrase. It now FAILS CLOSED: no
passphrase, the historical default, an over-short passphrase, or root material named as content each
raise `INSECURE_BACKUP_CONFIGURATION`. The approved creator refuses the same configurations, and
`ciph.key` is absent from `included` by construction. Historical archives are classified
`INSECURE_HISTORICAL` and are never promoted by improving today's code.

**Finding 2: the destruction mechanism.** `DeadMansSwitch._emergency_destruct` can overwrite the vault
and the root. It now refuses without a named operator authorization, and an historically ARMED timer is
reported and left DISARMED after recovery — a restore cannot carry the instruction to destroy the machine
it was restored onto.

Both specimens CALL the unsafe paths rather than scanning for them.

## Transport — evidence and scope

`REAL_TRANSPORT_SESSION_V1` over actual loopback sockets between separate processes (12 specimens):
disconnect after send, duplicate delivery, unsigned mutation (`REFUSED`) versus authenticated
equivocation (`INTEGRITY_CONFLICT`), stale generation, unsupported protocol, revoked key on open and
mid-session, membership revoked mid-session, forged envelope, out-of-order arrival, and an unreachable
owner who stays the owner.

**SCOPE, stated rather than blurred: same-host, multi-process socket testing.** No independent physical
host participated, so nothing here validates NAT, packet loss, half-open connections or genuinely
independent clocks.

## The founding clean-host recovery (B7, 4 specimens)

A disposable Ciph was populated from the REAL modules (missions, `ciph_observations`, federation nodes,
transport keys, an authority domain, a permit generation), backed up and manifested, and then **its
installation directory was deleted**. Recovery material was kept outside it.

```text
copy without authorization                       REFUSED
valid candidate, no enforceable fence           RECOVERY_ACTIVATION_HOLD
fenced candidate, through the real engine       ACTIVATED   (last_proven_restore recorded)
sovereign identity + vault reference            unchanged across host destruction
canonical mission history                       preserved
transport sessions, armed destruction timer     NOT revived
clone of the same bytes                          standing NONE, no proven restore
```

Fencing has teeth: after it, the superseded credential is refused BY THE TRANSPORT BOUNDARY, including a
session opened before the revocation — refused on its next envelope.

## Recovery-generation fencing at the EXECUTION boundary

This is the phase's sharpest result, and it came from the final check rather than from design.

The permit store ALREADY refused permits minted under a superseded authorization epoch — but it compared
against a **caller-supplied** epoch. A stale instance could present its own epoch, pass the comparison,
and claim after supersession: a fence made of the prisoner's testimony. Measured, then closed inside
4.0's own owner module:

```text
stale caller-supplied epoch        -> DENY_PERMIT_AUTHORIZATION_EPOCH_NOT_AUTHORITATIVE
epoch parameter omitted            -> DENY_PERMIT_AUTHORIZATION_EPOCH_MISMATCH (store's own epoch used)
non-superseding generation         -> DENY_AUTHORITY_EPOCH_NOT_SUPERSEDING
superseded permit                  -> REVOKED, reason AUTHORIZATION_EPOCH_SUPERSEDED, history intact
successor at the new epoch         -> claims normally
```

No second executor and no competing permit constitution: the write lives in `permit_store.py`, and the
five sealed 4.0 permit suites are green beside the six new specimens (89 tests).

### The boundary this DOES NOT cross — stated, not implied

Local fencing is PROVEN: within a node whose store has recorded the supersession, no caller can talk the
boundary back into the old epoch. **Global fencing against an ISOLATED, STALE HOST is NOT proven and is
not claimed.** A host that never received the supersession still holds a local store whose authoritative
epoch is unset, so its own local boundary would admit its own permit. What stops it is the rest of the
constitution rather than local state: revoked transport credentials (proven), no authority-domain
ownership (7.x, proven), and R7 as the sole activation path. A deployment that gives a superseded host
continued local execution authority would defeat recovery fencing, and this seal says so plainly instead
of implying otherwise.

## Catastrophic matrix — coverage and the two mandatory negatives

```text
host/runtime destruction ......... B7 (destroyed installation, restored into a clean host)
corrupted / incomplete backup .... CORRUPTED vs INCOMPLETE distinguished; refused before activation
tampered manifest ................ MANIFEST_TAMPERED (a changed requirement IS the digest)
missing root material ............ UNRECOVERABLE, no invented identity, no fallback
historical insecure backup ....... INSECURE_HISTORICAL, never approved
stale-but-valid backup ........... reconstitution refuses stale ownership; orphaned domains reported
competing candidates ............. one authorization per (identity, candidate, environment, scope) + generations
unfenced previous instance ....... RECOVERY_ACTIVATION_HOLD (produced from a VALID backup)
unauthorized clone ............... standing NONE, no path to activation
stale permit ..................... refused at the execution boundary (see above)
stale federation ownership ....... refused; governed transfer is the only way back
peers ahead in epochs ............ evidence reconciles, authority does not
revoked credentials .............. refused on open and mid-session
unsupported migration ............ UNSUPPORTED_TRANSITION, no partial activation
armed historical dead-man state ... reported, left disarmed
network interruption / duplicate ... transport specimens
model/provider loss ............... substitution records identity unchanged, capabilities NOT carried
secret-local replication .......... REFUSED_CLASS by the 7.2 classification
canonical history conflict ........ INTEGRITY_CONFLICT, surfaced not merged
```

**The two negatives are successful outcomes, not defects**: `UNRECOVERABLE` (indispensable material
absent, nothing invented) and `RECOVERY_ACTIVATION_HOLD` (a valid candidate whose predecessor cannot be
conclusively fenced).

## Measured results

```text
full project sweep            Ran 1818 tests in 1664.914s   OK   (frozen tree 6b37f387dcfdd99a96e94d29d3c1a465,
                              digest identical before and after)
sanitized clone sweep         Ran 1818 tests in 1185.217s   OK   (176/176 test files, no ambient vault,
                              no key material)
scanner censuses (both trees) 8.x 16 zero · 7.x 16 zero · 6.x 12 zero · 5.x 12 zero · 4.7 12 zero
ownership censuses            R12 19 clean · R11 19 clean · R10 0 · R6 0 · R7 0 · no duplicate owners
live vault                    VAULT-0E79C7AFD84940BB / VAULT_ID_V1, 4 protected rows decrypt,
                              live_permitless = 0, integrity_check ok, no recovery artifacts
```

## Claim to evidence

| Claim | Evidence |
| --- | --- |
| R12 backup finding remediated | `test_the_legacy_backup_entry_point_refuses_its_own_configuration`, `..._refuses_root_material_and_weak_passphrases` |
| R12 destruction finding remediated | `test_an_armed_dead_man_state_does_not_survive_recovery` |
| Authenticated transport | `test_gate_8_1_real_transport_torture` (12 specimens, real sockets) |
| Recovery engine + authorization | `test_gate_8_5_recovery_engine_and_matrix` (16 specimens) |
| Founding destroy-and-restore | `test_gate_8_6_founding_clean_host_recovery` (4 specimens) |
| Execution-boundary fencing | `test_gate_8_9_recovery_generation_fencing` (6 specimens) |
| Clone vs restoration | `test_a_clone_of_the_same_material_never_activates` |
| UNRECOVERABLE | `test_missing_root_material_is_unrecoverable_and_invents_nothing` |
| RECOVERY_ACTIVATION_HOLD | `test_a_valid_candidate_without_enforceable_fencing_is_held` |
| Reconstitution refuses stale authority | `test_reconstitution_refuses_stale_authority_and_reconciles_evidence` |
| Portability / model substitution | `test_host_and_path_change_do_not_change_identity`, `test_model_substitution_...` |
| Migration lineage | `test_migration_lineage_is_ordered_checked_and_fail_closed` |
| LAST_PROVEN_RESTORE | `test_monitoring_reports_proven_restore_separately_from_backups` |

## Remaining limitations (stated)

- **Same-host socket testing.** No independent physical hosts; no NAT, loss, or independent clocks.
- **Global fencing across an isolated stale host is not proven** (see above). It rests on revoked
  credentials, absent domain ownership and R7, not on the stale host's local state.
- **Lazy invalidation.** A superseded permit reads `ISSUED` until presented; the refusal happens at the
  boundary, which is where it would otherwise have had an effect.
- **Root custody is operator-held and offline.** Absence of that material yields UNRECOVERABLE rather
  than a distributed key scheme; how to distribute root custody safely is deliberately unsolved here.
- **Scanners are static and syntactic**, with catalogue modules excluded by suffix rule; several
  scanners are presence checks and cannot see a semantically wrong implementation, only a missing one.
- **No production recovery history exists**, so the live check confirms absence rather than exercising a
  read path. Nothing was written to production to make the table look complete.

## The seal decision

Every claim above is backed by a specimen, a measured run, or a measured structural invariant, on the
frozen tree `6b37f387`. One criterion is deliberately scoped rather than blanket-claimed, and the
scoping is the seal's honest edge:

```text
LOCAL execution-boundary fencing (a node whose store recorded the supersession)   PROVEN
GLOBAL fencing against an ISOLATED STALE HOST                                    NOT CLAIMED
    -> what stops such a host is revoked transport credentials (proven), absent
       authority-domain ownership (7.x, proven) and R7 as the sole activation path (proven),
       NOT its local state. A deployment that grants a superseded host continued local
       execution authority would defeat recovery fencing - and this seal says so.
```

```text
R12 CLOSED

CIPH 8.x — SOVEREIGNTY & RECOVERY
SEALED
```

**Ciph survives the loss of its machine without allowing a copy of its machine to become Ciph by
accident.**
