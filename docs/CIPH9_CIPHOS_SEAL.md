# CIPH 9.x — CIPHOS

**Status:** IMPLEMENTATION COMPLETE · FULL SOURCE-TREE VERIFICATION GREEN · SANITIZED CLONE
VERIFICATION GREEN · **FINAL SEAL: HOLD — PRIVILEGED-HOST PROOFS OUTSTANDING**.

```text
The operating environment hosts Ciph. It does not become Ciph's authority.

Boot != activation.  Process running != authorized.  Root privileges != constitutional permission.
Service readiness != constitutional readiness.  File ownership != sovereign identity.
Model availability != verified capability.  OS supervision != execution authority.
Update installed != update constitutionally promoted.
```

## Measured verification (this campaign)

```text
frozen tree         265ce3401cf823d2a9b9e0a208ff7634   (identical before and after the sweep)
full project sweep  Ran 1845 tests in 1438.197s   OK    (178 test files)
sanitized clone     Ran 1845 tests in 1065.885s   OK    (178/178 test files, 0 ambient dbs, 0 keys)
scanner censuses    86 of 86 zeros in BOTH trees
                    9.x 18 · 8.x 16 · 7.x 16 · 6.x 12 · 5.x 12 · 4.7 12
ownership censuses  R13 11 clean · R12 19 clean · R11 19 clean · R10 0 (0 dormant)
                    R6 0 (0 missing) · R7 0 primitives (0 bypasses) · no duplicate canonical owners
live vault          VAULT-0E79C7AFD84940BB / VAULT_ID_V1 · 4 protected rows decrypt ·
                    live_permitless = 0 · integrity ok · md5 unchanged (b4157b45f02f418bd4923bc085e07855)
                    ZERO 8.x/9.x artifacts in production; no leftover test units
host package        exit 2 (fail-closed) · 0 passed · 15 skipped, every skip naming its prerequisite
                    no destructive operations (read-only probes only)
```

Test discovery matched exactly between the real tree and the clone (1845 both), so there is no difference
to explain.

**Process note, recorded rather than hidden:** the FIRST full sweep of this campaign reported 1845 OK, but
the tree digest changed during it — because *this campaign edited `tools/ciphos_host_verification.py`* while
that run was in flight. The measurement was therefore discarded and re-run on the frozen tree, digest
verified identical before and after. A run whose tree moved is not evidence.

## What 9.x built (on top of 4.x–8.x; no second executor, operator authority, recovery system or
deployment authority)

| Phase | Module | Frozen identity |
| --- | --- | --- |
| 9.0/9.1/9.2/9.3 | `environment_boot.py` | `BOOT_CONSTITUTION_V1`, `SERVICE_IDENTITY_V1`, `ENVIRONMENT_CAPABILITIES_V1` |
| 9.4/9.5 | `environment_operator.py` | `OPERATOR_CONTROL_PLANE_V1`, `EGRESS_POLICY_V1`, `ISOLATED_HOST_EFFECT_BOUNDARY_V1` |
| 9.6–9.9 | `environment_runtime.py` | `ENVIRONMENT_STORAGE_V1`, `MODEL_RUNTIME_V1`, `ENVIRONMENT_UPDATE_V1`, `CIPHOS_IMAGE_V1`, `PRIVILEGED_HOST_PROFILE_V1` |
| C1 | `environment_scanners.py` | the eighteen CiphOS structural zeros |
| C | `tools/ciphos_host_verification.py` | 15 privileged-host cases, fail-closed |

**27 user-scope specimens green** (10 for 9.0–9.3, 17 for 9.4–9.9 incl. the 18 scanner catch-specimens),
including: boot granting nothing; four forged authorizations refused and terminal per boot; a REAL
`systemd --user` service started, SIGKILLed and restarted with a new MainPID; a mode-000 secret refused to
its own owner; symlink escape refused; scrubbed worker environment; escalation unreachable; operator
refusals per reason with replayed-generation and ambient-forgery refusal; a service unable to
self-authorize *with the refusal audited*; deny-by-default egress; a snapshot refused as authority; **real
kernel `setrlimit` enforcement**; the full update lifecycle with rollback landing in a NEW state; and a
guard that refuses to report a user-scope run as system-scope.

## What remains — the exact outstanding host tests

`tools/ciphos_host_verification.py --list` reports 15 cases; **13–15 are
`SKIPPED_UNAVAILABLE_PREREQUISITE`** on this host (uid 1001, no sudo, `/etc` unwritable, no usable
namespaces or hypervisor):

```text
system install · service identity · cross-user restriction · escalation refusal (system scope)
namespace/sandbox enforcement in effect · worker vault access · KERNEL egress denial
real boot without authority · operator activation on an installed CiphOS
restart/recovery on system units · disconnected stale host with netns
update/rollback on an installed system · clean-install reproducibility
destroyed-host recovery · the C3 end-to-end torture
```

Run them with:

```bash
python3 tools/ciphos_host_verification.py --run --json     # exit 0 = measured, 2 = prerequisites missing
```

## Standing limitations (unchanged and still load-bearing)

- **Local OS-integrity checks are not hardware-backed attestation.** No TPM/UEFI measured boot was
  implemented or tested, and none is claimed. TPM/UEFI remains outside V1 unless actually included.
- **Same-host multi-process socket testing**, not independent physical hosts (8.x transport).
- **Resource-enforced revocation vs disconnected local physical control**: externally governed effects are
  refusable by the resource; a physically unreachable host that still holds the means keeps producing
  local effects. That is reported as *residual physical control*, never as a proven guarantee.
- **A reproducible installer/VM image is not a new kernel.** CiphOS is a hardened Linux environment, not
  a kernel, and this seal says so.
- **Egress is policy-layer here, not kernel-enforced**; a real connection in this environment SUCCEEDS, and
  the package exists to measure the difference on a capable host.
- Node-local fencing is proven (8.x); global fencing against an isolated stale host is not, and cannot be.

```text
CIPH 9.x — IMPLEMENTATION COMPLETE
FULL SOURCE-TREE VERIFICATION — GREEN
SANITIZED CLONE VERIFICATION — GREEN
FINAL SEAL — HOLD: PRIVILEGED-HOST PROOFS OUTSTANDING
```

Release candidate preserved as the frozen tree `265ce3401cf823d2a9b9e0a208ff7634` plus the executable
host-verification package, for testing on a separate, disposable, root-controlled Linux VM.
