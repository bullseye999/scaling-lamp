# Phase 3 remediation and verification checkpoint

Updated: 2026-09-05T14:45:26+02:00

Status: **REMEDIATED & VERIFIED**. Phase 1/2 tests remain passing. Phase 4 is the next planned milestone.

## Final verification

| Environment | Full discovery | Duration | Governance matrix | Compilation |
| --- | --- | --- | --- | --- |
| venv | 280/280 | 150.796s | 16/16 | PASS |
| ciph_env | 280/280 | 119.105s | 16/16 | PASS |

No failures, errors, or skipped tests. Full discovery includes 46 Phase 1 tests,
36 Phase 2 tests, 52 Gate Zero tests, and 40 Phase 3 tests (10 worker/recovery
checks plus 30 new adversarial and integration regressions).

Runs used separate temporary working directories and databases. The matrix used
its deterministic isolated mode, without external capability backends. Compilation
covered the repository with bytecode redirected under the verification directories.

- [.venv verification artifacts](/tmp/ciph-phase3-final-venv-du2sx03k)
- [ciph_env verification artifacts](/tmp/ciph-phase3-final-ciph_env-n4f9ngdi)
- [Permanent Phase 3 adversarial suite](test_phase3_adversarial_recovery.py)
- [Worker/recovery suite](test_phase3_worker_daemons_and_crash_recovery.py)

## Authority and retry changes

- Leasing and dispatch never mint replacement tokens. A fresh token is created only
  within the transaction committing an authenticated read-only execution failure.
- The coordinator verifies the parent token, active KERNEL signing authority, consumed
  token/nonce ownership, worker attribution, signed input and attempt evidence, and
  the remaining attempt budget. The public signing primitive cannot fetch private
  authority from a caller-provided database.
- Renewal preserves the original execution fields and expiry. The signed nonce binds
  parent authority, job ID and retry budget position; durable lineage binds the token
  to that job. Cross-job replay, stolen child tokens, missing lineage, tampered inputs,
  and retired signing authority fail closed.
- Unused tokens survive pre-execution lease crashes without being renewed. Every lease
  permits only one activation. Failures with possible side effects require reconciliation
  instead of automatic replay.

## Durable evidence and recovery changes

- Reconciliation-required transitions verify the current unexpired EXECUTING lease,
  worker signature, job/input/attempt bindings, and sample time after BEGIN IMMEDIATE.
  Terminal jobs, foreign workers, stale owners and forged receipts cannot be overwritten.
- The full signed execution receipt is retained in pending_receipt and the audit event
  in one transaction. Event-write failure rolls the transition back; the job stays
  in-flight until lease expiry requires reconciliation. It is never blindly retried.
- Storage failures and exceptions after execution return explicit non-success receipts.
  Fresh success publication uses the same authenticated terminal evidence verifier as
  replay, including the complete EventStore chain. No verified claim is published from
  an uncommitted receipt.
- Success telemetry counts committed executions. Counter updates are protected against
  concurrent workers.

## Threading and network changes

- Stable audit hooks enforce policy without replacing socket constructors. Thread.start,
  low-level thread starts, and ThreadPoolExecutor submission propagate restrictions.
- Helper restrictions survive parent-scope exit and cannot be relaxed by a nested policy.
  Reusable pool workers restore task context, including workers first started inside a
  restricted submission. Local/Tor policies also reject external DNS and datagram bypasses.
- The heartbeat regression establishes running state before starting the watchdog and
  asserts actual sweeps. Tests include an uncaught worker-thread exit and actual process
  kills before execution and after an in-flight side-effect marker.
- These are interpreter-level guards for supported execution paths. They are not a claim
  of OS isolation against arbitrary hostile Python/native code; process/container isolation
  remains a separate blueprint boundary.

## Related integration fixes

- Ordinary EventStore writers acquire BEGIN IMMEDIATE before reading the chain head,
  preventing concurrent writers from forking the hash chain.
- Legacy runtime dispatch and DAG/compensation execution lease the submitted job rather
  than an unrelated older job. Legacy success/replay preserves one authenticated receipt
  event and no longer fabricates a receipt from a queue row.
- Idempotency lookup includes the signed attempt number; target normalization agrees with
  capability receipts. Unsigned legacy failure cannot bypass governed receipt ingress.
- Hot-reload subprocess imports resolve from the source location, independently of cwd.
  The code-audit test uses an explicit fixture path.

## Re-run

From the project directory:

```bash
./.venv/bin/python -B -m unittest discover -s . -p 'test_*.py'
./ciph_env/bin/python -B -m unittest discover -s . -p 'test_*.py'
./.venv/bin/python -B -m unittest test_phase3_worker_daemons_and_crash_recovery test_phase3_adversarial_recovery -v
```

Changes remain local and unstaged. Pre-edit source snapshots are retained at
`/tmp/ciph-p3-before-u5hxdqgp` for review.
