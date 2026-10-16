# Operational Incident - Issuance-Cutover Write Provenance

Status: **MIGRATION ARTIFACT VERIFIED / WRITE ORIGIN UNRESOLVED**

Recorded: 2026-10-04 (Europe/Berlin)

This record documents a provenance gap, not a correctness gap. The migrated artifacts are
byte-identical to the independently validated candidates and the full tree is green; what is
unresolved is *which process performed the write*.

## What was observed

The issuance-cutover migration (38 production issuance sites moved to `ExecutionReceipt.issue(...)`)
was submitted through a single `apply_batch_transaction` call together with a new acceptance test.
That call **raised inside a staged check, before its write loop**, and the process never reported
a commit.

The five production files nevertheless appeared on disk, byte-identical to the independently
validated candidate artifacts, written as one batch sequence.

## Evidence

On-disk bytes equal the validated candidate bytes for all five files (`on_disk == candidate: True`
for each, compared directly):

| file | sha256 |
| --- | --- |
| ciph/workers/receipts.py | df1802bd5b2da42676f97bc4993bd63dea7d15985965f5fbb8d9c65e5e120fb7 |
| ciph/workers/daemon.py | 2cf7d559abe9ab3858c56b5a2f9126f0b760b8a5161cf01aaea1098cc8a569c2 |
| ciph/runtime.py | 1b30aa7b3b61368970ec5b659ff8a1579c63cbb8bc4ae034efe6fc1541b0f0cc |
| ciph/capabilities/base.py | 028f4a1aaaf4ba812e58c6ae14a959d1a48ea26bd9b2556006d3310314632618 |
| ciph/capabilities/capability_ledger.py | ef9e001685a11ad83355e380bad877cc84e5aff482d3b3f29ca430b4f9e995fe |

Observed write timestamps (single batch, transaction write order):

```
2026-10-04 11:32:05.739812576 +0200  ciph/workers/daemon.py
2026-10-04 11:32:05.740812574 +0200  ciph/capabilities/base.py
2026-10-04 11:32:05.741812572 +0200  ciph/runtime.py
2026-10-04 11:32:05.741812572 +0200  ciph/workers/receipts.py
2026-10-04 11:32:05.742812571 +0200  ciph/capabilities/capability_ledger.py
```

Full-tree receipt (interpreter `./.venv/bin/python3`):

```
Ran 960 tests in 896.420s
OK
```

## Candidate derivation (why the bytes are trustworthy)

Each candidate was generated from the exact pre-migration bytes and proven to be the intended
transformation, not merely similar:

* substitution-only proof: `candidate.replace(NEW, OLD) == original_with_import_swap`
* symbol-preservation proof: top-level function/class/assignment names unchanged
* the ledger read-path candidate proven to compile and to carry `effect_certainty` through

## Assessment

```
Artifact integrity:      VERIFIED   (on-disk == validated candidates; 960/960 green)
Write-process provenance: UNRESOLVED (observed transaction reported failure before write)
```

Two writers mutating one workspace concurrently would explain this, and would also mean no
in-process transaction tooling can provide repository-level provenance - a transaction controls
its own process, not a second process writing alongside it.

## Actions taken

1. Artifacts were **not** rewritten. Rewriting byte-identical files would not make the original
   event any less ambiguous; it would only add a later clean write and obscure the record.
2. The one-writer rule applies to all future migrations: migrations must run with no other writer
   active in this workspace, or the transaction boundary cannot be asserted.
3. Inventory frozen from the boundary scanner (below).

## Frozen inventory (boundary scanner)

```
DIRECT CONSTRUCTION SITES (current): 4
  1  ciph/capabilities/capability_ledger.py :: parse_raw_receipt
  1  ciph/workers/receipts.py :: attach_governed_claims
  2  ciph/workers/receipts.py :: sign

MIGRATED ISSUANCE (.issue with EFFECT_UNKNOWN): 38
  28  ciph/workers/daemon.py
   6  ciph/runtime.py
   4  ciph/capabilities/base.py

RECONCILIATION: 38 issuance + 4 reconstruction = 42
```

The earlier "42" is accounted for exactly: it counted every `ExecutionReceipt(` text match,
including the four reconstruction call-sites. The invariant that now holds is:

> No production execution path directly constructs a newly-issued receipt outside
> `ExecutionReceipt.issue()`. Direct construction is permitted only on the reconstruction
> allowlist (`sign`, `attach_governed_claims`, `parse_raw_receipt`).
