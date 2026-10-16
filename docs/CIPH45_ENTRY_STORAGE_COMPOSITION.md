# 4.5 ENTRY — Production Storage Composition

**Goal:** the runtime, 4.2 epistemics, 4.3 world/self model and 4.4 curiosity must inhabit **one**
runtime-shaped vault with no schema-ownership ambiguity. Until that holds, the Crucible must not write
its own durable records.

**Modules:** `ciph/kernel/schema_ownership.py` — `test_gate_4_5_storage_composition.py`, 11 specimens.

**Status: SEALED.** Code, production-shaped proof, and the live migration are all complete; R5 is
closed.

## Why this gate exists

R4 was found the hard way: two subsystems declared `ciph_observations` with different shapes and
`CREATE TABLE IF NOT EXISTS`, so whichever initialized first silently won. They were mutually
exclusive in one database:

```
runtime first   ledger INSERT refused:    table ciph_observations has no column named source_ref
ledger first    runtime refused to start: no such column: subject
```

The rename fixed ownership for newly created databases. A rename is not a guarantee, so this gate makes
the guarantee structural and then checks what production actually contains.

## 1. Schema ownership scanner

Every `CREATE TABLE` in the production tree is parsed, and a table's canonical identity is its
**ordered column set**, not its name:

```
TableDeclaration(table, owner, columns, fingerprint)
scan_project()                         every declaration, root modules included, tests excluded
duplicate_canonical_table_owners()     names with two or more INCOMPATIBLE shapes
classify_live_table(db, table)         which declared shape a LIVE table actually has
migrate_legacy_observations(...)       the one verified migration
```

Result on the project as it stands:

```
declared tables                     97
duplicate canonical table owners    0
```

Re-declaring a table with the **same** column set (the ordinary repeated `IF NOT EXISTS` idiom) is
compatible and not reported. A different column set for one name is always reported.

Two parser properties are themselves specimens, because a scanner that invents tables is worse than no
scanner:

```
prose mentioning `CREATE TABLE IF NOT EXISTS`   -> no declaration (there is no column list)
template placeholders {HEADER_TABLE}            -> recorded verbatim, so those tables stay covered
```

The first was a real defect during development: folding the optional `IF NOT EXISTS` into the name
capture let the regex backtrack onto the word `IF` and invent a table called `if`.

## 2. The integration matrix

Four initialization orders, then a restart in a different order, all on runtime-shaped temporary
vaults:

```
A  runtime  -> ledger -> world -> curiosity
B  ledger   -> runtime -> world -> curiosity
C  world    -> runtime -> ledger -> curiosity
D  curiosity-> runtime -> ledger -> world
   restart:  curiosity -> world -> ledger -> runtime
```

Each order must end with the same ownership:

```
ciph_observations columns == the ledger's canonical six
a ledger observation write succeeds
the world digest projects
the uncertainty registry derives
a CiphRuntime constructs
```

## 3. Classification by fingerprint, not by name

`classify_live_table` reports, against **every** declaration in the project, one of:

```
EXACT           identical column order
EXTENDS         the declared shape is the live table's prefix, with extra TRAILING columns
INCOMPATIBLE    anything else
```

`EXTENDS` exists because production is not a clean declaration. The live observation table carries the
legacy 16 columns **plus two added by an upgrade**, so an exact-match classifier recognized it as
nobody's table — and then migrated nothing. Cross-name matching matters for the same reason: the
production question is not "is this the ledger's table?" but "which declared shape does this live table
actually have?".

## 4. The read-only live-vault preflight

```
live ciph_observations            18 columns
                                  legacy MaterializedWorldview shape (16)
                                  + canonical_payload, revision_event_id (additive upgrade)
live ciph_mv_observations         does not exist
classified owner                  ciph/memory/materialized_views.py, relation EXTENDS
```

So production **does** hold the pre-migration shape, and the ledger cannot write to that vault today.

## 5. The migration, proven on a production-shaped snapshot

Never a raw copy of a WAL database — a `sqlite3` backup snapshot of the live vault:

```
snapshot classified          legacy owner, EXTENDS
BEGIN IMMEDIATE
verify exact expected fingerprint                 (refuses a mismatch, changes nothing)
verify destination does not already exist         (refuses rather than overwrite)
ALTER TABLE ciph_observations RENAME TO ciph_mv_observations
verify row count identical
verify full-content digest identical
let the LEDGER create its canonical ciph_observations
COMMIT

result                       rows 0 -> 0, content digest unchanged
                             ciph_mv_observations preserved, 18 columns
                             ciph_observations now the ledger's 6 columns
                             ledger write succeeds; uncertainty registry runs; CiphRuntime starts
```

There is no `DROP TABLE`, and `CREATE TABLE IF NOT EXISTS` is never allowed to decide ownership.

## 6. Verification

```
ENTRY suite                        11 specimens, green            (Ran 11, OK)
full project suite                 1447 tests, green             (+11 on the 1436 before this pass)
sanitized read-only clone          1447 tests, green; no ambient .db created in the clone
project-wide ownership scan        97 declared tables, 0 duplicate canonical owners
production-shaped snapshot         migrated and verified (rows, content digest, ledger write,
                                   uncertainty registry, CiphRuntime)
live vault                         UNCHANGED - opened strictly read-only (header check and a
                                   sqlite3 backup snapshot); still holds the legacy 18-column
                                   ciph_observations and no ciph_mv_observations
```

## 7. The live migration (applied)

```
1  SIGTERM the resident ciph_evolution.py --daemon   process gone in 2s, pid file removed
   verify no remaining writer                        no other ciph writer held the vault
2  SQLite Backup API backup, before any mutation
   ciph_backups/pre_r5_migration_20261009T202844.db   49,790,976 bytes
3  re-classify the LIVE fingerprint immediately before migrating
   eab8231e70528c6b2fb525c2e5089133a19e01272c67282ed55e2f6de4583462
   = the exact fingerprint the migration specimen proved   -> no abort
4  migrate (BEGIN IMMEDIATE, verify, rename, verify content, let the ledger claim the name, COMMIT)
   rows 0 -> 0, content digest unchanged
```

### Post-migration invariants, measured on the live vault

```
ciph_mv_observations         18 columns, owner ciph/memory/materialized_views.py (EXTENDS)
ciph_observations            6 columns,  owner ciph/kernel/epistemic_ledger.py (EXACT)
duplicate canonical owners   0
4.2 ledger reconstructs      yes (read-only; the live ledger is empty, 0 propositions)
4.3 / 4.4 projections        yes (full set, on a post-migration snapshot)
runtime starts               yes
vault identity               VAULT-0E79C7AFD84940BB / VAULT_ID_V1, unchanged
protected rows               all 4 decrypt
live_permitless              0, s3_gate_satisfied True
backup                       still serves the exact PRE-migration state (fingerprint match)
```

### The write-path proof, and why it is split

The 4.3 world projection **registers entities** as part of projecting, so a "read-only" run of the full
4.3/4.4 stack against production would write. That would confuse *testing the machinery* with *creating
production epistemic history*, so the proof is split deliberately:

```
live vault,       rollback-only probe: BEGIN IMMEDIATE, insert one canonical observation, verify the
                  row count, ROLLBACK -> rows 0 -> 1 -> 0, content identical, nothing persisted.
                  Proves the live table accepts the canonical write shape.
live vault,       read/reconstruction proof: 4.2 reconstructs read-only.
post-migration    write path + full 4.2/4.3/4.4 projection set + runtime coexistence.
snapshot
```

No fake evidence was appended and later deleted. The ledger API opens its own connection and commits,
so a caller-controlled rollback cannot span it; rather than invent a cleanup mechanism to make a
stronger claim, the write path is proven on the snapshot and the real vault is proven read-only.

### Daemon restart

The daemon was restarted on current code. It writes its pid file, then exits immediately at its own loop
guard because `CURIOSITY_DAEMON_ENABLED` is not `"1"` in the live vault:

```python
while vault.get_config("CURIOSITY_DAEMON_ENABLED") == "1":
```

So the daemon is **disabled by configuration**, not unhealthy. The restart exercised its startup path
against the migrated vault; flipping a production enable flag is the operator's call, so it was left
alone. A stale `curiosity_daemon.pid` remains from that clean exit.
