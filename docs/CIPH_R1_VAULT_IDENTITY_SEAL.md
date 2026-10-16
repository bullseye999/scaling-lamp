# R1 SEAL — path-independent vault identity

Status: **SEALED and APPLIED to the live vault.**

## The principle

> A vault's cryptographic identity must survive moving the vault, and must not be forgeable by editing
> its location metadata.

## What changed

```
LEGACY      sha256(machine_seed + db_path_string + salt)              -> KEK_v0
MIGRATED    root secret -> header-authentication key                  (own domain separator)
            authenticated header: vault_id, vault_schema_version, key_derivation_version
            sha256(root secret + "…V1|" + vault_id)                   -> KEK_v1
```

The header is MAC'd with a key derived from the **root secret alone**, so `vault_id` is verified
*without first acting upon it* — no circularity — and a header edit cannot authenticate itself.

## The downgrade law

```
header says VAULT_ID_V1 and v1 derivation fails
    -> HARD FAILURE
    -> never a legacy fallback
```

There is no `try v1 except -> v0` anywhere in the process. A damaged or tampered v1 header fails
closed instead of silently becoming a downgrade path.

## The migration

`ciph.kernel.vault_identity.migrate_vault` does the whole thing inside **one `BEGIN IMMEDIATE`**:

```
1. precondition  every protected row READ under its legacy identity, or refuse (nothing is touched)
2. rewrap        each row encrypted under KEK_v1 into a shadow representation
3. proof         decrypt legacy -> A, decrypt new -> B, assert A == B byte-for-byte, EVERY row
4. flip          install the v1 rows as primary AND write key_derivation_version=VAULT_ID_V1
5. commit        representation and declaration can never disagree
```

A crash before the commit leaves the **legacy representation authoritative and no shadow rows at
all** — there is no window with two plausible identities — and re-running completes the migration.
A crash after the commit leaves v1 authoritative. Both are specimens
(`test_gate_r1_vault_identity.py`, 13 cases), including the tampered-header, wrong-`vault_id`,
unknown-version, damage-after-migration and never-decrypted-precondition cases.

## The live migration record

```
backup        /tmp/ciph_vault_backup_r1_20261008_194936  (SQLite backup semantics; vault is in WAL)
vault_id      VAULT-0E79C7AFD84940BB
header        vault_schema_version=1  key_derivation_version=VAULT_ID_V1  (MAC verified)
rows          4 rewrapped, 4 verified byte-identical
verify        all rows decrypt under KEK_v1; KEK_v0 is no longer the current key
```

Per-row provenance, which is where the real work was:

```
execution_authority_primary   PATH_V0:ciph_vault.db   (encrypted 2026-10-04, path-derived)
kernel_primary                PLAINTEXT_LEGACY        (stored as BARE HEX since 2026-09-03)
operator_root                 PLAINTEXT_LEGACY
worker_primary                PLAINTEXT_LEGACY
```

### Three findings the migration exposed

1. **The vault held rows under more than one legacy identity.** One row was encrypted under a
   relative-path KEK while three were stored as bare hex. A migration that assumed a single legacy
   identity would have failed its own precondition — `read_row_plaintext` now enumerates the legacy
   spellings and reports which one each row matched.
2. **Three private keys were never encrypted at all** (operator, kernel and worker, since 2026-09-03).
   This migration therefore does more than rewrap: it encrypts them for the first time
   (`plaintext_rows_now_encrypted: 3`).
3. **The vault is in WAL mode.** Backups for a migration must use SQLite's backup API; a raw main-file
   copy while the WAL is active is not a consistent snapshot.

## Portability proof

```
same vault at relative / absolute / dot-relative / roundabout / renamed / copied path
    -> the SAME execution-authority key decrypts        (specimen + live check)

root secret + a different vault_id
    -> cannot decrypt, and no fallback                 (specimen)

tampered vault_id / version / schema in the header
    -> authentication failure                          (specimen)

crash during rewrap   -> legacy authoritative, no shadow rows, resumable
crash after the flip  -> v1 authoritative, second migration is a no-op
post-migration legacy fallback -> impossible
```

And the live demonstration of the original defect being fixed: the governed smoke against the vault at
its **absolute** path used to fail with `InvalidTag`; it now **PASSES** (permit carried, claim
attributed, receipt naming the exact attempt).

## Boundary (unchanged by this seal)

The root secret is still machine-local (`/etc/machine-id` when present). This makes a vault independent
of its **path**, not of its **machine**. Multi-machine portability, federation and CiphOS relocation
need a key-custody decision of their own, and this seal deliberately does not pretend to make one.
