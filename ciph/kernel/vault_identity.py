"""
ciph.kernel.vault_identity - a vault's cryptographic identity, independent of where it lives.

R1. The key-encryption key protecting private key material used to be derived from the vault's PATH:

    LEGACY   sha256(machine_seed + db_path_string + salt) -> KEK_v0

so the same file opened by a different path string - relative vs absolute, renamed, copied, restored -
produced a different key and every protected row failed to decrypt. A path answers "where is the
vault". It must not answer "which vault is this".

    MIGRATED
        root secret -> header-authentication key                  (its own domain separator)
        authenticated header: vault_id, vault_schema_version, key_derivation_version
        root secret + vault_id + domain separation -> KEK_v1

There is no circularity: the header is authenticated with a key derived from the ROOT SECRET ALONE,
so `vault_id` is verified before it is used to derive anything. Editing the location metadata cannot
mint a vault identity, because the MAC cannot be produced without the root secret.

THE DOWNGRADE LAW
    the header says VAULT_ID_V1 and v1 derivation fails -> HARD FAILURE.
    Never a legacy fallback: a damaged or tampered v1 header must not silently become a downgrade.

WHAT IS OUT OF SCOPE
    The root secret is still machine-local (`/etc/machine-id` when present). This migration makes a
    vault independent of its PATH, not of its MACHINE. Multi-machine portability needs a key-custody
    decision of its own, and is deliberately not smuggled in here.
"""

import hashlib
import hmac
import os
import sqlite3
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

HEADER_TABLE = "ciph_vault_identity"
SHADOW_TABLE = "ciph_key_vault_v1"
KEY_VAULT_TABLE = "ciph_key_vault"

HEADER_ID = "PRIMARY"
VAULT_SCHEMA_VERSION = 1

KEY_DERIVATION_V0 = "PATH_V0"        # legacy; retained so a migration can read what it migrates
KEY_DERIVATION_V1 = "VAULT_ID_V1"

_DOMAIN_HEADER = b"CIPH_VAULT_HEADER_AUTH_V1"
_DOMAIN_ROW_V1 = b"CIPH_VAULT_ROW_PROTECTION_V1"
_LEGACY_SALT = b"CIPH_VAULT_KEK_V1_SALT_KEYPAIR_PROTECTION"

_SCHEMA = (
    f"""
    CREATE TABLE IF NOT EXISTS {HEADER_TABLE} (
        header_id TEXT PRIMARY KEY,
        vault_id TEXT NOT NULL,
        vault_schema_version INTEGER NOT NULL,
        key_derivation_version TEXT NOT NULL,
        header_mac TEXT NOT NULL,
        created_at REAL,
        migrated_at REAL
    );
    """,
    f"""
    CREATE TABLE IF NOT EXISTS {SHADOW_TABLE} (
        key_id TEXT PRIMARY KEY,
        private_key_hex_v1 TEXT NOT NULL,
        rewrapped_at REAL
    );
    """,
)


class VaultIdentityError(Exception):
    """A vault identity operation was refused. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


@dataclass(frozen=True)
class VaultHeader:
    vault_id: str
    vault_schema_version: int
    key_derivation_version: str
    created_at: Optional[float]
    migrated_at: Optional[float]


# ---------------------------------------------------------------------------- key derivation
def root_secret() -> bytes:
    """The machine-local root secret. Machine-scoped on purpose; see the module docstring."""
    seed = b"CIPH_LOCAL_KEY_VAULT"
    try:
        if os.path.exists("/etc/machine-id"):
            with open("/etc/machine-id", "rb") as handle:
                seed = handle.read().strip()
    except Exception:
        pass
    return seed


def header_auth_key(secret: Optional[bytes] = None) -> bytes:
    """Derived from the ROOT SECRET ALONE, so the header can be verified before vault_id is used."""
    return hashlib.sha256((secret or root_secret()) + _DOMAIN_HEADER).digest()


def row_kek_v0(db_path: str, secret: Optional[bytes] = None) -> bytes:
    """The legacy, path-derived KEK. Kept exactly as it was so the migration can read its input."""
    return hashlib.sha256((secret or root_secret()) + db_path.encode("utf-8") + _LEGACY_SALT).digest()


def row_kek_v1(vault_id: str, secret: Optional[bytes] = None) -> bytes:
    """The path-independent KEK. The vault's identity, not its location, selects the key."""
    return hashlib.sha256(
        (secret or root_secret()) + b"CIPH_VAULT_ROW_PROTECTION_V1|" + str(vault_id).encode("utf-8")
    ).digest()


def legacy_kek_candidates(db_path: str, secret: Optional[bytes] = None) -> Dict[str, bytes]:
    """
    Every legacy spelling this vault's rows could have been written under.

    A row's key was derived from whatever path STRING the writing process happened to use, so the same
    file can hold rows under several identities (`ciph_vault.db`, an absolute path, a realpath, a
    dot-relative form). A migration that assumed one spelling would fail its own precondition on a
    vault that is merely older, so the candidates are enumerated and each row reports the one it
    actually matched.
    """
    seen: Dict[str, bytes] = {}
    for spelling in (db_path, os.path.abspath(db_path), os.path.realpath(db_path),
                     os.path.join(".", db_path)):
        if spelling not in seen:
            seen[spelling] = row_kek_v0(spelling, secret)
    return seen


def read_row_plaintext(row: Dict[str, Any], *, db_path: str,
                       secret: Optional[bytes] = None) -> Tuple[bytes, str]:
    """
    The plaintext of ONE protected row, and WHERE it came from.

    Mirrors the runtime reader exactly - a migration precondition that disagrees with the reader is not
    a precondition. `ENC:` rows are decrypted under whichever legacy identity matches; anything else is
    legacy PLAINTEXT hex, which older code wrote and which this migration then genuinely encrypts.
    """
    ciphertext = str(row["private_key_hex"])
    if not ciphertext.startswith("ENC:"):
        return bytes.fromhex(ciphertext), "PLAINTEXT_LEGACY"
    for spelling, kek in legacy_kek_candidates(db_path, secret).items():
        try:
            return _decrypt(ciphertext, kek, row["key_id"]), f"PATH_V0:{spelling}"
        except Exception:
            continue
    raise VaultIdentityError(
        "MIGRATION_PRECONDITION_FAILED",
        f"{row['key_id']} does not decrypt under any legacy identity",
    )


def _header_canonical(vault_id: str, schema_version: int, derivation_version: str) -> bytes:
    return f"{vault_id}|{int(schema_version)}|{derivation_version}".encode("utf-8")


def _header_mac(vault_id: str, schema_version: int, derivation_version: str,
                secret: Optional[bytes] = None) -> str:
    return hmac.new(header_auth_key(secret),
                    _header_canonical(vault_id, schema_version, derivation_version),
                    hashlib.sha256).hexdigest()


# ---------------------------------------------------------------------------- header storage
def _connect(db_path: str, *, read_only: bool = False) -> sqlite3.Connection:
    if read_only:
        try:
            conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True, timeout=10.0)
            conn.row_factory = sqlite3.Row
            return conn
        except sqlite3.OperationalError:
            pass
    conn = sqlite3.connect(db_path, timeout=10.0)
    conn.row_factory = sqlite3.Row
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    for statement in _SCHEMA:
        conn.execute(statement)


def write_header(conn: sqlite3.Connection, *, vault_id: str, derivation_version: str,
                 secret: Optional[bytes] = None, created_at: Optional[float] = None,
                 migrated_at: Optional[float] = None) -> None:
    conn.execute(
        f"INSERT INTO {HEADER_TABLE} (header_id, vault_id, vault_schema_version, "
        "key_derivation_version, header_mac, created_at, migrated_at) VALUES (?,?,?,?,?,?,?) "
        "ON CONFLICT(header_id) DO UPDATE SET vault_id = excluded.vault_id, "
        "vault_schema_version = excluded.vault_schema_version, "
        "key_derivation_version = excluded.key_derivation_version, "
        "header_mac = excluded.header_mac, migrated_at = excluded.migrated_at;",
        (HEADER_ID, vault_id, VAULT_SCHEMA_VERSION, derivation_version,
         _header_mac(vault_id, VAULT_SCHEMA_VERSION, derivation_version, secret),
         created_at, migrated_at),
    )


def read_header(conn: sqlite3.Connection, secret: Optional[bytes] = None) -> Optional[VaultHeader]:
    """
    Read and VERIFY the vault header. A tampered header is a hard failure, not a missing one.
    """
    try:
        row = conn.execute(
            f"SELECT * FROM {HEADER_TABLE} WHERE header_id = ?;", (HEADER_ID,)
        ).fetchone()
    except sqlite3.Error:
        return None
    if row is None:
        return None
    expected = _header_mac(row["vault_id"], row["vault_schema_version"],
                           row["key_derivation_version"], secret)
    if not hmac.compare_digest(str(row["header_mac"]), expected):
        raise VaultIdentityError(
            "VAULT_HEADER_AUTHENTICATION_FAILED",
            "the vault identity header does not authenticate under this root secret",
        )
    version = str(row["key_derivation_version"])
    if version != KEY_DERIVATION_V1:
        raise VaultIdentityError("VAULT_KEY_DERIVATION_UNKNOWN", version)
    return VaultHeader(
        vault_id=str(row["vault_id"]),
        vault_schema_version=int(row["vault_schema_version"]),
        key_derivation_version=version,
        created_at=row["created_at"],
        migrated_at=row["migrated_at"],
    )


def derive_kek(db_path: str, *, conn: Optional[sqlite3.Connection] = None,
               secret: Optional[bytes] = None) -> bytes:
    """
    THE ONE decision about which key protects this vault's rows.

        no header            -> legacy path-derived KEK (a pre-migration vault keeps working)
        header VAULT_ID_V1   -> vault-id-derived KEK, and a failure here is FINAL
        anything else        -> refuse

    There is deliberately no `try v1 except -> v0` anywhere in this process.
    """
    owned = conn is None
    conn = _connect(db_path, read_only=True) if owned else conn
    try:
        header = read_header(conn, secret)
    finally:
        if owned:
            conn.close()
    if header is None:
        return row_kek_v0(db_path, secret)
    return row_kek_v1(header.vault_id, secret)


# ---------------------------------------------------------------------------- row crypto
def _encrypt(plaintext: bytes, key: bytes, key_id: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    return f"ENC:{nonce.hex()}:{AESGCM(key).encrypt(nonce, plaintext, key_id.encode('utf-8')).hex()}"


def _decrypt(ciphertext: str, key: bytes, key_id: str) -> bytes:
    if not ciphertext.startswith("ENC:"):
        raise VaultIdentityError(
            "VAULT_ROW_NOT_ENCRYPTED_UNDER_A_KEK", f"{key_id}:{str(ciphertext)[:12]}"
        )
    _, nonce_hex, ct_hex = ciphertext.split(":", 2)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    return AESGCM(key).decrypt(bytes.fromhex(nonce_hex), bytes.fromhex(ct_hex),
                               key_id.encode("utf-8"))


# ---------------------------------------------------------------------------- the migration
def protected_rows(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    try:
        return [dict(r) for r in conn.execute(
            f"SELECT key_id, private_key_hex FROM {KEY_VAULT_TABLE} ORDER BY key_id;")]
    except sqlite3.Error:
        return []


def migrate_vault(db_path: str, *, secret: Optional[bytes] = None,
                  now: Optional[float] = None, vault_id: Optional[str] = None,
                  inject_failure_after: Optional[int] = None) -> Dict[str, Any]:
    """
    Rewrap every protected row from the path-derived KEK to the vault-identity KEK, atomically.

    ONE transaction contains: header creation, per-row rewrap into the shadow representation, the
    byte-equality proof for every row, and the flip of `key_derivation_version`. A crash anywhere
    before the commit leaves the LEGACY representation authoritative and no shadow rows at all - there
    is no window in which two identities are both plausible. Re-running is idempotent.

    `inject_failure_after` exists so the crash specimen can prove that property from a real failure
    rather than from a promise.
    """
    moment = time.time() if now is None else float(now)
    conn = _connect(db_path)
    try:
        init_schema(conn)
        conn.execute("BEGIN IMMEDIATE")

        rows = protected_rows(conn)
        existing = conn.execute(
            f"SELECT * FROM {HEADER_TABLE} WHERE header_id = ?;", (HEADER_ID,)
        ).fetchone()

        if existing is None:
            identity = vault_id or f"VAULT-{uuid.uuid4().hex[:16].upper()}"
            write_header(conn, vault_id=identity, derivation_version=KEY_DERIVATION_V0,
                         secret=secret, created_at=moment)
        else:
            verified = read_header(conn, secret)
            identity = verified.vault_id
            if verified.key_derivation_version == KEY_DERIVATION_V1:
                conn.execute("COMMIT")
                return {"status": "ALREADY_MIGRATED", "vault_id": identity,
                        "rewrapped": 0, "verified": len(rows)}

        legacy_key = row_kek_v0(db_path, secret)
        new_key = row_kek_v1(identity, secret)

        # 1. PRECONDITION: every protected row must decrypt under the legacy identity, or we refuse to
        #    touch anything. A vault that is already inconsistent is not a migration candidate.
        plaintexts: Dict[str, bytes] = {}
        sources: Dict[str, str] = {}
        for row in rows:
            try:
                plaintext, source = read_row_plaintext(row, db_path=db_path, secret=secret)
            except VaultIdentityError:
                conn.execute("ROLLBACK")
                raise
            plaintexts[row["key_id"]] = plaintext
            sources[row["key_id"]] = source
        plaintext_rows = sum(1 for value in sources.values() if value == "PLAINTEXT_LEGACY")

        # 2. REWRAP into the shadow representation (still inside the same transaction).
        for index, row in enumerate(rows, start=1):
            if inject_failure_after is not None and index > inject_failure_after:
                raise VaultIdentityError("MIGRATION_INJECTED_FAILURE", f"after row {index - 1}")
            conn.execute(
                f"INSERT INTO {SHADOW_TABLE} (key_id, private_key_hex_v1, rewrapped_at) "
                "VALUES (?,?,?) ON CONFLICT(key_id) DO UPDATE SET "
                "private_key_hex_v1 = excluded.private_key_hex_v1, rewrapped_at = excluded.rewrapped_at;",
                (row["key_id"], _encrypt(plaintexts[row["key_id"]], new_key, row["key_id"]), moment),
            )

        # 3. PROOF: legacy plaintext == new plaintext, byte for byte, for EVERY row.
        verifications: List[Dict[str, Any]] = []
        for row in rows:
            shadow = conn.execute(
                f"SELECT private_key_hex_v1 FROM {SHADOW_TABLE} WHERE key_id = ?;", (row["key_id"],)
            ).fetchone()
            assert shadow is not None
            new_plain = _decrypt(shadow["private_key_hex_v1"], new_key, row["key_id"])
            if plaintexts[row["key_id"]] != new_plain:
                conn.execute("ROLLBACK")
                raise VaultIdentityError("MIGRATION_VERIFICATION_FAILED", row["key_id"])
            verifications.append({"key_id": row["key_id"], "byte_identical": True,
                                  "length": len(new_plain), "legacy_source": sources[row["key_id"]]})

        # 4. FLIP: install the v1 representation as the primary one and change the version. Both in
        #    this transaction, so the representation and the declaration can never disagree.
        for row in rows:
            conn.execute(
                f"UPDATE {KEY_VAULT_TABLE} SET private_key_hex = "
                f"(SELECT private_key_hex_v1 FROM {SHADOW_TABLE} WHERE key_id = ?) WHERE key_id = ?;",
                (row["key_id"], row["key_id"]),
            )
        write_header(conn, vault_id=identity, derivation_version=KEY_DERIVATION_V1,
                     secret=secret, created_at=moment, migrated_at=moment)
        conn.execute("COMMIT")
        return {"status": "MIGRATED", "vault_id": identity, "rewrapped": len(rows),
                "verified": len(verifications), "verifications": verifications,
                "legacy_sources": sources,
                "plaintext_rows_now_encrypted": plaintext_rows}
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()


def purge_legacy_representation(db_path: str, *, now: Optional[float] = None) -> int:
    """
    Optional hygiene AFTER a verified migration: drop the shadow staging rows.

    The legacy ciphertext is not kept anywhere: `migrate_vault` overwrote it in place, so a purge is
    about not leaving a stale staging table behind, not about erasing a decryptable copy.
    """
    conn = _connect(db_path)
    try:
        init_schema(conn)
        header = read_header(conn)
        if header is None:
            raise VaultIdentityError("MIGRATION_NOT_COMPLETE", db_path)
        cursor = conn.execute(f"DELETE FROM {SHADOW_TABLE};")
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def verify_all_rows(db_path: str, *, secret: Optional[bytes] = None) -> Dict[str, Any]:
    """Read-only proof that every protected row decrypts under the vault's CURRENT identity."""
    conn = _connect(db_path, read_only=True)
    try:
        key = derive_kek(db_path, conn=conn, secret=secret)
        results = []
        for row in protected_rows(conn):
            ciphertext = str(row["private_key_hex"])
            if not ciphertext.startswith("ENC:"):
                # Legacy plaintext: readable, but not protected. Reported honestly rather than counted
                # as a failure, because the runtime can read it too.
                try:
                    results.append({"key_id": row["key_id"], "decrypts": True,
                                    "length": len(bytes.fromhex(ciphertext)),
                                    "source": "PLAINTEXT_LEGACY"})
                except Exception as error:
                    results.append({"key_id": row["key_id"], "decrypts": False,
                                    "error": f"{type(error).__name__}"})
                continue
            try:
                plaintext = _decrypt(ciphertext, key, row["key_id"])
                results.append({"key_id": row["key_id"], "decrypts": True, "length": len(plaintext),
                                "source": "KEK"})
            except Exception as error:
                results.append({"key_id": row["key_id"], "decrypts": False,
                                "error": f"{type(error).__name__}"})
        return {"rows": results, "all_decrypt": all(r["decrypts"] for r in results)}
    finally:
        conn.close()
