"""
ciph/kernel/crypto_identity.py - Asymmetric Cryptographic Trust Chain & Trust Registry
CIPH 4.0 Gate Zero Sealed Specification

Implements:
1. Ed25519 Asymmetric Authority Separation:
   - K_operator: Signs OperatorConsentGrant (human consent)
   - K_kernel: Signs ExecutionToken (governed execution authority)
   - K_worker: Signs ExecutionReceipt (operational attestation)
2. TrustRegistry:
   - Key lifecycle: ACTIVE -> RETIRED (preserves historical validity) / REVOKED (compromised)
   - Pinned root operator public key verification
3. Expanded ExecutionToken:
   - 14-field canonical binding: nonce, plan_hash, step_id, capability, manifest_hash,
     parameters_hash, scope_grant_id, authorization_grant_id, lane, worker_class,
     timestamps, attempts.
"""

import os
import time
import json
import hashlib
import sqlite3
import uuid
from enum import Enum
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import ed25519


class KeyRole(str, Enum):
    OPERATOR = "OPERATOR"
    KERNEL = "KERNEL"
    WORKER = "WORKER"


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


class Ed25519KeyManager:
    """Helper for Ed25519 keypair generation, signing, and verification."""

    @staticmethod
    def generate_keypair() -> Tuple[bytes, bytes]:
        """
        Generate Ed25519 private and public key bytes.
        Returns: (private_bytes_32, public_bytes_32)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        priv_bytes = private_key.private_bytes_raw()
        pub_bytes = public_key.public_bytes_raw()
        return priv_bytes, pub_bytes

    @staticmethod
    def sign(private_key_bytes: bytes, message: bytes) -> str:
        """Sign message using private key bytes and return hex signature."""
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        signature = private_key.sign(message)
        return signature.hex()

    @staticmethod
    def verify(public_key_bytes: bytes, message: bytes, signature_hex: str) -> bool:
        """Verify hex signature on message using public key bytes."""
        try:
            public_key = ed25519.Ed25519PublicKey.from_bytes(public_key_bytes) if hasattr(ed25519.Ed25519PublicKey, "from_bytes") else ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
            signature = bytes.fromhex(signature_hex)
            public_key.verify(signature, message)
            return True
        except Exception:
            return False


class TrustRegistry:
    """
    SQLite-backed registry for public keys, key IDs, validity windows,
    and revocation status.
    """

    def __init__(self, db_path: str = ":memory:", pinned_operator_pub_hex: Optional[str] = None):
        self.db_path = db_path
        self._configured_operator_pin = pinned_operator_pub_hex.lower() if pinned_operator_pub_hex else None
        if self.db_path != ":memory:":
            if not os.path.exists(self.db_path):
                # Ensure file is created with restricted mode 0600 (owner only)
                fd = os.open(self.db_path, os.O_CREAT | os.O_RDWR, 0o600)
                os.close(fd)
            try:
                os.chmod(self.db_path, 0o600)
            except Exception:
                pass
        if self.db_path == ":memory:":
            self._persistent_conn = sqlite3.connect(":memory:")
        else:
            self._persistent_conn = None
        self._init_db()
        self._load_or_validate_operator_pin()

    @property
    def pinned_operator_pub_hex(self) -> Optional[str]:
        """Return the durable root pin without exposing a writable authority attribute."""
        try:
            conn = self._get_connection()
            row = conn.execute(
                "SELECT metadata_value FROM ciph_trust_metadata WHERE metadata_key = ?",
                ("operator_root_public_key",),
            ).fetchone()
            if self._persistent_conn is None:
                conn.close()
            if row:
                return str(row[0]).lower()
        except sqlite3.Error:
            pass
        return self._configured_operator_pin

    def _get_connection(self):
        if self._persistent_conn is not None:
            return self._persistent_conn
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        conn = self._get_connection()
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ciph_trust_registry (
                key_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                created_at REAL NOT NULL,
                valid_until REAL,
                status TEXT NOT NULL,
                revocation_reason TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ciph_key_vault (
                key_id TEXT PRIMARY KEY,
                role TEXT NOT NULL,
                private_key_hex TEXT NOT NULL,
                public_key_hex TEXT NOT NULL,
                created_at REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ciph_trust_metadata (
                metadata_key TEXT PRIMARY KEY,
                metadata_value TEXT NOT NULL
            )
        """)
        conn.commit()
        if self._persistent_conn is None:
            conn.close()

    def _load_or_validate_operator_pin(self) -> None:
        """Load the durable operator-root pin and reject conflicting configuration."""
        conn = self._get_connection()
        row = conn.execute(
            "SELECT metadata_value FROM ciph_trust_metadata WHERE metadata_key = ?",
            ("operator_root_public_key",),
        ).fetchone()
        if self._persistent_conn is None:
            conn.close()

        stored_pin = str(row[0]).lower() if row else None
        configured_pin = self._configured_operator_pin
        if stored_pin and configured_pin and stored_pin != configured_pin:
            raise PermissionError(
                "CRITICAL: Configured operator root does not match the registry's durable operator-root pin."
            )

    def pin_operator_root(self, public_key_hex: str) -> str:
        """Persist the first operator root and make subsequent authority changes signature-gated."""
        normalized = str(public_key_hex).lower()
        existing_root = self.get_key("operator_root")
        if not existing_root or str(existing_root["public_key_hex"]).lower() != normalized:
            raise PermissionError("CRITICAL: Cannot pin an operator key that is not the registered operator_root.")
        if existing_root.get("role") != KeyRole.OPERATOR.value:
            raise PermissionError("CRITICAL: Registered operator_root does not have the OPERATOR role.")
        if self.pinned_operator_pub_hex and self.pinned_operator_pub_hex != normalized:
            raise PermissionError("CRITICAL: Operator root is already pinned to a different public key.")

        conn = self._get_connection()
        conn.execute(
            "INSERT OR IGNORE INTO ciph_trust_metadata (metadata_key, metadata_value) VALUES (?, ?)",
            ("operator_root_public_key", normalized),
        )
        row = conn.execute(
            "SELECT metadata_value FROM ciph_trust_metadata WHERE metadata_key = ?",
            ("operator_root_public_key",),
        ).fetchone()
        conn.commit()
        if self._persistent_conn is None:
            conn.close()
        durable_pin = str(row[0]).lower()
        if durable_pin != normalized:
            raise PermissionError("CRITICAL: Durable operator-root pin conflicts with the requested key.")
        return durable_pin

    def _get_vault_kek(self) -> bytes:
        """Derive key encryption key for the local vault."""
        salt = b"CIPH_VAULT_KEK_V1_SALT_KEYPAIR_PROTECTION"
        machine_seed = b"CIPH_LOCAL_KEY_VAULT"
        try:
            if os.path.exists("/etc/machine-id"):
                with open("/etc/machine-id", "rb") as f:
                    machine_seed = f.read().strip()
        except Exception:
            pass
        return hashlib.sha256(machine_seed + self.db_path.encode('utf-8') + salt).digest()

    def _encrypt_private_key(self, private_key_bytes: bytes, key_id: str) -> str:
        """Encrypt private key bytes using AES-GCM before storing in ciph_key_vault."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kek = self._get_vault_kek()
        aesgcm = AESGCM(kek)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, private_key_bytes, key_id.encode('utf-8'))
        return f"ENC:{nonce.hex()}:{ct.hex()}"

    def _decrypt_private_key(self, enc_str: str, key_id: str) -> bytes:
        """Decrypt private key bytes from ciph_key_vault, supporting backwards compatibility."""
        if not enc_str.startswith("ENC:"):
            return bytes.fromhex(enc_str)
        parts = enc_str.split(":")
        nonce = bytes.fromhex(parts[1])
        ct = bytes.fromhex(parts[2])
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        kek = self._get_vault_kek()
        aesgcm = AESGCM(kek)
        return aesgcm.decrypt(nonce, ct, key_id.encode('utf-8'))

    def register_key(
        self,
        key_id: str,
        role: KeyRole,
        public_key_hex: str,
        valid_until: Optional[float] = None,
        operator_signature: Optional[str] = None
    ) -> bool:
        """
        Register a public key in the trust registry.
        If a pinned root operator key is configured, all key registrations (except root genesis)
        strictly require an authentic Ed25519 signature from K_operator.
        Existing keys can NEVER be overwritten (INSERT OR REPLACE is forbidden).
        """
        now = time.time()
        if self.pinned_operator_pub_hex:
            is_root_genesis = (public_key_hex.lower() == self.pinned_operator_pub_hex.lower() and role == KeyRole.OPERATOR)
            if not is_root_genesis:
                if operator_signature is None:
                    return False
                payload = f"REGISTER_KEY:{key_id}:{role.value}:{public_key_hex}:{valid_until}".encode("utf-8")
                if not Ed25519KeyManager.verify(bytes.fromhex(self.pinned_operator_pub_hex), payload, operator_signature):
                    return False
            else:
                if public_key_hex.lower() != self.pinned_operator_pub_hex.lower():
                    return False

        conn = self._get_connection()
        # Immutable key store: reject overwriting existing keys
        cursor = conn.execute("SELECT key_id FROM ciph_trust_registry WHERE key_id = ?", (key_id,))
        if cursor.fetchone():
            if self._persistent_conn is None:
                conn.close()
            return False

        conn.execute("""
            INSERT INTO ciph_trust_registry
            (key_id, role, public_key_hex, created_at, valid_until, status, revocation_reason)
            VALUES (?, ?, ?, ?, ?, ?, NULL)
        """, (key_id, role.value, public_key_hex, now, valid_until, KeyStatus.ACTIVE.value))
        conn.commit()
        if self._persistent_conn is None:
            conn.close()
        return True

    def get_key(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve key record by key_id."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT * FROM ciph_trust_registry WHERE key_id = ?",
            (key_id,)
        )
        row = cursor.fetchone()
        res = dict(row) if row else None
        if self._persistent_conn is None:
            conn.close()
        return res

    def get_keypair(self, key_id: str) -> Optional[Tuple[bytes, bytes]]:
        """Retrieve persistent private and public key bytes from key vault."""
        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT private_key_hex, public_key_hex FROM ciph_key_vault WHERE key_id = ?",
            (key_id,)
        )
        row = cursor.fetchone()
        if self._persistent_conn is None:
            conn.close()
        if not row:
            return None
        priv_bytes = self._decrypt_private_key(row["private_key_hex"], key_id)
        pub_bytes = bytes.fromhex(row["public_key_hex"])
        return priv_bytes, pub_bytes

    def store_keypair(
        self,
        key_id: str,
        role: KeyRole,
        private_key_bytes: bytes,
        public_key_bytes: bytes,
        valid_until: Optional[float] = None,
        operator_signature: Optional[str] = None
    ) -> bool:
        """Register public authority first, then store matching private material."""
        now = time.time()
        enc_priv = self._encrypt_private_key(private_key_bytes, key_id)
        public_key_hex = public_key_bytes.hex()

        # Enrollment is the authority boundary. A denied registration must leave
        # no vault-only key that a downstream verifier could accidentally trust.
        registry_record = self.get_key(key_id)
        if registry_record is None:
            registered = self.register_key(
                key_id=key_id,
                role=role,
                public_key_hex=public_key_hex,
                valid_until=valid_until,
                operator_signature=operator_signature
            )
            if not registered:
                if self.pinned_operator_pub_hex:
                    raise PermissionError(f"CRITICAL: Failed to register key '{key_id}' in TrustRegistry under pinned root.")
                return False
        else:
            if registry_record.get("role") != role.value:
                raise PermissionError(
                    f"CRITICAL: Registered key '{key_id}' has role '{registry_record.get('role')}', expected '{role.value}'."
                )
            if str(registry_record.get("public_key_hex", "")).lower() != public_key_hex.lower():
                raise PermissionError(
                    f"CRITICAL: Keypair for '{key_id}' does not match its immutable TrustRegistry public key."
                )

        conn = self._get_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.execute(
            "SELECT role, public_key_hex FROM ciph_key_vault WHERE key_id = ?",
            (key_id,),
        )
        vault_record = cursor.fetchone()
        if vault_record:
            if (
                str(vault_record["role"]).upper() != role.value
                or str(vault_record["public_key_hex"]).lower() != public_key_hex.lower()
            ):
                if self._persistent_conn is None:
                    conn.close()
                raise PermissionError(
                    f"CRITICAL: Vault key '{key_id}' conflicts with the authoritative TrustRegistry record."
                )
        else:
            conn.execute("""
                INSERT INTO ciph_key_vault (key_id, role, private_key_hex, public_key_hex, created_at)
                VALUES (?, ?, ?, ?, ?)
            """, (key_id, role.value, enc_priv, public_key_hex, now))
            conn.commit()
        if self._persistent_conn is None:
            conn.close()
        return True

    def get_or_create_keypair(
        self,
        key_id: str,
        role: KeyRole,
        valid_until: Optional[float] = None,
        operator_signature: Optional[str] = None
    ) -> Tuple[bytes, bytes]:
        """
        Retrieve persistent keypair by key_id, generating and registering it if not existing.
        """
        pair = self.get_keypair(key_id)
        if pair is not None:
            record = self.get_key(key_id)
            if record is not None:
                if record.get("role") != role.value:
                    raise PermissionError(
                        f"CRITICAL: Stored key '{key_id}' has role '{record.get('role')}', expected '{role.value}'."
                    )
                if str(record.get("public_key_hex", "")).lower() != pair[1].hex().lower():
                    raise PermissionError(
                        f"CRITICAL: Stored keypair for '{key_id}' does not match its TrustRegistry public key."
                    )
            else:
                registered = self.register_key(
                    key_id=key_id,
                    role=role,
                    public_key_hex=pair[1].hex(),
                    valid_until=valid_until,
                    operator_signature=operator_signature
                )
                if not registered and self.pinned_operator_pub_hex:
                    raise PermissionError(f"CRITICAL: Failed to register key '{key_id}' in TrustRegistry under pinned root.")
            return pair

        priv_bytes, pub_bytes = Ed25519KeyManager.generate_keypair()
        stored = self.store_keypair(
            key_id=key_id,
            role=role,
            private_key_bytes=priv_bytes,
            public_key_bytes=pub_bytes,
            valid_until=valid_until,
            operator_signature=operator_signature
        )
        if not stored and self.pinned_operator_pub_hex:
            raise PermissionError(f"CRITICAL: Failed to store and register key '{key_id}' under pinned root.")
        return priv_bytes, pub_bytes

    def retire_key(
        self,
        key_id: str,
        retirement_timestamp: Optional[float] = None,
        operator_signature: Optional[str] = None
    ) -> bool:
        """
        Retire a key. Receipts signed prior to retirement_timestamp remain valid.
        Future signatures using this key are rejected.
        Requires K_operator signature if root is pinned.
        """
        now = retirement_timestamp if retirement_timestamp is not None else time.time()
        if self.pinned_operator_pub_hex:
            if operator_signature is None:
                return False
            payload = f"RETIRE_KEY:{key_id}:{now}".encode("utf-8")
            if not Ed25519KeyManager.verify(bytes.fromhex(self.pinned_operator_pub_hex), payload, operator_signature):
                return False

        conn = self._get_connection()
        cursor = conn.execute(
            "UPDATE ciph_trust_registry SET status = ?, valid_until = ? WHERE key_id = ? AND status = ?",
            (KeyStatus.RETIRED.value, now, key_id, KeyStatus.ACTIVE.value)
        )
        conn.commit()
        affected = cursor.rowcount > 0
        if self._persistent_conn is None:
            conn.close()
        return affected

    def revoke_key(
        self,
        key_id: str,
        reason: str,
        operator_signature: Optional[str] = None
    ) -> bool:
        """
        Compromise revocation: immediately marks the key REVOKED.
        All signatures (historical and new) are considered disputed/untrusted.
        Requires K_operator signature if root is pinned.
        """
        if self.pinned_operator_pub_hex:
            if operator_signature is None:
                return False
            payload = f"REVOKE_KEY:{key_id}:{reason}".encode("utf-8")
            if not Ed25519KeyManager.verify(bytes.fromhex(self.pinned_operator_pub_hex), payload, operator_signature):
                return False

        conn = self._get_connection()
        cursor = conn.execute(
            "UPDATE ciph_trust_registry SET status = ?, revocation_reason = ? WHERE key_id = ?",
            (KeyStatus.REVOKED.value, reason, key_id)
        )
        conn.commit()
        affected = cursor.rowcount > 0
        if self._persistent_conn is None:
            conn.close()
        return affected

    def verify_signature_at_time(
        self,
        key_id: str,
        message: bytes,
        signature_hex: str,
        signed_at: float
    ) -> Tuple[bool, str]:
        """
        Verify signature against key validity period at the exact timestamp when signed.
        Returns: (is_valid, reason)
        """
        record = self.get_key(key_id)
        if not record:
            return False, f"KEY_NOT_FOUND: {key_id}"

        status = KeyStatus(record["status"])
        if status == KeyStatus.REVOKED:
            return False, f"KEY_REVOKED: {record.get('revocation_reason', 'Compromise')}"

        if status == KeyStatus.RETIRED:
            valid_until = record["valid_until"]
            if valid_until is not None and signed_at > valid_until:
                return False, f"SIGNED_AFTER_RETIREMENT: signed_at={signed_at} > retired_at={valid_until}"

        if status == KeyStatus.ACTIVE:
            valid_until = record["valid_until"]
            if valid_until is not None and signed_at > valid_until:
                return False, f"KEY_EXPIRED: signed_at={signed_at} > valid_until={valid_until}"

        public_key_bytes = bytes.fromhex(record["public_key_hex"])
        if not Ed25519KeyManager.verify(public_key_bytes, message, signature_hex):
            return False, "INVALID_SIGNATURE"

        return True, "VALID"


@dataclass(frozen=True)
class OperatorConsentGrant:
    """
    Independently signed human operator authorization grant.
    Signed by K_operator_priv.
    """
    grant_id: str
    plan_hash: str
    step_id: str
    capability: str
    parameters_hash: str
    scope_grant_id: str
    max_budget: Dict[str, float] = field(default_factory=dict)
    issued_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    operator_key_id: str = "operator_root"
    signature: str = ""

    def compute_canonical_payload(self) -> bytes:
        """Deterministically serialize consent fields for signing."""
        budget_str = json.dumps(self.max_budget, sort_keys=True)
        raw = f"{self.grant_id}:{self.plan_hash}:{self.step_id}:{self.capability}:{self.parameters_hash}:{self.scope_grant_id}:{budget_str}:{self.issued_at}:{self.expires_at}:{self.operator_key_id}"
        return raw.encode("utf-8")

    def sign(self, operator_private_key_bytes: bytes) -> "OperatorConsentGrant":
        """Produce an Ed25519 signed copy of OperatorConsentGrant."""
        payload = self.compute_canonical_payload()
        sig = Ed25519KeyManager.sign(operator_private_key_bytes, payload)
        d = asdict(self)
        d["signature"] = sig
        return OperatorConsentGrant(**d)

    def verify(self, trust_registry: TrustRegistry, current_time: Optional[float] = None) -> Tuple[bool, str]:
        """Verify operator signature against TrustRegistry."""
        if not self.signature:
            return False, "MISSING_SIGNATURE"
        now = current_time if current_time is not None else time.time()
        if self.expires_at > 0 and now > self.expires_at:
            return False, "GRANT_EXPIRED"
        payload = self.compute_canonical_payload()
        return trust_registry.verify_signature_at_time(
            self.operator_key_id, payload, self.signature, self.issued_at
        )


@dataclass(frozen=True)
class ExecutionToken:
    """
    Governed execution token minted by the Kernel Coordinator.
    Signed by K_kernel_priv.
    Includes all 14 mandatory binding fields.
    """
    token_id: str
    nonce: str
    plan_hash: str
    step_id: str
    capability: str
    manifest_hash: str
    manifest_version: str
    parameters_hash: str
    scope_grant_id: Optional[str]
    authorization_grant_id: Optional[str]
    execution_lane: str
    authorized_worker_class: str
    issued_at: float
    expires_at: float
    max_attempts: int
    kernel_key_id: str = "kernel_primary"
    signature: str = ""
    scope_payload_json: str = ""
    source_policy_hash: str = ""

    def compute_canonical_payload(self) -> bytes:
        """Deterministic canonical representation across all 14 binding fields."""
        fields = [
            self.token_id,
            self.nonce,
            self.plan_hash,
            self.step_id,
            self.capability,
            self.manifest_hash,
            self.manifest_version,
            self.parameters_hash,
            self.scope_grant_id or "NONE",
            self.authorization_grant_id or "NONE",
            self.execution_lane,
            self.authorized_worker_class,
            str(self.issued_at),
            str(self.expires_at),
            str(self.max_attempts),
            self.kernel_key_id
        ]
        if self.scope_payload_json or self.source_policy_hash:
            fields.append(json.dumps([self.scope_payload_json, self.source_policy_hash], separators=(",", ":")))
        raw = ":".join(fields)
        return raw.encode("utf-8")

    def token_hash(self) -> str:
        """Compute SHA-256 hash of the complete token for receipt referencing."""
        return hashlib.sha256(self.compute_canonical_payload()).hexdigest()

    def sign(self, kernel_private_key_bytes: bytes) -> "ExecutionToken":
        """Produce an Ed25519 signed copy of ExecutionToken."""
        payload = self.compute_canonical_payload()
        sig = Ed25519KeyManager.sign(kernel_private_key_bytes, payload)
        d = asdict(self)
        d["signature"] = sig
        return ExecutionToken(**d)

    def verify(
        self,
        trust_registry: TrustRegistry,
        current_time: Optional[float] = None,
        expected_plan_hash: Optional[str] = None,
        expected_step_id: Optional[str] = None,
        expected_capability: Optional[str] = None,
        expected_params_hash: Optional[str] = None,
        expected_manifest_hash: Optional[str] = None,
        worker_class: Optional[str] = None
    ) -> Tuple[bool, str]:
        """
        Verify token signature against TrustRegistry and ensure context matches
        every bound execution field.
        """
        if not self.signature:
            return False, "MISSING_SIGNATURE"

        now = current_time if current_time is not None else time.time()
        if self.expires_at > 0 and now > self.expires_at:
            return False, "TOKEN_EXPIRED"

        if expected_plan_hash and self.plan_hash != expected_plan_hash:
            return False, f"PLAN_HASH_MISMATCH: expected {expected_plan_hash}, got {self.plan_hash}"
        if expected_step_id and self.step_id != expected_step_id:
            return False, f"STEP_ID_MISMATCH: expected {expected_step_id}, got {self.step_id}"
        if expected_capability and self.capability != expected_capability:
            return False, f"CAPABILITY_MISMATCH: expected {expected_capability}, got {self.capability}"
        if expected_params_hash and self.parameters_hash != expected_params_hash:
            return False, f"PARAMS_HASH_MISMATCH: expected {expected_params_hash}, got {self.parameters_hash}"
        if expected_manifest_hash and self.manifest_hash != expected_manifest_hash:
            return False, f"MANIFEST_HASH_MISMATCH: expected {expected_manifest_hash}, got {self.manifest_hash}"
        if worker_class and self.authorized_worker_class != "ALL" and self.authorized_worker_class != worker_class:
            return False, f"WORKER_CLASS_UNAUTHORIZED: expected {self.authorized_worker_class}, got {worker_class}"

        payload = self.compute_canonical_payload()
        return trust_registry.verify_signature_at_time(
            self.kernel_key_id, payload, self.signature, self.issued_at
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize ExecutionToken to dictionary."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutionToken":
        """Reconstruct ExecutionToken from dictionary."""
        field_names = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in field_names}
        return cls(**filtered)

    def mint_attempt_token(
        self, kernel_private_key_bytes: Optional[bytes] = None,
        trust_registry: Optional["TrustRegistry"] = None,
        db_path: Optional[str] = None, current_time: Optional[float] = None,
        *, job_id: Optional[str] = None, attempt_number: Optional[int] = None,
    ) -> "ExecutionToken":
        """Coordinator-only signing primitive; requires authenticated retry context."""
        return mint_attempt_token(self, kernel_private_key_bytes, trust_registry, db_path,
                                  current_time, job_id=job_id, attempt_number=attempt_number)


def mint_attempt_token(
    base_token: Union[ExecutionToken, Dict[str, Any], str],
    kernel_private_key_bytes: Optional[bytes] = None,
    trust_registry: Optional["TrustRegistry"] = None,
    db_path: Optional[str] = None,
    current_time: Optional[float] = None,
    *,
    job_id: Optional[str] = None,
    attempt_number: Optional[int] = None,
) -> ExecutionToken:
    """Sign a job-bound retry after the coordinator authenticates its failed attempt.

    This primitive never obtains private authority from a caller-supplied database.
    The queue calls it only inside the failure receipt transaction. Original
    authority and expiry remain binding, including after key revocation.
    """
    if isinstance(base_token, str):
        base_token = ExecutionToken.from_dict(json.loads(base_token))
    elif isinstance(base_token, dict):
        base_token = ExecutionToken.from_dict(base_token)
    now = current_time if current_time is not None else time.time()
    if trust_registry is None or kernel_private_key_bytes is None:
        raise PermissionError("RETRY_AUTHORIZATION_REQUIRED: explicit coordinator signing authority required")
    valid, reason = base_token.verify(trust_registry, current_time=now)
    record = trust_registry.get_key(base_token.kernel_key_id)
    role = getattr((record or {}).get("role"), "value", (record or {}).get("role"))
    active, active_reason = trust_registry.verify_signature_at_time(
        base_token.kernel_key_id, base_token.compute_canonical_payload(), base_token.signature, now
    )
    if not valid or not active or role != "KERNEL":
        raise PermissionError(f"INVALID_RETRY_AUTHORITY: {reason}; {active_reason}")
    if not job_id or not isinstance(attempt_number, int) or not 1 < attempt_number <= base_token.max_attempts:
        raise PermissionError("RETRY_ATTEMPTS_EXCEEDED_OR_UNBOUND")
    data = base_token.to_dict()
    data.update(token_id=f"tok_retry_{uuid.uuid4().hex}", nonce=retry_nonce(base_token, job_id, attempt_number), signature="")
    token = ExecutionToken.from_dict(data).sign(kernel_private_key_bytes)
    if not token.verify(trust_registry, current_time=now)[0]:
        raise PermissionError("RETRY_SIGNING_KEY_MISMATCH")
    return token


def retry_nonce(parent: ExecutionToken, job_id: str, attempt_number: int) -> str:
    """Cryptographically bind renewed authority to its parent, job and budget."""
    payload = json.dumps([parent.token_hash(), job_id, attempt_number], separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
