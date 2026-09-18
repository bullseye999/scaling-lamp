"""
ciph.federation.ghost_mesh - Distributed Ghost Mesh & Tor P2P Federation (Stage 5).
Secures cross-node capability execution and mutual evidence projection using asymmetric Ed25519 signatures.
"""

import time
import json
import uuid
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError

from ciph.kernel.crypto_identity import Ed25519KeyManager, TrustRegistry, KeyStatus, KeyRole
from ciph.planner.schemas import IntentProposal
from ciph.workers.receipts import ExecutionReceipt


def _canonical_bytes(data: Dict[str, Any]) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), default=str).encode('utf-8')


@dataclass
class MeshHandshake:
    handshake_id: str
    sender_node_id: str
    recipient_node_id: str
    challenge_nonce: str
    timestamp: float
    signature: str = ""

    def sign(self, signing_key: SigningKey) -> "MeshHandshake":
        payload = {
            "handshake_id": self.handshake_id,
            "sender_node_id": self.sender_node_id,
            "recipient_node_id": self.recipient_node_id,
            "challenge_nonce": self.challenge_nonce,
            "timestamp": self.timestamp
        }
        signed = signing_key.sign(_canonical_bytes(payload))
        self.signature = signed.signature.hex()
        return self

    def verify(self, verify_key_hex: str) -> bool:
        if not self.signature:
            return False
        payload = {
            "handshake_id": self.handshake_id,
            "sender_node_id": self.sender_node_id,
            "recipient_node_id": self.recipient_node_id,
            "challenge_nonce": self.challenge_nonce,
            "timestamp": self.timestamp
        }
        try:
            vk = VerifyKey(bytes.fromhex(verify_key_hex))
            vk.verify(_canonical_bytes(payload), bytes.fromhex(self.signature))
            return True
        except BadSignatureError:
            return False


@dataclass
class MeshTaskEnvelope:
    envelope_id: str
    sender_node_id: str
    recipient_node_id: str
    proposal_dict: Dict[str, Any]
    timestamp: float
    signature: str = ""

    def sign(self, signing_key: SigningKey) -> "MeshTaskEnvelope":
        payload = {
            "envelope_id": self.envelope_id,
            "sender_node_id": self.sender_node_id,
            "recipient_node_id": self.recipient_node_id,
            "proposal_dict": self.proposal_dict,
            "timestamp": self.timestamp
        }
        signed = signing_key.sign(_canonical_bytes(payload))
        self.signature = signed.signature.hex()
        return self

    def verify(self, verify_key_hex: str) -> bool:
        if not self.signature:
            return False
        payload = {
            "envelope_id": self.envelope_id,
            "sender_node_id": self.sender_node_id,
            "recipient_node_id": self.recipient_node_id,
            "proposal_dict": self.proposal_dict,
            "timestamp": self.timestamp
        }
        try:
            vk = VerifyKey(bytes.fromhex(verify_key_hex))
            vk.verify(_canonical_bytes(payload), bytes.fromhex(self.signature))
            return True
        except BadSignatureError:
            return False


class GhostMeshNode:
    """
    Sovereign P2P Node participating in the distributed CIPH mesh.
    """

    def __init__(
        self,
        node_id: str,
        trust_registry: TrustRegistry,
        onion_address: Optional[str] = None,
        signing_key: Optional[SigningKey] = None,
        operator_signing_key: Optional[bytes] = None,
    ):
        self.node_id = node_id
        self.trust_registry = trust_registry
        self.onion_address = onion_address or f"{uuid.uuid4().hex[:16]}.onion"
        self.signing_key = signing_key or SigningKey.generate()
        self.verify_key = self.signing_key.verify_key
        self.public_key_hex = self.verify_key.encode().hex()
        self._operator_signing_key = operator_signing_key

        # Register self into TrustRegistry as an active node/worker key
        self._register_peer_key(self.node_id, self.public_key_hex)

        self.known_peers: Dict[str, Dict[str, Any]] = {}

    def add_trusted_peer(self, peer_node_id: str, peer_public_key_hex: str, onion_address: Optional[str] = None):
        """Add an authorized peer node to the local mesh topology."""
        self._register_peer_key(peer_node_id, peer_public_key_hex)
        self.known_peers[peer_node_id] = {
            "node_id": peer_node_id,
            "public_key_hex": peer_public_key_hex,
            "onion_address": onion_address or f"{peer_node_id}.onion"
        }

    def _register_peer_key(self, peer_node_id: str, public_key_hex: str) -> None:
        """Register a mesh worker key under the local pinned operator authority."""
        key_id = f"key_{peer_node_id}"
        existing = self.trust_registry.get_key(key_id)
        if existing:
            if (
                str(existing.get("public_key_hex", "")).lower() != public_key_hex.lower()
                or existing.get("role") != KeyRole.WORKER.value
            ):
                raise PermissionError(f"Mesh key '{key_id}' conflicts with an existing identity.")
            return

        operator_signature = None
        if self.trust_registry.pinned_operator_pub_hex:
            if self._operator_signing_key is None:
                raise PermissionError(
                    f"Pinned TrustRegistry requires operator authorization to register mesh key '{key_id}'."
                )
            payload = f"REGISTER_KEY:{key_id}:WORKER:{public_key_hex}:None".encode("utf-8")
            operator_signature = Ed25519KeyManager.sign(self._operator_signing_key, payload)

        if not self.trust_registry.register_key(
            key_id=key_id,
            role=KeyRole.WORKER,
            public_key_hex=public_key_hex,
            operator_signature=operator_signature,
        ):
            raise PermissionError(f"Failed to register mesh key '{key_id}' under local authority.")

    def initiate_handshake(self, recipient_node_id: str) -> MeshHandshake:
        """Create a cryptographically signed mutual authentication challenge."""
        handshake = MeshHandshake(
            handshake_id=f"HSK-{uuid.uuid4().hex[:8].upper()}",
            sender_node_id=self.node_id,
            recipient_node_id=recipient_node_id,
            challenge_nonce=uuid.uuid4().hex,
            timestamp=time.time()
        )
        return handshake.sign(self.signing_key)

    def verify_incoming_handshake(self, handshake: MeshHandshake) -> bool:
        """Verify peer signature and confirm key is active in TrustRegistry."""
        peer_node_id = handshake.sender_node_id
        peer = self.known_peers.get(peer_node_id)
        if not peer:
            return False

        # Fail closed if key is retired or revoked in TrustRegistry
        key_record = self.trust_registry.get_key(f"key_{peer_node_id}")
        if not key_record or key_record.get("status") != KeyStatus.ACTIVE.value:
            return False

        return handshake.verify(peer["public_key_hex"])

    def create_task_envelope(self, recipient_node_id: str, proposal: IntentProposal) -> MeshTaskEnvelope:
        """Package and sign an IntentProposal for remote execution across the mesh."""
        envelope = MeshTaskEnvelope(
            envelope_id=f"ENV-{uuid.uuid4().hex[:8].upper()}",
            sender_node_id=self.node_id,
            recipient_node_id=recipient_node_id,
            proposal_dict={
                "proposal_id": proposal.proposal_id,
                "objective": proposal.objective,
                "proposed_capability": proposal.proposed_capability,
                "provided_parameters": proposal.provided_parameters
            },
            timestamp=time.time()
        )
        return envelope.sign(self.signing_key)

    def execute_remote_mesh_task(
        self,
        envelope: MeshTaskEnvelope,
        local_runtime
    ) -> Dict[str, Any]:
        """Verify incoming envelope and execute through local runtime reference loop."""
        sender_id = envelope.sender_node_id
        peer = self.known_peers.get(sender_id)
        if not peer:
            return {"status": "PEER_NOT_TRUSTED", "error": f"Unknown peer {sender_id}"}

        if not envelope.verify(peer["public_key_hex"]):
            return {"status": "INVALID_ENVELOPE_SIGNATURE", "error": "Signature verification failed"}

        prop_data = envelope.proposal_dict
        proposal = IntentProposal(
            proposal_id=prop_data["proposal_id"],
            objective=prop_data["objective"],
            proposed_capability=prop_data["proposed_capability"],
            provided_parameters=prop_data.get("provided_parameters", {})
        )

        res = local_runtime.execute_reference_loop(proposal)
        return {
            "status": res.get("status"),
            "receipt": res.get("receipt"),
            "event_id": res.get("event_id"),
            "responder_node_id": self.node_id
        }
