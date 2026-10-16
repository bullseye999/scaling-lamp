"""
ciph/kernel/conversation_channels - the interface-independent conversation contract (10.1, B3).

    The channel is a TRANSPORT. It is not an identity, and it is not an authority.

Two genuinely separate disposable adapters exercise channel transitions: a local terminal channel and a
disposable message channel standing in for Session's future integration. Both speak the SAME continuity
contract, so the same historical finding stays the same finding across them - and each one enforces the
participant identity and the access boundary on the way in.

A LOCAL adapter does not deliver anything outside this process, and it must not claim to. `delivery()` reports
`external_delivery: False`, and `claim_external_delivery()` REFUSES rather than let a fake transport look
like real Session delivery.
"""

from typing import Any, Dict, Optional

from ciph.kernel.conversational_continuity import (ASSISTANT, REASON_PARTICIPANT_NOT_AUTHORIZED,
                                                   UTTERANCE, authorized_history, channel,
                                                   record_turn, session)
from ciph.kernel.crucible_types import CrucibleError

CONVERSATION_CHANNELS_V1 = "CONVERSATION_CHANNELS_V1"

REASON_UNTRUSTED_CHANNEL = "CHANNEL_IS_NOT_TRUSTED"
REASON_EXTERNAL_DELIVERY_NOT_PROVIDED = "LOCAL_ADAPTER_PROVIDES_NO_EXTERNAL_DELIVERY"
REASON_NO_SUCH_ADAPTER = "UNKNOWN_CHANNEL_ADAPTER"


class ConversationChannel:
    """The shared contract. Subclasses supply only the transport behaviour."""

    kind = "ABSTRACT"

    def __init__(self, *, channel_id: str, external_delivery: bool = False):
        self.channel_id = str(channel_id)
        self.external_delivery = bool(external_delivery)
        self.sent: list = []          # what this adapter was asked to carry (test-visible, in-process)
        self.received: list = []

    # -- registration ------------------------------------------------------------------
    def register(self, db_path: str, *, trusted: bool = True, now: Optional[float] = None) -> Dict[str, Any]:
        from ciph.kernel.conversational_continuity import register_channel
        return register_channel(db_path, channel_id=self.channel_id, kind=self.kind,
                                adapter_ref=type(self).__name__, trusted=trusted,
                                external_delivery=self.external_delivery, now=now)

    def _require_trusted(self, db_path: str) -> Dict[str, Any]:
        record = channel(db_path, self.channel_id)
        if not record["trusted"]:
            raise CrucibleError(REASON_UNTRUSTED_CHANNEL, self.channel_id)
        return record

    # -- the shared conversation behaviour ----------------------------------------------
    def deliver(self, db_path: str, *, session_id: str, text: str, kind: str = UTTERANCE,
                now: Optional[float] = None) -> Dict[str, Any]:
        """Ciph speaks. The turn is durable; the TRANSPORT is whatever this adapter is."""
        self._require_trusted(db_path)
        self.sent.append({"session_id": session_id, "text": text})
        turn = record_turn(db_path, session_id=session_id, speaker=ASSISTANT, text=text, kind=kind,
                           provenance=f"channel:{self.channel_id}", now=now)
        return {"turn": turn, "channel_id": self.channel_id,
                "external_delivery": self.external_delivery,
                "delivery_status": "DELIVERED_LOCALLY" if not self.external_delivery
                                   else "DELIVERED_EXTERNALLY"}

    def receive(self, db_path: str, *, session_id: str, participant_id: str, text: str,
                now: Optional[float] = None) -> Dict[str, Any]:
        """Someone speaks. IDENTITY IS CHECKED HERE, before anything is recorded."""
        self._require_trusted(db_path)
        record = session(db_path, session_id)
        if str(participant_id) != str(record["participant_id"]):
            raise CrucibleError(REASON_PARTICIPANT_NOT_AUTHORIZED,
                                f"{participant_id}:{session_id}@{self.channel_id}")
        self.received.append({"session_id": session_id, "text": text})
        turn = record_turn(db_path, session_id=session_id, speaker=str(participant_id), text=text,
                           kind=UTTERANCE, provenance=f"channel:{self.channel_id}", now=now)
        return {"turn": turn, "channel_id": self.channel_id, "identity_checked": True}

    def history(self, db_path: str, *, session_id: str, participant_id: str) -> Dict[str, Any]:
        """The same access boundary as every other channel: identity is re-checked on the way out."""
        self._require_trusted(db_path)
        return authorized_history(db_path, session_id=session_id, participant_id=participant_id)

    # -- honesty about what this adapter is ---------------------------------------------
    def delivery(self) -> Dict[str, Any]:
        return {"channel_id": self.channel_id, "kind": self.kind,
                "external_delivery": self.external_delivery,
                "external_identity_verification": False,
                "is_a_real_transport": self.external_delivery,
                "policy_version": CONVERSATION_CHANNELS_V1}

    def claim_external_delivery(self) -> Dict[str, Any]:
        """A local adapter that claims external delivery is REFUSED, not believed."""
        if not self.external_delivery:
            raise CrucibleError(REASON_EXTERNAL_DELIVERY_NOT_PROVIDED, self.channel_id)
        return {"channel_id": self.channel_id, "external_delivery": True,
                "verified_by": "the transport itself"}


class LocalTerminalChannel(ConversationChannel):
    """The real, local operator terminal. No external delivery, and it says so."""

    kind = "LOCAL_TERMINAL"

    def __init__(self, channel_id: str = "terminal"):
        super().__init__(channel_id=channel_id, external_delivery=False)


class DisposableMessageChannel(ConversationChannel):
    """
    A DISPOSABLE stand-in for Session's future messaging integration.

    It models the SHAPE of a messaging transport - an out-of-band queue with delivery states - and it
    deliberately does NOT claim real external delivery or external identity verification.
    """

    kind = "DISPOSABLE_MESSAGE"

    def __init__(self, channel_id: str = "disposable-message"):
        super().__init__(channel_id=channel_id, external_delivery=False)
        self.queue: list = []
        self.delivery_states: Dict[str, str] = {}

    def enqueue(self, db_path: str, *, session_id: str, text: str,
                now: Optional[float] = None) -> Dict[str, Any]:
        result = self.deliver(db_path, session_id=session_id, text=text, now=now)
        message_ref = f"MSG-{len(self.queue) + 1}"
        self.queue.append({"message_ref": message_ref, "session_id": session_id, "text": text})
        self.delivery_states[message_ref] = "QUEUED_NOT_TRANSMITTED"
        return {"message_ref": message_ref, "turn_id": result["turn"]["turn_id"],
                "delivery_state": "QUEUED_NOT_TRANSMITTED", "external_delivery": False}

    def drain(self) -> list:
        """The messages this adapter was asked to carry. Local and test-visible by construction."""
        return list(self.queue)
