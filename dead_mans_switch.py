#!/usr/bin/env python3
# dead_mans_switch.py - Automatic data destruction

import threading
import time
import os

DESTRUCTION_REQUIRES_OPERATOR_AUTHORIZATION = "DESTRUCTION_REQUIRES_AN_OPERATOR_AUTHORIZATION"


class DestructionRefused(Exception):
    """A destruction attempt without explicit operator authorization. Carries a stable reason."""

    def __init__(self, reason: str, detail: str = ""):
        self.reason = reason
        self.detail = detail
        super().__init__(f"{reason}: {detail}" if detail else reason)


class DeadMansSwitch:
    """Destroy everything if compromised"""
    
    def __init__(self, vault):
        self.vault = vault
        # R12: destruction is ARMED BY A PERSON, never by a restored file.  The mechanism is unchanged;
        # what changed is that it will not act without an authorization that recovery cannot fabricate.
        self.destruction_authorized_by = None
        self.destruction_evidence_ref = None
        self.alive_signal = True
        self.check_interval = 300  # 5 minutes
        self.trigger_thread = None
        
    def start_switch(self, hours=24):
        """Start monitoring - wipe if no check-in"""
        self.trigger_thread = threading.Thread(
            target=self._monitor_switch,
            args=(hours * 3600,),
            daemon=True
        )
        self.trigger_thread.start()
        return f"‖ Dead man's switch active: {hours}h countdown ‖"
    
    def _monitor_switch(self, timeout_seconds):
        """Monitor for activity"""
        last_check = time.time()
        
        while time.time() - last_check < timeout_seconds:
            if not self.alive_signal:
                # Signal received - reset timer
                last_check = time.time()
                self.alive_signal = True
            
            time.sleep(60)  # Check every minute
        
        # TIMEOUT REACHED - WIPE EVERYTHING
       # self._emergency_destruct()
    
    def check_in(self):
        """Call this regularly to prove you're alive"""
        self.alive_signal = False
        return "‖ Switch check-in recorded ‖"

    def stop_switch(self):
        """Stop the dead man's switch"""
        self.alive_signal = True  # Prevent trigger
        if self.trigger_thread and self.trigger_thread.is_alive():
            # Can't really stop thread, but mark as stopped
            pass
        return "‖ Dead man's switch stopped ‖"
    
    def secure_delete(self, filepath: str, passes: int = 3):
        """Overwrite file with random data multiple times before deleting"""
        if not os.path.exists(filepath):
            return
        try:
            size = os.path.getsize(filepath)
            for _ in range(passes):
                with open(filepath, 'wb') as f:
                    f.write(os.urandom(size))
                    f.flush()
                    os.fsync(f.fileno())
            with open(filepath, 'wb') as f:
                f.write(b'\x00' * size)
                f.flush()
                os.fsync(f.fileno())
            os.remove(filepath)
        except Exception:
            pass

    def wipe_memory(self):
        """Force garbage collection to clean up memory references"""
        import gc
        gc.collect()

    def authorize_destruction(self, *, actor: str, evidence_ref: str) -> None:
        """
        Arm the destructive path, explicitly and auditably.

        Recovery MUST NOT call this.  A restored installation starts disarmed, and re-arming is a
        separate operator decision made after recovery verification - otherwise a backup could carry the
        instruction to destroy the machine it was just restored onto.
        """
        if not str(actor).startswith("operator:"):
            raise DestructionRefused("DESTRUCTION_REQUIRES_AN_OPERATOR", str(actor))
        if not str(evidence_ref).strip():
            raise DestructionRefused("DESTRUCTION_REQUIRES_EVIDENCE", str(evidence_ref))
        self.destruction_authorized_by = str(actor)
        self.destruction_evidence_ref = str(evidence_ref)

    def disarm_destruction(self) -> None:
        self.destruction_authorized_by = None
        self.destruction_evidence_ref = None

    def _emergency_destruct(self):
        """
        Complete system destruction - REFUSED unless an operator armed it first.

        This refusal is the whole point of the R12 remediation: the files below are the vault and the
        root, and a mechanism that can erase them on a timer is destruction authority.  It is allowed to
        exist; it is not allowed to be reachable by accident, by a restored configuration file, or by
        anything that is not a named person.
        """
        if self.destruction_authorized_by is None:
            raise DestructionRefused(DESTRUCTION_REQUIRES_OPERATOR_AUTHORIZATION,
                                     "no operator authorization on this instance")
        destructive_files = [
            "ciph_vault.db", "ciph.key", 
            "quantum_vault.db", "quantum.key"
        ]
        for f in destructive_files:
            if os.path.exists(f):
                self.secure_delete(f)
        self.wipe_memory()
        os._exit(0)  # Hard exit