"""
ciph.operator.cadence_engine - Operator Cadence & Interrupt Budget Engine (CIPH 4.0).
Governs how and when CIPH interrupts Arthur based on operational rhythms and alert severities.
"""

import time
from enum import Enum
from typing import Dict, Any, List, Optional


class OperatorCadence(str, Enum):
    DEEP_FOCUS  = "DEEP_FOCUS"   # High concentration mode: zero non-critical interruptions
    TACTICAL    = "TACTICAL"     # Active collaboration mode: interactive confirmations
    ASYNC_AWAY  = "ASYNC_AWAY"   # Operator offline: background daemons run autonomously
    RE_ENGAGING = "RE_ENGAGING"  # Operator resurfaced: Executive Debrief mode


class AlertSeverity(str, Enum):
    INFO     = "INFO"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


class CadenceManager:
    """
    Manages operator focus states and alert batching.
    Prevents notification fatigue while ensuring critical security alerts break through.
    """

    def __init__(self, initial_cadence: OperatorCadence = OperatorCadence.TACTICAL):
        self.current_cadence = initial_cadence
        self._batched_alerts: List[Dict[str, Any]] = []
        self.last_transition_time = time.time()

    def set_cadence(self, cadence: OperatorCadence) -> None:
        """Switch the operator focus cadence."""
        self.current_cadence = cadence
        self.last_transition_time = time.time()

    def should_interrupt(self, severity: AlertSeverity) -> bool:
        """
        Determines if an incoming event/alert should immediately interrupt the operator.
        """
        if severity == AlertSeverity.CRITICAL:
            return True  # Critical integrity/security events always break through

        if self.current_cadence == OperatorCadence.DEEP_FOCUS:
            return False  # Suppress everything else during Deep Focus

        if self.current_cadence == OperatorCadence.ASYNC_AWAY:
            return False  # Batch everything while operator is away

        if self.current_cadence == OperatorCadence.TACTICAL:
            return severity in (AlertSeverity.MEDIUM, AlertSeverity.HIGH, AlertSeverity.CRITICAL)

        return True

    def record_alert(self, alert_type: str, message: str, severity: AlertSeverity, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Record alert. Returns True if caller should notify immediately, False if batched.
        """
        entry = {
            "type": alert_type,
            "message": message,
            "severity": severity.value,
            "metadata": metadata or {},
            "timestamp": time.time()
        }
        self._batched_alerts.append(entry)
        return self.should_interrupt(severity)

    def get_batched_alerts(self, clear: bool = True) -> List[Dict[str, Any]]:
        """Retrieve and optionally clear the pending alert queue."""
        alerts = list(self._batched_alerts)
        if clear:
            self._batched_alerts.clear()
        return alerts

    def generate_executive_debrief(self) -> str:
        """Render a single-glance briefing of queued items and completed background work."""
        if not self._batched_alerts:
            return "‖ Executive Debrief: Zero pending notifications or queued alerts. ‖"

        lines = [f"📋 EXECUTIVE DEBRIEF ({len(self._batched_alerts)} Batched Events):"]
        for a in self._batched_alerts:
            sev_tag = f"[{a['severity']}]"
            lines.append(f"  • {sev_tag} {a['type']}: {a['message']}")

        self._batched_alerts.clear()
        return "\n".join(lines)
