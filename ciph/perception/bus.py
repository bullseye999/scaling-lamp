"""
ciph.perception.bus - Sensory Event Bus for Raw Telemetry Ingestion.
Broadcasts structured Observation events from Git, CVE feeds, Tor sensors, and local monitors.
"""

from typing import Dict, Any, List, Optional, Callable
from ciph.perception.observation import Observation


class SensoryBus:
    """
    Central pub/sub bus for sensory telemetry and environment observations.
    """

    def __init__(self):
        self._listeners: Dict[Optional[str], List[Callable[[Observation], None]]] = {}
        self._history: List[Observation] = []

    def subscribe(self, predicate: Optional[str], callback: Callable[[Observation], None]) -> None:
        """Subscribe a listener callback to a specific predicate or all observations (predicate=None)."""
        if predicate not in self._listeners:
            self._listeners[predicate] = []
        self._listeners[predicate].append(callback)

    def publish(self, observation: Observation) -> None:
        """Publish an observation to all matching subscribers."""
        self._history.append(observation)
        if len(self._history) > 200:
            self._history = self._history[-200:]

        # Notify general listeners
        for cb in self._listeners.get(None, []):
            try:
                cb(observation)
            except Exception:
                pass

        # Notify predicate-specific listeners
        for cb in self._listeners.get(observation.predicate, []):
            try:
                cb(observation)
            except Exception:
                pass

    def get_recent(self, limit: int = 50) -> List[Observation]:
        """Return recently ingested observations."""
        return self._history[-limit:]
