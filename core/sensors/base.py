"""
Immunis Sensor Base Class — Abstract Base for All System Sensors

Each sensor reads a specific system signal source, embeds events,
and produces ThreatSignal instances for the Quartermaster pipeline.
Subclass this. Override SENSOR_TYPE, _poll(), and _embed().

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: Sensor ABC with ThreatSignal dataclass. Provides polling
#         loop, embedding dispatch, and signal production contract.
#   Why:  PRD §5 specifies a Sensor ABC with SENSOR_TYPE, _poll(),
#         _embed(), and _is_relevant() methods.
#   Settings: POLL_INTERVAL_SECONDS default 5.0, configurable per sensor.
#   How:  ABC pattern. Subclasses implement system-specific polling
#         and embedding. Base class handles the poll→filter→embed→emit
#         cycle via collect_signals().
# -------------------
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger("immunis.sensors")

EMBEDDING_DIM = 384


@dataclass
class ThreatSignal:
    """A single system-level signal for the Quartermaster to process.

    Created by sensor modules (PRD §5). Consumed by the Quartermaster
    pipeline (PRD §4).
    """

    signal_id: str = ""
    timestamp: float = 0.0
    sensor_type: str = ""
    event_type: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)
    embedding: Optional[np.ndarray] = None
    source_module: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.signal_id:
            self.signal_id = str(uuid.uuid4())
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class Sensor(ABC):
    """Abstract base class for all Immunis sensors.

    Each sensor reads a specific system signal source, embeds events,
    and produces ThreatSignal instances for the Quartermaster.

    Subclass this. Override:
        SENSOR_TYPE  — string identifier (required)
        _poll()      — read raw events from the system (required)
        _embed()     — embed a raw event into a vector (required)
        _is_relevant() — filter irrelevant events (optional, default: True)
    """

    SENSOR_TYPE: str = ""
    POLL_INTERVAL_SECONDS: float = 5.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}
        self._last_poll_time: float = 0.0
        self._total_events: int = 0
        self._total_signals: int = 0

        if "poll_interval_seconds" in self._config:
            self.POLL_INTERVAL_SECONDS = self._config["poll_interval_seconds"]

    @abstractmethod
    def _poll(self) -> List[Dict[str, Any]]:
        """Read raw events from the system. Return a list of event dicts."""
        ...

    @abstractmethod
    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a raw event into a normalized np.ndarray vector."""
        ...

    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """Filter irrelevant events. Override to customize. Default: all relevant."""
        return True

    def collect_signals(self) -> List[ThreatSignal]:
        """Poll for events, filter, embed, and return ThreatSignals.

        This is the main entry point called by the Quartermaster.
        Returns an empty list if the poll interval has not elapsed.
        """
        now = time.time()
        if now - self._last_poll_time < self.POLL_INTERVAL_SECONDS:
            return []

        self._last_poll_time = now

        try:
            raw_events = self._poll()
        except Exception as exc:
            logger.warning(
                "[%s] Poll failed: %s", self.SENSOR_TYPE, exc
            )
            return []

        signals: List[ThreatSignal] = []
        for event in raw_events:
            self._total_events += 1

            if not self._is_relevant(event):
                continue

            try:
                embedding = self._embed(event)
            except Exception as exc:
                logger.debug(
                    "[%s] Embed failed for event: %s", self.SENSOR_TYPE, exc
                )
                embedding = self._hash_embed(str(event))

            signal = ThreatSignal(
                sensor_type=self.SENSOR_TYPE,
                event_type=event.get("event_type", "unknown"),
                raw_data=event,
                embedding=embedding,
            )
            signals.append(signal)
            self._total_signals += 1

        return signals

    def get_stats(self) -> Dict[str, Any]:
        """Sensor telemetry."""
        return {
            "sensor_type": self.SENSOR_TYPE,
            "poll_interval": self.POLL_INTERVAL_SECONDS,
            "total_events": self._total_events,
            "total_signals": self._total_signals,
            "last_poll_time": self._last_poll_time,
        }

    # -------------------------------------------------------------------
    # Embedding Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _hash_embed(text: str, dims: int = EMBEDDING_DIM) -> np.ndarray:
        """Hash-based embedding fallback. Deterministic, normalized."""
        rng_seed = int(hashlib.sha256(text.encode()).hexdigest(), 16) % (2**32)
        rng = np.random.RandomState(rng_seed)
        vec = rng.randn(dims).astype(np.float32)
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec

    @staticmethod
    def _feature_embed(features: List[float], dims: int = EMBEDDING_DIM) -> np.ndarray:
        """Create a normalized embedding from numeric features.

        Pads or truncates to dims, then L2-normalizes.
        """
        vec = np.zeros(dims, dtype=np.float32)
        n = min(len(features), dims)
        vec[:n] = features[:n]
        # Hash remaining dims from feature content for richer representation
        if n < dims:
            feature_str = ",".join(f"{f:.6f}" for f in features)
            seed = int(hashlib.sha256(feature_str.encode()).hexdigest(), 16) % (2**32)
            rng = np.random.RandomState(seed)
            vec[n:] = rng.randn(dims - n).astype(np.float32) * 0.1
        norm = np.linalg.norm(vec)
        return vec / norm if norm > 0 else vec
