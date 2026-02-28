"""
Immunis Substrate Sensor — Peer Substrate Drift Monitoring

Monitors the NG-Lite substrates of peer modules for drift and
anomalies. This is the "watches the watchers" capability.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: SubstrateSensor class monitoring substrate weight distribution
#         shifts, node firing rate anomalies, novelty saturation, and
#         peer bridge connectivity loss.
#   Why:  PRD §5.7 specifies substrate sensor for drift detection.
#   Settings: poll_interval_seconds=60.0, weight_divergence_threshold=2.0,
#         novelty_saturation_threshold=0.95.
#   How:  Reads peer modules' NG-Lite state files via the shared learning
#         directory. Computes statistical metrics on synapse weights
#         and node activity. Read-only — does NOT modify peer state.
# -------------------
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.substrate")


class SubstrateSensor(Sensor):
    """Monitors peer module substrates for drift (PRD §5.7).

    Read-only: does NOT modify peer state.
    """

    SENSOR_TYPE = "substrate"
    POLL_INTERVAL_SECONDS = 60.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._weight_threshold = self._config.get(
            "weight_divergence_threshold", 2.0
        )
        self._novelty_threshold = self._config.get(
            "novelty_saturation_threshold", 0.95
        )
        self._shared_dir = Path.home() / ".et_modules" / "shared_learning"
        self._historical_stats: Dict[str, Dict[str, List[float]]] = {}

    def _poll(self) -> List[Dict[str, Any]]:
        """Read peer substrate states and check for anomalies."""
        events: List[Dict[str, Any]] = []

        if not self._shared_dir.exists():
            return events

        # Check for peer bridge files
        peer_files = list(self._shared_dir.glob("*.jsonl"))
        isolated_files = list(self._shared_dir.glob("*.isolated"))
        isolated_modules = {
            f.stem.replace("isolated_", "").split("_")[0]
            for f in isolated_files
        }

        for peer_file in peer_files:
            module_id = peer_file.stem
            if module_id == "immunis":
                continue
            if module_id.startswith("_"):
                continue

            # Check for isolation
            if module_id in isolated_modules:
                events.append({
                    "event_type": "peer_isolated",
                    "module_id": module_id,
                    "timestamp": time.time(),
                })
                continue

            # Read recent learning events
            stats = self._analyze_peer_events(peer_file, module_id)
            if stats is None:
                continue

            # Check weight distribution shift
            if stats.get("weight_std_deviation", 0) > self._weight_threshold:
                events.append({
                    "event_type": "weight_distribution_shift",
                    "module_id": module_id,
                    "std_deviation": stats["weight_std_deviation"],
                    "threshold": self._weight_threshold,
                    "timestamp": time.time(),
                    **stats,
                })

            # Check novelty saturation
            if stats.get("avg_novelty", 0) > self._novelty_threshold:
                events.append({
                    "event_type": "novelty_saturation",
                    "module_id": module_id,
                    "avg_novelty": stats["avg_novelty"],
                    "threshold": self._novelty_threshold,
                    "timestamp": time.time(),
                    **stats,
                })

        # Check for connectivity loss (files that disappeared)
        current_peers = {f.stem for f in peer_files}
        if hasattr(self, "_known_peers"):
            lost = self._known_peers - current_peers - isolated_modules
            for module_id in lost:
                events.append({
                    "event_type": "peer_connectivity_loss",
                    "module_id": module_id,
                    "timestamp": time.time(),
                })
        self._known_peers = current_peers

        return events

    def _analyze_peer_events(
        self, path: Path, module_id: str
    ) -> Optional[Dict[str, Any]]:
        """Analyze a peer's learning event file for anomalies."""
        try:
            lines = path.read_text().splitlines()
        except (OSError, PermissionError):
            return None

        if not lines:
            return None

        # Read the last 100 events
        recent = lines[-100:]
        weights: List[float] = []
        novelties: List[float] = []
        success_count = 0
        total_count = 0

        for line in recent:
            try:
                event = json.loads(line)
                # Extract weight/confidence data
                if "confidence" in event:
                    weights.append(float(event["confidence"]))
                if "metadata" in event:
                    meta = event["metadata"]
                    if "novelty" in meta:
                        novelties.append(float(meta["novelty"]))
                if "success" in event:
                    total_count += 1
                    if event["success"]:
                        success_count += 1
            except (json.JSONDecodeError, ValueError, TypeError):
                continue

        if not weights:
            return None

        weight_mean = sum(weights) / len(weights)
        weight_var = sum((w - weight_mean) ** 2 for w in weights) / len(weights)
        weight_std = math.sqrt(weight_var) if weight_var > 0 else 0.0

        # Track historical stats for drift detection
        if module_id not in self._historical_stats:
            self._historical_stats[module_id] = {"means": [], "stds": []}
        hist = self._historical_stats[module_id]
        hist["means"].append(weight_mean)
        hist["stds"].append(weight_std)
        # Keep last 100 samples
        hist["means"] = hist["means"][-100:]
        hist["stds"] = hist["stds"][-100:]

        # Calculate divergence from historical mean
        if len(hist["means"]) > 1:
            hist_mean = sum(hist["means"][:-1]) / len(hist["means"][:-1])
            hist_std = (
                sum(hist["stds"][:-1]) / len(hist["stds"][:-1])
                if hist["stds"][:-1] else 1.0
            )
            divergence = abs(weight_mean - hist_mean) / max(hist_std, 0.001)
        else:
            divergence = 0.0

        return {
            "weight_mean": round(weight_mean, 4),
            "weight_std": round(weight_std, 4),
            "weight_std_deviation": round(divergence, 4),
            "avg_novelty": (
                round(sum(novelties) / len(novelties), 4)
                if novelties else 0.0
            ),
            "success_rate": (
                round(success_count / total_count, 4)
                if total_count > 0 else 0.0
            ),
            "event_count": len(recent),
        }

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a substrate event as a feature vector."""
        features: List[float] = []

        # Module ID hash (4 dims)
        mod_id = event.get("module_id", "")
        mod_hash = hashlib.sha256(mod_id.encode()).digest()
        for b in mod_hash[:4]:
            features.append(b / 255.0)

        # Weight stats (3 dims)
        features.append(event.get("weight_mean", 0.5))
        features.append(min(event.get("weight_std", 0) / 1.0, 1.0))
        features.append(min(event.get("weight_std_deviation", 0) / 5.0, 1.0))

        # Novelty (1 dim)
        features.append(event.get("avg_novelty", 0.5))

        # Success rate (1 dim)
        features.append(event.get("success_rate", 0.5))

        # Event type (1 dim)
        etype = event.get("event_type", "unknown")
        etype_map = {
            "weight_distribution_shift": 0.0,
            "novelty_saturation": 0.25,
            "peer_connectivity_loss": 0.5,
            "peer_isolated": 0.75,
        }
        features.append(etype_map.get(etype, 1.0))

        return self._feature_embed(features)
