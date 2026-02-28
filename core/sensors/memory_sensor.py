"""
Immunis Memory Sensor — System Memory Pattern Monitoring

Monitors system-wide memory patterns for anomalies. Reads /proc/meminfo
and per-process memory maps at a moderate interval.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: MemorySensor class monitoring system memory spikes, per-process
#         growth rate anomalies, and unusual memory mapping patterns.
#   Why:  PRD §5.6 specifies memory sensor reading /proc/meminfo.
#   Settings: poll_interval_seconds=30.0, system_memory_threshold_pct=95.0,
#         process_growth_rate_threshold_mb_per_min=100.0.
#   How:  Reads /proc/meminfo for system-wide stats. Tracks per-process
#         RSS growth rate over time. Embedding from meminfo values
#         normalized to [0,1] per PRD §5.6.
# -------------------
"""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.memory")


class MemorySensor(Sensor):
    """Monitors system memory patterns for anomalies (PRD §5.6)."""

    SENSOR_TYPE = "memory"
    POLL_INTERVAL_SECONDS = 30.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._mem_threshold = self._config.get(
            "system_memory_threshold_pct", 95.0
        )
        self._growth_threshold = self._config.get(
            "process_growth_rate_threshold_mb_per_min", 100.0
        )
        self._prev_meminfo: Dict[str, int] = {}
        self._process_rss_history: Dict[int, List[tuple]] = {}

    def _poll(self) -> List[Dict[str, Any]]:
        """Read /proc/meminfo and check per-process memory."""
        events: List[Dict[str, Any]] = []

        meminfo = self._read_meminfo()
        if not meminfo:
            return events

        # System memory usage spike
        total = meminfo.get("MemTotal", 1)
        available = meminfo.get("MemAvailable", meminfo.get("MemFree", total))
        usage_pct = (1.0 - available / total) * 100.0 if total > 0 else 0.0

        if usage_pct > self._mem_threshold:
            events.append({
                "event_type": "system_memory_spike",
                "usage_pct": round(usage_pct, 2),
                "total_kb": total,
                "available_kb": available,
                "timestamp": time.time(),
                **{k: v for k, v in meminfo.items()},
            })

        # Per-process memory growth rate
        events.extend(self._check_process_growth())

        self._prev_meminfo = meminfo
        return events

    @staticmethod
    def _read_meminfo() -> Dict[str, int]:
        """Parse /proc/meminfo into a dict of kB values."""
        result: Dict[str, int] = {}
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                parts = line.split()
                if len(parts) >= 2:
                    key = parts[0].rstrip(":")
                    try:
                        result[key] = int(parts[1])
                    except ValueError:
                        pass
        except (OSError, PermissionError):
            pass
        return result

    def _check_process_growth(self) -> List[Dict[str, Any]]:
        """Check per-process RSS growth rate."""
        events: List[Dict[str, Any]] = []
        now = time.time()

        try:
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                pid = int(entry.name)

                try:
                    status_text = (entry / "status").read_text()
                    rss_kb = 0
                    comm = ""
                    for line in status_text.splitlines():
                        if line.startswith("VmRSS:"):
                            rss_kb = int(line.split()[1])
                        elif line.startswith("Name:"):
                            comm = line.split(":", 1)[1].strip()
                except (OSError, PermissionError, ValueError):
                    continue

                if rss_kb == 0:
                    continue

                # Track history
                if pid not in self._process_rss_history:
                    self._process_rss_history[pid] = []
                self._process_rss_history[pid].append((now, rss_kb))

                # Keep only last 5 minutes of history
                cutoff = now - 300
                self._process_rss_history[pid] = [
                    (t, r) for t, r in self._process_rss_history[pid]
                    if t > cutoff
                ]

                # Calculate growth rate (MB/min)
                history = self._process_rss_history[pid]
                if len(history) >= 2:
                    dt = history[-1][0] - history[0][0]
                    if dt > 0:
                        dr_kb = history[-1][1] - history[0][1]
                        rate_mb_per_min = (dr_kb / 1024.0) / (dt / 60.0)
                        if rate_mb_per_min > self._growth_threshold:
                            events.append({
                                "event_type": "process_memory_growth",
                                "pid": pid,
                                "comm": comm,
                                "growth_rate_mb_per_min": round(rate_mb_per_min, 2),
                                "current_rss_kb": rss_kb,
                                "timestamp": now,
                            })
        except (OSError, PermissionError):
            pass

        # Prune dead PIDs
        active_pids = set()
        try:
            for entry in Path("/proc").iterdir():
                if entry.name.isdigit():
                    active_pids.add(int(entry.name))
        except OSError:
            pass
        dead = set(self._process_rss_history.keys()) - active_pids
        for pid in dead:
            del self._process_rss_history[pid]

        return events

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a memory event as a feature vector.

        PRD §5.6: Feature vector from /proc/meminfo values normalized
        to [0,1] plus per-process RSS/VSZ ratios.
        """
        features: List[float] = []

        if event.get("event_type") == "system_memory_spike":
            total = event.get("MemTotal", event.get("total_kb", 1))
            if total == 0:
                total = 1
            features.append(event.get("MemTotal", 0) / max(total, 1))
            features.append(event.get("MemFree", 0) / max(total, 1))
            features.append(event.get("MemAvailable", 0) / max(total, 1))
            features.append(event.get("Buffers", 0) / max(total, 1))
            features.append(event.get("Cached", 0) / max(total, 1))
            features.append(event.get("SwapTotal", 0) / max(total, 1))
            features.append(event.get("usage_pct", 0) / 100.0)
            features.append(0.0)  # event type: system
        else:
            # Process memory growth
            features.append(min(event.get("current_rss_kb", 0) / (4 * 1024 * 1024), 1.0))
            features.append(min(event.get("growth_rate_mb_per_min", 0) / 1000.0, 1.0))
            features.append(0.0)
            features.append(0.0)
            features.append(0.0)
            features.append(0.0)
            features.append(0.0)
            features.append(1.0)  # event type: process

        return self._feature_embed(features)
