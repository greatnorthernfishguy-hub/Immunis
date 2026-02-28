"""
Immunis File System Sensor — File System Event Monitoring

Monitors file system events using the watchdog library (cross-platform
file system event monitoring). Falls back to periodic polling if
watchdog is unavailable.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: FilesystemSensor class monitoring file create/modify/delete/
#         move/permission events. Uses watchdog for real-time events,
#         falls back to periodic stat-based polling.
#   Why:  PRD §5.1 specifies filesystem sensor with watchdog + fallback.
#   Settings: poll_interval_seconds=5.0, watched_paths=["/"],
#         excluded_paths=["/proc","/sys","/dev","/tmp/.immunis_*"],
#         sensitive_paths per PRD §5.1.
#   How:  Watchdog Observer watches configured paths. Events queued
#         internally. _poll() drains the queue. Embedding strategy
#         per PRD §5.1: path hash + extension + depth + size delta +
#         permission delta + timestamp features + name entropy.
# -------------------
"""

from __future__ import annotations

import hashlib
import logging
import math
import os
import queue
import stat
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.sensors.base import EMBEDDING_DIM, Sensor

logger = logging.getLogger("immunis.sensors.filesystem")


class FilesystemSensor(Sensor):
    """Monitors file system events for the Quartermaster pipeline.

    PRD §5.1: File system events are encoded as feature vectors combining
    path hash, extension encoding, directory depth, size delta, permission
    delta, timestamp features, and file name entropy.
    """

    SENSOR_TYPE = "filesystem"
    POLL_INTERVAL_SECONDS = 5.0

    # Common file extensions mapped to indices for one-hot encoding
    _EXT_MAP = {
        ".py": 0, ".sh": 1, ".bash": 2, ".js": 3, ".rb": 4,
        ".pl": 5, ".php": 6, ".exe": 7, ".bin": 8, ".so": 9,
        ".dll": 10, ".conf": 11, ".cfg": 12, ".yaml": 13, ".yml": 14,
        ".json": 15, ".xml": 16, ".txt": 17, ".log": 18, ".key": 19,
        ".pem": 20, ".crt": 21, ".cron": 22, ".service": 23,
    }
    _NUM_EXTS = 24

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._event_queue: queue.Queue = queue.Queue(maxsize=5000)
        self._observer = None
        self._file_cache: Dict[str, Dict[str, Any]] = {}

        self._watched_paths = [
            os.path.expanduser(p)
            for p in self._config.get("watched_paths", ["/"])
        ]
        self._excluded_paths = [
            os.path.expanduser(p)
            for p in self._config.get(
                "excluded_paths",
                ["/proc", "/sys", "/dev", "/tmp/.immunis_*"],
            )
        ]
        self._sensitive_paths = [
            os.path.expanduser(p)
            for p in self._config.get(
                "sensitive_paths",
                ["/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system",
                 "/etc/ssh", "~/.ssh", "~/.et_modules"],
            )
        ]

        self._init_watchdog()

    def _init_watchdog(self) -> None:
        """Initialize watchdog observer if available."""
        try:
            from watchdog.events import FileSystemEventHandler
            from watchdog.observers import Observer

            sensor = self

            class _Handler(FileSystemEventHandler):
                def on_any_event(self, event):
                    if event.is_directory:
                        return
                    try:
                        sensor._event_queue.put_nowait({
                            "event_type": event.event_type,
                            "src_path": event.src_path,
                            "dest_path": getattr(event, "dest_path", None),
                            "timestamp": time.time(),
                        })
                    except queue.Full:
                        pass

            self._observer = Observer()
            for wp in self._watched_paths:
                if os.path.exists(wp):
                    self._observer.schedule(
                        _Handler(), wp, recursive=True
                    )
            self._observer.daemon = True
            self._observer.start()
            logger.info("Watchdog observer started for %s", self._watched_paths)

        except ImportError:
            logger.info("watchdog not available — using poll-based fallback")
            self._observer = None

    def _poll(self) -> List[Dict[str, Any]]:
        """Drain the watchdog event queue."""
        events: List[Dict[str, Any]] = []

        # Drain watchdog queue
        while not self._event_queue.empty():
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break

        # If no watchdog, do a stat-based scan of sensitive paths
        if self._observer is None:
            events.extend(self._poll_sensitive_paths())

        return events

    def _poll_sensitive_paths(self) -> List[Dict[str, Any]]:
        """Fallback: stat sensitive paths for changes."""
        events: List[Dict[str, Any]] = []
        for sp in self._sensitive_paths:
            p = Path(sp)
            if not p.exists():
                continue
            try:
                for child in p.iterdir():
                    str_path = str(child)
                    try:
                        st = child.stat()
                    except OSError:
                        continue
                    cached = self._file_cache.get(str_path)
                    if cached is None:
                        self._file_cache[str_path] = {
                            "mtime": st.st_mtime,
                            "size": st.st_size,
                            "mode": st.st_mode,
                        }
                        continue
                    if st.st_mtime != cached["mtime"]:
                        events.append({
                            "event_type": "modified",
                            "src_path": str_path,
                            "dest_path": None,
                            "timestamp": time.time(),
                            "size_delta": st.st_size - cached["size"],
                            "mode_delta": st.st_mode ^ cached["mode"],
                        })
                        self._file_cache[str_path] = {
                            "mtime": st.st_mtime,
                            "size": st.st_size,
                            "mode": st.st_mode,
                        }
            except PermissionError:
                continue
        return events

    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """Filter out events from excluded paths."""
        src = event.get("src_path", "")
        for excl in self._excluded_paths:
            if excl.endswith("*"):
                if src.startswith(excl[:-1]):
                    return False
            elif src.startswith(excl):
                return False
        return True

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a filesystem event as a feature vector.

        PRD §5.1 embedding strategy:
        - File path hash (deterministic, position-independent)
        - File extension one-hot encoding
        - Directory depth
        - File size delta (for modifications)
        - Permission bitmask delta (for permission changes)
        - Timestamp features (time of day, day of week)
        - Entropy of file name (randomized names are suspicious)
        """
        src_path = event.get("src_path", "")
        features: List[float] = []

        # Path hash features (8 dims)
        path_hash = hashlib.sha256(src_path.encode()).digest()
        for b in path_hash[:8]:
            features.append(b / 255.0)

        # Extension one-hot (24 dims)
        ext = os.path.splitext(src_path)[1].lower()
        ext_vec = [0.0] * self._NUM_EXTS
        if ext in self._EXT_MAP:
            ext_vec[self._EXT_MAP[ext]] = 1.0
        features.extend(ext_vec)

        # Directory depth (1 dim)
        depth = src_path.count("/")
        features.append(min(depth / 20.0, 1.0))

        # File size delta (1 dim)
        size_delta = event.get("size_delta", 0)
        features.append(
            min(abs(size_delta) / (10 * 1024 * 1024), 1.0)
            * (1.0 if size_delta >= 0 else -1.0)
        )

        # Permission delta (1 dim)
        mode_delta = event.get("mode_delta", 0)
        features.append(min(mode_delta / 0o777, 1.0) if mode_delta else 0.0)

        # Timestamp features (2 dims: time of day, day of week)
        ts = event.get("timestamp", time.time())
        lt = time.localtime(ts)
        features.append(lt.tm_hour / 24.0)
        features.append(lt.tm_wday / 7.0)

        # File name entropy (1 dim)
        filename = os.path.basename(src_path)
        features.append(self._name_entropy(filename))

        # Event type encoding (1 dim)
        event_type = event.get("event_type", "unknown")
        type_map = {
            "created": 0.0, "modified": 0.2, "deleted": 0.4,
            "moved": 0.6, "closed": 0.8,
        }
        features.append(type_map.get(event_type, 1.0))

        # Is in sensitive path? (1 dim)
        is_sensitive = any(src_path.startswith(sp) for sp in self._sensitive_paths)
        features.append(1.0 if is_sensitive else 0.0)

        # Is executable? (1 dim)
        try:
            st_mode = os.stat(src_path).st_mode
            is_exec = bool(st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except OSError:
            is_exec = False
        features.append(1.0 if is_exec else 0.0)

        return self._feature_embed(features)

    @staticmethod
    def _name_entropy(name: str) -> float:
        """Shannon entropy of filename characters, normalized to [0, 1]."""
        if not name:
            return 0.0
        counts = Counter(name)
        length = len(name)
        entropy = 0.0
        for count in counts.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        max_entropy = math.log2(max(length, 1))
        return entropy / max_entropy if max_entropy > 0 else 0.0

    def shutdown(self) -> None:
        """Stop the watchdog observer."""
        if self._observer is not None:
            self._observer.stop()
            self._observer.join(timeout=5)
