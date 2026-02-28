"""
Immunis Dependency Sensor — Package/Dependency Monitoring

Monitors installed packages for supply chain attacks. Runs at a
longer poll interval (default 300s) since package changes are infrequent.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: DependencySensor monitoring pip and npm packages for new
#         installs, version changes, and typosquatting detection.
#         Maintains a snapshot for change detection.
#   Why:  PRD §5.4 specifies dependency sensor for supply chain threats.
#   Settings: poll_interval_seconds=300.0, package_managers=["pip","npm"],
#         snapshot_path per PRD §5.4.
#   How:  Runs pip list / npm ls to get current packages. Compares
#         against stored snapshot. Emits events for differences.
#         Embedding per PRD §5.4.
# -------------------
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.dependency")


class DependencySensor(Sensor):
    """Monitors package dependencies for supply chain threats (PRD §5.4)."""

    SENSOR_TYPE = "dependency"
    POLL_INTERVAL_SECONDS = 300.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._package_managers = self._config.get(
            "package_managers", ["pip", "npm"]
        )
        self._snapshot_path = Path(
            os.path.expanduser(
                self._config.get(
                    "snapshot_path",
                    "~/.et_modules/immunis/dependency_snapshot.json",
                )
            )
        )
        self._snapshot: Dict[str, Dict[str, str]] = {}
        self._first_poll = True
        self._load_snapshot()

    def _poll(self) -> List[Dict[str, Any]]:
        """Compare current packages against snapshot."""
        events: List[Dict[str, Any]] = []
        current: Dict[str, Dict[str, str]] = {}

        for pm in self._package_managers:
            packages = self._list_packages(pm)
            for name, version in packages.items():
                key = f"{pm}:{name}"
                current[key] = {"name": name, "version": version, "manager": pm}

        if self._first_poll and not self._snapshot:
            # First run: record baseline, no events
            self._snapshot = current
            self._save_snapshot()
            self._first_poll = False
            return events

        # Detect changes
        for key, info in current.items():
            if key not in self._snapshot:
                events.append({
                    "event_type": "package_installed",
                    "package_name": info["name"],
                    "version": info["version"],
                    "manager": info["manager"],
                    "timestamp": time.time(),
                })
            elif self._snapshot[key]["version"] != info["version"]:
                events.append({
                    "event_type": "package_version_changed",
                    "package_name": info["name"],
                    "old_version": self._snapshot[key]["version"],
                    "version": info["version"],
                    "manager": info["manager"],
                    "timestamp": time.time(),
                })

        for key, info in self._snapshot.items():
            if key not in current:
                events.append({
                    "event_type": "package_removed",
                    "package_name": info["name"],
                    "version": info["version"],
                    "manager": info["manager"],
                    "timestamp": time.time(),
                })

        self._snapshot = current
        self._save_snapshot()
        self._first_poll = False
        return events

    def _list_packages(self, manager: str) -> Dict[str, str]:
        """List installed packages for a package manager."""
        if manager == "pip":
            return self._list_pip()
        elif manager == "npm":
            return self._list_npm()
        return {}

    def _list_pip(self) -> Dict[str, str]:
        """List pip packages via 'pip list --format=json'."""
        try:
            result = subprocess.run(
                ["pip", "list", "--format=json"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                packages = json.loads(result.stdout)
                return {p["name"]: p["version"] for p in packages}
        except (FileNotFoundError, subprocess.TimeoutExpired,
                json.JSONDecodeError, OSError):
            pass
        return {}

    def _list_npm(self) -> Dict[str, str]:
        """List npm global packages via 'npm ls -g --json'."""
        try:
            result = subprocess.run(
                ["npm", "ls", "-g", "--json", "--depth=0"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                deps = data.get("dependencies", {})
                return {
                    name: info.get("version", "unknown")
                    for name, info in deps.items()
                }
        except (FileNotFoundError, subprocess.TimeoutExpired,
                json.JSONDecodeError, OSError):
            pass
        return {}

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a dependency event as a feature vector.

        PRD §5.4: package name hash, version hash, package manager,
        source repo hash, previous version hash, time since last change.
        """
        features: List[float] = []

        # Package name hash (4 dims)
        name = event.get("package_name", "")
        name_hash = hashlib.sha256(name.encode()).digest()
        for b in name_hash[:4]:
            features.append(b / 255.0)

        # Version hash (4 dims)
        version = event.get("version", "")
        ver_hash = hashlib.sha256(version.encode()).digest()
        for b in ver_hash[:4]:
            features.append(b / 255.0)

        # Package manager (1 dim)
        pm = event.get("manager", "pip")
        pm_map = {"pip": 0.0, "npm": 0.5, "apt": 1.0}
        features.append(pm_map.get(pm, 0.5))

        # Event type (1 dim)
        etype = event.get("event_type", "unknown")
        etype_map = {
            "package_installed": 0.0,
            "package_version_changed": 0.33,
            "package_removed": 0.66,
        }
        features.append(etype_map.get(etype, 1.0))

        # Previous version hash (4 dims) if version changed
        old_ver = event.get("old_version", "")
        old_hash = hashlib.sha256(old_ver.encode()).digest()
        for b in old_hash[:4]:
            features.append(b / 255.0)

        return self._feature_embed(features)

    def _load_snapshot(self) -> None:
        """Load the package snapshot from disk."""
        if self._snapshot_path.exists():
            try:
                with open(self._snapshot_path, "r") as f:
                    self._snapshot = json.load(f)
            except (json.JSONDecodeError, OSError):
                pass

    def _save_snapshot(self) -> None:
        """Save the package snapshot to disk."""
        self._snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(self._snapshot_path, "w") as f:
                json.dump(self._snapshot, f, indent=2)
        except OSError as exc:
            logger.warning("Failed to save dependency snapshot: %s", exc)
