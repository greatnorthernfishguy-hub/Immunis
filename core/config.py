"""
Immunis Configuration — YAML Config with Dataclass Loader

Centralizes all user-configurable settings. Loads from config.yaml
with PRD-specified defaults for every value. Follows the identical
pattern to THC's core/config.py.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: ImmunisConfig dataclass with from_yaml() class method.
#         All default values match PRD §11 exactly.
#   Why:  PRD §11 specifies YAML config with dataclass loader,
#         following THC core/config.py pattern.
#   Settings: All defaults per PRD §11.
#   How:  Nested dataclasses for each config section. YAML loaded
#         via PyYAML, merged over defaults. Path expansion for ~.
# -------------------
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("immunis.config")


# ---------------------------------------------------------------------------
# Sensor Configuration Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FilesystemSensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 5.0
    watched_paths: List[str] = field(default_factory=lambda: ["/"])
    excluded_paths: List[str] = field(
        default_factory=lambda: ["/proc", "/sys", "/dev", "/tmp/.immunis_*"]
    )
    sensitive_paths: List[str] = field(
        default_factory=lambda: [
            "/etc/cron.d", "/etc/cron.daily", "/etc/systemd/system",
            "/etc/ssh", "~/.ssh", "~/.et_modules",
        ]
    )


@dataclass
class ProcessSensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 10.0
    cpu_threshold_pct: float = 90.0
    memory_threshold_pct: float = 80.0
    known_process_allowlist: List[str] = field(
        default_factory=lambda: ["sshd", "systemd", "python3"]
    )
    suspicious_locations: List[str] = field(
        default_factory=lambda: ["/tmp", "/dev/shm", "/var/tmp"]
    )


@dataclass
class NetworkSensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 15.0
    suspicious_ports: List[int] = field(
        default_factory=lambda: [4444, 5555, 8888, 1337]
    )
    known_good_destinations: List[str] = field(
        default_factory=lambda: ["127.0.0.1", "::1"]
    )
    max_outbound_connections: int = 100


@dataclass
class DependencySensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 300.0
    package_managers: List[str] = field(
        default_factory=lambda: ["pip", "npm"]
    )
    snapshot_path: str = "~/.et_modules/immunis/dependency_snapshot.json"


@dataclass
class LogSensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 30.0
    log_sources: List[str] = field(
        default_factory=lambda: ["/var/log/auth.log", "/var/log/syslog"]
    )
    use_journalctl: bool = True
    auth_failure_window_seconds: int = 300
    auth_failure_threshold: int = 5


@dataclass
class MemorySensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 30.0
    system_memory_threshold_pct: float = 95.0
    process_growth_rate_threshold_mb_per_min: float = 100.0


@dataclass
class SubstrateSensorConfig:
    enabled: bool = True
    poll_interval_seconds: float = 60.0
    weight_divergence_threshold: float = 2.0
    novelty_saturation_threshold: float = 0.95


@dataclass
class SensorsConfig:
    filesystem: FilesystemSensorConfig = field(default_factory=FilesystemSensorConfig)
    process: ProcessSensorConfig = field(default_factory=ProcessSensorConfig)
    network: NetworkSensorConfig = field(default_factory=NetworkSensorConfig)
    dependency: DependencySensorConfig = field(default_factory=DependencySensorConfig)
    log: LogSensorConfig = field(default_factory=LogSensorConfig)
    memory: MemorySensorConfig = field(default_factory=MemorySensorConfig)
    substrate: SubstrateSensorConfig = field(default_factory=SubstrateSensorConfig)


# ---------------------------------------------------------------------------
# Top-Level Configuration Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class QuartermasterConfig:
    signal_buffer_size: int = 10000
    learn_observation_window: int = 300


@dataclass
class ThresholdsConfig:
    auto_execute: float = 0.70
    recommend: float = 0.40
    host_premium: float = 0.15


@dataclass
class ArmoryConfig:
    max_entries: int = 10000
    persistence_format: str = "msgpack"
    search_top_k: int = 10
    match_threshold: float = 0.90
    eviction_policy: str = "lru"


@dataclass
class ResponseConfig:
    kill_grace_seconds: int = 5
    quarantine_dir: str = "~/.et_modules/immunis/quarantine"
    forensics_dir: str = "~/.et_modules/immunis/forensics"
    forensics_min_disk_mb: int = 100
    protected_pids: List[int] = field(default_factory=list)
    protected_paths: List[str] = field(
        default_factory=lambda: [
            "/etc/passwd", "/etc/shadow", "/etc/group", "/boot",
        ]
    )
    protected_destinations: List[str] = field(
        default_factory=lambda: ["127.0.0.1", "::1"]
    )


@dataclass
class TrainingWheelsConfig:
    min_armory_entries: int = 50
    min_substrate_outcomes: int = 100
    min_user_feedbacks: int = 20
    min_runtime_hours: int = 24


@dataclass
class NGLiteConfig:
    enabled: bool = True
    module_id: str = "immunis"
    state_path: str = "~/.et_modules/immunis/ng_lite_state.json"


@dataclass
class EmbeddingConfig:
    model: str = "sentence-transformers/all-MiniLM-L6-v2"
    dim: int = 384
    device: str = "auto"
    fallback_to_hash: bool = True


@dataclass
class EmergencyConfig:
    kill_switch: bool = False


@dataclass
class ImmunisConfig:
    """Full configuration for Immunis.

    All values have PRD-specified defaults (§11).  Override via config.yaml.
    """

    quartermaster: QuartermasterConfig = field(default_factory=QuartermasterConfig)
    thresholds: ThresholdsConfig = field(default_factory=ThresholdsConfig)
    armory: ArmoryConfig = field(default_factory=ArmoryConfig)
    response: ResponseConfig = field(default_factory=ResponseConfig)
    sensors: SensorsConfig = field(default_factory=SensorsConfig)
    training_wheels: TrainingWheelsConfig = field(default_factory=TrainingWheelsConfig)
    ng_lite: NGLiteConfig = field(default_factory=NGLiteConfig)
    embedding: EmbeddingConfig = field(default_factory=EmbeddingConfig)
    checkpoint_interval_seconds: int = 300
    emergency: EmergencyConfig = field(default_factory=EmergencyConfig)

    @classmethod
    def from_yaml(cls, path: Optional[str] = None) -> "ImmunisConfig":
        """Load configuration from YAML file, merging over defaults.

        Args:
            path: Path to config.yaml. Defaults to
                  ~/.et_modules/immunis/config.yaml

        Returns:
            ImmunisConfig with all values populated.
        """
        if path is None:
            path = str(Path.home() / ".et_modules" / "immunis" / "config.yaml")

        config = cls()
        expanded = os.path.expanduser(path)

        if not os.path.exists(expanded):
            logger.info("No config file at %s — using defaults", expanded)
            return config

        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed — using defaults")
            return config

        try:
            with open(expanded, "r") as f:
                raw = yaml.safe_load(f)
        except Exception as exc:
            logger.warning("Failed to load %s: %s — using defaults", expanded, exc)
            return config

        if not raw or "immunis" not in raw:
            return config

        data = raw["immunis"]
        _apply_dict(config, data)
        return config


def _apply_dict(target: Any, source: Dict[str, Any]) -> None:
    """Recursively apply dict values to a dataclass instance."""
    if not isinstance(source, dict):
        return
    for key, val in source.items():
        if not hasattr(target, key):
            continue
        current = getattr(target, key)
        if hasattr(current, "__dataclass_fields__") and isinstance(val, dict):
            _apply_dict(current, val)
        else:
            setattr(target, key, val)
