"""
Immunis OpenClaw Hook — E-T Systems Standard Integration

Exposes Immunis's full-spectrum system security as an OpenClaw skill,
using the standardized OpenClawAdapter base class.

OpenClaw calls get_instance().on_message(text) on every turn.
The adapter handles all ecosystem wiring (Tier 1/2/3 learning) and
memory logging.  This file implements what's unique to Immunis:

  - _embed():              Sensor embedding dispatcher / hash fallback
  - _module_on_message():  Check Quartermaster status, report active threats
  - _module_stats():       Immunis-specific telemetry

SKILL.md entry:
    name: immunis
    autoload: true
    hook: immunis_hook.py::get_instance

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation (all 4 phases).
#   What: ImmunisHook class subclassing OpenClawAdapter. Initializes
#         all core components: config, sensors, Quartermaster, Armory,
#         response primitives, feedback, autonomic state. Runs sensor
#         polling and pipeline processing on on_message().
#   Why:  PRD §10.3 specifies the OpenClaw hook pattern. PRD §2.1
#         defines Immunis as an OpenClaw skill participating in the
#         NG-Lite substrate.
#   Settings: All settings loaded from config.yaml via ImmunisConfig.
#   How:  OpenClawAdapter subclass with singleton get_instance().
#         Sensors poll on each on_message() call. Quartermaster
#         processes buffered signals. Training wheels active on
#         fresh systems. Autonomic state transitions on CRITICAL.
# -------------------
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from openclaw_adapter import OpenClawAdapter

logger = logging.getLogger("immunis_hook")


class ImmunisHook(OpenClawAdapter):
    """OpenClaw integration hook for Immunis (PRD §10.3)."""

    MODULE_ID = "immunis"
    SKILL_NAME = "Immunis System Security"
    WORKSPACE_ENV = "IMMUNIS_WORKSPACE_DIR"
    DEFAULT_WORKSPACE = "~/.openclaw/immunis"

    def __init__(self) -> None:
        super().__init__()

        # --- Load Configuration (PRD §11) ---
        from core.config import ImmunisConfig
        config_path = os.path.join(
            os.path.expanduser("~/.et_modules/immunis"), "config.yaml"
        )
        # Also check local config.yaml
        if not os.path.exists(config_path):
            local_config = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "config.yaml"
            )
            if os.path.exists(local_config):
                config_path = local_config

        self._cfg = ImmunisConfig.from_yaml(config_path)

        # Kill switch check
        if self._cfg.emergency.kill_switch:
            logger.critical("KILL SWITCH ACTIVE — Immunis rejecting all processing")
            self._killed = True
        else:
            self._killed = False

        # --- Data Directories ---
        self._data_dir = Path(
            os.path.expanduser("~/.et_modules/immunis")
        )
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._threat_log_path = self._data_dir / "threat_log.jsonl"

        # --- Initialize Armory (PRD §6) ---
        from core.armory import Armory
        self._armory = Armory(
            config={
                "max_entries": self._cfg.armory.max_entries,
                "persistence_format": self._cfg.armory.persistence_format,
                "search_top_k": self._cfg.armory.search_top_k,
                "match_threshold": self._cfg.armory.match_threshold,
                "eviction_policy": self._cfg.armory.eviction_policy,
            },
            data_dir=str(self._data_dir),
            ecosystem=self._eco,
        )

        # --- Initialize Response Primitives (PRD §7) ---
        from core.response_primitives import get_all_primitives
        response_config = {
            "kill_grace_seconds": self._cfg.response.kill_grace_seconds,
            "quarantine_dir": self._cfg.response.quarantine_dir,
            "forensics_dir": self._cfg.response.forensics_dir,
            "forensics_min_disk_mb": self._cfg.response.forensics_min_disk_mb,
            "protected_pids": self._cfg.response.protected_pids,
            "protected_paths": self._cfg.response.protected_paths,
            "protected_destinations": self._cfg.response.protected_destinations,
        }
        self._primitives = get_all_primitives(response_config)

        # --- Initialize Feedback Manager (PRD §9) ---
        from core.feedback import FeedbackManager
        self._feedback = FeedbackManager(
            config={
                "training_wheels": {
                    "min_armory_entries": self._cfg.training_wheels.min_armory_entries,
                    "min_substrate_outcomes": self._cfg.training_wheels.min_substrate_outcomes,
                    "min_user_feedbacks": self._cfg.training_wheels.min_user_feedbacks,
                    "min_runtime_hours": self._cfg.training_wheels.min_runtime_hours,
                },
            },
            data_dir=str(self._data_dir),
            armory=self._armory,
            ecosystem=self._eco,
        )

        # --- Initialize Quartermaster (PRD §4) ---
        from core.quartermaster import Quartermaster
        self._quartermaster = Quartermaster(
            config={
                "signal_buffer_size": self._cfg.quartermaster.signal_buffer_size,
                "learn_observation_window": self._cfg.quartermaster.learn_observation_window,
                "thresholds": {
                    "auto_execute": self._cfg.thresholds.auto_execute,
                    "recommend": self._cfg.thresholds.recommend,
                    "host_premium": self._cfg.thresholds.host_premium,
                },
                "armory": {
                    "match_threshold": self._cfg.armory.match_threshold,
                },
            },
            armory=self._armory,
            ecosystem=self._eco,
            response_primitives=self._primitives,
            feedback=self._feedback,
            threat_logger=self._log_threat,
            training_wheels_active=self._feedback.is_training_wheels_active(),
        )

        # --- Initialize Sensors (PRD §5) ---
        self._sensors = []
        self._init_sensors()

        # --- Autonomic State (PRD §8) ---
        self._autonomic_state = "PARASYMPATHETIC"
        try:
            import ng_autonomic
            state = ng_autonomic.read_state()
            self._autonomic_state = state.get("state", "PARASYMPATHETIC")
        except Exception:
            pass

        # --- Checkpointing ---
        self._last_checkpoint = time.time()
        self._checkpoint_interval = self._cfg.checkpoint_interval_seconds

        logger.info(
            "[Immunis] Initialized — %d sensors active, "
            "training_wheels=%s, autonomic=%s",
            len(self._sensors),
            self._feedback.is_training_wheels_active(),
            self._autonomic_state,
        )

    def _init_sensors(self) -> None:
        """Initialize all enabled sensors (PRD §5)."""
        sensor_classes = []

        if self._cfg.sensors.filesystem.enabled:
            from core.sensors.filesystem_sensor import FilesystemSensor
            sensor_classes.append(
                (FilesystemSensor, self._sensor_config("filesystem"))
            )

        if self._cfg.sensors.process.enabled:
            from core.sensors.process_sensor import ProcessSensor
            sensor_classes.append(
                (ProcessSensor, self._sensor_config("process"))
            )

        if self._cfg.sensors.network.enabled:
            from core.sensors.network_sensor import NetworkSensor
            sensor_classes.append(
                (NetworkSensor, self._sensor_config("network"))
            )

        if self._cfg.sensors.dependency.enabled:
            from core.sensors.dependency_sensor import DependencySensor
            sensor_classes.append(
                (DependencySensor, self._sensor_config("dependency"))
            )

        if self._cfg.sensors.log.enabled:
            from core.sensors.log_sensor import LogSensor
            sensor_classes.append(
                (LogSensor, self._sensor_config("log"))
            )

        if self._cfg.sensors.memory.enabled:
            from core.sensors.memory_sensor import MemorySensor
            sensor_classes.append(
                (MemorySensor, self._sensor_config("memory"))
            )

        if self._cfg.sensors.substrate.enabled:
            from core.sensors.substrate_sensor import SubstrateSensor
            sensor_classes.append(
                (SubstrateSensor, self._sensor_config("substrate"))
            )

        for cls, cfg in sensor_classes:
            try:
                self._sensors.append(cls(config=cfg))
                logger.info("[Immunis] Sensor initialized: %s", cls.SENSOR_TYPE)
            except Exception as exc:
                logger.warning(
                    "[Immunis] Sensor init failed (%s): %s",
                    cls.SENSOR_TYPE, exc,
                )

    def _sensor_config(self, sensor_type: str) -> Dict[str, Any]:
        """Extract sensor config as a dict for the sensor constructor."""
        sensor_cfg = getattr(self._cfg.sensors, sensor_type, None)
        if sensor_cfg is None:
            return {}
        result = {}
        for k, v in sensor_cfg.__dict__.items():
            result[k] = v
        return result

    # -----------------------------------------------------------------
    # OpenClawAdapter implementation
    # -----------------------------------------------------------------

    def _embed(self, text: str) -> np.ndarray:
        """Embed text using sentence-transformers, fall back to hash.

        PRD §10.4: Use sentence-transformer if available, otherwise
        hash-based fallback.
        """
        if self._cfg.embedding.device != "disabled":
            try:
                from sentence_transformers import SentenceTransformer

                if not hasattr(self, "_st_model"):
                    self._st_model = SentenceTransformer(
                        self._cfg.embedding.model
                    )
                vec = self._st_model.encode(text, normalize_embeddings=True)
                return np.array(vec, dtype=np.float32)
            except Exception:
                pass

        return self._hash_embed(text)

    def _module_on_message(
        self, text: str, embedding: np.ndarray
    ) -> Dict[str, Any]:
        """Immunis-specific processing on each OpenClaw message.

        1. Poll all sensors for new signals
        2. Feed signals to the Quartermaster
        3. Process pipeline
        4. Check autonomic state transitions
        5. Process feedback responses
        6. Auto-checkpoint
        """
        if self._killed:
            return {"status": "killed", "reason": "Emergency kill switch active"}

        result: Dict[str, Any] = {"status": "ok"}

        # 1. Poll sensors
        total_signals = 0
        for sensor in self._sensors:
            try:
                signals = sensor.collect_signals()
                if signals:
                    self._quartermaster.ingest_signals(signals)
                    total_signals += len(signals)
            except Exception as exc:
                logger.debug("Sensor poll error (%s): %s", sensor.SENSOR_TYPE, exc)

        # 2. Process pipeline
        pipeline_results = self._quartermaster.process_batch(max_count=50)

        # 3. Check for autonomic state transitions (PRD §8.4)
        self._check_autonomic_transitions(pipeline_results)

        # 4. Process pending feedback responses
        self._feedback.process_responses()

        # 5. Update training wheels state
        self._quartermaster._training_wheels = (
            self._feedback.is_training_wheels_active()
        )

        # 6. Auto-checkpoint
        now = time.time()
        if now - self._last_checkpoint > self._checkpoint_interval:
            self._checkpoint()
            self._last_checkpoint = now

        # Build result
        active_threats = self._quartermaster.active_threats
        result["signals_ingested"] = total_signals
        result["pipeline_processed"] = len(pipeline_results)
        result["active_threats"] = len(active_threats)
        result["autonomic_state"] = self._autonomic_state
        result["training_wheels"] = self._feedback.is_training_wheels_active()
        result["buffer_size"] = self._quartermaster.buffer_size

        if active_threats:
            result["threat_summary"] = [
                {
                    "severity": t.assessment.severity.value if t.assessment else "unknown",
                    "category": t.classification.category if t.classification else "unknown",
                    "signal_id": t.signal.signal_id,
                }
                for t in active_threats[:5]
            ]

        return result

    def _module_stats(self) -> Dict[str, Any]:
        """Immunis-specific telemetry."""
        stats: Dict[str, Any] = {
            "quartermaster": self._quartermaster.get_stats(),
            "armory": self._armory.get_stats(),
            "feedback": self._feedback.get_stats(),
            "autonomic_state": self._autonomic_state,
            "sensors": {
                s.SENSOR_TYPE: s.get_stats() for s in self._sensors
            },
        }
        return stats

    # -----------------------------------------------------------------
    # Autonomic State Transitions (PRD §8.4)
    # -----------------------------------------------------------------

    def _check_autonomic_transitions(
        self, results: List[Any]
    ) -> None:
        """Check if autonomic state should change (PRD §8.4).

        Immunis writes SYMPATHETIC on CRITICAL severity.
        Writes PARASYMPATHETIC when threat neutralized and no
        other CRITICAL/HIGH events active.
        """
        from core.quartermaster import Severity

        has_critical = any(
            r.assessment is not None and r.assessment.severity == Severity.CRITICAL
            for r in results
        )

        if has_critical and self._autonomic_state != "SYMPATHETIC":
            self._set_autonomic("SYMPATHETIC", "critical", "CRITICAL threat detected")

        elif self._autonomic_state == "SYMPATHETIC":
            # Check if we can de-escalate
            active = self._quartermaster.active_threats
            has_active_critical = any(
                t.assessment is not None
                and t.assessment.severity in (Severity.CRITICAL, Severity.HIGH)
                for t in active
            )
            if not has_active_critical:
                self._set_autonomic(
                    "PARASYMPATHETIC", "none", "All threats neutralized"
                )

    def _set_autonomic(
        self, state: str, threat_level: str, reason: str
    ) -> None:
        """Write autonomic state (PRD §8.4)."""
        try:
            import ng_autonomic
            ng_autonomic.write_state(
                state=state,
                threat_level=threat_level,
                triggered_by="immunis",
                reason=reason,
            )
            self._autonomic_state = state
            logger.info(
                "[Immunis] Autonomic state → %s (reason: %s)", state, reason
            )
            # Checkpoint on state transition (PRD §12.4)
            self._checkpoint()
        except Exception as exc:
            logger.warning("Autonomic state write failed: %s", exc)

    # -----------------------------------------------------------------
    # Threat Logging (PRD §12.2)
    # -----------------------------------------------------------------

    def _log_threat(self, result: Any) -> None:
        """Log a pipeline result to threat_log.jsonl (PRD §12.2)."""
        try:
            entry = {
                "timestamp": time.time(),
                "signal_id": result.signal.signal_id,
                "sensor_type": result.signal.sensor_type,
                "event_type": result.signal.event_type,
            }
            if result.classification:
                entry["category"] = result.classification.category
                entry["known_signature_match"] = result.classification.known_signature_match
                entry["substrate_confidence"] = round(
                    result.classification.substrate_confidence, 4
                )
                entry["substrate_novelty"] = round(
                    result.classification.substrate_novelty, 4
                )
            if result.assessment:
                entry["severity"] = result.assessment.severity.value
            if result.response:
                entry["response_primitive"] = result.response.primitive_name
                entry["response_status"] = result.response.status
            entry["autonomic_state"] = self._autonomic_state

            with open(self._threat_log_path, "a") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as exc:
            logger.debug("Threat log write failed: %s", exc)

    # -----------------------------------------------------------------
    # Checkpointing (PRD §12.4)
    # -----------------------------------------------------------------

    def _checkpoint(self) -> None:
        """Save Armory and ecosystem state (PRD §12.4).

        Uses atomic write for consistency.
        """
        try:
            self._armory.save()
        except Exception as exc:
            logger.warning("Armory checkpoint failed: %s", exc)

        try:
            self._eco.save()
        except Exception as exc:
            logger.debug("Ecosystem checkpoint failed: %s", exc)

    # -----------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------

    def shutdown(self) -> None:
        """Graceful shutdown — checkpoint and stop sensors."""
        self._checkpoint()
        for sensor in self._sensors:
            if hasattr(sensor, "shutdown"):
                sensor.shutdown()
        logger.info("[Immunis] Shutdown complete")


# --------------------------------------------------------------------------
# Singleton wiring — identical pattern for all E-T Systems modules
# --------------------------------------------------------------------------

_INSTANCE: Optional[ImmunisHook] = None


def get_instance() -> ImmunisHook:
    """Return the Immunis OpenClaw hook singleton."""
    global _INSTANCE
    if _INSTANCE is None:
        _INSTANCE = ImmunisHook()
    return _INSTANCE
