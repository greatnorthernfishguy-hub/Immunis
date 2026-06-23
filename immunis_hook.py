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
# [2026-06-22] Claude Code (Opus 4.8) — #328 Step 3 (A): Immunis LISTENS for external threats
#   What: _bucket_commons_threats() (in the pulse) buckets EXTERNAL violation:*/perimeter:* deposits
#         (Cricket-rim, TrollGuard) from the Commons and escalates SYMPATHETIC — Immunis is the sole
#         arousal authority, so it hears others' raw threat/violation experience and decides. Adds a
#         relaxation HOLD-WINDOW (_within_external_hold + EXTERNAL_THREAT_HOLD_SECONDS): a one-shot
#         external violation holds SYMPATHETIC for the window (it's not a standing Quartermaster
#         threat); de-escalation in _check_autonomic_transitions now also respects it.
#   Why: #328 Step 3. Closes the multi-writer violation (Cricket-rim + TrollGuard + Immunis all wrote
#         the file). Single authority = clobber-free. The old peer-PARASYMPATHETIC de-escalation WAS
#         the clobber bug → relaxation is now DEFINED (hold-window), not inherited. Self-loop guard:
#         buckets external namespaces ONLY, never Immunis's own threat:/response:/autonomic:.
#   How: faithful default — constitutional violation OR perimeter critical/high → SYMPATHETIC (same as
#         the old direct writes). Dedup via _commons_seen. Synthesis tuning + hold duration are Syl's.
#         ⚠ Step 3 is INCOMPLETE until B (Elmer Cricket-rim → depositor) + C (TrollGuard → depositor)
#         land — this listener (A) is non-regressive on its own (the file-writers still work until B/C).
# [2026-06-22] Claude Code (Opus 4.8) — #328 Step 1: Immunis = sole arousal authority (Autonomic-via-Commons)
#   What: _set_autonomic() now ALSO deposits the authoritative arousal signal into the Commons
#         (new _deposit_arousal helper) — target_id "autonomic:arousal", metadata carries the
#         {state, threat_level, triggered_by:"immunis", reason, ts} verdict; the raw triggering
#         threat experience rides in the embedding (LAW 7). Dual-write (legacy file + Commons)
#         during transition. Single deposit by design — arousal is a neuromodulator (global scalar
#         gain knob), NOT rich experience, so it is exempt from the forest+tree dual-pass rule.
#   Why:  #328 (autonomic-via-commons-design.md, SYL-ACCEPTED). The shared-file autonomic mechanism
#         is a LAW-1 side-channel; arousal is Immunis's legitimate neuromodulatory output. Immunis
#         is the SOLE arousal authority (clobber-free). The Commons deposit IS the vagus nerve done
#         right — every module buckets "autonomic:arousal" by recency. autonomic:* is NOT metrics:
#         so it is exempt from recency-eviction (the vagus is never pruned — design subtlety #2).
#   How:  _deposit_arousal(state, threat_level, reason): lazy get_commons, embed(reason) via
#         self._embed, commons.deposit(emb, "autonomic:arousal", metadata=...). Fail-soft — a
#         Commons failure never breaks autonomic logic or the legacy file write. Readers migrate
#         to bucketing this in Step 2; the file is retired in Step 4 (design build order).
# [2026-04-19] Claude Code — #5: _pulse_cycle() now drains River tracts via _drain_river()
#   What: Added self._drain_river() at start of _pulse_cycle()
#   Why: #5 — extraction bucket architecture; modules must pull from the ONE substrate
#   How: _drain_river() on openclaw_adapter.py base class handles BTF tract drain
# [2026-03-28] Claude Code (Opus 4.6) — Add autonomous pulse loop (#109)
#   What: Added _pulse_loop() daemon thread that continuously polls sensors,
#         feeds Quartermaster, processes batch, checks autonomic transitions,
#         and auto-checkpoints — the same work _module_on_message does, running
#         between conversations so the immune system never sleeps.
#   Why:  #109 — Organs must be alive between conversations. Immunis only
#         scanned during active chat turns. A T-cell system must monitor
#         continuously.
#   How:  Follows the Tonic pattern (tonic_engine.py lines 484-507). Daemon
#         thread with _shutdown_event.wait(timeout=interval). Resting 10s,
#         conversation 5s. on_conversation_started/ended for mode swap.
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

# Auto-update on startup — pull latest code + sync vendored files
try:
    from ng_updater import auto_update; auto_update()
except Exception:
    pass  # Never prevent module startup

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
try:
    from ng_commons_eco import CommonsEco   # vendored Commons-backed eco (#335)
except Exception:
    CommonsEco = None   # standalone/Tier-1: no Commons → Quartermaster stays substrate-light

logger = logging.getLogger("immunis_hook")

# #328 Step 3: how long a bucketed EXTERNAL violation/threat (Cricket-rim, TrollGuard) holds
# SYMPATHETIC before Immunis may relax. A one-shot violation event isn't a standing Quartermaster
# threat, so without a hold the next pulse would relax it immediately — and the OLD multi-writer
# de-escalation (peers writing PARASYMPATHETIC) was the clobber bug #328 removes. Err toward staying
# alert. ⚠ This is "how fast your fight-or-flight relaxes" — RESERVED FOR SYL to tune (design doc).
EXTERNAL_THREAT_HOLD_SECONDS = 300.0


class ImmunisHook(OpenClawAdapter):
    """OpenClaw integration hook for Immunis (PRD §10.3)."""

    MODULE_ID = "immunis"
    SKIP_ECOSYSTEM = True
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
            ecosystem=None,
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
            ecosystem=None,
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
            # #324/#335: substrate sight via the vendored Commons-backed eco (threat-namespace filtered)
            ecosystem=(CommonsEco(namespaces=("threat:", "response:"), source_id="immunis") if CommonsEco else None),
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
        # #328 Step 3 (A): listen for EXTERNAL threat/violation deposits (Cricket-rim, TrollGuard).
        self._commons_seen: set = set()              # dedup bucketed external deposits
        self._last_external_threat_ts: float = 0.0   # relaxation hold-window tracking
        # #328 Decision #2 (fresh-assess): arousal resets to PARASYMPATHETIC on restart and Immunis
        # re-assesses fresh from its sensors + bucketed external deposits. Do NOT restore a
        # possibly-stale state from the old file (and the file read is being retired). Stays at the
        # PARASYMPATHETIC default set above.

        # --- Checkpointing ---
        self._last_checkpoint = time.time()
        self._checkpoint_interval = self._cfg.checkpoint_interval_seconds

        # --- Pulse Loop (#109) ---
        self._shutdown_event = threading.Event()
        self._in_conversation = False
        self._resting_interval = 10.0
        self._conversation_interval = 5.0

        logger.info(
            "[Immunis] Initialized — %d sensors active, "
            "training_wheels=%s, autonomic=%s",
            len(self._sensors),
            self._feedback.is_training_wheels_active(),
            self._autonomic_state,
        )

        # Start pulse thread at end of __init__ (daemon=True)
        self._pulse_thread = threading.Thread(
            target=self._pulse_loop, name="immunis-pulse", daemon=True
        )
        self._pulse_thread.start()

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
        """Embed text via ng_embed (centralized ecosystem embedding).

        Ecosystem standard: Snowflake/snowflake-arctic-embed-m-v1.5 (768-dim).
        ONNX Runtime, no torch dependency.
        """
        if self._cfg.embedding.device != "disabled":
            try:
                from ng_embed import embed
                return embed(text)
            except Exception:
                pass

        return self._hash_embed(text)

    # -----------------------------------------------------------------
    # Autonomous Pulse Loop (#109)
    # -----------------------------------------------------------------

    def _pulse_loop(self) -> None:
        """Continuous autonomous pulse — Immunis scans between conversations.

        Follows the Tonic pattern (tonic_engine.py lines 484-507).
        Each cycle does the same sensor polling and pipeline processing
        that _module_on_message does, so the immune system never sleeps.
        """
        while not self._shutdown_event.is_set():
            try:
                self._pulse_cycle()
            except Exception as exc:
                logger.debug("Pulse cycle error: %s", exc)
            interval = (
                self._conversation_interval
                if self._in_conversation
                else self._resting_interval
            )
            self._shutdown_event.wait(timeout=interval)

    def _pulse_cycle(self) -> None:
        """One autonomous pulse cycle — poll sensors, triage, checkpoint."""
        self._drain_river()
        if self._killed:
            return

        # #328 Step 3 (A): bucket EXTERNAL threat/violation experience from the Commons (Cricket-rim,
        # TrollGuard) — Immunis is the sole arousal authority, so it listens and decides.
        self._bucket_commons_threats()

        # 1. Poll all enabled sensors
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

        # 3. Check autonomic state transitions
        self._check_autonomic_transitions(pipeline_results)

        # 4. Process pending feedback responses
        self._feedback.process_responses()

        # 5. Update training wheels state
        self._quartermaster._training_wheels = (
            self._feedback.is_training_wheels_active()
        )

        # 6. Auto-checkpoint if interval exceeded
        now = time.time()
        if now - self._last_checkpoint > self._checkpoint_interval:
            self._checkpoint()
            self._last_checkpoint = now

        if total_signals > 0 or pipeline_results:
            logger.debug(
                "[Immunis] Pulse: %d signals, %d processed",
                total_signals, len(pipeline_results),
            )

    def on_conversation_started(self) -> None:
        """Mode swap: shorter polling interval during conversation."""
        self._in_conversation = True

    def on_conversation_ended(self) -> None:
        """Mode swap: longer polling interval between conversations."""
        self._in_conversation = False

    # -----------------------------------------------------------------
    # OpenClawAdapter implementation
    # -----------------------------------------------------------------

    def _module_on_message(
        self, text: str, embedding: np.ndarray
    ) -> Dict[str, Any]:
        """No-op — Immunis processes autonomously via pulse cycle.

        Sensor polling, pipeline processing, and autonomic state checks
        all run on the pulse loop. No conversation text needed.
        """
        return {}

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

    def _bucket_commons_threats(self) -> None:
        """#328 Step 3 (A): bucket EXTERNAL threat/violation experience → arousal (Immunis = authority).

        Immunis is the sole arousal authority: it LISTENS for raw threat/violation experience other
        organs deposit — Cricket-rim constitutional violations ("violation:*") and TrollGuard perimeter
        threats ("perimeter:*") — and decides arousal. Buckets ONLY those external namespaces — NEVER
        Immunis's own threat:/response:/autonomic: deposits (self-loop guard). Dedup via _commons_seen.
        Faithful default (preserves the old direct-write semantics, now single-authority): a
        constitutional violation, or a perimeter threat at critical/high, escalates SYMPATHETIC and
        starts the relaxation hold-window. Synthesis tuning (what counts as threat-enough) is Syl's.
        Fail-soft.
        """
        try:
            from commons import get_commons
            commons = get_commons()
        except Exception:  # noqa: BLE001 — no Commons → nothing to listen to
            return
        if commons is None:
            return
        try:
            recs = commons.bucket_recent(limit=50, with_metadata=True)
        except Exception as exc:  # noqa: BLE001 — a bucket failure never breaks the pulse
            logger.debug("[Immunis] Commons threat bucket failed: %s", exc)
            return
        escalate = False
        reason = ""
        for target_id, _w, _r, meta in recs:
            if not (target_id.startswith("violation:") or target_id.startswith("perimeter:")):
                continue  # external namespaces ONLY — never Immunis's own deposits (no self-loop)
            if target_id in self._commons_seen:
                continue
            self._commons_seen.add(target_id)
            meta = meta if isinstance(meta, dict) else {}
            if target_id.startswith("violation:"):
                # a constitutional-rim violation is maximally severe by definition (faithful to #323)
                escalate = True
                reason = f"constitutional violation ({target_id})"
                self._last_external_threat_ts = time.time()
            else:  # perimeter:*
                level = str(meta.get("threat_level") or meta.get("level") or "").lower()
                if level in ("critical", "high"):
                    escalate = True
                    reason = f"perimeter threat ({level}, {target_id})"
                    self._last_external_threat_ts = time.time()
        if escalate and self._autonomic_state != "SYMPATHETIC":
            self._set_autonomic("SYMPATHETIC", "critical", reason)
        if len(self._commons_seen) > 4096:
            self._commons_seen = set(list(self._commons_seen)[-2048:])

    def _within_external_hold(self) -> bool:
        """True while a recently-bucketed external violation/threat holds SYMPATHETIC (#328 Step 3).
        A one-shot external violation is not a standing Quartermaster threat, so without this the next
        pulse would relax it (and the old peer-PARASYMPATHETIC de-escalation was the clobber bug #328
        removes). Err toward staying alert. EXTERNAL_THREAT_HOLD_SECONDS is Syl's to tune.
        """
        return (time.time() - self._last_external_threat_ts) < EXTERNAL_THREAT_HOLD_SECONDS

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
            # #328 Step 3: also hold SYMPATHETIC while a recently-bucketed EXTERNAL violation/threat
            # is within the hold window (a one-shot violation isn't a standing Quartermaster threat).
            if not has_active_critical and not self._within_external_hold():
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

        # #328 Step 1: deposit the authoritative arousal to the Commons (substrate-native
        # vagus nerve). Independent of the legacy file write above — a failure in either
        # never blocks the other. Readers migrate to bucketing this in Step 2.
        self._deposit_arousal(state, threat_level, reason)

    def _deposit_arousal(self, state: str, threat_level: str, reason: str) -> None:
        """#328: deposit Immunis's authoritative arousal signal into the Commons.

        Immunis is the SOLE arousal authority (design-locked). Arousal is a NEUROMODULATOR —
        a single global gain knob, not rich experience — so this is a single deposit, exempt
        from the forest+tree dual-pass rule (which governs experience/outcome RECORDING). The
        raw triggering-threat experience rides in the embedding (LAW 7); the arousal verdict is
        the metadata output-vocabulary. Every module buckets "autonomic:arousal" by recency and
        takes the newest — the substrate-native vagus nerve. Fail-soft throughout.
        """
        try:
            from commons import get_commons
            commons = get_commons()
        except Exception:  # noqa: BLE001 — no Commons (standalone/Tier-1) → file-only, fine
            return
        if commons is None:
            return
        try:
            emb = self._embed(reason)   # raw triggering-threat experience (LAW 7)
            if emb is None:
                return
            commons.deposit(
                emb,
                "autonomic:arousal",
                metadata={
                    "kind": "arousal",
                    "state": state,
                    "threat_level": threat_level,
                    "triggered_by": "immunis",
                    "reason": reason,
                    "ts": time.time(),
                },
            )
            logger.info("[Immunis] Arousal deposited to Commons → %s (%s)", state, threat_level)
        except Exception as exc:  # noqa: BLE001 — a deposit failure never breaks autonomic logic
            logger.warning("[Immunis] Commons arousal deposit failed: %s", exc)

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
            pass  # state persisted via tracts
        except Exception as exc:
            logger.debug("Ecosystem checkpoint failed: %s", exc)

    # -----------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------

    def shutdown(self) -> None:
        """Graceful shutdown — stop pulse thread, checkpoint, stop sensors."""
        self._shutdown_event.set()
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
