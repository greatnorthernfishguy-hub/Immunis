"""
The Quartermaster — Immunis Threat Detection and Response Pipeline

Processes system-level signals through six stages:
  1. DETECT  — Receive signals from sensors
  2. CLASSIFY — Known signature match vs novel (substrate-based)
  3. ASSESS  — Severity scoring via substrate confidence
  4. RESPOND — Containment proportional to confidence
  5. REPORT  — Record outcome on substrate
  6. LEARN   — Evaluate response effectiveness

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation (Phases 1-4).
#   What: Quartermaster pipeline with all 6 stages. Stages 1-3 per
#         PRD §4.2-§4.4, stages 4-6 per PRD §4.5-§4.7. Signal buffer
#         via collections.deque. ThreatClassification and
#         ThreatAssessment dataclasses.
#   Why:  PRD §4 specifies the complete 6-stage pipeline.
#   Settings: signal_buffer_size=10000, learn_observation_window=300,
#         thresholds per PRD §4.4.
#   How:  deque-based signal buffer with backpressure. CLASSIFY uses
#         Armory fast-path then substrate. ASSESS uses confidence ×
#         novelty matrix per PRD §4.4 table. RESPOND uses validate()
#         then execute() contract. REPORT records on substrate. LEARN
#         tracks response effectiveness over observation window.
# -------------------
"""

from __future__ import annotations

import collections
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from core.sensors.base import ThreatSignal

logger = logging.getLogger("immunis.quartermaster")


# ---------------------------------------------------------------------------
# Data Structures
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    HIGH_NOVEL = "HIGH_NOVEL"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    LOW_NOVEL = "LOW_NOVEL"


@dataclass
class ThreatClassification:
    """Result of the CLASSIFY stage (PRD §4.3)."""

    signal: ThreatSignal
    category: str = "unknown"
    known_signature_match: bool = False
    matched_signature_id: Optional[str] = None
    substrate_novelty: float = 1.0
    substrate_confidence: float = 0.0
    recommended_response: Optional[str] = None


@dataclass
class ThreatAssessment:
    """Result of the ASSESS stage (PRD §4.4)."""

    classification: ThreatClassification
    severity: Severity = Severity.LOW
    action: str = "log_only"
    should_auto_execute: bool = False
    should_recommend: bool = False


@dataclass
class ResponseResult:
    """Result of a response primitive execution."""

    primitive_name: str = ""
    status: str = "skipped"
    detail: str = ""
    rollback_info: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0


@dataclass
class PipelineResult:
    """Complete result of processing one signal through the pipeline."""

    signal: ThreatSignal
    classification: Optional[ThreatClassification] = None
    assessment: Optional[ThreatAssessment] = None
    response: Optional[ResponseResult] = None
    reported: bool = False
    learned: bool = False
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Observation tracking for LEARN stage
# ---------------------------------------------------------------------------

@dataclass
class _ObservationEntry:
    """Tracks a response for effectiveness evaluation (PRD §4.7)."""

    pipeline_result: PipelineResult
    response_time: float
    category: str
    observation_deadline: float
    followup_count: int = 0
    evaluated: bool = False


# ---------------------------------------------------------------------------
# Quartermaster Pipeline
# ---------------------------------------------------------------------------

class Quartermaster:
    """Immunis's threat detection and response pipeline (PRD §4).

    Processes system-level signals through six stages:
    DETECT → CLASSIFY → ASSESS → RESPOND → REPORT → LEARN
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        armory: Optional[Any] = None,
        ecosystem: Optional[Any] = None,
        response_primitives: Optional[Dict[str, Any]] = None,
        feedback: Optional[Any] = None,
        threat_logger: Optional[Callable] = None,
        training_wheels_active: bool = True,
    ) -> None:
        self._config = config or {}
        self._armory = armory
        self._eco = ecosystem
        self._primitives = response_primitives or {}
        self._feedback = feedback
        self._threat_logger = threat_logger
        self._training_wheels = training_wheels_active

        buffer_size = self._config.get("signal_buffer_size", 10000)
        self._signal_buffer: collections.deque = collections.deque(maxlen=buffer_size)
        self._observation_window = self._config.get("learn_observation_window", 300)

        # Thresholds (PRD §4.4)
        thresholds = self._config.get("thresholds", {})
        self._auto_execute_threshold = thresholds.get("auto_execute", 0.70)
        self._recommend_threshold = thresholds.get("recommend", 0.40)
        self._host_premium_threshold = thresholds.get("host_premium", 0.15)

        # Pipeline state
        self._results: List[PipelineResult] = []
        self._observations: List[_ObservationEntry] = []
        self._lock = threading.Lock()
        self._total_processed = 0
        self._total_threats = 0
        self._dropped_signals = 0

    # -------------------------------------------------------------------
    # Stage 1: DETECT (PRD §4.2)
    # -------------------------------------------------------------------

    def ingest_signal(self, signal: ThreatSignal) -> bool:
        """Add a signal to the processing buffer.

        Returns True if accepted, False if dropped (buffer full).
        """
        if len(self._signal_buffer) >= self._signal_buffer.maxlen:
            self._dropped_signals += 1
            logger.warning(
                "Signal buffer full — dropping oldest. Total dropped: %d",
                self._dropped_signals,
            )
        self._signal_buffer.append(signal)
        return True

    def ingest_signals(self, signals: List[ThreatSignal]) -> int:
        """Ingest multiple signals. Returns count accepted."""
        for s in signals:
            self.ingest_signal(s)
        return len(signals)

    # -------------------------------------------------------------------
    # Stage 2: CLASSIFY (PRD §4.3)
    # -------------------------------------------------------------------

    def _classify(self, signal: ThreatSignal) -> ThreatClassification:
        """Classify a signal via Armory fast-path then substrate."""
        classification = ThreatClassification(signal=signal)

        if signal.embedding is None:
            return classification

        # Step 1: Known signature prefilter (fast path)
        if self._armory is not None:
            match = self._armory.search(signal.embedding, top_k=1)
            if match:
                best = match[0]
                threshold = self._config.get("armory", {}).get(
                    "match_threshold", 0.90
                )
                if best.get("similarity", 0) >= threshold:
                    classification.known_signature_match = True
                    classification.matched_signature_id = best.get("entry_id")
                    classification.category = best.get("category", "unknown")
                    classification.substrate_confidence = best.get("similarity", 0)
                    classification.recommended_response = best.get(
                        "response_primitive"
                    )
                    return classification

        # Step 2: Substrate-based classification (novel path)
        if self._eco is not None:
            try:
                ctx = self._eco.get_context(signal.embedding)
                classification.substrate_novelty = ctx.get("novelty", 1.0)

                recs = ctx.get("recommendations", [])
                if recs:
                    # Recommendations from substrate
                    if isinstance(recs[0], (list, tuple)) and len(recs[0]) >= 2:
                        classification.substrate_confidence = float(recs[0][1])
                        target = str(recs[0][0])
                        if target.startswith("threat:"):
                            classification.category = self._infer_category(target)
                    elif isinstance(recs[0], dict):
                        classification.substrate_confidence = float(
                            recs[0].get("confidence", 0)
                        )
            except Exception as exc:
                logger.debug("Substrate classification failed: %s", exc)

        return classification

    @staticmethod
    def _infer_category(target_id: str) -> str:
        """Infer threat category from a substrate target_id."""
        categories = [
            "malware", "exploit", "exfiltration", "persistence",
            "lateral_movement", "supply_chain", "resource_abuse",
            "substrate_drift",
        ]
        lower = target_id.lower()
        for cat in categories:
            if cat in lower:
                return cat
        return "unknown"

    # -------------------------------------------------------------------
    # Stage 3: ASSESS (PRD §4.4)
    # -------------------------------------------------------------------

    def _assess(self, classification: ThreatClassification) -> ThreatAssessment:
        """Determine severity and recommended action.

        PRD §4.4 severity matrix:
        Confidence ≥ 0.70, Any novelty       → CRITICAL, auto-execute
        0.40–0.70, novelty < 0.50            → HIGH, recommend
        0.40–0.70, novelty ≥ 0.50            → HIGH_NOVEL, recommend + flag
        0.15–0.40, Any                       → MEDIUM, log + observe
        < 0.15, novelty < 0.50               → LOW, log only
        < 0.15, novelty ≥ 0.50               → LOW_NOVEL, log + observe elevated
        """
        conf = classification.substrate_confidence
        novelty = classification.substrate_novelty

        if conf >= self._auto_execute_threshold:
            severity = Severity.CRITICAL
            action = "auto_execute"
            auto = True
            recommend = False
        elif conf >= self._recommend_threshold:
            if novelty >= 0.50:
                severity = Severity.HIGH_NOVEL
                action = "recommend_and_flag"
            else:
                severity = Severity.HIGH
                action = "recommend"
            auto = False
            recommend = True
        elif conf >= self._host_premium_threshold:
            severity = Severity.MEDIUM
            action = "log_and_observe"
            auto = False
            recommend = False
        else:
            if novelty >= 0.50:
                severity = Severity.LOW_NOVEL
                action = "log_and_observe_elevated"
            else:
                severity = Severity.LOW
                action = "log_only"
            auto = False
            recommend = False

        return ThreatAssessment(
            classification=classification,
            severity=severity,
            action=action,
            should_auto_execute=auto,
            should_recommend=recommend,
        )

    # -------------------------------------------------------------------
    # Stage 4: RESPOND (PRD §4.5)
    # -------------------------------------------------------------------

    def _respond(
        self, assessment: ThreatAssessment
    ) -> ResponseResult:
        """Select and execute a response primitive (PRD §4.5).

        Training wheels mode (PRD §9.1): Only AlertOnly and
        SnapshotForensics are allowed regardless of severity.
        """
        classification = assessment.classification
        result = ResponseResult()

        # Training wheels: limit to safe primitives
        if self._training_wheels:
            if assessment.severity in (Severity.CRITICAL, Severity.HIGH, Severity.HIGH_NOVEL):
                result = self._execute_primitive("SnapshotForensics", classification)
                # Also request feedback
                if self._feedback is not None:
                    self._feedback.request_feedback(classification, assessment)
            else:
                result = self._execute_primitive("AlertOnly", classification)
            return result

        # Normal operation: select primitive by severity
        if assessment.should_auto_execute:
            primitive_name = self._select_primitive(classification)
            result = self._execute_primitive(primitive_name, classification)
        elif assessment.should_recommend:
            # Request user feedback for HIGH/HIGH_NOVEL
            if self._feedback is not None:
                self._feedback.request_feedback(classification, assessment)
            result = self._execute_primitive("AlertOnly", classification)
        elif assessment.severity == Severity.MEDIUM:
            result = self._execute_primitive("SnapshotForensics", classification)
        else:
            result = self._execute_primitive("AlertOnly", classification)

        return result

    def _select_primitive(
        self, classification: ThreatClassification
    ) -> str:
        """Select the response primitive matching the signal type.

        PRD §4.5: Select the least-invasive response appropriate to
        the severity level.
        """
        # If known signature has a recorded effective response, use it
        if classification.known_signature_match and classification.recommended_response:
            return classification.recommended_response

        # Map sensor type to appropriate primitive
        sensor_type = classification.signal.sensor_type
        primitive_map = {
            "process": "KillProcess",
            "filesystem": "QuarantineFile",
            "network": "BlockConnection",
            "substrate": "IsolateModule",
            "dependency": "QuarantineFile",
            "log": "AlertOnly",
            "memory": "AlertOnly",
        }
        return primitive_map.get(sensor_type, "AlertOnly")

    def _execute_primitive(
        self,
        name: str,
        classification: ThreatClassification,
    ) -> ResponseResult:
        """Execute a response primitive with validate-before-execute contract.

        PRD §4.5: validate() MUST be called before execute(). Quartermaster
        MUST NOT call execute() without validate() returning passed=True.
        """
        primitive = self._primitives.get(name)
        if primitive is None:
            # Fallback to AlertOnly
            primitive = self._primitives.get("AlertOnly")
            if primitive is None:
                return ResponseResult(
                    primitive_name=name,
                    status="failed",
                    detail="Primitive not available",
                )

        context = {
            "signal": classification.signal,
            "classification": classification,
            "signal_id": classification.signal.signal_id,
            "pid": classification.signal.raw_data.get("pid"),
            "path": classification.signal.raw_data.get("src_path"),
            "ip": classification.signal.raw_data.get("dest_ip"),
            "port": classification.signal.raw_data.get("dest_port"),
            "module_id": classification.signal.raw_data.get("module_id"),
        }

        start = time.time()
        try:
            validation = primitive.validate(context)
            if not validation.passed:
                return ResponseResult(
                    primitive_name=name,
                    status="validation_failed",
                    detail=validation.reason,
                    duration_ms=(time.time() - start) * 1000,
                )

            execution = primitive.execute(context)
            return ResponseResult(
                primitive_name=name,
                status=execution.status,
                detail=execution.detail,
                rollback_info=execution.rollback_info,
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            return ResponseResult(
                primitive_name=name,
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )

    # -------------------------------------------------------------------
    # Stage 5: REPORT (PRD §4.6)
    # -------------------------------------------------------------------

    def _report(
        self,
        classification: ThreatClassification,
        assessment: ThreatAssessment,
        response: ResponseResult,
    ) -> bool:
        """Record outcome on the NG-Lite substrate (PRD §4.6)."""
        if self._eco is None or classification.signal.embedding is None:
            return False

        try:
            self._eco.record_outcome(
                embedding=classification.signal.embedding,
                target_id=f"threat:{classification.signal.signal_id}",
                success=response.status == "success",
                metadata={
                    "source": "immunis",
                    "category": classification.category,
                    "severity": assessment.severity.value,
                    "response_primitive": response.primitive_name,
                    "response_status": response.status,
                    "known_signature": classification.known_signature_match,
                    "novelty": classification.substrate_novelty,
                },
            )
            return True
        except Exception as exc:
            logger.warning("Substrate report failed: %s", exc)
            return False

    # -------------------------------------------------------------------
    # Stage 6: LEARN (PRD §4.7)
    # -------------------------------------------------------------------

    def _start_observation(
        self,
        result: PipelineResult,
    ) -> None:
        """Begin observation window for response effectiveness (PRD §4.7)."""
        if result.classification is None or result.assessment is None:
            return
        if result.response is None or result.response.status == "skipped":
            return

        entry = _ObservationEntry(
            pipeline_result=result,
            response_time=time.time(),
            category=result.classification.category,
            observation_deadline=time.time() + self._observation_window,
        )
        self._observations.append(entry)

    def _evaluate_observations(self) -> None:
        """Evaluate pending observations whose windows have elapsed.

        PRD §4.7: If no follow-up signals of the same category arrive
        within the observation window, the response is marked effective.
        """
        now = time.time()
        for obs in self._observations:
            if obs.evaluated or now < obs.observation_deadline:
                continue
            obs.evaluated = True

            pr = obs.pipeline_result
            if pr.response is None or pr.classification is None:
                continue

            if pr.response.status == "success" and obs.followup_count == 0:
                # Response was effective
                self._learn_outcome(pr, effective=True)
            elif pr.response.status == "success" and obs.followup_count > 0:
                # Partially effective
                self._learn_outcome(pr, effective=True, partial=True)
            elif pr.response.status == "failed":
                self._learn_outcome(pr, effective=False)

        # Prune evaluated observations
        self._observations = [
            o for o in self._observations if not o.evaluated
        ]

    def _learn_outcome(
        self,
        result: PipelineResult,
        effective: bool,
        partial: bool = False,
    ) -> None:
        """Update substrate based on response effectiveness (PRD §4.7)."""
        if self._eco is None or result.classification is None:
            return
        if result.classification.signal.embedding is None:
            return

        try:
            self._eco.record_outcome(
                embedding=result.classification.signal.embedding,
                target_id=f"response:{result.response.primitive_name}",
                success=effective,
                metadata={
                    "category": result.classification.category,
                    "partial": partial,
                    "followup_count": 0,
                },
            )
        except Exception as exc:
            logger.debug("Learn outcome failed: %s", exc)

    def _track_followups(self, classification: ThreatClassification) -> None:
        """Track follow-up signals for pending observations."""
        for obs in self._observations:
            if not obs.evaluated and obs.category == classification.category:
                obs.followup_count += 1

    # -------------------------------------------------------------------
    # Pipeline Processing
    # -------------------------------------------------------------------

    def process_one(self) -> Optional[PipelineResult]:
        """Process one signal through the full pipeline.

        Pops the oldest signal from the buffer and runs it through
        all six stages.
        """
        if not self._signal_buffer:
            return None

        signal = self._signal_buffer.popleft()
        result = PipelineResult(signal=signal)

        # Stage 2: CLASSIFY
        classification = self._classify(signal)
        result.classification = classification

        # Track follow-ups for pending observations
        self._track_followups(classification)

        # Stage 3: ASSESS
        assessment = self._assess(classification)
        result.assessment = assessment

        # Log to threat log
        if self._threat_logger is not None:
            self._threat_logger(result)

        # Stage 4: RESPOND
        response = self._respond(assessment)
        result.response = response

        # Stage 5: REPORT
        result.reported = self._report(classification, assessment, response)

        # Stage 6: LEARN (start observation)
        self._start_observation(result)
        result.learned = True

        # Evaluate any expired observations
        self._evaluate_observations()

        self._total_processed += 1
        if classification.category != "unknown":
            self._total_threats += 1

        with self._lock:
            self._results.append(result)
            # Keep bounded history
            if len(self._results) > 1000:
                self._results = self._results[-1000:]

        return result

    def process_batch(self, max_count: int = 100) -> List[PipelineResult]:
        """Process up to max_count signals from the buffer."""
        results: List[PipelineResult] = []
        for _ in range(max_count):
            r = self.process_one()
            if r is None:
                break
            results.append(r)
        return results

    # -------------------------------------------------------------------
    # Public State
    # -------------------------------------------------------------------

    @property
    def buffer_size(self) -> int:
        return len(self._signal_buffer)

    @property
    def active_threats(self) -> List[PipelineResult]:
        """Recent results with non-LOW severity."""
        with self._lock:
            return [
                r for r in self._results[-100:]
                if r.assessment is not None
                and r.assessment.severity in (
                    Severity.CRITICAL, Severity.HIGH, Severity.HIGH_NOVEL,
                )
            ]

    def get_stats(self) -> Dict[str, Any]:
        """Quartermaster telemetry."""
        return {
            "buffer_size": len(self._signal_buffer),
            "buffer_capacity": self._signal_buffer.maxlen,
            "total_processed": self._total_processed,
            "total_threats": self._total_threats,
            "dropped_signals": self._dropped_signals,
            "pending_observations": len(self._observations),
            "training_wheels_active": self._training_wheels,
        }
