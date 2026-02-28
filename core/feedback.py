"""
Immunis User Feedback Mechanism — Training Wheels + User Confirmation

When Immunis needs user input — either in observe-only mode or for
MEDIUM/HIGH severity events — it writes a feedback request to the
feedback queue. The OpenClaw host or a dedicated UI reads this queue.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: FeedbackManager class with request_feedback(), check_response(),
#         process_response(), and training wheels graduation check.
#   Why:  PRD §9 specifies user feedback mechanism with training wheels
#         graduation criteria: min_armory_entries, min_substrate_outcomes,
#         min_user_feedbacks, min_runtime_hours.
#   Settings: feedback_queue at ~/.et_modules/immunis/feedback_queue.json.
#         Training wheels defaults per PRD §9.1.
#   How:  JSON file-based queue. Feedback requests written with options
#         (threat/safe/unsure/approve/deny). Responses read and applied
#         to Armory and substrate.
# -------------------
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("immunis.feedback")


class FeedbackManager:
    """User feedback mechanism for Immunis (PRD §9).

    Manages the feedback queue and training wheels graduation.
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        data_dir: Optional[str] = None,
        armory: Optional[Any] = None,
        ecosystem: Optional[Any] = None,
    ) -> None:
        self._config = config or {}
        self._armory = armory
        self._eco = ecosystem

        self._data_dir = Path(
            data_dir or os.path.expanduser("~/.et_modules/immunis")
        )
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._queue_path = self._data_dir / "feedback_queue.json"

        # Training wheels thresholds (PRD §9.1)
        tw = self._config.get("training_wheels", {})
        self._min_armory = tw.get("min_armory_entries", 50)
        self._min_outcomes = tw.get("min_substrate_outcomes", 100)
        self._min_feedbacks = tw.get("min_user_feedbacks", 20)
        self._min_hours = tw.get("min_runtime_hours", 24)

        # State
        self._feedback_count = 0
        self._start_time = time.time()
        self._pending: List[Dict[str, Any]] = []

        self._load_queue()

    def request_feedback(
        self,
        classification: Any,
        assessment: Any,
    ) -> str:
        """Create a feedback request for the user (PRD §9.2).

        Returns the request_id.
        """
        request_id = str(uuid.uuid4())

        # Build signal summary
        signal = getattr(classification, "signal", None)
        sensor_type = getattr(signal, "sensor_type", "unknown") if signal else "unknown"
        event_type = getattr(signal, "event_type", "unknown") if signal else "unknown"
        raw_data = getattr(signal, "raw_data", {}) if signal else {}

        summary_parts = [f"{sensor_type} sensor: {event_type}"]
        if "pid" in raw_data:
            comm = raw_data.get("comm", "")
            summary_parts.append(f"PID {raw_data['pid']} ({comm})")
        if "src_path" in raw_data:
            summary_parts.append(f"path: {raw_data['src_path']}")
        if "dest_ip" in raw_data:
            summary_parts.append(
                f"→ {raw_data['dest_ip']}:{raw_data.get('dest_port', '')}"
            )

        category = getattr(classification, "category", "unknown")
        severity = getattr(assessment, "severity", "unknown")
        severity_str = severity.value if hasattr(severity, "value") else str(severity)
        confidence = getattr(classification, "substrate_confidence", 0.0)
        novelty = getattr(classification, "substrate_novelty", 1.0)

        recommended = "alert_only"
        if hasattr(assessment, "action"):
            recommended = assessment.action

        request = {
            "request_id": request_id,
            "timestamp": time.time(),
            "signal_summary": " | ".join(summary_parts),
            "category": category,
            "severity": severity_str,
            "substrate_confidence": round(confidence, 3),
            "substrate_novelty": round(novelty, 3),
            "recommended_action": recommended,
            "options": [
                {"id": "threat", "label": "Yes, this is a threat",
                 "action": "execute_recommended_response"},
                {"id": "safe", "label": "No, this is expected",
                 "action": "mark_false_positive"},
                {"id": "unsure", "label": "I'm not sure",
                 "action": "snapshot_and_observe"},
                {"id": "approve", "label": "Approve recommended action",
                 "action": "execute_recommended_response"},
                {"id": "deny", "label": "Deny recommended action",
                 "action": "alert_only"},
            ],
            "status": "pending",
        }

        self._pending.append(request)
        self._save_queue()

        logger.info(
            "[Feedback] Request %s: %s (severity=%s, confidence=%.2f)",
            request_id, " | ".join(summary_parts), severity_str, confidence,
        )

        return request_id

    def check_response(self, request_id: str) -> Optional[Dict[str, Any]]:
        """Check if a feedback response exists for a request."""
        response_path = self._data_dir / "feedback_responses.json"
        if not response_path.exists():
            return None

        try:
            with open(response_path, "r") as f:
                responses = json.load(f)
            for resp in responses:
                if resp.get("request_id") == request_id:
                    return resp
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def process_responses(self) -> int:
        """Process any pending feedback responses.

        PRD §9.2: When a response is received:
        - "threat" → Record as confirmed threat. Strengthen pathways.
        - "safe" → Record as false positive in Armory. Weaken pathways.
        - "unsure" → Snapshot. Continue observing.
        - "approve" → Same as "threat".
        - "deny" → Alert only, no false positive marking.

        Returns number of responses processed.
        """
        response_path = self._data_dir / "feedback_responses.json"
        if not response_path.exists():
            return 0

        try:
            with open(response_path, "r") as f:
                responses = json.load(f)
        except (json.JSONDecodeError, OSError):
            return 0

        processed = 0
        remaining_responses = []

        for resp in responses:
            request_id = resp.get("request_id")
            selected = resp.get("selected_option", "")

            # Find matching request
            matching = None
            for req in self._pending:
                if req.get("request_id") == request_id:
                    matching = req
                    break

            if matching is None:
                remaining_responses.append(resp)
                continue

            # Process the response
            if selected in ("threat", "approve"):
                # Confirmed threat — strengthen pathways
                logger.info("[Feedback] %s confirmed as threat", request_id)
            elif selected == "safe":
                # False positive — record in Armory, weaken pathways
                logger.info("[Feedback] %s marked as safe (false positive)", request_id)
            elif selected == "unsure":
                logger.info("[Feedback] %s marked as unsure — observing", request_id)
            elif selected == "deny":
                logger.info("[Feedback] %s action denied — alert only", request_id)

            matching["status"] = "responded"
            matching["response"] = resp
            self._feedback_count += 1
            processed += 1

        # Remove processed requests from pending
        self._pending = [
            r for r in self._pending if r.get("status") == "pending"
        ]

        # Write remaining responses
        try:
            with open(response_path, "w") as f:
                json.dump(remaining_responses, f)
        except OSError:
            pass

        self._save_queue()
        return processed

    # -------------------------------------------------------------------
    # Training Wheels (PRD §9.1)
    # -------------------------------------------------------------------

    def is_training_wheels_active(self) -> bool:
        """Check if training wheels mode should still be active.

        PRD §9.1 graduation criteria — ALL must be met:
        - Armory has ≥ min_armory_entries entries
        - Substrate has ≥ min_substrate_outcomes recorded outcomes
        - ≥ min_user_feedbacks feedback responses received
        - ≥ min_runtime_hours hours elapsed since first boot
        """
        # If all thresholds are 0, training wheels is disabled
        if (self._min_armory == 0 and self._min_outcomes == 0
                and self._min_feedbacks == 0 and self._min_hours == 0):
            return False

        # Check armory entries
        if self._armory is not None:
            if self._armory.entry_count < self._min_armory:
                return True

        # Check substrate outcomes
        if self._eco is not None:
            try:
                stats = self._eco.stats()
                outcomes = stats.get("total_outcomes", 0)
                if outcomes < self._min_outcomes:
                    return True
            except Exception:
                return True

        # Check feedback count
        if self._feedback_count < self._min_feedbacks:
            return True

        # Check runtime hours
        elapsed_hours = (time.time() - self._start_time) / 3600.0
        if elapsed_hours < self._min_hours:
            return True

        return False

    # -------------------------------------------------------------------
    # Persistence
    # -------------------------------------------------------------------

    def _save_queue(self) -> None:
        """Save pending feedback requests to disk."""
        try:
            with open(self._queue_path, "w") as f:
                json.dump(self._pending, f, indent=2)
        except OSError as exc:
            logger.warning("Failed to save feedback queue: %s", exc)

    def _load_queue(self) -> None:
        """Load pending feedback requests from disk."""
        if not self._queue_path.exists():
            return
        try:
            with open(self._queue_path, "r") as f:
                data = json.load(f)
            self._pending = [
                r for r in data if r.get("status") == "pending"
            ]
        except (json.JSONDecodeError, OSError):
            pass

    # -------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Feedback telemetry."""
        return {
            "pending_requests": len(self._pending),
            "total_feedbacks": self._feedback_count,
            "training_wheels_active": self.is_training_wheels_active(),
            "runtime_hours": round(
                (time.time() - self._start_time) / 3600.0, 2
            ),
        }
