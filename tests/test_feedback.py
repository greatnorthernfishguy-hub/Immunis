"""Tests for core/feedback.py — User Feedback Mechanism."""

import json
import os
import time

import numpy as np
import pytest

from core.feedback import FeedbackManager
from core.quartermaster import Severity, ThreatAssessment, ThreatClassification
from core.sensors.base import ThreatSignal


def _make_signal(seed=42):
    rng = np.random.RandomState(seed)
    emb = rng.randn(384).astype(np.float32)
    emb /= np.linalg.norm(emb)
    return ThreatSignal(
        sensor_type="filesystem",
        event_type="file_created",
        raw_data={"src_path": "/tmp/test", "test": True},
        embedding=emb,
    )


def _make_classification(signal=None, confidence=0.55, novelty=0.3):
    if signal is None:
        signal = _make_signal()
    return ThreatClassification(
        signal=signal,
        substrate_confidence=confidence,
        substrate_novelty=novelty,
        category="malware",
    )


def _make_assessment(classification=None, severity=Severity.HIGH):
    if classification is None:
        classification = _make_classification()
    return ThreatAssessment(
        classification=classification,
        severity=severity,
        action="recommend",
        should_recommend=True,
    )


@pytest.fixture
def data_dir(tmp_path):
    return str(tmp_path)


@pytest.fixture
def fm(data_dir):
    return FeedbackManager(
        config={
            "training_wheels": {
                "min_armory_entries": 5,
                "min_substrate_outcomes": 10,
                "min_user_feedbacks": 3,
                "min_runtime_hours": 0,
            },
        },
        data_dir=data_dir,
    )


def test_request_feedback_creates_entry(fm):
    """request_feedback() creates a pending entry and returns a request_id."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    request_id = fm.request_feedback(classification, assessment)
    assert request_id is not None
    assert len(request_id) > 0
    assert fm.get_stats()["pending_requests"] == 1


def test_request_feedback_persists(fm, data_dir):
    """Feedback requests are persisted to disk."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    fm.request_feedback(classification, assessment)

    queue_path = os.path.join(data_dir, "feedback_queue.json")
    assert os.path.exists(queue_path)
    with open(queue_path, "r") as f:
        data = json.load(f)
    assert len(data) == 1
    assert data[0]["status"] == "pending"


def test_request_feedback_includes_options(fm):
    """Feedback requests include the standard option set."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    fm.request_feedback(classification, assessment)

    stats = fm.get_stats()
    assert stats["pending_requests"] == 1


def test_check_response_no_responses(fm):
    """check_response returns None when no responses exist."""
    assert fm.check_response("nonexistent-id") is None


def test_check_response_with_response(fm, data_dir):
    """check_response returns the response when present."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    request_id = fm.request_feedback(classification, assessment)

    # Write a response
    response_path = os.path.join(data_dir, "feedback_responses.json")
    with open(response_path, "w") as f:
        json.dump([{
            "request_id": request_id,
            "selected_option": "threat",
            "timestamp": time.time(),
        }], f)

    resp = fm.check_response(request_id)
    assert resp is not None
    assert resp["selected_option"] == "threat"


def test_process_responses_threat(fm, data_dir):
    """process_responses handles 'threat' response correctly."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    request_id = fm.request_feedback(classification, assessment)

    response_path = os.path.join(data_dir, "feedback_responses.json")
    with open(response_path, "w") as f:
        json.dump([{
            "request_id": request_id,
            "selected_option": "threat",
        }], f)

    count = fm.process_responses()
    assert count == 1
    assert fm.get_stats()["pending_requests"] == 0
    assert fm.get_stats()["total_feedbacks"] == 1


def test_process_responses_safe(fm, data_dir):
    """process_responses handles 'safe' response correctly."""
    classification = _make_classification()
    assessment = _make_assessment(classification)
    request_id = fm.request_feedback(classification, assessment)

    response_path = os.path.join(data_dir, "feedback_responses.json")
    with open(response_path, "w") as f:
        json.dump([{
            "request_id": request_id,
            "selected_option": "safe",
        }], f)

    count = fm.process_responses()
    assert count == 1
    assert fm.get_stats()["total_feedbacks"] == 1


def test_process_responses_no_file(fm):
    """process_responses returns 0 when no response file exists."""
    assert fm.process_responses() == 0


def test_process_responses_unmatched(fm, data_dir):
    """Unmatched responses remain in the response file."""
    response_path = os.path.join(data_dir, "feedback_responses.json")
    with open(response_path, "w") as f:
        json.dump([{
            "request_id": "no-such-id",
            "selected_option": "threat",
        }], f)

    count = fm.process_responses()
    assert count == 0


def test_training_wheels_active_by_default(fm):
    """Training wheels is active on fresh start."""
    assert fm.is_training_wheels_active() is True


def test_training_wheels_disabled_when_all_zero():
    """Training wheels is disabled when all thresholds are 0."""
    fm = FeedbackManager(
        config={
            "training_wheels": {
                "min_armory_entries": 0,
                "min_substrate_outcomes": 0,
                "min_user_feedbacks": 0,
                "min_runtime_hours": 0,
            },
        },
    )
    assert fm.is_training_wheels_active() is False


def test_training_wheels_checks_feedback_count(data_dir):
    """Training wheels stays active until feedback threshold met."""
    fm = FeedbackManager(
        config={
            "training_wheels": {
                "min_armory_entries": 0,
                "min_substrate_outcomes": 0,
                "min_user_feedbacks": 2,
                "min_runtime_hours": 0,
            },
        },
        data_dir=data_dir,
    )
    assert fm.is_training_wheels_active() is True

    # Simulate receiving feedbacks
    fm._feedback_count = 2
    assert fm.is_training_wheels_active() is False


def test_load_queue_persistence(data_dir):
    """Pending requests survive manager restart."""
    fm1 = FeedbackManager(data_dir=data_dir)
    classification = _make_classification()
    assessment = _make_assessment(classification)
    request_id = fm1.request_feedback(classification, assessment)

    # Create new manager from same data dir
    fm2 = FeedbackManager(data_dir=data_dir)
    assert fm2.get_stats()["pending_requests"] == 1


def test_stats(fm):
    """Stats reflect feedback state."""
    stats = fm.get_stats()
    assert "pending_requests" in stats
    assert "total_feedbacks" in stats
    assert "training_wheels_active" in stats
    assert "runtime_hours" in stats
    assert stats["total_feedbacks"] == 0
