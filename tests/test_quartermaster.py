"""Tests for core/quartermaster.py — The Quartermaster pipeline."""

import numpy as np
import pytest

from core.quartermaster import (
    Quartermaster,
    Severity,
    ThreatClassification,
    ThreatAssessment,
    PipelineResult,
)
from core.sensors.base import ThreatSignal
from core.response_primitives import get_all_primitives


def _make_signal(sensor_type="filesystem", event_type="test", seed=42):
    rng = np.random.RandomState(seed)
    emb = rng.randn(384).astype(np.float32)
    emb /= np.linalg.norm(emb)
    return ThreatSignal(
        sensor_type=sensor_type,
        event_type=event_type,
        raw_data={"test": True},
        embedding=emb,
    )


@pytest.fixture
def qm():
    return Quartermaster(
        config={
            "signal_buffer_size": 100,
            "learn_observation_window": 1,
            "thresholds": {
                "auto_execute": 0.70,
                "recommend": 0.40,
                "host_premium": 0.15,
            },
        },
        response_primitives=get_all_primitives(),
        training_wheels_active=True,
    )


def test_ingest_signal(qm):
    """Signals enter the buffer."""
    sig = _make_signal()
    assert qm.ingest_signal(sig) is True
    assert qm.buffer_size == 1


def test_process_one(qm):
    """A signal can be processed through the pipeline."""
    sig = _make_signal()
    qm.ingest_signal(sig)
    result = qm.process_one()
    assert result is not None
    assert result.classification is not None
    assert result.assessment is not None
    assert result.response is not None


def test_empty_buffer(qm):
    """process_one returns None on empty buffer."""
    assert qm.process_one() is None


def test_assess_severity_critical():
    """CRITICAL when confidence >= 0.70."""
    qm = Quartermaster(config={"thresholds": {"auto_execute": 0.70}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.85,
        substrate_novelty=0.3,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.CRITICAL
    assert assessment.should_auto_execute is True


def test_assess_severity_high():
    """HIGH when confidence 0.40-0.70, novelty < 0.50."""
    qm = Quartermaster(config={"thresholds": {"auto_execute": 0.70, "recommend": 0.40}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.55,
        substrate_novelty=0.3,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.HIGH
    assert assessment.should_recommend is True


def test_assess_severity_high_novel():
    """HIGH_NOVEL when confidence 0.40-0.70, novelty >= 0.50."""
    qm = Quartermaster(config={"thresholds": {"auto_execute": 0.70, "recommend": 0.40}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.55,
        substrate_novelty=0.75,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.HIGH_NOVEL


def test_assess_severity_medium():
    """MEDIUM when confidence 0.15-0.40."""
    qm = Quartermaster(config={"thresholds": {"auto_execute": 0.70, "recommend": 0.40, "host_premium": 0.15}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.25,
        substrate_novelty=0.3,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.MEDIUM


def test_assess_severity_low():
    """LOW when confidence < 0.15, novelty < 0.50."""
    qm = Quartermaster(config={"thresholds": {"host_premium": 0.15}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.05,
        substrate_novelty=0.2,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.LOW


def test_assess_severity_low_novel():
    """LOW_NOVEL when confidence < 0.15, novelty >= 0.50."""
    qm = Quartermaster(config={"thresholds": {"host_premium": 0.15}})
    classification = ThreatClassification(
        signal=_make_signal(),
        substrate_confidence=0.05,
        substrate_novelty=0.8,
    )
    assessment = qm._assess(classification)
    assert assessment.severity == Severity.LOW_NOVEL


def test_training_wheels_limits_response(qm):
    """Training wheels mode limits responses to AlertOnly/SnapshotForensics."""
    sig = _make_signal()
    qm.ingest_signal(sig)
    result = qm.process_one()
    assert result.response is not None
    assert result.response.primitive_name in ("AlertOnly", "SnapshotForensics")


def test_process_batch(qm):
    """process_batch processes multiple signals."""
    for i in range(5):
        qm.ingest_signal(_make_signal(seed=i))
    results = qm.process_batch(max_count=10)
    assert len(results) == 5
    assert qm.buffer_size == 0


def test_stats(qm):
    """Stats reflect pipeline state."""
    qm.ingest_signal(_make_signal())
    qm.process_one()
    stats = qm.get_stats()
    assert stats["total_processed"] == 1
    assert stats["training_wheels_active"] is True


def test_buffer_overflow():
    """Signals are dropped when buffer is full."""
    qm = Quartermaster(config={"signal_buffer_size": 3})
    for i in range(5):
        qm.ingest_signal(_make_signal(seed=i))
    assert qm.buffer_size == 3
    assert qm._dropped_signals == 2
