"""Tests for core/sensors/ — Sensor ABC and concrete sensor implementations."""

import numpy as np
import pytest

from core.sensors.base import EMBEDDING_DIM, Sensor, ThreatSignal


# ---------------------------------------------------------------------------
# ThreatSignal Tests
# ---------------------------------------------------------------------------


def test_threat_signal_auto_id():
    """ThreatSignal auto-generates a UUID signal_id."""
    sig = ThreatSignal(sensor_type="test", event_type="test_event")
    assert len(sig.signal_id) > 0
    assert sig.sensor_type == "test"
    assert sig.event_type == "test_event"


def test_threat_signal_auto_timestamp():
    """ThreatSignal auto-generates a timestamp."""
    sig = ThreatSignal(sensor_type="test", event_type="test_event")
    assert sig.timestamp > 0


def test_threat_signal_preserves_explicit_id():
    """Explicit signal_id is preserved."""
    sig = ThreatSignal(
        signal_id="my-custom-id",
        sensor_type="test",
        event_type="test_event",
    )
    assert sig.signal_id == "my-custom-id"


def test_threat_signal_embedding():
    """ThreatSignal stores a numpy embedding."""
    emb = np.random.randn(384).astype(np.float32)
    sig = ThreatSignal(
        sensor_type="test",
        event_type="test_event",
        embedding=emb,
    )
    assert sig.embedding is not None
    assert sig.embedding.shape == (384,)


# ---------------------------------------------------------------------------
# Sensor ABC Tests (via stub subclass)
# ---------------------------------------------------------------------------


class StubSensor(Sensor):
    """Minimal sensor implementation for testing the ABC."""

    SENSOR_TYPE = "stub"
    POLL_INTERVAL_SECONDS = 0.0  # No delay between polls for testing

    def __init__(self, events=None, config=None):
        super().__init__(config=config)
        self._events = events or []

    def _poll(self):
        return self._events

    def _embed(self, event):
        return self._hash_embed(str(event))


def test_sensor_collect_signals_empty():
    """Sensor returns empty list when no events."""
    sensor = StubSensor(events=[])
    signals = sensor.collect_signals()
    assert signals == []


def test_sensor_collect_signals_produces_threat_signals():
    """Sensor converts events to ThreatSignals."""
    events = [
        {"event_type": "test_event", "data": "hello"},
        {"event_type": "test_event_2", "data": "world"},
    ]
    sensor = StubSensor(events=events)
    signals = sensor.collect_signals()
    assert len(signals) == 2
    assert all(isinstance(s, ThreatSignal) for s in signals)
    assert signals[0].sensor_type == "stub"
    assert signals[0].event_type == "test_event"


def test_sensor_embedding_is_normalized():
    """Sensor embeddings are L2-normalized."""
    events = [{"event_type": "test", "data": "normalize_check"}]
    sensor = StubSensor(events=events)
    signals = sensor.collect_signals()
    emb = signals[0].embedding
    norm = np.linalg.norm(emb)
    assert abs(norm - 1.0) < 1e-5


def test_sensor_embedding_dimension():
    """Sensor embeddings have correct dimensionality."""
    events = [{"event_type": "test", "data": "dim_check"}]
    sensor = StubSensor(events=events)
    signals = sensor.collect_signals()
    assert signals[0].embedding.shape == (EMBEDDING_DIM,)


def test_sensor_is_relevant_filter():
    """_is_relevant() filters out events."""

    class FilterSensor(StubSensor):
        def _is_relevant(self, event):
            return event.get("keep", False)

    events = [
        {"event_type": "keep_me", "keep": True},
        {"event_type": "drop_me", "keep": False},
        {"event_type": "keep_too", "keep": True},
    ]
    sensor = FilterSensor(events=events)
    signals = sensor.collect_signals()
    assert len(signals) == 2


def test_sensor_poll_interval():
    """Sensor respects POLL_INTERVAL_SECONDS."""
    sensor = StubSensor(events=[{"event_type": "test"}])
    sensor.POLL_INTERVAL_SECONDS = 999999  # Very long interval

    # First poll should work
    signals = sensor.collect_signals()
    assert len(signals) == 1

    # Immediate second poll should be skipped
    signals = sensor.collect_signals()
    assert len(signals) == 0


def test_sensor_stats():
    """Sensor tracks event and signal counts."""
    events = [{"event_type": "e1"}, {"event_type": "e2"}]
    sensor = StubSensor(events=events)
    sensor.collect_signals()

    stats = sensor.get_stats()
    assert stats["sensor_type"] == "stub"
    assert stats["total_events"] == 2
    assert stats["total_signals"] == 2


def test_sensor_config_poll_interval():
    """Poll interval can be set via config."""
    sensor = StubSensor(
        events=[], config={"poll_interval_seconds": 42.0}
    )
    assert sensor.POLL_INTERVAL_SECONDS == 42.0


def test_sensor_poll_exception_returns_empty():
    """Sensor returns empty list if _poll() raises."""

    class FailingSensor(StubSensor):
        def _poll(self):
            raise RuntimeError("poll failed")

    sensor = FailingSensor()
    signals = sensor.collect_signals()
    assert signals == []


def test_sensor_embed_exception_uses_hash_fallback():
    """Sensor uses hash fallback if _embed() raises."""

    class BadEmbedSensor(StubSensor):
        def _embed(self, event):
            raise ValueError("embed failed")

    events = [{"event_type": "test"}]
    sensor = BadEmbedSensor(events=events)
    signals = sensor.collect_signals()
    assert len(signals) == 1
    assert signals[0].embedding is not None
    assert signals[0].embedding.shape == (EMBEDDING_DIM,)


# ---------------------------------------------------------------------------
# Hash Embed Tests
# ---------------------------------------------------------------------------


def test_hash_embed_deterministic():
    """_hash_embed produces the same vector for the same input."""
    v1 = Sensor._hash_embed("hello world")
    v2 = Sensor._hash_embed("hello world")
    np.testing.assert_array_equal(v1, v2)


def test_hash_embed_different_inputs():
    """_hash_embed produces different vectors for different inputs."""
    v1 = Sensor._hash_embed("hello")
    v2 = Sensor._hash_embed("world")
    assert not np.allclose(v1, v2)


def test_hash_embed_normalized():
    """_hash_embed produces L2-normalized vectors."""
    v = Sensor._hash_embed("test normalization")
    norm = np.linalg.norm(v)
    assert abs(norm - 1.0) < 1e-5


def test_hash_embed_custom_dims():
    """_hash_embed respects the dims parameter."""
    v = Sensor._hash_embed("test", dims=128)
    assert v.shape == (128,)


# ---------------------------------------------------------------------------
# Feature Embed Tests
# ---------------------------------------------------------------------------


def test_feature_embed_produces_correct_shape():
    """_feature_embed produces EMBEDDING_DIM vector."""
    features = [1.0, 2.0, 3.0, 4.0, 5.0]
    v = Sensor._feature_embed(features)
    assert v.shape == (EMBEDDING_DIM,)


def test_feature_embed_normalized():
    """_feature_embed produces L2-normalized vectors."""
    features = [0.5, 1.0, -0.3, 2.0]
    v = Sensor._feature_embed(features)
    norm = np.linalg.norm(v)
    assert abs(norm - 1.0) < 1e-5


def test_feature_embed_preserves_leading_values():
    """Feature values appear in the leading positions."""
    features = [10.0, 20.0, 30.0]
    v = Sensor._feature_embed(features, dims=384)
    # The raw features are in v[:3] before normalization,
    # but after normalization the relative ratios are preserved
    assert v[0] != 0.0
    assert v[1] != 0.0
    assert v[2] != 0.0
