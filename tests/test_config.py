"""Tests for core/config.py — ImmunisConfig loading and defaults."""

import os
import tempfile

import pytest

from core.config import ImmunisConfig


def test_default_config():
    """All defaults match PRD §11 values."""
    cfg = ImmunisConfig()
    assert cfg.quartermaster.signal_buffer_size == 10000
    assert cfg.quartermaster.learn_observation_window == 300
    assert cfg.thresholds.auto_execute == 0.70
    assert cfg.thresholds.recommend == 0.40
    assert cfg.thresholds.host_premium == 0.15
    assert cfg.armory.max_entries == 10000
    assert cfg.armory.persistence_format == "msgpack"
    assert cfg.armory.match_threshold == 0.90
    assert cfg.response.kill_grace_seconds == 5
    assert cfg.sensors.filesystem.enabled is True
    assert cfg.sensors.process.poll_interval_seconds == 10.0
    assert cfg.sensors.network.poll_interval_seconds == 15.0
    assert cfg.sensors.dependency.poll_interval_seconds == 300.0
    assert cfg.training_wheels.min_armory_entries == 50
    assert cfg.training_wheels.min_runtime_hours == 24
    assert cfg.embedding.dim == 384
    assert cfg.emergency.kill_switch is False


def test_from_yaml_missing_file():
    """from_yaml with nonexistent path returns defaults."""
    cfg = ImmunisConfig.from_yaml("/nonexistent/path/config.yaml")
    assert cfg.quartermaster.signal_buffer_size == 10000


def test_from_yaml_override():
    """from_yaml merges YAML values over defaults."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("""
immunis:
  quartermaster:
    signal_buffer_size: 5000
  thresholds:
    auto_execute: 0.80
  sensors:
    filesystem:
      enabled: false
""")
        f.flush()
        path = f.name

    try:
        cfg = ImmunisConfig.from_yaml(path)
        assert cfg.quartermaster.signal_buffer_size == 5000
        assert cfg.thresholds.auto_execute == 0.80
        assert cfg.sensors.filesystem.enabled is False
        # Non-overridden values stay at defaults
        assert cfg.thresholds.recommend == 0.40
        assert cfg.armory.max_entries == 10000
    finally:
        os.unlink(path)


def test_from_yaml_empty_file():
    """from_yaml with empty YAML returns defaults."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        f.write("")
        f.flush()
        path = f.name
    try:
        cfg = ImmunisConfig.from_yaml(path)
        assert cfg.quartermaster.signal_buffer_size == 10000
    finally:
        os.unlink(path)
