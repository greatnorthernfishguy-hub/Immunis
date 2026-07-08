"""Tests for core/config.py — ImmunisConfig loading and defaults.

# ---- Changelog ----
# [2026-07-08] Claude Code (Sonnet 5) — #355: fix stale embedding.dim assertion
#   What: test_default_config asserted embedding.dim == 384; the real default has been 768
#         since the #45 ecosystem-wide embedding migration (2026-03-19, core/config.py:196).
#         cfg.embedding.model ("BAAI/bge-base-en-v1.5") is itself a separate, unused stale
#         label — _embed() in immunis_hook.py calls the centralized ng_embed.embed() (real
#         ecosystem standard: Snowflake/snowflake-arctic-embed-m-v1.5) unconditionally and
#         never reads cfg.embedding.model. Not fixed here — cosmetic, zero behavioral impact,
#         flagged for a future doc-hygiene pass, not worth its own punchlist item.
#   Why:  Test never updated when the code default changed. No code regression.
# -------------------
"""

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
    assert cfg.embedding.dim == 768
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
