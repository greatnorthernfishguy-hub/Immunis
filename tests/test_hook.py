"""Tests for immunis_hook.py — OpenClaw Integration Hook.

These tests verify the ImmunisHook initialization and interface
without requiring a live system or the OpenClaw host.

# ---- Changelog ----
# [2026-07-08] Claude Code (Sonnet 5) — #355: fix 2 tests targeting a dead API
#   What: test_hook_module_on_message_ok and test_hook_kill_switch both asserted on
#         _module_on_message()'s return dict (status/signals_ingested/active_threats/
#         autonomic_state) — but _module_on_message() is a documented no-op (`return {}`),
#         since Immunis moved to autonomous pulse-cycle processing. Verified the kill
#         switch itself is NOT broken: `self._killed` still gates _pulse_cycle() (the
#         real live processing path) at its top, confirmed by reading the code before
#         touching either test. Rewrote both against that live path instead of the dead
#         return-value contract; test_hook_module_on_message_ok now asserts the actual
#         no-op contract (`== {}`) rather than a stale populated-dict shape.
#   Why:  Same failure shape as THC's #348 — tests never updated when message-scanning
#         moved to the pulse cycle. Confirmed NOT masking a regression (unlike 2 of #348's
#         6 tests, which did mask one — #354) before deciding to fix rather than flag.
# -------------------
"""

import os
import sys
from unittest.mock import MagicMock, patch

import numpy as np
import pytest


# ---------------------------------------------------------------------------
# Mock external dependencies that won't be available in test environments
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def mock_external_modules(tmp_path, monkeypatch):
    """Mock external modules and file paths for testing."""
    # Create a minimal config.yaml for testing
    config_content = """
immunis:
  quartermaster:
    signal_buffer_size: 100
    learn_observation_window: 1

  thresholds:
    auto_execute: 0.70
    recommend: 0.40
    host_premium: 0.15

  armory:
    max_entries: 100
    persistence_format: json
    search_top_k: 5
    match_threshold: 0.90
    eviction_policy: lru

  response:
    kill_grace_seconds: 5
    quarantine_dir: "{qdir}"
    forensics_dir: "{fdir}"
    forensics_min_disk_mb: 10
    protected_pids: []
    protected_paths: []
    protected_destinations: []

  training_wheels:
    min_armory_entries: 0
    min_substrate_outcomes: 0
    min_user_feedbacks: 0
    min_runtime_hours: 0

  sensors:
    filesystem:
      enabled: false
    process:
      enabled: false
    network:
      enabled: false
    dependency:
      enabled: false
    log:
      enabled: false
    memory:
      enabled: false
    substrate:
      enabled: false

  ng_lite:
    nodes: 64
    lr: 0.01
    decay: 0.001

  embedding:
    model: "all-MiniLM-L6-v2"
    device: "disabled"

  emergency:
    kill_switch: false

  checkpoint_interval_seconds: 300
""".format(
        qdir=str(tmp_path / "quarantine"),
        fdir=str(tmp_path / "forensics"),
    )

    config_path = tmp_path / "config.yaml"
    config_path.write_text(config_content)

    # Set up module data directory
    module_dir = tmp_path / "immunis_data"
    module_dir.mkdir()

    # Mock the config path lookup
    monkeypatch.setenv("HOME", str(tmp_path))

    # Create the expected directory structure
    et_modules = tmp_path / ".et_modules" / "immunis"
    et_modules.mkdir(parents=True, exist_ok=True)
    (et_modules / "config.yaml").write_text(config_content)

    # Mock ng_autonomic
    mock_autonomic = MagicMock()
    mock_autonomic.read_state.return_value = {"state": "PARASYMPATHETIC"}
    monkeypatch.setitem(sys.modules, "ng_autonomic", mock_autonomic)

    return tmp_path


def test_hook_import():
    """ImmunisHook class can be imported."""
    from immunis_hook import ImmunisHook
    assert ImmunisHook is not None


def test_hook_module_id():
    """ImmunisHook has the correct MODULE_ID."""
    from immunis_hook import ImmunisHook
    assert ImmunisHook.MODULE_ID == "immunis"


def test_hook_instantiation(mock_external_modules):
    """ImmunisHook can be instantiated with test config."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    assert hook is not None
    assert hook._killed is False


def test_hook_kill_switch(mock_external_modules, tmp_path):
    """Kill switch prevents processing.

    #355: Immunis processes autonomously via the pulse cycle now (_module_on_message
    is a documented no-op — see test_hook_module_on_message_ok), so the kill switch's
    real enforcement point is the `if self._killed: return` guard at the top of
    _pulse_cycle(), not a message-scanning return value. Verify through that live path:
    _bucket_commons_threats() (the first real work _pulse_cycle does after the guard)
    must never be reached while killed.
    """
    # Rewrite config with kill_switch: true
    et_modules = tmp_path / ".et_modules" / "immunis"
    config_path = et_modules / "config.yaml"
    content = config_path.read_text()
    content = content.replace("kill_switch: false", "kill_switch: true")
    config_path.write_text(content)

    # Also update the local config.yaml at the repo-level fallback location
    local_config = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "config.yaml",
    )

    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    assert hook._killed is True

    calls = []
    hook._bucket_commons_threats = lambda: calls.append(True)
    hook._pulse_cycle()
    assert calls == [], "kill switch must prevent _pulse_cycle() from doing any real work"


def test_hook_embed_hash_fallback(mock_external_modules):
    """_embed uses hash fallback when device is disabled."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    emb = hook._embed("test text")
    assert emb is not None
    assert emb.shape == (384,)
    norm = np.linalg.norm(emb)
    assert abs(norm - 1.0) < 1e-5


def test_hook_embed_deterministic(mock_external_modules):
    """_embed produces deterministic results with hash fallback."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    emb1 = hook._embed("same input")
    emb2 = hook._embed("same input")
    np.testing.assert_array_equal(emb1, emb2)


def test_hook_module_on_message_ok(mock_external_modules):
    """_module_on_message is a documented no-op — Immunis processes via the pulse cycle.

    #355: this used to assert a {"status": "ok", "signals_ingested": ..., ...} return
    shape from a pre-pulse-cycle architecture. _module_on_message() is now genuinely
    just `return {}` (see immunis_hook.py) — real sensor polling/triage/telemetry live
    in _pulse_cycle() and _module_stats(), tested separately.
    """
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    emb = np.random.randn(384).astype(np.float32)
    result = hook._module_on_message("test message", emb)
    assert result == {}


def test_hook_module_stats(mock_external_modules):
    """_module_stats returns telemetry dict."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    stats = hook._module_stats()
    assert "quartermaster" in stats
    assert "armory" in stats
    assert "feedback" in stats
    assert "autonomic_state" in stats
    assert "sensors" in stats


def test_hook_no_sensors_when_disabled(mock_external_modules):
    """No sensors are initialized when all are disabled."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    assert len(hook._sensors) == 0


def test_hook_shutdown(mock_external_modules):
    """shutdown() runs without error."""
    from immunis_hook import ImmunisHook
    hook = ImmunisHook()
    hook.shutdown()


def test_hook_log_threat(mock_external_modules, tmp_path):
    """_log_threat writes to threat_log.jsonl."""
    import json
    from immunis_hook import ImmunisHook
    from core.quartermaster import (
        PipelineResult,
        ThreatClassification,
        ThreatAssessment,
        ResponseResult,
        Severity,
    )
    from core.sensors.base import ThreatSignal

    hook = ImmunisHook()

    signal = ThreatSignal(
        sensor_type="filesystem",
        event_type="file_created",
        raw_data={"test": True},
    )
    classification = ThreatClassification(
        signal=signal,
        category="malware",
        substrate_confidence=0.8,
        substrate_novelty=0.3,
    )
    assessment = ThreatAssessment(
        classification=classification,
        severity=Severity.CRITICAL,
    )
    response = ResponseResult(
        primitive_name="AlertOnly",
        status="success",
    )
    result = PipelineResult(
        signal=signal,
        classification=classification,
        assessment=assessment,
        response=response,
    )

    hook._log_threat(result)

    log_path = hook._threat_log_path
    assert log_path.exists()
    with open(log_path, "r") as f:
        line = f.readline()
    entry = json.loads(line)
    assert entry["sensor_type"] == "filesystem"
    assert entry["severity"] == "CRITICAL"
    assert entry["category"] == "malware"


def test_get_instance_singleton(mock_external_modules):
    """get_instance() returns a singleton."""
    import immunis_hook

    # Reset singleton
    immunis_hook._INSTANCE = None

    instance1 = immunis_hook.get_instance()
    instance2 = immunis_hook.get_instance()
    assert instance1 is instance2

    # Clean up singleton
    immunis_hook._INSTANCE = None
