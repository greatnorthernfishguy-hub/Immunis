"""
#328 Step 1 — Immunis as sole arousal authority: deposits "autonomic:arousal" to the Commons.

# ---- Changelog ----
# [2026-06-22] Claude Code (Opus 4.8) — #328 Step 1 arousal-deposit test
# What: Proves ImmunisHook._deposit_arousal deposits the authoritative arousal signal into the
#       Commons under target_id "autonomic:arousal" with the {state, threat_level, triggered_by,
#       reason, ts} verdict in metadata, the raw triggering-threat experience in the embedding
#       (LAW 7), single deposit (neuromodulator — exempt from dual-pass), and fail-soft.
# Why: Immunis is the sole arousal authority (autonomic-via-commons-design.md). This is the
#       substrate-native vagus-nerve deposit that replaces the LAW-1 shared file.
# How: bind the real ImmunisHook._deposit_arousal to a minimal harness (the full hook spawns
#      threads + sensors). Patch commons.get_commons to a sandbox Commons; stub _embed.
"""

import os
import sys
import numpy as np

_IMM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _IMM)
sys.path.insert(0, os.path.expanduser("~/NeuroGraph"))

import commons as commons_mod


def _fake_embed(text, *a, **k):
    rng = np.random.RandomState(abs(hash(text)) % (2**31))
    v = rng.randn(768).astype(np.float32)
    return v / (np.linalg.norm(v) + 1e-8)


def _load_immunis_hook():
    import importlib.util
    spec = importlib.util.spec_from_file_location("immunis_hook", os.path.join(_IMM, "immunis_hook.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Harness:
    def __init__(self, mod):
        self._mod = mod

    def _embed(self, text):
        return _fake_embed(text)

    def __getattr__(self, name):
        import inspect
        try:
            raw = inspect.getattr_static(self._mod.ImmunisHook, name)
        except AttributeError:
            raise AttributeError(name)
        if isinstance(raw, staticmethod):
            return raw.__func__
        return raw.__get__(self, _Harness)


def _arousal_deposits(commons):
    # NGLite.record_outcome stores the deposited metadata dict under s.metadata["last_context"]
    return [s.metadata.get("last_context", {}) for s in commons._ng.synapses.values()
            if getattr(s, "target_id", "") == "autonomic:arousal"]


def test_arousal_deposited_with_verdict():
    """Immunis deposits autonomic:arousal carrying the state/threat_level verdict in metadata."""
    commons = commons_mod.Commons()
    h = _Harness(_load_immunis_hook())
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: commons
    try:
        h._deposit_arousal("SYMPATHETIC", "critical", "CRITICAL threat detected")
    finally:
        commons_mod.get_commons = orig
    deps = _arousal_deposits(commons)
    assert len(deps) == 1, "exactly one autonomic:arousal deposit"
    m = deps[0]
    assert m["state"] == "SYMPATHETIC" and m["threat_level"] == "critical"
    assert m["triggered_by"] == "immunis" and m["kind"] == "arousal"
    assert m["reason"] == "CRITICAL threat detected" and "ts" in m


def test_arousal_is_single_deposit_not_dual_pass():
    """Arousal is a neuromodulator → ONE deposit, no forest+tree tree-ids (exempt from dual-pass)."""
    commons = commons_mod.Commons()
    h = _Harness(_load_immunis_hook())
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: commons
    try:
        h._deposit_arousal("PARASYMPATHETIC", "none", "All threats neutralized")
    finally:
        commons_mod.get_commons = orig
    all_targets = [getattr(s, "target_id", "") for s in commons._ng.synapses.values()]
    assert all_targets.count("autonomic:arousal") == 1
    assert not any("::tree::" in t or t.startswith("autonomic:arousal::") for t in all_targets), \
        "arousal must be a single deposit, not forest+tree"


def test_arousal_not_in_metrics_namespace():
    """autonomic:arousal is NOT metrics: → exempt from recency-eviction (vagus never pruned)."""
    commons = commons_mod.Commons()
    h = _Harness(_load_immunis_hook())
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: commons
    try:
        h._deposit_arousal("SYMPATHETIC", "high", "x")
    finally:
        commons_mod.get_commons = orig
    targets = [getattr(s, "target_id", "") for s in commons._ng.synapses.values()]
    assert "autonomic:arousal" in targets
    assert not any(t.startswith("metrics:") for t in targets), "arousal must not be a metric"


def test_arousal_failsoft_no_commons():
    h = _Harness(_load_immunis_hook())
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: None
    try:
        h._deposit_arousal("SYMPATHETIC", "critical", "x")  # no Commons — must not raise
    finally:
        commons_mod.get_commons = orig


if __name__ == "__main__":
    test_arousal_deposited_with_verdict();        print("PASS arousal deposited with state/threat_level verdict")
    test_arousal_is_single_deposit_not_dual_pass(); print("PASS arousal is a single deposit (neuromodulator, not dual-pass)")
    test_arousal_not_in_metrics_namespace();      print("PASS autonomic:arousal exempt from metric recency-eviction")
    test_arousal_failsoft_no_commons();           print("PASS arousal deposit fail-soft when no Commons")
    print("\n#328 Step 1 (Immunis arousal authority): ALL PASS — sole-authority arousal deposit to the Commons")
