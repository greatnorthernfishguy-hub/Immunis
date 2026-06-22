"""
#328 Step 3 (A) — Immunis listens for EXTERNAL threat/violation deposits and decides arousal.

# ---- Changelog ----
# [2026-06-22] Claude Code (Opus 4.8) — #328 Step 3 (A) end-to-end test
# What: Proves the FULL chain (advisor: prove end-to-end, not per-piece): a Cricket/TrollGuard
#       deposit to the Commons → Immunis._bucket_commons_threats buckets it → escalates SYMPATHETIC
#       → deposits autonomic:arousal → read_arousal sees SYMPATHETIC. Plus: self-loop guard (ignores
#       Immunis's own threat:/response:/autonomic:), perimeter severity gate, dedup, hold-window.
# How: bind the real ImmunisHook methods to a minimal harness; sandbox Commons via get_commons patch;
#      stub _checkpoint + ng_autonomic.write_state (avoid real file/checkpoint side effects).
"""

import os
import sys
import time
import numpy as np

_IMM = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _IMM)
sys.path.insert(0, os.path.expanduser("~/NeuroGraph"))

import commons as commons_mod


def _emb(s):
    r = np.random.RandomState(abs(hash(s)) % (2**31)); v = r.randn(768).astype(np.float32)
    return v / (np.linalg.norm(v) + 1e-8)


def _load():
    import importlib.util
    spec = importlib.util.spec_from_file_location("immunis_hook", os.path.join(_IMM, "immunis_hook.py"))
    mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); return mod


class _Harness:
    def __init__(self, mod):
        self._mod = mod
        self._autonomic_state = "PARASYMPATHETIC"
        self._commons_seen = set()
        self._last_external_threat_ts = 0.0

    def _embed(self, text):
        return _emb(text)

    def _checkpoint(self):
        pass

    def __getattr__(self, name):
        import inspect
        try:
            raw = inspect.getattr_static(self._mod.ImmunisHook, name)
        except AttributeError:
            raise AttributeError(name)
        if isinstance(raw, staticmethod):
            return raw.__func__
        return raw.__get__(self, _Harness)


def _run(commons, h, deposits):
    """Deposit given (target_id, meta) then run one bucket cycle with patched get_commons + write_state."""
    import ng_autonomic
    for tid, meta in deposits:
        commons.deposit(_emb(tid), tid, metadata=meta)
    orig_gc, orig_ws = commons_mod.get_commons, ng_autonomic.write_state
    commons_mod.get_commons = lambda: commons
    ng_autonomic.write_state = lambda *a, **k: None   # no real file write
    try:
        h._bucket_commons_threats()
    finally:
        commons_mod.get_commons, ng_autonomic.write_state = orig_gc, orig_ws


def test_constitutional_violation_escalates_end_to_end():
    """Cricket deposit → bucket → SYMPATHETIC → autonomic:arousal deposit → read_arousal sees it."""
    commons = commons_mod.Commons(); h = _Harness(_load())
    _run(commons, h, [("violation:constitutional:node42", {"node_id": "node42", "triggered_by": "elmer"})])
    assert h._autonomic_state == "SYMPATHETIC", "constitutional violation escalates"
    assert commons.read_arousal() == "SYMPATHETIC", "arousal deposited + readable end-to-end"
    assert h._within_external_hold() is True, "hold-window active right after escalation"


def test_perimeter_critical_escalates_but_low_does_not():
    commons = commons_mod.Commons(); h = _Harness(_load())
    _run(commons, h, [("perimeter:threat:abc", {"threat_level": "critical"})])
    assert h._autonomic_state == "SYMPATHETIC"
    commons2 = commons_mod.Commons(); h2 = _Harness(_load())
    _run(commons2, h2, [("perimeter:threat:xyz", {"threat_level": "medium"})])
    assert h2._autonomic_state == "PARASYMPATHETIC", "low-severity perimeter does NOT escalate"


def test_self_loop_guard_ignores_immunis_own_namespaces():
    """Immunis must NOT escalate on its OWN threat:/response:/autonomic: deposits (no feedback loop)."""
    commons = commons_mod.Commons(); h = _Harness(_load())
    _run(commons, h, [
        ("threat:sig1", {"source": "immunis", "severity": "critical"}),
        ("response:isolate", {"source": "immunis"}),
        ("autonomic:arousal", {"state": "SYMPATHETIC"}),
    ])
    assert h._autonomic_state == "PARASYMPATHETIC", "own deposits must never self-escalate"


def test_dedup_no_reprocess():
    commons = commons_mod.Commons(); h = _Harness(_load())
    _run(commons, h, [("violation:constitutional:n1", {"node_id": "n1"})])
    assert h._autonomic_state == "SYMPATHETIC"
    seen_after_first = set(h._commons_seen)
    # second cycle, same deposit, no new ones → still seen, no error
    import ng_autonomic
    orig_gc, orig_ws = commons_mod.get_commons, ng_autonomic.write_state
    commons_mod.get_commons = lambda: commons; ng_autonomic.write_state = lambda *a, **k: None
    try:
        h._bucket_commons_threats()
    finally:
        commons_mod.get_commons, ng_autonomic.write_state = orig_gc, orig_ws
    assert h._commons_seen == seen_after_first, "dedup: same deposit not re-processed"


def test_hold_window_blocks_relaxation_then_expires():
    h = _Harness(_load())
    h._last_external_threat_ts = time.time()
    assert h._within_external_hold() is True
    # simulate the window having elapsed
    h._last_external_threat_ts = time.time() - (_load().EXTERNAL_THREAT_HOLD_SECONDS + 1)
    assert h._within_external_hold() is False, "hold expires after EXTERNAL_THREAT_HOLD_SECONDS"


def test_failsoft_no_commons():
    import ng_autonomic
    h = _Harness(_load())
    orig_gc = commons_mod.get_commons
    commons_mod.get_commons = lambda: None
    try:
        h._bucket_commons_threats()   # no Commons — must not raise
    finally:
        commons_mod.get_commons = orig_gc
    assert h._autonomic_state == "PARASYMPATHETIC"


if __name__ == "__main__":
    test_constitutional_violation_escalates_end_to_end(); print("PASS constitutional violation → SYMPATHETIC → arousal → read_arousal (end-to-end)")
    test_perimeter_critical_escalates_but_low_does_not(); print("PASS perimeter critical escalates; low does not")
    test_self_loop_guard_ignores_immunis_own_namespaces(); print("PASS self-loop guard (own threat:/response:/autonomic: ignored)")
    test_dedup_no_reprocess(); print("PASS dedup — same deposit not re-processed")
    test_hold_window_blocks_relaxation_then_expires(); print("PASS hold-window holds then expires")
    test_failsoft_no_commons(); print("PASS fail-soft when no Commons")
    print("\n#328 Step 3 (A) Immunis listener: ALL PASS — external threat/violation → arousal, single-authority")
