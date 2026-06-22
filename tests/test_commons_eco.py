"""
Immunis Commons migration (#324) — _CommonsEco restores substrate sight via the Commons.

# ---- Changelog ----
# [2026-06-22] Claude Code (Fable 5) — test the Commons-backed Quartermaster eco adapter
# What: Proves _CommonsEco.get_context buckets the Commons FILTERED to Immunis's threat:/response:
#       namespace (preserving threat-classification semantics), derives novelty (1 - top match),
#       record_outcome deposits, and fail-soft when no Commons. Restores #324 (substrate-blindness).
# How: stub ng_updater (the hook auto_update()s at import) + NeuroGraph on path for commons;
#       drive the real _CommonsEco against a sandbox Commons (patch commons.get_commons).
# -------------------
"""

import os
import sys
import types

_IMMUNIS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _IMMUNIS)
sys.path.insert(0, os.path.expanduser("~/NeuroGraph"))

# the hook runs ng_updater.auto_update() at import — stub it for a clean unit test
_stub = types.ModuleType("ng_updater")
_stub.auto_update = lambda *a, **k: None
sys.modules.setdefault("ng_updater", _stub)

import numpy as np
import commons as commons_mod
from immunis_hook import _CommonsEco


def _emb(seed, dim=768):
    r = np.random.RandomState(seed); v = r.randn(dim).astype(np.float32)
    return v / (np.linalg.norm(v) + 1e-8)


def _with_commons(commons, fn):
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: commons
    try:
        return fn()
    finally:
        commons_mod.get_commons = orig


def test_get_context_filters_to_threat_namespace():
    c = commons_mod.Commons()
    c.deposit(_emb(1), "threat:sig123", metadata={"category": "intrusion"})
    c.deposit(_emb(1), "experience:conv", metadata={"kind": "experience"})  # same emb, non-threat
    ctx = _with_commons(c, lambda: _CommonsEco().get_context(_emb(1)))
    recs = ctx["recommendations"]
    assert recs, "a threat deposit must surface"
    assert all(str(r[0]).startswith(("threat:", "response:")) for r in recs), "only threat/response namespace"
    assert not any(str(r[0]).startswith("experience:") for r in recs), "conversation deposits filtered out"


def test_novelty_high_when_no_known_threat():
    c = commons_mod.Commons()
    c.deposit(_emb(2), "experience:x", metadata={})  # only non-threat present
    ctx = _with_commons(c, lambda: _CommonsEco().get_context(_emb(2)))
    assert ctx["novelty"] == 1.0, "no known threat match → max novelty"
    assert ctx["recommendations"] == []


def test_record_outcome_deposits_threat():
    c = commons_mod.Commons()
    r = _with_commons(c, lambda: _CommonsEco().record_outcome(
        _emb(3), "threat:sigABC", True, metadata={"source": "immunis"}))
    assert r is not None
    syns = [s for s in c._ng.synapses.values() if getattr(s, "target_id", "").startswith("threat:")]
    assert len(syns) == 1, "threat outcome deposited to the Commons"


def test_failsoft_no_commons():
    eco = _CommonsEco()
    orig = commons_mod.get_commons
    commons_mod.get_commons = lambda: None
    try:
        assert eco.get_context(_emb(4)) == {"recommendations": [], "novelty": 1.0}
        assert eco.record_outcome(_emb(4), "threat:x", True) is None
    finally:
        commons_mod.get_commons = orig


def test_none_embedding_is_safe():
    c = commons_mod.Commons()
    out = _with_commons(c, lambda: _CommonsEco().get_context(None))
    assert out == {"recommendations": [], "novelty": 1.0}


if __name__ == "__main__":
    test_get_context_filters_to_threat_namespace(); print("PASS get_context filters to threat:/response: namespace")
    test_novelty_high_when_no_known_threat();       print("PASS novelty=1.0 when no known threat match")
    test_record_outcome_deposits_threat();          print("PASS record_outcome deposits threat to Commons")
    test_failsoft_no_commons();                     print("PASS fail-soft when no Commons")
    test_none_embedding_is_safe();                  print("PASS None embedding is safe")
    print("\nImmunis Commons migration (#324): ALL PASS — substrate sight restored via threat-filtered Commons bucket/deposit")
