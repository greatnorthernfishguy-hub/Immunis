"""Tests for core/armory.py — The Armory threat intelligence store."""

import json
import os
import tempfile

import numpy as np
import pytest

from core.armory import Armory, ArmoryEntry, ArmoryEntryType


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


@pytest.fixture
def armory(tmp_dir):
    return Armory(
        config={"max_entries": 100, "persistence_format": "json"},
        data_dir=tmp_dir,
    )


def _random_embedding(seed=42):
    rng = np.random.RandomState(seed)
    vec = rng.randn(384).astype(np.float32)
    return vec / np.linalg.norm(vec)


def test_add_and_get_entry(armory):
    emb = _random_embedding()
    entry_id = armory.add_threat_signature(
        embedding=emb, category="malware", severity="CRITICAL"
    )
    entry = armory.get_entry(entry_id)
    assert entry is not None
    assert entry.category == "malware"
    assert entry.severity == "CRITICAL"
    assert entry.access_count == 1


def test_search_cosine(armory):
    emb1 = _random_embedding(1)
    emb2 = _random_embedding(2)
    armory.add_threat_signature(embedding=emb1, category="malware", severity="HIGH")
    armory.add_threat_signature(embedding=emb2, category="exploit", severity="MEDIUM")

    # Search with emb1 should find emb1 most similar
    results = armory.search(emb1, top_k=2)
    assert len(results) >= 1
    assert results[0]["category"] == "malware"


def test_false_positive(armory):
    emb = _random_embedding()
    armory.add_false_positive(embedding=emb, category="test")
    assert armory.is_false_positive(emb) is True
    assert armory.is_false_positive(_random_embedding(99)) is False


def test_eviction(tmp_dir):
    armory = Armory(
        config={"max_entries": 5, "persistence_format": "json"},
        data_dir=tmp_dir,
    )
    for i in range(10):
        armory.add_threat_signature(
            embedding=_random_embedding(i),
            category="test",
            severity="LOW",
        )
    assert armory.entry_count <= 5


def test_json_persistence(tmp_dir):
    armory = Armory(
        config={"max_entries": 100, "persistence_format": "json"},
        data_dir=tmp_dir,
    )
    emb = _random_embedding()
    armory.add_threat_signature(embedding=emb, category="malware", severity="HIGH")
    armory.save()

    # Load into new instance
    armory2 = Armory(
        config={"max_entries": 100, "persistence_format": "json"},
        data_dir=tmp_dir,
    )
    assert armory2.entry_count == 1
    results = armory2.search(emb, top_k=1)
    assert results[0]["category"] == "malware"


def test_load_signatures(tmp_dir):
    armory = Armory(
        config={"max_entries": 100, "persistence_format": "json"},
        data_dir=tmp_dir,
    )
    sig_file = os.path.join(tmp_dir, "sigs.json")
    sigs = [
        {
            "category": "ransomware",
            "severity": "critical",
            "description": "Test signature",
            "embedding": _random_embedding(42).tolist(),
            "metadata": {"source": "test"},
        }
    ]
    with open(sig_file, "w") as f:
        json.dump(sigs, f)

    loaded = armory.load_signatures(sig_file)
    assert loaded == 1
    assert armory.entry_count == 1


def test_response_record(armory):
    emb = _random_embedding()
    entry_id = armory.add_response_record(
        embedding=emb,
        category="malware",
        response_primitive="KillProcess",
        effectiveness=0.95,
    )
    entry = armory.get_entry(entry_id)
    assert entry.response_primitive == "KillProcess"
    assert entry.response_effectiveness == 0.95


def test_behavioral_baseline(armory):
    emb = _random_embedding()
    entry_id = armory.add_behavioral_baseline(
        embedding=emb, category="process_normal"
    )
    entry = armory.get_entry(entry_id)
    assert entry.entry_type == ArmoryEntryType.BEHAVIORAL_BASELINE.value


def test_causal_chain(armory):
    emb = _random_embedding()
    entry_id = armory.add_causal_chain(
        embedding=emb,
        category="exfiltration",
        chain_signals=["sig1", "sig2", "sig3"],
    )
    entry = armory.get_entry(entry_id)
    assert entry.entry_type == ArmoryEntryType.CAUSAL_CHAIN.value
    assert entry.metadata["chain_signals"] == ["sig1", "sig2", "sig3"]


def test_stats(armory):
    armory.add_threat_signature(
        embedding=_random_embedding(), category="test", severity="LOW"
    )
    stats = armory.get_stats()
    assert stats["total_entries"] == 1
    assert "THREAT_SIGNATURE" in stats["type_counts"]
