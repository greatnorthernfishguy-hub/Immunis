"""Forensics retention — the safety properties, pinned.

Written against the live failure: 241,065 snapshot directories / 17 GB on the
VPS, accumulated over 79 days because nothing ever deleted one.
"""

import time
import uuid
from pathlib import Path

import pytest

from core.forensics_retention import (
    PruneResult,
    RetentionPolicy,
    archive_roots,
    prune_forensics,
    prune_root,
    select_for_removal,
    should_prune,
)

DAY = 86_400


def _snap(root: Path, ts: int, body: bytes = b"x" * 100) -> Path:
    d = root / f"{ts}_{uuid.uuid4()}"
    d.mkdir(parents=True)
    (d / "processes.json").write_bytes(body)
    (d / "network.json").write_bytes(body)
    return d


# --------------------------------------------------------------------------
# Selection is pure and testable without touching a filesystem
# --------------------------------------------------------------------------

def test_age_removes_only_what_is_past_the_cutoff():
    now = 1_000_000.0
    pol = RetentionPolicy(retain_days=7, max_snapshots=10_000)
    items = [
        (int(now - 8 * DAY), Path("/f/old")),
        (int(now - 6 * DAY), Path("/f/recent")),
        (int(now), Path("/f/now")),
    ]
    doomed = select_for_removal(items, pol, now)
    assert doomed == [Path("/f/old")]


def test_count_cap_removes_oldest_first():
    now = 1_000_000.0
    pol = RetentionPolicy(retain_days=365, max_snapshots=2)
    items = [(int(now - i), Path(f"/f/s{i}")) for i in range(5)]
    doomed = select_for_removal(items, pol, now)
    # 5 in window, cap 2 → the 3 oldest go
    assert len(doomed) == 3
    assert Path("/f/s4") in doomed and Path("/f/s3") in doomed
    assert Path("/f/s0") not in doomed


def test_age_and_cap_compose_without_double_counting():
    now = 1_000_000.0
    pol = RetentionPolicy(retain_days=1, max_snapshots=1)
    items = [
        (int(now - 5 * DAY), Path("/f/ancient")),
        (int(now - 100), Path("/f/a")),
        (int(now - 50), Path("/f/b")),
    ]
    doomed = select_for_removal(items, pol, now)
    assert sorted(str(p) for p in doomed) == ["/f/a", "/f/ancient"]
    assert len(doomed) == len(set(doomed)), "nothing selected twice"


def test_empty_input_is_not_an_error():
    assert select_for_removal([], RetentionPolicy(), time.time()) == []


# --------------------------------------------------------------------------
# The blast radius: only well-formed snapshot directories are ever touched
# --------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "notes.txt",
    "README",
    "important-evidence",
    "1788955786",                      # timestamp, no uuid
    "1788955786_not-a-uuid",
    "_1788955786_" + str(uuid.uuid4()),
    "forensics_archive_20260429",
    "12_" + str(uuid.uuid4()),         # implausible timestamp
])
def test_unrecognised_entries_are_never_removed(tmp_path, name):
    root = tmp_path / "forensics"
    root.mkdir()
    victim = root / name
    if "." in name and not name.startswith("_"):
        victim.write_text("keep me")
    else:
        victim.mkdir()
        (victim / "evidence.json").write_text("keep me")
    _snap(root, int(time.time() - 400 * DAY))   # something that WILL be pruned

    res = prune_root(root, RetentionPolicy(retain_days=1), time.time())
    assert res.removed == 1, "only the real snapshot should go"
    assert victim.exists(), f"{name} must survive"
    assert res.skipped_unrecognised >= 1


def test_a_file_named_like_a_snapshot_is_not_removed(tmp_path):
    """`is_dir` is checked as well as the name."""
    root = tmp_path / "forensics"
    root.mkdir()
    decoy = root / f"{int(time.time() - 999 * DAY)}_{uuid.uuid4()}"
    decoy.write_text("I am a file, not a snapshot")
    res = prune_root(root, RetentionPolicy(retain_days=1), time.time())
    assert res.removed == 0
    assert decoy.exists()


# --------------------------------------------------------------------------
# Actually pruning a directory tree
# --------------------------------------------------------------------------

def test_prune_removes_old_and_reports_bytes(tmp_path):
    root = tmp_path / "forensics"
    root.mkdir()
    now = time.time()
    old = [_snap(root, int(now - 30 * DAY)) for _ in range(3)]
    new = [_snap(root, int(now - 1 * DAY)) for _ in range(2)]

    res = prune_root(root, RetentionPolicy(retain_days=7), now)
    assert res.removed == 3 and res.kept == 2
    assert res.bytes_freed == 3 * 200
    assert all(not p.exists() for p in old)
    assert all(p.exists() for p in new)


def test_dry_run_reports_but_deletes_nothing(tmp_path):
    root = tmp_path / "forensics"
    root.mkdir()
    now = time.time()
    old = [_snap(root, int(now - 30 * DAY)) for _ in range(4)]
    res = prune_root(root, RetentionPolicy(retain_days=7), now, dry_run=True)
    assert res.removed == 4 and res.bytes_freed == 4 * 200
    assert all(p.exists() for p in old), "dry run must not delete"


def test_pruning_is_idempotent(tmp_path):
    root = tmp_path / "forensics"
    root.mkdir()
    now = time.time()
    _snap(root, int(now - 30 * DAY))
    _snap(root, int(now))
    pol = RetentionPolicy(retain_days=7)
    assert prune_root(root, pol, now).removed == 1
    assert prune_root(root, pol, now).removed == 0


def test_missing_root_is_not_an_error(tmp_path):
    assert prune_root(tmp_path / "nope", RetentionPolicy(), time.time()) == PruneResult()


# --------------------------------------------------------------------------
# Archives are bounded by the same policy
# --------------------------------------------------------------------------

def test_archives_are_discovered_and_pruned(tmp_path):
    base = tmp_path / ".et_modules" / "immunis"
    live = base / "forensics"
    arch = base / "forensics_archive_20260429"
    live.mkdir(parents=True)
    arch.mkdir(parents=True)
    now = time.time()
    _snap(live, int(now - 30 * DAY))
    _snap(arch, int(now - 30 * DAY))
    _snap(arch, int(now))

    assert archive_roots(live) == [arch]
    res = prune_forensics(live, RetentionPolicy(retain_days=7), now)
    assert res.removed == 2, "one from live, one from the archive"
    assert res.kept == 1


def test_archives_can_be_excluded(tmp_path):
    base = tmp_path / ".et_modules" / "immunis"
    live = base / "forensics"
    arch = base / "forensics_archive_20260429"
    live.mkdir(parents=True)
    arch.mkdir(parents=True)
    now = time.time()
    _snap(live, int(now - 30 * DAY))
    kept = _snap(arch, int(now - 30 * DAY))
    res = prune_forensics(live, RetentionPolicy(retain_days=7), now, include_archives=False)
    assert res.removed == 1
    assert kept.exists()


# --------------------------------------------------------------------------
# Amortisation
# --------------------------------------------------------------------------

def test_should_prune_fires_on_the_interval():
    pol = RetentionPolicy(prune_every=50)
    assert should_prune(50, pol) and should_prune(100, pol)
    assert not should_prune(49, pol) and not should_prune(51, pol)


def test_prune_every_of_one_always_fires():
    pol = RetentionPolicy(prune_every=1)
    assert all(should_prune(n, pol) for n in range(1, 5))


def test_default_policy_bounds_the_observed_growth():
    """At the measured ~3,038 snapshots/day the cap must bind before 14 days."""
    pol = RetentionPolicy()
    assert pol.max_snapshots < pol.retain_days * 3038, (
        "count cap must be the binding constraint at observed volume"
    )
