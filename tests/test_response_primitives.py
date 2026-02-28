"""Tests for core/response_primitives.py — Response primitive validate/execute contract."""

import os
import stat
import tempfile

import pytest

from core.response_primitives import (
    AlertOnly,
    SnapshotForensics,
    QuarantineFile,
    RevokePermissions,
    get_all_primitives,
    ValidationResult,
    ExecutionResult,
)


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield d


def test_alert_only_always_passes():
    """AlertOnly validates and executes successfully always."""
    p = AlertOnly()
    assert p.severity_floor == "LOW"
    v = p.validate({"signal_id": "test-123"})
    assert v.passed is True
    e = p.execute({"signal_id": "test-123"})
    assert e.status == "success"


def test_snapshot_forensics(tmp_dir):
    """SnapshotForensics captures a snapshot directory."""
    p = SnapshotForensics(config={"forensics_dir": tmp_dir})
    v = p.validate({})
    assert v.passed is True

    e = p.execute({"signal_id": "test-snap"})
    assert e.status == "success"
    assert e.rollback_info is not None
    assert os.path.isdir(e.rollback_info["snapshot_path"])


def test_quarantine_file(tmp_dir):
    """QuarantineFile moves a file to quarantine with metadata."""
    # Create test file
    test_file = os.path.join(tmp_dir, "suspicious.sh")
    with open(test_file, "w") as f:
        f.write("#!/bin/bash\nrm -rf /")

    quarantine_dir = os.path.join(tmp_dir, "quarantine")
    p = QuarantineFile(config={"quarantine_dir": quarantine_dir})

    v = p.validate({"path": test_file})
    assert v.passed is True

    e = p.execute({"path": test_file})
    assert e.status == "success"
    assert not os.path.exists(test_file)
    assert e.rollback_info is not None


def test_quarantine_file_protected(tmp_dir):
    """QuarantineFile refuses to quarantine protected paths."""
    test_file = os.path.join(tmp_dir, "important")
    with open(test_file, "w") as f:
        f.write("important data")

    p = QuarantineFile(config={"protected_paths": [tmp_dir]})
    v = p.validate({"path": test_file})
    assert v.passed is False
    assert "protected" in v.reason.lower()


def test_quarantine_file_missing():
    """QuarantineFile fails for nonexistent file."""
    p = QuarantineFile()
    v = p.validate({"path": "/nonexistent/file.txt"})
    assert v.passed is False


def test_revoke_permissions(tmp_dir):
    """RevokePermissions sets a file to read-only."""
    test_file = os.path.join(tmp_dir, "writable.sh")
    with open(test_file, "w") as f:
        f.write("content")
    os.chmod(test_file, 0o755)

    p = RevokePermissions()
    v = p.validate({"path": test_file})
    assert v.passed is True

    e = p.execute({"path": test_file})
    assert e.status == "success"
    assert e.rollback_info is not None
    # File should now be read-only (check mode bits, not os.access which ignores mode for root)
    mode = os.stat(test_file).st_mode
    assert not (mode & stat.S_IWUSR), "Owner write bit should be cleared"


def test_get_all_primitives():
    """get_all_primitives returns all 7 primitives."""
    primitives = get_all_primitives()
    assert len(primitives) == 7
    expected = {
        "AlertOnly", "SnapshotForensics", "KillProcess",
        "QuarantineFile", "BlockConnection", "RevokePermissions",
        "IsolateModule",
    }
    assert set(primitives.keys()) == expected


def test_severity_floors():
    """Verify severity floors per PRD §7."""
    primitives = get_all_primitives()
    assert primitives["AlertOnly"].severity_floor == "LOW"
    assert primitives["SnapshotForensics"].severity_floor == "LOW"
    assert primitives["KillProcess"].severity_floor == "HIGH"
    assert primitives["QuarantineFile"].severity_floor == "MEDIUM"
    assert primitives["BlockConnection"].severity_floor == "HIGH"
    assert primitives["RevokePermissions"].severity_floor == "MEDIUM"
    assert primitives["IsolateModule"].severity_floor == "CRITICAL"
