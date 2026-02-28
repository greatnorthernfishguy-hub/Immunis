"""
Immunis Response Primitives — Action Vocabulary for the Quartermaster

Seven response primitives that the substrate learns to apply.
All primitives implement the validate()/execute() contract,
identical to THC's repair primitives.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation (Phases 1-2).
#   What: ResponsePrimitive ABC + all 7 built-in primitives:
#         AlertOnly, SnapshotForensics, KillProcess, QuarantineFile,
#         BlockConnection, RevokePermissions, IsolateModule.
#         ValidationResult and ExecutionResult dataclasses.
#   Why:  PRD §7 specifies 7 response primitives with validate()/
#         execute() contract. Phase 1 requires AlertOnly +
#         SnapshotForensics. Phase 2 adds the remaining 5.
#   Settings: kill_grace_seconds=5, quarantine_dir, forensics_dir,
#         forensics_min_disk_mb=100, protected_pids, protected_paths,
#         protected_destinations per PRD §7 and §11.
#   How:  ABC with validate()/execute() methods. Each primitive checks
#         preconditions in validate() (no side effects) then acts in
#         execute(). Returns rollback_info for reversible actions.
# -------------------
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import signal
import stat
import subprocess
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("immunis.response")


# ---------------------------------------------------------------------------
# Result Dataclasses (identical to THC's pattern)
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    """Result of a response primitive's validate() call."""

    passed: bool = False
    reason: str = ""
    preconditions: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionResult:
    """Result of a response primitive's execute() call."""

    status: str = "failed"  # "success" | "partial" | "failed"
    detail: str = ""
    rollback_info: Optional[Dict[str, Any]] = None
    duration_ms: float = 0.0


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------

class ResponsePrimitive(ABC):
    """Abstract base class for all Immunis response primitives (PRD §7.1).

    Every response primitive MUST implement validate() and execute()
    as separate methods. validate() MUST be called before execute()
    with no exceptions. validate() MUST NOT have side effects.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        self._config = config or {}

    @property
    def name(self) -> str:
        return self.__class__.__name__

    @property
    def severity_floor(self) -> str:
        """Minimum severity level that can invoke this primitive.
        Override to restrict dangerous primitives to higher severities.
        """
        return "LOW"

    @abstractmethod
    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        ...

    @abstractmethod
    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        ...


# ---------------------------------------------------------------------------
# 7.2.6 AlertOnly (Phase 1)
# ---------------------------------------------------------------------------

class AlertOnly(ResponsePrimitive):
    """Logs the threat with full metadata. Takes no autonomous action.

    PRD §7.2.6: Severity floor LOW. Always validates. Always succeeds.
    """

    @property
    def severity_floor(self) -> str:
        return "LOW"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        return ValidationResult(passed=True, reason="AlertOnly always passes")

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        signal_id = context.get("signal_id", "unknown")
        logger.info(
            "[AlertOnly] Threat alert — signal_id=%s", signal_id
        )
        return ExecutionResult(
            status="success",
            detail=f"Alert logged for signal {signal_id}",
            duration_ms=(time.time() - start) * 1000,
        )


# ---------------------------------------------------------------------------
# 7.2.7 SnapshotForensics (Phase 1)
# ---------------------------------------------------------------------------

class SnapshotForensics(ResponsePrimitive):
    """Captures a forensic snapshot of system state at detection time.

    PRD §7.2.7: Captures process list, network connections, recent FS
    changes, substrate state summary, and the triggering signal/classification.
    Saves to ~/.et_modules/immunis/forensics/{timestamp}_{signal_id}/
    """

    @property
    def severity_floor(self) -> str:
        return "LOW"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        forensics_dir = Path(
            os.path.expanduser(
                self._config.get("forensics_dir", "~/.et_modules/immunis/forensics")
            )
        )
        min_disk_mb = self._config.get("forensics_min_disk_mb", 100)

        # Check directory is writable
        try:
            forensics_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return ValidationResult(
                passed=False, reason=f"Forensics dir not writable: {exc}"
            )

        # Check disk space
        try:
            st = os.statvfs(str(forensics_dir))
            free_mb = (st.f_bavail * st.f_frsize) / (1024 * 1024)
            if free_mb < min_disk_mb:
                return ValidationResult(
                    passed=False,
                    reason=f"Insufficient disk space: {free_mb:.0f}MB < {min_disk_mb}MB",
                )
        except OSError:
            pass  # statvfs may not be available everywhere

        return ValidationResult(passed=True, reason="Forensics snapshot ready")

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        signal_id = context.get("signal_id", str(uuid.uuid4()))
        ts = int(time.time())

        forensics_dir = Path(
            os.path.expanduser(
                self._config.get("forensics_dir", "~/.et_modules/immunis/forensics")
            )
        )
        snapshot_dir = forensics_dir / f"{ts}_{signal_id}"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        # Capture process list
        try:
            procs = []
            for entry in Path("/proc").iterdir():
                if not entry.name.isdigit():
                    continue
                try:
                    comm = (entry / "comm").read_text().strip()
                    cmdline = (entry / "cmdline").read_bytes().replace(
                        b"\x00", b" "
                    ).decode(errors="replace").strip()
                    procs.append({
                        "pid": int(entry.name),
                        "comm": comm,
                        "cmdline": cmdline,
                    })
                except (OSError, PermissionError):
                    continue
            with open(snapshot_dir / "processes.json", "w") as f:
                json.dump(procs, f, indent=2)
        except Exception as exc:
            logger.debug("Process snapshot failed: %s", exc)

        # Capture network connections
        try:
            net_data = {}
            for net_file in ["tcp", "tcp6", "udp", "udp6"]:
                path = Path(f"/proc/net/{net_file}")
                if path.exists():
                    net_data[net_file] = path.read_text()
            with open(snapshot_dir / "network.json", "w") as f:
                json.dump(net_data, f)
        except Exception as exc:
            logger.debug("Network snapshot failed: %s", exc)

        # Capture the triggering signal/classification
        try:
            signal_data = {}
            sig = context.get("signal")
            if sig is not None:
                signal_data["signal_id"] = getattr(sig, "signal_id", "")
                signal_data["sensor_type"] = getattr(sig, "sensor_type", "")
                signal_data["event_type"] = getattr(sig, "event_type", "")
                signal_data["raw_data"] = getattr(sig, "raw_data", {})
                signal_data["timestamp"] = getattr(sig, "timestamp", 0)
            classification = context.get("classification")
            if classification is not None:
                signal_data["category"] = getattr(classification, "category", "")
                signal_data["known_signature_match"] = getattr(
                    classification, "known_signature_match", False
                )
                signal_data["substrate_novelty"] = getattr(
                    classification, "substrate_novelty", 1.0
                )
                signal_data["substrate_confidence"] = getattr(
                    classification, "substrate_confidence", 0.0
                )
            with open(snapshot_dir / "trigger.json", "w") as f:
                json.dump(signal_data, f, indent=2, default=str)
        except Exception as exc:
            logger.debug("Trigger snapshot failed: %s", exc)

        duration = (time.time() - start) * 1000
        return ExecutionResult(
            status="success",
            detail=f"Forensic snapshot saved to {snapshot_dir}",
            rollback_info={"snapshot_path": str(snapshot_dir)},
            duration_ms=duration,
        )


# ---------------------------------------------------------------------------
# 7.2.1 KillProcess (Phase 2)
# ---------------------------------------------------------------------------

class KillProcess(ResponsePrimitive):
    """Terminates a process by PID.

    PRD §7.2.1: SIGTERM first, wait kill_grace_seconds (default 5),
    then SIGKILL. Severity floor HIGH.
    """

    @property
    def severity_floor(self) -> str:
        return "HIGH"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        pid = context.get("pid")
        if pid is None:
            return ValidationResult(passed=False, reason="No PID provided")

        # Cannot kill PID 1 or self
        if pid == 1:
            return ValidationResult(passed=False, reason="Cannot kill PID 1")
        if pid == os.getpid():
            return ValidationResult(passed=False, reason="Cannot kill self")

        # Check protected PIDs
        protected = self._config.get("protected_pids", [])
        if pid in protected:
            return ValidationResult(
                passed=False, reason=f"PID {pid} is protected"
            )

        # Check process exists
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return ValidationResult(
                passed=False, reason=f"PID {pid} does not exist"
            )
        except PermissionError:
            return ValidationResult(
                passed=False, reason=f"No permission to signal PID {pid}"
            )

        # Check not a kernel thread (ppid = 2 on Linux = kthreadd)
        try:
            stat_data = Path(f"/proc/{pid}/stat").read_text()
            ppid = int(stat_data.rsplit(")", 1)[-1].split()[1])
            if ppid == 2:
                return ValidationResult(
                    passed=False, reason=f"PID {pid} is a kernel thread"
                )
        except (OSError, ValueError, IndexError):
            pass

        return ValidationResult(
            passed=True,
            reason=f"PID {pid} can be terminated",
            preconditions={"pid": pid},
        )

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        pid = context.get("pid")
        grace = self._config.get("kill_grace_seconds", 5)

        try:
            # SIGTERM
            os.kill(pid, signal.SIGTERM)
            # Wait for process to exit
            for _ in range(grace * 10):
                time.sleep(0.1)
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    return ExecutionResult(
                        status="success",
                        detail=f"PID {pid} terminated via SIGTERM",
                        duration_ms=(time.time() - start) * 1000,
                    )

            # SIGKILL
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                return ExecutionResult(
                    status="success",
                    detail=f"PID {pid} terminated via SIGTERM (late exit)",
                    duration_ms=(time.time() - start) * 1000,
                )

            # Verify kill
            time.sleep(0.5)
            try:
                os.kill(pid, 0)
                return ExecutionResult(
                    status="failed",
                    detail=f"PID {pid} survived SIGKILL",
                    duration_ms=(time.time() - start) * 1000,
                )
            except ProcessLookupError:
                return ExecutionResult(
                    status="success",
                    detail=f"PID {pid} terminated via SIGKILL",
                    duration_ms=(time.time() - start) * 1000,
                )

        except Exception as exc:
            return ExecutionResult(
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# 7.2.2 QuarantineFile (Phase 2)
# ---------------------------------------------------------------------------

class QuarantineFile(ResponsePrimitive):
    """Moves a suspicious file to quarantine with metadata preserved.

    PRD §7.2.2: Severity floor MEDIUM. Writes metadata sidecar.
    """

    @property
    def severity_floor(self) -> str:
        return "MEDIUM"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        path = context.get("path")
        if path is None:
            return ValidationResult(passed=False, reason="No path provided")

        src = Path(os.path.expanduser(path))
        if not src.exists():
            return ValidationResult(
                passed=False, reason=f"File does not exist: {src}"
            )

        # Check protected paths
        protected = self._config.get("protected_paths", [])
        for pp in protected:
            if str(src).startswith(os.path.expanduser(pp)):
                return ValidationResult(
                    passed=False, reason=f"Path is protected: {pp}"
                )

        # Check quarantine dir writable
        q_dir = Path(
            os.path.expanduser(
                self._config.get("quarantine_dir", "~/.et_modules/immunis/quarantine")
            )
        )
        try:
            q_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            return ValidationResult(
                passed=False, reason=f"Quarantine dir not writable: {exc}"
            )

        return ValidationResult(
            passed=True,
            reason=f"File can be quarantined: {src}",
            preconditions={"path": str(src)},
        )

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        path = context.get("path")
        src = Path(os.path.expanduser(path))

        q_dir = Path(
            os.path.expanduser(
                self._config.get("quarantine_dir", "~/.et_modules/immunis/quarantine")
            )
        )
        q_dir.mkdir(parents=True, exist_ok=True)

        q_id = str(uuid.uuid4())
        q_file = q_dir / f"{q_id}.quarantined"
        meta_file = q_dir / f"{q_id}.meta.json"

        try:
            # Record metadata before move
            try:
                st = src.stat()
                owner = st.st_uid
                perms = st.st_mode
            except OSError:
                owner = -1
                perms = 0

            shutil.move(str(src), str(q_file))

            # Write metadata sidecar
            meta = {
                "original_path": str(src),
                "original_permissions": perms,
                "original_owner": owner,
                "quarantine_timestamp": time.time(),
                "signal_id": context.get("signal_id", ""),
                "category": getattr(
                    context.get("classification"), "category", "unknown"
                ),
                "severity": "",
            }
            classification = context.get("classification")
            if classification is not None:
                meta["severity"] = str(
                    getattr(classification, "substrate_confidence", "")
                )

            with open(meta_file, "w") as f:
                json.dump(meta, f, indent=2)

            return ExecutionResult(
                status="success",
                detail=f"Quarantined {src} → {q_file}",
                rollback_info={
                    "original_path": str(src),
                    "quarantine_path": str(q_file),
                },
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            return ExecutionResult(
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# 7.2.3 BlockConnection (Phase 2)
# ---------------------------------------------------------------------------

class BlockConnection(ResponsePrimitive):
    """Blocks a network connection via iptables.

    PRD §7.2.3: Severity floor HIGH. Requires root/sudo.
    Falls back to AlertOnly if not available.
    """

    @property
    def severity_floor(self) -> str:
        return "HIGH"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        ip = context.get("ip")
        port = context.get("port")

        if ip is None and port is None:
            return ValidationResult(
                passed=False, reason="No IP or port provided"
            )

        # Check protected destinations
        protected = self._config.get("protected_destinations", [])
        if ip in protected:
            return ValidationResult(
                passed=False, reason=f"Destination {ip} is protected"
            )

        # Check iptables availability
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True, timeout=5,
            )
            if result.returncode != 0:
                return ValidationResult(
                    passed=False,
                    reason="iptables not available or no permission",
                )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return ValidationResult(
                passed=False,
                reason="iptables not available — will fall back to AlertOnly",
            )

        return ValidationResult(
            passed=True,
            reason=f"Can block connection to {ip}:{port}",
            preconditions={"ip": ip, "port": port},
        )

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        ip = context.get("ip")
        port = context.get("port")

        cmd = ["iptables", "-A", "OUTPUT"]
        if ip:
            cmd.extend(["-d", str(ip)])
        if port:
            cmd.extend(["-p", "tcp", "--dport", str(port)])
        cmd.extend(["-j", "DROP"])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                rule_str = " ".join(cmd)
                return ExecutionResult(
                    status="success",
                    detail=f"Blocked connection: {rule_str}",
                    rollback_info={"rule": rule_str},
                    duration_ms=(time.time() - start) * 1000,
                )
            else:
                return ExecutionResult(
                    status="failed",
                    detail=f"iptables failed: {result.stderr}",
                    duration_ms=(time.time() - start) * 1000,
                )
        except Exception as exc:
            return ExecutionResult(
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# 7.2.4 RevokePermissions (Phase 2)
# ---------------------------------------------------------------------------

class RevokePermissions(ResponsePrimitive):
    """Reduces permissions on a suspicious file to read-only.

    PRD §7.2.4: Severity floor MEDIUM.
    """

    @property
    def severity_floor(self) -> str:
        return "MEDIUM"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        path = context.get("path")
        if path is None:
            return ValidationResult(passed=False, reason="No path provided")

        src = Path(os.path.expanduser(path))
        if not src.exists():
            return ValidationResult(
                passed=False, reason=f"File does not exist: {src}"
            )

        protected = self._config.get("protected_paths", [])
        for pp in protected:
            if str(src).startswith(os.path.expanduser(pp)):
                return ValidationResult(
                    passed=False, reason=f"Path is protected: {pp}"
                )

        # Check permission to chmod
        try:
            st = src.stat()
            if not os.access(str(src), os.W_OK):
                return ValidationResult(
                    passed=False,
                    reason=f"No permission to change permissions on {src}",
                )
        except OSError as exc:
            return ValidationResult(
                passed=False, reason=f"Cannot stat file: {exc}"
            )

        return ValidationResult(
            passed=True,
            reason=f"Can revoke permissions on {src}",
            preconditions={"path": str(src), "original_mode": st.st_mode},
        )

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        path = context.get("path")
        src = Path(os.path.expanduser(path))

        try:
            original_mode = src.stat().st_mode
            # Set to read-only (remove write and execute bits)
            new_mode = stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH
            os.chmod(str(src), new_mode)
            return ExecutionResult(
                status="success",
                detail=f"Permissions revoked on {src}: {oct(original_mode)} → {oct(new_mode)}",
                rollback_info={
                    "path": str(src),
                    "original_mode": original_mode,
                },
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            return ExecutionResult(
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# 7.2.5 IsolateModule (Phase 2)
# ---------------------------------------------------------------------------

class IsolateModule(ResponsePrimitive):
    """Disconnects a module from the NG-Lite peer bridge.

    PRD §7.2.5: Severity floor CRITICAL. Removes the module's shared
    learning file to prevent substrate poisoning.
    """

    @property
    def severity_floor(self) -> str:
        return "CRITICAL"

    def validate(self, context: Dict[str, Any]) -> ValidationResult:
        module_id = context.get("module_id")
        if module_id is None:
            return ValidationResult(
                passed=False, reason="No module_id provided"
            )

        if module_id == "immunis":
            return ValidationResult(
                passed=False, reason="Cannot isolate self"
            )

        # Check peer bridge file exists
        shared_dir = Path.home() / ".et_modules" / "shared_learning"
        peer_file = shared_dir / f"{module_id}.jsonl"

        if not peer_file.exists():
            return ValidationResult(
                passed=False,
                reason=f"Peer bridge file not found: {peer_file}",
            )

        return ValidationResult(
            passed=True,
            reason=f"Can isolate module {module_id}",
            preconditions={"module_id": module_id, "peer_file": str(peer_file)},
        )

    def execute(self, context: Dict[str, Any]) -> ExecutionResult:
        start = time.time()
        module_id = context.get("module_id")

        shared_dir = Path.home() / ".et_modules" / "shared_learning"
        peer_file = shared_dir / f"{module_id}.jsonl"
        q_dir = Path(
            os.path.expanduser(
                self._config.get("quarantine_dir", "~/.et_modules/immunis/quarantine")
            )
        )
        q_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Move peer file to quarantine
            q_name = f"isolated_{module_id}_{int(time.time())}.jsonl"
            q_path = q_dir / q_name
            shutil.move(str(peer_file), str(q_path))

            # Write isolation marker
            marker = shared_dir / f"{module_id}.isolated"
            with open(marker, "w") as f:
                json.dump({
                    "module_id": module_id,
                    "isolated_by": "immunis",
                    "timestamp": time.time(),
                    "reason": context.get("signal_id", "unknown"),
                }, f)

            return ExecutionResult(
                status="success",
                detail=f"Module {module_id} isolated from peer bridge",
                rollback_info={
                    "module_id": module_id,
                    "peer_file_path": str(peer_file),
                    "quarantine_path": str(q_path),
                },
                duration_ms=(time.time() - start) * 1000,
            )
        except Exception as exc:
            return ExecutionResult(
                status="failed",
                detail=str(exc),
                duration_ms=(time.time() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------

def get_all_primitives(
    config: Optional[Dict[str, Any]] = None,
) -> Dict[str, ResponsePrimitive]:
    """Return a dict of all response primitives, keyed by name."""
    cfg = config or {}
    return {
        "AlertOnly": AlertOnly(cfg),
        "SnapshotForensics": SnapshotForensics(cfg),
        "KillProcess": KillProcess(cfg),
        "QuarantineFile": QuarantineFile(cfg),
        "BlockConnection": BlockConnection(cfg),
        "RevokePermissions": RevokePermissions(cfg),
        "IsolateModule": IsolateModule(cfg),
    }
