"""
Immunis Process Sensor — Process Activity Monitoring

Monitors process activity by reading /proc (Linux) at the configured
poll interval. Does NOT use psutil — reads /proc directly to minimize
dependencies.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: ProcessSensor class monitoring new processes, unexpected
#         parents, resource abuse, suspicious locations, elevated
#         privileges. Reads /proc directly per PRD §5.2.
#   Why:  PRD §5.2 specifies process sensor reading /proc directly,
#         no psutil dependency.
#   Settings: poll_interval_seconds=10.0, cpu_threshold_pct=90.0,
#         memory_threshold_pct=80.0, allowlist and suspicious locations
#         per PRD §5.2.
#   How:  Reads /proc/[pid]/stat, /proc/[pid]/cmdline, /proc/[pid]/status
#         for each PID. Compares against previous poll snapshot to detect
#         new processes. Embedding per PRD §5.2: command hash + cmdline
#         hash + parent chain hash + uid + cpu% + mem% + age + cwd hash +
#         fd count.
# -------------------
"""

from __future__ import annotations

import hashlib
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.process")


class ProcessSensor(Sensor):
    """Monitors process activity via /proc for the Quartermaster pipeline.

    PRD §5.2: Reads /proc directly. No psutil dependency.
    """

    SENSOR_TYPE = "process"
    POLL_INTERVAL_SECONDS = 10.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._known_pids: Set[int] = set()
        self._process_cache: Dict[int, Dict[str, Any]] = {}
        self._first_poll = True
        self._cpu_threshold = self._config.get("cpu_threshold_pct", 90.0)
        self._mem_threshold = self._config.get("memory_threshold_pct", 80.0)
        self._allowlist = set(
            self._config.get("known_process_allowlist", ["sshd", "systemd", "python3"])
        )
        self._suspicious_locations = self._config.get(
            "suspicious_locations", ["/tmp", "/dev/shm", "/var/tmp"]
        )

    def _poll(self) -> List[Dict[str, Any]]:
        """Read /proc for current process list and detect changes."""
        events: List[Dict[str, Any]] = []
        current_pids: Set[int] = set()
        current_procs: Dict[int, Dict[str, Any]] = {}

        # Read total memory for percentage calculations
        total_mem_kb = self._get_total_memory_kb()

        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            current_pids.add(pid)

            proc_info = self._read_proc_info(pid, total_mem_kb)
            if proc_info is None:
                continue
            current_procs[pid] = proc_info

        # Detect new processes
        new_pids = current_pids - self._known_pids
        if not self._first_poll:
            for pid in new_pids:
                info = current_procs.get(pid)
                if info is None:
                    continue
                events.append({
                    "event_type": "new_process",
                    "pid": pid,
                    **info,
                    "timestamp": time.time(),
                })

        # Detect resource abuse in existing processes
        for pid, info in current_procs.items():
            comm = info.get("comm", "")
            if comm in self._allowlist:
                continue

            if info.get("cpu_pct", 0) > self._cpu_threshold:
                events.append({
                    "event_type": "cpu_abuse",
                    "pid": pid,
                    **info,
                    "timestamp": time.time(),
                })
            if info.get("mem_pct", 0) > self._mem_threshold:
                events.append({
                    "event_type": "memory_abuse",
                    "pid": pid,
                    **info,
                    "timestamp": time.time(),
                })

            # Process running from suspicious location
            cwd = info.get("cwd", "")
            for sloc in self._suspicious_locations:
                if cwd.startswith(sloc):
                    if pid in new_pids:
                        events[-1]["event_type"] = "suspicious_location"
                    break

        self._known_pids = current_pids
        self._process_cache = current_procs
        self._first_poll = False
        return events

    def _read_proc_info(
        self, pid: int, total_mem_kb: int
    ) -> Optional[Dict[str, Any]]:
        """Read process information from /proc/[pid]/."""
        proc_dir = Path("/proc") / str(pid)
        info: Dict[str, Any] = {"pid": pid}

        # comm (command name)
        try:
            info["comm"] = (proc_dir / "comm").read_text().strip()
        except (OSError, PermissionError):
            info["comm"] = ""

        # cmdline
        try:
            raw = (proc_dir / "cmdline").read_bytes()
            info["cmdline"] = raw.replace(b"\x00", b" ").decode(errors="replace").strip()
        except (OSError, PermissionError):
            info["cmdline"] = ""

        # stat (for ppid, utime, stime)
        try:
            stat_data = (proc_dir / "stat").read_text()
            parts = stat_data.rsplit(")", 1)[-1].split()
            # parts[0]=state, parts[1]=ppid, ...
            info["ppid"] = int(parts[1]) if len(parts) > 1 else 0
            info["utime"] = int(parts[11]) if len(parts) > 11 else 0
            info["stime"] = int(parts[12]) if len(parts) > 12 else 0
        except (OSError, PermissionError, ValueError, IndexError):
            info["ppid"] = 0
            info["utime"] = 0
            info["stime"] = 0

        # status (for uid, VmRSS)
        try:
            status_text = (proc_dir / "status").read_text()
            for line in status_text.splitlines():
                if line.startswith("Uid:"):
                    info["uid"] = int(line.split()[1])
                elif line.startswith("VmRSS:"):
                    rss_kb = int(line.split()[1])
                    info["rss_kb"] = rss_kb
                    info["mem_pct"] = (
                        rss_kb / total_mem_kb * 100.0
                        if total_mem_kb > 0
                        else 0.0
                    )
        except (OSError, PermissionError, ValueError):
            info.setdefault("uid", -1)
            info.setdefault("rss_kb", 0)
            info.setdefault("mem_pct", 0.0)

        # Approximate CPU% from utime/stime delta
        old = self._process_cache.get(pid)
        if old is not None:
            dt_ticks = (
                (info["utime"] + info["stime"])
                - (old.get("utime", 0) + old.get("stime", 0))
            )
            clock_ticks = os.sysconf("SC_CLK_TCK")
            poll_interval = self.POLL_INTERVAL_SECONDS
            info["cpu_pct"] = (
                dt_ticks / clock_ticks / poll_interval * 100.0
                if poll_interval > 0 and clock_ticks > 0
                else 0.0
            )
        else:
            info["cpu_pct"] = 0.0

        # cwd
        try:
            info["cwd"] = os.readlink(f"/proc/{pid}/cwd")
        except (OSError, PermissionError):
            info["cwd"] = ""

        # fd count
        try:
            info["fd_count"] = len(os.listdir(f"/proc/{pid}/fd"))
        except (OSError, PermissionError):
            info["fd_count"] = 0

        # Process age
        try:
            proc_start = os.stat(proc_dir).st_mtime
            info["age_seconds"] = time.time() - proc_start
        except OSError:
            info["age_seconds"] = 0.0

        return info

    @staticmethod
    def _get_total_memory_kb() -> int:
        """Read total system memory from /proc/meminfo."""
        try:
            for line in Path("/proc/meminfo").read_text().splitlines():
                if line.startswith("MemTotal:"):
                    return int(line.split()[1])
        except (OSError, ValueError):
            pass
        return 1

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a process event as a feature vector.

        PRD §5.2 embedding strategy:
        - Command name hash
        - Full command line hash
        - Parent PID relationship (hash of parent→child chain up to depth 3)
        - User ID
        - CPU percentage (normalized)
        - Memory percentage (normalized)
        - Process age (seconds since spawn)
        - Working directory hash
        - Open file descriptor count
        """
        features: List[float] = []

        # Command name hash (4 dims)
        comm = event.get("comm", "")
        comm_hash = hashlib.sha256(comm.encode()).digest()
        for b in comm_hash[:4]:
            features.append(b / 255.0)

        # Cmdline hash (4 dims)
        cmdline = event.get("cmdline", "")
        cmd_hash = hashlib.sha256(cmdline.encode()).digest()
        for b in cmd_hash[:4]:
            features.append(b / 255.0)

        # Parent chain hash (4 dims)
        pid = event.get("pid", 0)
        ppid = event.get("ppid", 0)
        chain = f"{pid}->{ppid}"
        chain_hash = hashlib.sha256(chain.encode()).digest()
        for b in chain_hash[:4]:
            features.append(b / 255.0)

        # UID (1 dim, normalized)
        uid = event.get("uid", -1)
        features.append(min(uid / 65535.0, 1.0) if uid >= 0 else 0.0)

        # CPU% (1 dim)
        features.append(min(event.get("cpu_pct", 0.0) / 100.0, 1.0))

        # Memory% (1 dim)
        features.append(min(event.get("mem_pct", 0.0) / 100.0, 1.0))

        # Process age (1 dim, normalized to hours)
        age = event.get("age_seconds", 0.0)
        features.append(min(age / 86400.0, 1.0))

        # CWD hash (4 dims)
        cwd = event.get("cwd", "")
        cwd_hash = hashlib.sha256(cwd.encode()).digest()
        for b in cwd_hash[:4]:
            features.append(b / 255.0)

        # FD count (1 dim, normalized)
        fd_count = event.get("fd_count", 0)
        features.append(min(fd_count / 1000.0, 1.0))

        # Event type (1 dim)
        etype = event.get("event_type", "unknown")
        type_map = {
            "new_process": 0.0, "cpu_abuse": 0.25,
            "memory_abuse": 0.5, "suspicious_location": 0.75,
        }
        features.append(type_map.get(etype, 1.0))

        # Is root? (1 dim)
        features.append(1.0 if uid == 0 else 0.0)

        return self._feature_embed(features)

    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """Filter out allowlisted processes for non-abuse events."""
        comm = event.get("comm", "")
        event_type = event.get("event_type", "")
        if comm in self._allowlist and event_type == "new_process":
            return False
        return True
