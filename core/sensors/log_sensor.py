"""
Immunis Log Sensor — System Log Monitoring

Monitors system logs for security-relevant events. Tails log files
and emits events for patterns the substrate should learn from.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-04-08] Claude (Sonnet 4.6) — Ecosystem process log monitoring.
#   What: Added ecosystem WARNING/ERROR pattern matching alongside
#         existing security patterns. Produces ecosystem_warning and
#         ecosystem_error event types from neurograph-rpc log output.
#         Uses ng_embed (semantic) for these events so similar failures
#         cluster in the substrate — enabling THC to recognize patterns.
#   Why:  THC needs ecosystem failure signals from the River to trigger
#         diagnosis and repair. Immunis already watches journalctl;
#         pointing it at [neurograph-rpc] WARNING/ERROR lines closes
#         the loop between real ecosystem failures and THC's detection
#         pipeline. Existing security patterns unchanged.
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: LogSensor class monitoring auth failures, brute force,
#         sudo usage, SSH key changes, service start/stop.
#   Why:  PRD §5.5 specifies log sensor for auth failures, brute
#         force detection, and security-relevant log events.
#   Settings: poll_interval_seconds=30.0, log_sources from
#         /var/log/auth.log and /var/log/syslog, auth_failure
#         window and threshold per PRD §5.5.
#   How:  Tails log files from last-read position. Uses journalctl
#         if available. Hash-based embedding per PRD §5.5.
# -------------------
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.log")


class LogSensor(Sensor):
    """Monitors system logs for security events (PRD §5.5)."""

    SENSOR_TYPE = "log"
    POLL_INTERVAL_SECONDS = 30.0

    # Patterns for security-relevant log lines
    _AUTH_FAIL_RE = re.compile(
        r"(authentication failure|Failed password|pam_unix.*auth.*failure)",
        re.IGNORECASE,
    )
    _SUDO_RE = re.compile(r"sudo:.*COMMAND=", re.IGNORECASE)
    _SSH_KEY_RE = re.compile(
        r"(Accepted publickey|authorized_keys|ssh-keygen)", re.IGNORECASE,
    )
    _SERVICE_RE = re.compile(
        r"(Started|Stopped|Starting|Stopping)\s+\S+", re.IGNORECASE,
    )

    # Ecosystem process health patterns — neurograph-rpc WARNING/ERROR output.
    # These feed THC's detection pipeline via the substrate River.
    _ECOSYSTEM_WARNING_RE = re.compile(
        r"\[neurograph-rpc\]\s+WARNING"
        r"|\[py\].*WARNING.*(?:failed|error|missing|invalid)",
        re.IGNORECASE,
    )
    _ECOSYSTEM_ERROR_RE = re.compile(
        r"\[neurograph-rpc\]\s+ERROR"
        r"|Python process exited"
        r"|\[py\].*ERROR",
        re.IGNORECASE,
    )

    # Ecosystem process health patterns — neurograph-rpc WARNING/ERROR output.
    # These feed THC's detection pipeline via the substrate River.
    _ECOSYSTEM_WARNING_RE = re.compile(
        r"\[neurograph-rpc\]\s+WARNING|\[py\].*WARNING.*(?:failed|error|missing|invalid)",
        re.IGNORECASE,
    )
    _ECOSYSTEM_ERROR_RE = re.compile(
        r"\[neurograph-rpc\]\s+ERROR"
        r"|Python process exited"
        r"|\[py\].*ERROR",
        re.IGNORECASE,
    )

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._log_sources = self._config.get(
            "log_sources", ["/var/log/auth.log", "/var/log/syslog"]
        )
        self._use_journalctl = self._config.get("use_journalctl", True)
        self._auth_fail_window = self._config.get(
            "auth_failure_window_seconds", 300
        )
        self._auth_fail_threshold = self._config.get(
            "auth_failure_threshold", 5
        )
        self._max_log_line = self._config.get("max_log_line_chars", 500)

        # File position tracking for tailing
        self._file_positions: Dict[str, int] = {}
        # Journalctl cursor
        self._journal_cursor: Optional[str] = None
        # Auth failure tracking for brute force detection
        self._auth_failures: Dict[str, List[float]] = defaultdict(list)

    def _poll(self) -> List[Dict[str, Any]]:
        """Read new log entries from all sources."""
        events: List[Dict[str, Any]] = []

        # Read from log files
        for source in self._log_sources:
            events.extend(self._tail_file(source))

        # Read from journalctl if available
        if self._use_journalctl:
            events.extend(self._read_journal())

        return events

    def _tail_file(self, path: str) -> List[Dict[str, Any]]:
        """Read new lines from a log file since last poll."""
        events: List[Dict[str, Any]] = []
        p = Path(path)
        if not p.exists():
            return events

        try:
            last_pos = self._file_positions.get(path, 0)
            file_size = p.stat().st_size

            # File was truncated/rotated
            if file_size < last_pos:
                last_pos = 0

            with open(p, "r", errors="replace") as f:
                f.seek(last_pos)
                for line in f:
                    event = self._parse_log_line(line.strip(), path)
                    if event is not None:
                        events.append(event)
                self._file_positions[path] = f.tell()

        except (PermissionError, OSError):
            pass

        return events

    def _read_journal(self) -> List[Dict[str, Any]]:
        """Read new entries from systemd journal."""
        events: List[Dict[str, Any]] = []
        cmd = ["journalctl", "--no-pager", "-o", "short"]

        if self._journal_cursor is not None:
            cmd.extend(["--after-cursor", self._journal_cursor])
        else:
            cmd.extend(["--since", "30 seconds ago"])

        cmd.append("--show-cursor")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                for line in lines:
                    if line.startswith("-- cursor:"):
                        self._journal_cursor = line.split(":", 1)[1].strip()
                        continue
                    event = self._parse_log_line(line.strip(), "journalctl")
                    if event is not None:
                        events.append(event)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

        return events

    def _parse_log_line(
        self, line: str, source: str
    ) -> Optional[Dict[str, Any]]:
        """Parse a log line for security-relevant events."""
        if not line:
            return None

        event: Optional[Dict[str, Any]] = None

        # Authentication failure
        if self._AUTH_FAIL_RE.search(line):
            # Extract source IP/user if possible
            src = self._extract_source(line)
            self._record_auth_failure(src)

            event = {
                "event_type": "auth_failure",
                "source": source,
                "line": line[:self._max_log_line],
                "auth_source": src,
                "timestamp": time.time(),
            }

            # Check for brute force
            if self._is_brute_force(src):
                event["event_type"] = "brute_force"
                event["failure_count"] = len(self._auth_failures[src])

        # Sudo usage
        elif self._SUDO_RE.search(line):
            event = {
                "event_type": "sudo_usage",
                "source": source,
                "line": line[:self._max_log_line],
                "timestamp": time.time(),
            }

        # SSH key changes
        elif self._SSH_KEY_RE.search(line):
            event = {
                "event_type": "ssh_key_event",
                "source": source,
                "line": line[:self._max_log_line],
                "timestamp": time.time(),
            }

        # Service start/stop
        elif self._SERVICE_RE.search(line):
            event = {
                "event_type": "service_change",
                "source": source,
                "line": line[:self._max_log_line],
                "timestamp": time.time(),
            }

        # Ecosystem process error — feeds THC detection pipeline
        elif self._ECOSYSTEM_ERROR_RE.search(line):
            event = {
                "event_type": "ecosystem_error",
                "source": source,
                "line": line[:self._max_log_line],
                "timestamp": time.time(),
            }

        # Ecosystem process warning — feeds THC detection pipeline
        elif self._ECOSYSTEM_WARNING_RE.search(line):
            event = {
                "event_type": "ecosystem_warning",
                "source": source,
                "line": line[:self._max_log_line],
                "timestamp": time.time(),
            }

        return event

    @staticmethod
    def _extract_source(line: str) -> str:
        """Extract source IP or user from an auth failure line."""
        # Try to find IP
        ip_match = re.search(r"from\s+(\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            return ip_match.group(1)
        # Try to find user
        user_match = re.search(r"user[= ]+(\S+)", line, re.IGNORECASE)
        if user_match:
            return user_match.group(1)
        return "unknown"

    def _record_auth_failure(self, source: str) -> None:
        """Record an auth failure for brute force detection."""
        now = time.time()
        self._auth_failures[source].append(now)
        # Prune old entries
        cutoff = now - self._auth_fail_window
        self._auth_failures[source] = [
            t for t in self._auth_failures[source] if t > cutoff
        ]

    def _is_brute_force(self, source: str) -> bool:
        """Check if failures from this source exceed threshold."""
        return len(self._auth_failures[source]) >= self._auth_fail_threshold

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a log event.

        PRD §5.5: Security events use hash-based embedding for consistency.
        Ecosystem events (ecosystem_warning, ecosystem_error) use ng_embed
        so similar failures cluster semantically in the substrate — enabling
        THC to recognise patterns across restarts via cosine similarity.
        """
        line = event.get("line", "")
        etype = event.get("event_type", "unknown")
        text = f"{etype}:{line}"

        if etype in ("ecosystem_warning", "ecosystem_error"):
            try:
                from ng_embed import embed
                return embed(text)
            except Exception:
                pass  # fall through to hash

        return self._hash_embed(text)
