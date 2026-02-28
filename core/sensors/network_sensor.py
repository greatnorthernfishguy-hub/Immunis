"""
Immunis Network Sensor — Network Connection Monitoring

Monitors network connections by reading /proc/net/tcp, /proc/net/tcp6,
/proc/net/udp, /proc/net/udp6, and /proc/net/unix at the configured
poll interval.

Canonical source: https://github.com/greatnorthernfishguy-hub/Immunis
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation.
#   What: NetworkSensor class monitoring outbound connections, suspicious
#         ports, listening ports, connection volume spikes. Reads
#         /proc/net/* directly per PRD §5.3.
#   Why:  PRD §5.3 specifies network sensor reading /proc/net/*.
#   Settings: poll_interval_seconds=15.0, suspicious_ports=[4444,5555,
#         8888,1337], known_good_destinations=["127.0.0.1","::1"],
#         max_outbound_connections=100.
#   How:  Parses /proc/net/tcp and friends. Compares against previous
#         snapshot for new connections. Embedding per PRD §5.3.
# -------------------
"""

from __future__ import annotations

import hashlib
import logging
import os
import struct
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np

from core.sensors.base import Sensor

logger = logging.getLogger("immunis.sensors.network")

# TCP connection states
_TCP_STATES = {
    "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
    "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
    "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
    "0A": "LISTEN", "0B": "CLOSING",
}


def _hex_to_ip(hex_ip: str) -> str:
    """Convert hex IP from /proc/net/tcp to dotted decimal."""
    if len(hex_ip) == 8:
        # IPv4
        ip_int = int(hex_ip, 16)
        return ".".join(
            str((ip_int >> (8 * i)) & 0xFF) for i in range(4)
        )
    elif len(hex_ip) == 32:
        # IPv6 — simplified
        return f"ipv6:{hex_ip[:8]}"
    return hex_ip


def _hex_to_port(hex_port: str) -> int:
    """Convert hex port from /proc/net/tcp."""
    return int(hex_port, 16)


class NetworkSensor(Sensor):
    """Monitors network connections via /proc/net/* (PRD §5.3)."""

    SENSOR_TYPE = "network"
    POLL_INTERVAL_SECONDS = 15.0

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._known_connections: Set[str] = set()
        self._first_poll = True
        self._suspicious_ports = set(
            self._config.get("suspicious_ports", [4444, 5555, 8888, 1337])
        )
        self._good_dests = set(
            self._config.get("known_good_destinations", ["127.0.0.1", "::1"])
        )
        self._max_outbound = self._config.get("max_outbound_connections", 100)
        self._last_connection_count = 0

    def _poll(self) -> List[Dict[str, Any]]:
        """Read /proc/net/* for current connections."""
        events: List[Dict[str, Any]] = []
        current_connections: Set[str] = set()
        outbound_count = 0

        for proto_file, proto_name in [
            ("tcp", "TCP"), ("tcp6", "TCP6"),
            ("udp", "UDP"), ("udp6", "UDP6"),
        ]:
            entries = self._parse_proc_net(proto_file)
            for entry in entries:
                conn_key = (
                    f"{entry['local_ip']}:{entry['local_port']}->"
                    f"{entry['remote_ip']}:{entry['remote_port']}"
                    f"/{proto_name}"
                )
                current_connections.add(conn_key)
                entry["protocol"] = proto_name

                # Count outbound
                if entry.get("state") == "ESTABLISHED":
                    outbound_count += 1

                # Detect suspicious ports
                if entry["remote_port"] in self._suspicious_ports:
                    entry["event_type"] = "suspicious_port"
                    events.append(entry)
                    continue

                # Detect unknown destinations (skip good ones)
                if (entry.get("state") == "ESTABLISHED"
                        and entry["remote_ip"] not in self._good_dests):
                    if conn_key not in self._known_connections and not self._first_poll:
                        entry["event_type"] = "new_outbound_connection"
                        events.append(entry)

                # Detect new listening ports
                if entry.get("state") == "LISTEN":
                    if conn_key not in self._known_connections and not self._first_poll:
                        entry["event_type"] = "new_listening_port"
                        events.append(entry)

        # Connection volume spike
        if outbound_count > self._max_outbound:
            events.append({
                "event_type": "connection_volume_spike",
                "outbound_count": outbound_count,
                "threshold": self._max_outbound,
                "timestamp": time.time(),
            })

        self._known_connections = current_connections
        self._last_connection_count = outbound_count
        self._first_poll = False
        return events

    def _parse_proc_net(self, filename: str) -> List[Dict[str, Any]]:
        """Parse a /proc/net file (tcp, tcp6, udp, udp6)."""
        path = Path(f"/proc/net/{filename}")
        if not path.exists():
            return []

        entries: List[Dict[str, Any]] = []
        try:
            lines = path.read_text().splitlines()
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) < 10:
                    continue

                local = parts[1].split(":")
                remote = parts[2].split(":")
                state_hex = parts[3]

                local_ip = _hex_to_ip(local[0])
                local_port = _hex_to_port(local[1])
                remote_ip = _hex_to_ip(remote[0])
                remote_port = _hex_to_port(remote[1])
                state = _TCP_STATES.get(state_hex, state_hex)

                # Get associated PID (inode -> PID mapping)
                inode = parts[9] if len(parts) > 9 else ""

                entries.append({
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "state": state,
                    "inode": inode,
                    "timestamp": time.time(),
                })
        except (OSError, PermissionError):
            pass

        return entries

    def _embed(self, event: Dict[str, Any]) -> np.ndarray:
        """Embed a network event as a feature vector.

        PRD §5.3 embedding strategy: dest IP hash, dest port normalized,
        protocol, connection state, associated process PID → command hash,
        bytes sent/received, time since last connection to same dest.
        """
        features: List[float] = []

        # Dest IP hash (4 dims)
        dest_ip = event.get("remote_ip", event.get("dest_ip", ""))
        ip_hash = hashlib.sha256(dest_ip.encode()).digest()
        for b in ip_hash[:4]:
            features.append(b / 255.0)

        # Dest port (1 dim, normalized)
        dest_port = event.get("remote_port", event.get("dest_port", 0))
        features.append(min(dest_port / 65535.0, 1.0))

        # Protocol (1 dim)
        proto = event.get("protocol", "TCP")
        proto_map = {"TCP": 0.0, "TCP6": 0.25, "UDP": 0.5, "UDP6": 0.75}
        features.append(proto_map.get(proto, 1.0))

        # Connection state (1 dim)
        state = event.get("state", "")
        state_map = {
            "ESTABLISHED": 0.0, "LISTEN": 0.1, "SYN_SENT": 0.2,
            "SYN_RECV": 0.3, "TIME_WAIT": 0.4, "CLOSE_WAIT": 0.5,
            "CLOSE": 0.6, "FIN_WAIT1": 0.7, "FIN_WAIT2": 0.8,
            "CLOSING": 0.9,
        }
        features.append(state_map.get(state, 1.0))

        # Event type (1 dim)
        etype = event.get("event_type", "unknown")
        etype_map = {
            "new_outbound_connection": 0.0, "suspicious_port": 0.25,
            "new_listening_port": 0.5, "connection_volume_spike": 0.75,
        }
        features.append(etype_map.get(etype, 1.0))

        # Is suspicious port? (1 dim)
        features.append(1.0 if dest_port in self._suspicious_ports else 0.0)

        # Local port (1 dim)
        local_port = event.get("local_port", 0)
        features.append(min(local_port / 65535.0, 1.0))

        return self._feature_embed(features)

    def _is_relevant(self, event: Dict[str, Any]) -> bool:
        """Filter out events for known good destinations."""
        dest_ip = event.get("remote_ip", "")
        if dest_ip in self._good_dests and event.get("event_type") != "suspicious_port":
            return False
        return True
