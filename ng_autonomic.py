"""
NG Autonomic Nervous System — Ecosystem-Wide Threat Level State

This is a VENDORED FILE.  Copy it verbatim into any module that
participates in the autonomic nervous system.  Do NOT modify this
file per-module.  Changes propagate by updating the canonical source
in the NeuroGraph repository and re-vendoring.

The autonomic state file lives at:
    ~/.et_modules/autonomic_state.json

This location is OUTSIDE any individual module's directory because
the state belongs to the ecosystem, not to any module.

State transitions:
    PARASYMPATHETIC (rest/digest) → normal operations
    SYMPATHETIC (fight/flight) → elevated threat, all modules adjust

When SYMPATHETIC:
    - TrollGuard lowers its suspicious threshold
    - Immunis increases sensor poll frequency
    - THC holds off on auto-executing repairs (wait for threat to clear)
    - All modules increase logging granularity
    - Bunyan switches to maximum-detail causal narrative mode

The file wakes when a security module (Immunis, TrollGuard, Cricket)
is detected in the ecosystem.  If no security module is present, the
autonomic state file is inert.

Canonical source: https://github.com/greatnorthernfishguy-hub/NeuroGraph
License: AGPL-3.0

# ---- Changelog ----
# [2026-02-28] Claude (Opus 4.6) — Initial creation per PRD §8.2.
#   What: read_state() and write_state() functions for ecosystem-wide
#         sympathetic/parasympathetic threat level coordination.
#   Why:  PRD §8 specifies a vendored autonomic state file for fast-read
#         ecosystem-wide threat level. Sub-millisecond read access.
#   Settings: State file at ~/.et_modules/autonomic_state.json.
#         Valid states: PARASYMPATHETIC, SYMPATHETIC.
#         Valid threat levels: none, low, medium, high, critical.
#   How:  JSON state file with atomic write (temp file + os.replace).
#         read_state() returns default PARASYMPATHETIC if file missing.
#         write_state() validates state before writing.
# -------------------
"""

import json
import os
import time
from pathlib import Path
from typing import Optional

_STATE_PATH = Path.home() / ".et_modules" / "autonomic_state.json"
_VALID_STATES = {"PARASYMPATHETIC", "SYMPATHETIC"}
_VALID_THREAT_LEVELS = {"none", "low", "medium", "high", "critical"}


def read_state() -> dict:
    """Read the current autonomic state.  Fast path — ~0.1ms.

    Returns:
        {
            "state": "PARASYMPATHETIC" | "SYMPATHETIC",
            "threat_level": "none" | "low" | "medium" | "high" | "critical",
            "triggered_by": str,          # module_id that set the state
            "timestamp": float,           # when the state was last changed
            "reason": str,                # human-readable reason
        }

    If the state file does not exist, returns PARASYMPATHETIC with
    threat_level "none".  This is the default state.
    """
    if not _STATE_PATH.exists():
        return {
            "state": "PARASYMPATHETIC",
            "threat_level": "none",
            "triggered_by": "",
            "timestamp": 0.0,
            "reason": "default — no security module has written state",
        }
    try:
        with open(_STATE_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {
            "state": "PARASYMPATHETIC",
            "threat_level": "none",
            "triggered_by": "",
            "timestamp": 0.0,
            "reason": "state file unreadable — defaulting to PARASYMPATHETIC",
        }


def write_state(
    state: str,
    threat_level: str,
    triggered_by: str,
    reason: str,
) -> None:
    """Write the autonomic state.  Only security modules should call this.

    Args:
        state: "PARASYMPATHETIC" or "SYMPATHETIC"
        threat_level: "none" | "low" | "medium" | "high" | "critical"
        triggered_by: module_id of the calling module
        reason: human-readable reason for the state change
    """
    if state not in _VALID_STATES:
        raise ValueError(f"Invalid state: {state}. Must be one of {_VALID_STATES}")

    _STATE_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "state": state,
        "threat_level": threat_level,
        "triggered_by": triggered_by,
        "timestamp": time.time(),
        "reason": reason,
    }
    # Atomic write: temp file + rename
    tmp_path = _STATE_PATH.with_suffix(".tmp")
    with open(tmp_path, "w") as f:
        json.dump(data, f)
    os.replace(tmp_path, _STATE_PATH)
