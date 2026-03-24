# Immunis Repository
## Claude Code Onboarding — Repo-Specific

**You have already read the global `CLAUDE.md` and `ARCHITECTURE.md`.**
**If you have not, stop. Go read them. The Laws defined there govern this repo.**
**This document adds Immunis-specific rules on top of those Laws.**

---
## Vault Context
For full ecosystem context, read these from the Obsidian vault (`~/docs/`):
- **Module page:** `~/docs/modules/Immunis.md`
- **Concepts:** `~/docs/concepts/The Triad.md`, `~/docs/concepts/Autonomic State.md`, `~/docs/concepts/Vendored Files.md`
- **Systems:** `~/docs/systems/NG-Lite.md`, `~/docs/systems/NG Peer Bridge.md`
- **Audits:** `~/docs/audits/ecosystem-test-suite-audit-2026-03-23.md`, `~/docs/audits/ecosystem-static-value-audit-2026-03-23.md`

Each vault page has a Context Map at the top linking to related docs. Follow those links for ripple effects and dependencies.

---


## What This Repo Is

Immunis is the T-cell system of the E-T Systems digital organism. It detects and responds to host-level threats — filesystem intrusions, process anomalies, network irregularities, memory corruption, dependency tampering, log indicators, and substrate topology disturbances.

Immunis is part of the **Triad** (Immunis, Elmer, THC). The Triad forms a closed-loop self-regulating system:
- **Immunis** detects host-level threats
- **Elmer** maintains substrate-level cognitive conditions
- **THC** diagnoses and repairs

They do not coordinate directly. The River flows. The topology reshapes itself.

**Status: Built, not integrated.** Vendored files synced to NeuroGraph canonical (2026-03-18). Code is architecturally compliant. Not yet running as a service on the VPS.

---

## 1. Repository Structure

```
~/Immunis/
├── immunis_hook.py                # OpenClaw skill entry point (ImmunisHook singleton)
├── et_module.json                 # Module manifest (v2 schema)
├── config.yaml                    # All configuration
├── SKILL.md                       # OpenClaw skill discovery
├── core/                          # Core domain logic
│   ├── config.py                  # ImmunisConfig — all settings from config.yaml
│   ├── quartermaster.py           # Signal triage pipeline (PRD §4)
│   ├── armory.py                  # Known threat signature store (PRD §6)
│   ├── response_primitives.py     # Response actions: isolate, kill, quarantine, etc. (PRD §7)
│   ├── feedback.py                # Training wheels + user feedback loop (PRD §9)
│   └── sensors/                   # Seven sensor types (PRD §5)
│       ├── base.py                # Sensor ABC
│       ├── filesystem_sensor.py   # File creation/modification/deletion monitoring
│       ├── process_sensor.py      # Process spawning, resource usage, anomaly
│       ├── network_sensor.py      # Connection tracking, port scanning detection
│       ├── dependency_sensor.py   # Package/module integrity verification
│       ├── log_sensor.py          # System and application log pattern scanning
│       ├── memory_sensor.py       # Memory usage anomalies, OOM indicators
│       └── substrate_sensor.py    # Peer substrate topology monitoring (read-only)
├── ng_lite.py                     # VENDORED — canonical from NeuroGraph
├── ng_peer_bridge.py              # VENDORED — canonical from NeuroGraph
├── ng_ecosystem.py                # VENDORED — canonical from NeuroGraph
├── ng_autonomic.py                # VENDORED — canonical from NeuroGraph
├── openclaw_adapter.py            # VENDORED — canonical from NeuroGraph
└── tests/                         # Test suite
    ├── test_armory.py
    ├── test_config.py
    ├── test_feedback.py
    ├── test_hook.py
    ├── test_quartermaster.py
    ├── test_response_primitives.py
    └── test_sensors.py
```

---

## 2. Key Architectural Constraint: Immunis WRITES Autonomic State

Immunis is one of only three modules authorized to write to `ng_autonomic.py` (the others are TrollGuard and Cricket when built).

### When Immunis Writes

- **SYMPATHETIC**: On CRITICAL severity threat detection
- **PARASYMPATHETIC**: When all CRITICAL/HIGH threats are neutralized

### How It Writes

`immunis_hook.py` lines 398-417: `_set_autonomic()` calls `ng_autonomic.write_state()` with atomic JSON write (temp file + `os.replace`). Checkpoints immediately after state transition.

### What It Must Never Do

- Write autonomic state for non-security reasons (health monitoring is Elmer's domain)
- Write arbitrary state values — only `SYMPATHETIC` and `PARASYMPATHETIC`
- Write without a clear security trigger

---

## 3. The Quartermaster Pipeline

The Quartermaster (`core/quartermaster.py`, PRD §4) is Immunis's central triage system. On each `on_message()` call:

```
Sensors poll → raw ThreatSignals buffered
  → Quartermaster.ingest_signals(signals)
  → Quartermaster.process_batch(max_count=50)
    → For each signal:
      1. Armory fast-path (known signature match?)
      2. Substrate classification (get_recommendations from NG-Lite)
      3. Severity assessment (confidence × novelty matrix)
      4. Response selection (primitive matching)
      5. Training wheels gate (auto-execute vs recommend)
      6. Response execution
      7. Outcome recording to substrate
  → Check autonomic transitions
  → Process feedback responses
  → Auto-checkpoint
```

### The Severity Matrix (PRD §4.4)

The Quartermaster uses a confidence × novelty decision tree for severity assessment. This is a **constitutional rule** (bounded response behavior), not a substrate-learnable parameter. Do not attempt to make it dynamic without explicit Josh approval.

---

## 4. The Seven Sensors

Each sensor polls on every `on_message()` call and emits raw `ThreatSignal` objects:

| Sensor | What It Monitors | Poll Interval |
|--------|-----------------|---------------|
| `FilesystemSensor` | File creation/modification/deletion in watched paths | 5s |
| `ProcessSensor` | Process spawning, CPU/memory usage anomalies | 10s |
| `NetworkSensor` | Connection tracking, unexpected ports, scan detection | 15s |
| `DependencySensor` | Package integrity, unexpected dependency changes | 30s |
| `LogSensor` | System/app log patterns matching threat indicators | 30s |
| `MemorySensor` | Memory usage anomalies, OOM indicators | 10s |
| `SubstrateSensor` | Peer substrate topology via shared learning files | 60s |

All sensors are configurable and individually disableable via `config.yaml`. Poll intervals are config-driven, not hardcoded.

The `SubstrateSensor` reads `~/.et_modules/shared_learning/*.jsonl` in **read-only** mode. This is not inter-module communication — it is topology inspection via the River. No writes, no commands, no coupling.

---

## 5. Training Wheels

Immunis starts in training wheels mode on fresh systems (PRD §9). In this mode:
- **No auto-execution** of responses regardless of confidence
- All responses are logged as recommendations only
- Deactivation requires meeting all thresholds:
  - Minimum Armory entries
  - Minimum substrate outcomes
  - Minimum user feedbacks
  - Minimum runtime hours

Training wheels state is tracked by `FeedbackManager` and checked on every message cycle.

---

## 6. The Armory

`core/armory.py` (PRD §6) stores known threat signatures for fast-path matching. When a new signal matches a known signature above the match threshold, the Quartermaster can skip substrate classification and go directly to response selection.

The Armory learns from outcomes: successful threat responses are stored as signatures. This is substrate-compatible learning — the Armory enriches itself from experience.

---

## 7. Response Primitives

`core/response_primitives.py` (PRD §7) defines the available response actions:

- Process termination (with grace period)
- File quarantine (move to isolation directory)
- Network connection blocking
- Forensic snapshot capture
- Cache clearing

All primitives have `validate()` and `execute()` methods. Protected PIDs, paths, and network destinations are configurable and enforced — Immunis will not kill `sshd` or quarantine `/etc/ssh`.

---

## 8. Vendored Files

All five vendored files synced to NeuroGraph canonical on 2026-03-18:

| File | Location | Purpose |
|------|----------|---------|
| `ng_lite.py` | Repo root | Tier 1 learning substrate |
| `ng_peer_bridge.py` | Repo root | Tier 2 cross-module learning |
| `ng_ecosystem.py` | Repo root | Tier management lifecycle |
| `ng_autonomic.py` | Repo root | Autonomic state (**Immunis has write permission**) |
| `openclaw_adapter.py` | Repo root | OpenClaw skill base class |

---

## 9. What Immunis Does NOT Do

- Immunis **never** performs substrate maintenance — Elmer's domain
- Immunis **never** executes repairs — THC's domain
- Immunis **never** calls other modules directly — Law 1
- Immunis **never** classifies experience before feeding it to the substrate — Law 7

When Immunis detects something outside its domain, it records to the substrate and steps back.

---

## 10. What Claude Code May and May Not Do

### Without Josh's Approval

**Permitted:**
- Read any file in the repo
- Run the test suite (`tests/`)
- Edit Immunis-specific files (core/, immunis_hook.py, config.yaml)
- Add or modify tests
- Update documentation

**Not permitted without explicit Josh approval:**
- Modify any vendored file
- Delete any file
- Change the autonomic state write logic
- Modify protected paths/PIDs lists in a way that weakens security
- Change the Quartermaster pipeline order
- Restart any service

---

## 11. Environment and Paths

| What | Where |
|------|-------|
| Repo root | `~/Immunis/` |
| Configuration | `~/Immunis/config.yaml` |
| Module manifest | `~/Immunis/et_module.json` |
| Module data (runtime) | `~/.et_modules/immunis/` |
| Threat log | `~/.et_modules/immunis/threat_log.jsonl` |
| Shared learning JSONL | `~/.et_modules/shared_learning/immunis.jsonl` |
| Peer registry | `~/.et_modules/shared_learning/_peer_registry.json` |

---

*E-T Systems / Immunis*
*Last updated: 2026-03-18*
*Maintained by Josh — do not edit without authorization*
*Parent documents: `~/.claude/CLAUDE.md` (global), `~/.claude/ARCHITECTURE.md`*
