# Immunis

**Full-Spectrum System Security for the E-T Systems Ecosystem**

Immunis detects and responds to host-level threats — filesystem intrusions, process anomalies, network irregularities, memory corruption, dependency tampering, and substrate topology disturbances. Part of the Triad (Immunis, Elmer, THC) that forms the organism's closed-loop self-regulating system.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  OpenClaw Skill Interface            │
│        on_message() · recall() · stats()            │
├─────────────────────────────────────────────────────┤
│                 immunis_hook.py                      │
│    ┌───────────────────────────────────────────┐    │
│    │             Quartermaster                  │    │
│    │  (Signal triage + severity assessment)     │    │
│    └───────────────────────────────────────────┘    │
│    ┌──────────┐  ┌──────────┐  ┌──────────────┐    │
│    │  Armory  │  │ Response │  │  Feedback    │    │
│    │ (Known   │  │ Prims    │  │  Manager     │    │
│    │  sigs)   │  │          │  │  (Training   │    │
│    │          │  │          │  │   wheels)    │    │
│    └──────────┘  └──────────┘  └──────────────┘    │
│    ┌───────────────────────────────────────────┐    │
│    │               7 Sensors                    │    │
│    │  FS · Process · Network · Deps · Log ·    │    │
│    │  Memory · Substrate                        │    │
│    └───────────────────────────────────────────┘    │
├─────────────────────────────────────────────────────┤
│          NG-Lite Substrate + NGEcosystem             │
│  Tier 1: Standalone → Tier 2: Peer → Tier 3: SNN   │
└─────────────────────────────────────────────────────┘
```

## Pipeline

On each `on_message()` call:

1. **Poll** all enabled sensors for new signals
2. **Ingest** raw signals into the Quartermaster buffer
3. **Process** batch through triage pipeline:
   - Armory fast-path (known signature match?)
   - Substrate classification (NG-Lite recommendations)
   - Severity assessment (confidence × novelty matrix)
   - Response primitive selection
   - Training wheels gate
   - Execution + outcome recording
4. **Check** autonomic state transitions
5. **Process** pending feedback responses
6. **Auto-checkpoint** state

## Seven Sensors

| Sensor | What It Monitors |
|--------|-----------------|
| `FilesystemSensor` | File creation/modification/deletion in watched paths |
| `ProcessSensor` | Process spawning, CPU/memory anomalies |
| `NetworkSensor` | Connection tracking, port scanning detection |
| `DependencySensor` | Package integrity, unexpected changes |
| `LogSensor` | System/app log pattern matching |
| `MemorySensor` | Memory usage anomalies, OOM indicators |
| `SubstrateSensor` | Peer substrate topology (read-only) |

All sensors are individually configurable and disableable.

## Key Privilege: Autonomic State Write

Immunis is one of only three modules authorized to write to `ng_autonomic.py`:
- Writes **SYMPATHETIC** on CRITICAL threat detection
- Writes **PARASYMPATHETIC** when all threats are neutralized

## Training Wheels

Fresh Immunis systems start in training wheels mode:
- No auto-execution regardless of confidence
- All responses logged as recommendations only
- Deactivates after meeting experience thresholds

## Usage

### As an OpenClaw Skill

```yaml
# SKILL.md
name: immunis
autoload: true
hook: immunis_hook.py::get_instance
```

### Programmatic

```python
from immunis_hook import get_instance

immunis = get_instance()

# Processing happens automatically on each on_message()
result = immunis.on_message("Check system security status")
print(result)
# {
#   "status": "ok",
#   "signals_ingested": 3,
#   "active_threats": 0,
#   "autonomic_state": "PARASYMPATHETIC",
#   "training_wheels": true
# }
```

## Configuration

All settings in `config.yaml`. Key sections:

```yaml
sensors:
  filesystem:
    enabled: true
    poll_interval: 5
    watched_paths: ["/etc", "/home/josh"]
  process:
    enabled: true
    poll_interval: 10
  # ... all 7 sensors configurable

thresholds:
  auto_execute: 0.70
  recommend: 0.40
  host_premium: 0.15

training_wheels:
  min_armory_entries: 10
  min_substrate_outcomes: 50
  min_user_feedbacks: 5
  min_runtime_hours: 24

response:
  protected_pids: ["sshd", "systemd"]
  protected_paths: ["/etc/ssh"]
```

## Testing

```bash
python -m pytest tests/ -v
```

## The Triad

Immunis operates as part of a closed-loop with Elmer and THC:
- **Immunis** detects threats → records to substrate, writes autonomic state
- **Elmer** reads autonomic state, monitors substrate health
- **THC** absorbs signals via shared topology, diagnoses and repairs

Nobody sends anything. The River flows.

## License

AGPL-3.0 (see [NeuroGraph LICENSE](https://github.com/greatnorthernfishguy-hub/NeuroGraph))

## E-T Systems Ecosystem

Part of the E-T Systems module ecosystem:
- **NeuroGraph** — Dynamic Spiking Neuro-Hypergraph foundation
- **TrollGuard** — AI agent security pipeline
- **The Inference Difference** — Transparent inference routing proxy
- **Immunis** — Full-spectrum system security (this module)
- **The Healing Collective** — Self-healing intelligence
- **Elmer** — Cognitive substrate awareness
