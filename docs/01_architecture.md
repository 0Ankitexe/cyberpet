# 01 — System Architecture

> How all the pieces of CyberPet fit together.

---

## What Is CyberPet?

CyberPet is a **Linux endpoint security daemon** with a reinforcement learning brain. It runs as a root systemd service and:

1. **Watches your system** — reads CPU, memory, network, process, and filesystem metrics every 30 seconds
2. **Makes security decisions** — a PPO neural network decides what (if anything) to do about what it sees
3. **Guards your shell** — intercepts every command you type and scores it for danger before it runs
4. **Scans your files** — on-demand file scanner using YARA rules + hash database
5. **Quarantines threats** — moves suspicious files to an encrypted-at-rest vault
6. **Learns from you** — remembers false positives, confirmed threats, and adapts over time

---

## Process Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          cyberpet daemon (root)                         │
│                                                                         │
│  ┌─────────────┐   EventBus   ┌─────────────┐   ┌───────────────────┐   │
│  │  RL Brain   │◄────────────►│  Scanner    │   │  Terminal Guard   │   │
│  │  (30s loop) │             │  (on-demand) │   │  (socket server)  │   │
│  └──────┬──────┘             └──────┬───────┘   └────────┬──────────┘   │
│         │                          │                     │              │
│  ┌──────▼──────┐             ┌──────▼───────┐   ┌────────▼──────────┐   │
│  │  State      │             │  Quarantine  │   │  Shell Hook       │   │
│  │  Collector  │             │  Vault       │   │  (zsh/bash)       │   │
│  └──────┬──────┘             └──────────────┘   └───────────────────┘   │
│         │                                                               │
│  ┌──────▼──────┐   EventBus   ┌──────────────┐                          │
│  │  Action     │◄────────────►│  Scan        │                          │
│  │  Executor   │             │  Scheduler   │                           │
│  └─────────────┘             └──────────────┘                           │
│                                                                         │
│  All components communicate via the internal EventBus.                  │
│  The TUI connects via a Unix socket (event stream at /var/run/)         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Module Map

| File | Size | What It Does |
|------|------|-------------|
| `daemon.py` | 694 lines | Main daemon — starts all subsystems, runs the RL loop |
| `cli.py` | ~550 lines | All `cyberpet` CLI commands |
| `config.py` | ~150 lines | Loads and validates `config.toml` with safe defaults |
| `events.py` | ~80 lines | `EventBus` and `EventType` definitions |
| `state.py` | ~60 lines | `PetState` dataclass (mood, stats, counters) |
| `logger.py` | ~100 lines | Structured JSON logging to `/var/log/cyberpet/` |
| **RL Brain** | | |
| `rl_engine.py` | 310 lines | PPO lifecycle: warmup, predict, batch-train, checkpoint |
| `rl_env.py` | 230 lines | Gymnasium environment: obs/action spaces, reward calculation |
| `rl_prior.py` | 197 lines | Bootstrap from human decisions (FP memory + scan history) |
| `rl_explainer.py` | 191 lines | Human-readable explanations for RL decisions |
| `state_collector.py` | 326 lines | 44-feature system state vector (normalised 0–1) |
| `action_executor.py` | 360 lines | Executes 8 RL actions with 3-layer FP protection |
| **Scanner** | | |
| `scanner.py` | ~800 lines | Full file scanning pipeline (entropy, hash, YARA, heuristics) |
| `yara_engine.py` | ~200 lines | Loads and runs YARA rules against file bytes |
| `hash_db.py` | ~130 lines | SQLite hash database (clean hashes + known malware) |
| `scan_scheduler.py` | 292 lines | Manages quick/full scans + manual trigger file watcher |
| `scan_history.py` | ~220 lines | SQLite store of past scan results |
| **Shell Guard** | | |
| `terminal_guard.py` | ~440 lines | Unix socket server — scores commands for danger |
| `cmd_scorer.py` | ~380 lines | Multi-layer command danger scoring (rules + heuristics) |
| **Security** | | |
| `quarantine.py` | ~300 lines | Move/restore/delete files from the vault |
| `false_positive_memory.py` | ~250 lines | SQLite store of user-confirmed safe files |
| `pkg_trust.py` | ~150 lines | Package manager trust verification |
| `socket_security.py` | ~60 lines | Unix socket ACL helpers |
| **UI** | | |
| `ui/pet.py` | ~1250 lines | Main TUI app — pet face, stats, scan section, event log |
| `ui/brain_screen.py` | 422 lines | Full-screen RL brain detail view |
| `ui/scan_screen.py` | ~700 lines | Live scan progress screen |
| `ui/scan_menu.py` | ~80 lines | Quick/Full scan selection modal |
| `ui/threat_action.py` | ~150 lines | Per-threat action modal (quarantine/mark safe) |

---

## Daemon Startup Sequence

When `sudo systemctl start cyberpet` runs:

```
1.  Load config from /etc/cyberpet/config.toml (fallback: defaults)
2.  Set up logger → /var/log/cyberpet/cyberpet.log
3.  Write PID file → /var/run/cyberpet.pid
4.  Start EventBus (internal async pub/sub)
5.  Initialize PetState (mood, counters)
6.  Load FalsePositiveMemory (SQLite)
7.  Load ScanHistory (SQLite)
8.  Start ScanScheduler
    ├── Clear /var/run/cyberpet_scan_trigger (prevents stale triggers)
    └── Start trigger file watcher (polls every 2s)
9.  Start RL brain (if enabled in config)
    ├── Load RLPriorKnowledge from FP memory + scan history
    ├── Calculate warmup period (25/50/100 steps based on priors)
    ├── Create or load PPO model (cyberpet_ppo.zip)
    └── Start _rl_loop() — begins in READY/PAUSED state
10. Start TerminalGuard (Unix socket server at /var/run/cyberpet.sock)
11. Start event stream server (broadcasts events → /var/run/cyberpet_events.sock)
12. Start SystemStateCollector (subscribes to EventBus)
13. Run main loop until SIGTERM/SIGINT
14. On shutdown: save PPO checkpoint, close databases
```

---

## EventBus

All internal communication uses an async pub/sub `EventBus`. Every component can publish and subscribe to typed events:

```python
class EventType(Enum):
    # System
    SYSTEM_STATS = "SYSTEM_STATS"
    PET_MOOD_CHANGE = "PET_MOOD_CHANGE"

    # Scanning
    SCAN_STARTED = "SCAN_STARTED"
    SCAN_PROGRESS = "SCAN_PROGRESS"
    SCAN_COMPLETE = "SCAN_COMPLETE"
    SCAN_FILE_SCANNED = "SCAN_FILE_SCANNED"

    # Threats
    THREAT_DETECTED = "THREAT_DETECTED"
    QUARANTINE_CONFIRMED = "QUARANTINE_CONFIRMED"
    FP_MARKED_SAFE = "FP_MARKED_SAFE"

    # RL
    RL_DECISION = "RL_DECISION"

    # Shell
    COMMAND_BLOCKED = "COMMAND_BLOCKED"
    COMMAND_WARNED = "COMMAND_WARNED"
    COMMAND_SUSPICIOUS = "COMMAND_SUSPICIOUS"

    # Security
    LOCKDOWN_ACTIVATED = "LOCKDOWN_ACTIVATED"
    LOCKDOWN_DEACTIVATED = "LOCKDOWN_DEACTIVATED"
```

The TUI connects to the **event stream socket** (`/var/run/cyberpet_events.sock`) which broadcasts every event as a JSON line, keeping the UI in sync with the daemon without being in the same process.

---

## Data Files

| Path | Format | Contains |
|------|--------|---------|
| `/var/lib/cyberpet/hashes.db` | SQLite | Known clean + malware file hashes |
| `/var/lib/cyberpet/false_positives.db` | SQLite | User-confirmed safe files |
| `/var/lib/cyberpet/scan_history.db` | SQLite | Past scan results and threat records |
| `/var/lib/cyberpet/quarantine/` | Directory | Quarantined files (renamed, permissions stripped) |
| `/var/lib/cyberpet/models/cyberpet_ppo.zip` | ZIP | Trained PPO model checkpoint |
| `/var/lib/cyberpet/models/rl_state.json` | JSON | `{total_steps, avg_reward, state}` |
| `/var/log/cyberpet/cyberpet.log` | JSON lines | Structured daemon log |
| `/etc/cyberpet/config.toml` | TOML | User configuration |
| `/var/run/cyberpet.sock` | Unix socket | Terminal guard (command scoring) |
| `/var/run/cyberpet_events.sock` | Unix socket | Event stream → TUI |
| `/var/run/cyberpet_scan_trigger` | Text file | Write `quick` or `full` to trigger a scan |
| `/var/run/cyberpet_rl_control` | Text file | Write `start` or `paused` to control RL |
