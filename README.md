# 🛡️ CyberPet — Your Linux Security Companion

> A terminal-based cybersecurity daemon for Linux that guards your system while living as an ASCII pet in your terminal.

CyberPet intercepts dangerous commands, scans for malware, monitors process execution via eBPF, blocks suspicious file access using fanotify, and **learns from your decisions with a reinforcement learning brain** — all while displaying an interactive ASCII pet whose mood reflects your system's security health.

**Linux only** — relies on Unix domain sockets, `/proc`, eBPF, and fanotify.

---

## ✨ Features

### V1 — Terminal Guard
- **Command Interception** — Shell hook intercepts commands before execution and scores them for danger
- **Smart Scoring Engine** — Rule-based scorer with severity levels (block, warn, allow)
- **Override System** — Blocked commands can be overridden with a passphrase
- **ASCII Pet** — Mood-reactive pet that responds to security events
- **Real-time Activity Log** — Live event stream showing all intercepted commands
- **System Stats** — CPU, RAM, uptime monitoring in the TUI

### V2 — The Watcher
- **11-Stage File Scanner** — Pre-filter → hash lookup → package trust → YARA → entropy → magic mismatch → ELF anomaly → score combination → context adjustment
- **YARA Integration** — 15+ rules covering ransomware, cryptominers, webshells, and generic malware (multi-indicator required to reduce false positives)
- **Package Manager Trust** — Automatically skips unmodified `dpkg`/`rpm` package files
- **Quarantine Vault** — Atomic file isolation with permission stripping, restore, and permanent delete
- **Interactive Scan UI** — In-TUI scan screen with live progress bar, real-time threat list, and per-threat actions
- **False Positive Memory** — Remembers user safe-decisions so files are never flagged again
- **eBPF Exec Monitor** — Kernel-level process execution tracing via `sched_process_exec` tracepoint
- **fanotify File Monitor** — Permission-based file access blocking on sensitive system paths
- **Scan Scheduler** — Startup scan, periodic quick scans, daily full scans
- **CLI Commands** — `scan quick/full`, `quarantine list/restore/delete`

All features **degrade gracefully** — if eBPF, fanotify, YARA, or the package manager aren't available, the system continues working with reduced capabilities.

### V3 — The RL Brain
- **Reinforcement Learning Engine** — PPO-based brain (stable-baselines3) that learns optimal threat responses from real system events
- **Prior Knowledge Bootstrap** — Loads human-confirmed decisions from FP memory and scan history to avoid blind starts
- **44-Feature State Vector** — Comprehensive system observation including CPU, RAM, network, threats, scan quality, and FP rate
- **8 Action Types** — ALLOW, LOG_WARN, BLOCK_PROCESS, QUARANTINE_FILE, NETWORK_ISOLATE, RESTORE_FILE, TRIGGER_SCAN, ESCALATE_LOCKDOWN
- **False Positive Protection** — Multi-layer FP checks (FP memory + prior safe set + hash matching) before every blocking action
- **Syscall Anomaly Monitor** — eBPF-based detection of PTRACE_ABUSE, FORK_BOMB, MEMFD_MALWARE, MMAP_EXEC, PERSONA_TRICK
- **Decision Explainability** — Human-readable explanations for every RL decision citing elevated features
- **TUI Brain Panel** — Live RL stats (steps, action, reward, state) with action distribution bar chart
- **CLI Commands** — `model status/reset/info`, `fp list/clear`
- **Dynamic Warmup** — 100/50/25 steps based on prior knowledge depth
- **Model Persistence** — PPO model saved on clean shutdown, restored on restart

---

## 🚀 Quick Start

### Prerequisites

- Linux (kernel ≥ 5.8 for eBPF, ≥ 4.20 for fanotify — degrades gracefully on older kernels)
- Python 3.11+
- Root access (for system paths, eBPF, and fanotify)

### Installation

```bash
# Clone the repo
git clone https://github.com/0Ankitexe/cyberpet.git
cd cyberpet

# Install V1 base (terminal guard, shell hook, TUI)
sudo ./install_v1.sh

# Install V2 (scanner, YARA, quarantine, eBPF, fanotify)
sudo ./install_v2.sh

# Install V3 (RL brain, syscall monitor, explainability)
sudo ./install_v3.sh
```

### Usage

```bash
# Start the daemon
sudo systemctl start cyberpet

# Launch the pet TUI
cyberpet pet

# Run a quick scan from CLI
cyberpet scan quick

# Run a full filesystem scan
cyberpet scan full

# Check RL brain status (V3)
cyberpet model status

# Start RL training (V3)
cyberpet model start

# Pause RL training — progress preserved (V3)
cyberpet model stop

# View RL brain architecture (V3)
cyberpet model info
```

### Shell Hook

The installer auto-wires the shell hook globally. For manual activation:

```bash
source /etc/cyberpet/shell_hook.sh
```

---

## 🎮 TUI Keybindings

| Key | Action                                    |
| --- | ----------------------------------------- |
| `Q` | Quit TUI (daemon keeps running)           |
| `S` | Open scan menu / reconnect to active scan |
| `B` | Open Brain screen (RL details)            |
| `D` | Toggle dark/light mode                    |
| `C` | Clear event log                           |

## 🔍 Interactive Scan UI

Press **`S`** in the pet TUI to open the scan menu:

```
Main TUI  →  [S]  →  Quick Scan / Full Scan
                          ↓
                    Live Scan Screen
                      • Real-time progress bar + file count
                      • Threats appear as they're found
                      • Click any threat to:
                          🔒 Quarantine  — isolate to vault
                          ✅ Mark Safe   — remember as false positive
```

Scans run in the daemon — press **Q** to quit the TUI and the scan keeps running. Reopen with `cyberpet pet` and press **S** to reconnect.

---

## 🔧 CLI Reference

| Command                            | Description                                 |
| ---------------------------------- | ------------------------------------------- |
| `cyberpet start`                   | Start daemon in background                  |
| `cyberpet stop`                    | Stop running daemon                         |
| `cyberpet status`                  | Check daemon status and stats               |
| `cyberpet pet`                     | Launch terminal pet UI                      |
| `cyberpet log`                     | Tail the log file                           |
| `cyberpet hook install`            | Print shell hook install instructions       |
| `cyberpet scan quick`              | Quick scan of high-risk locations           |
| `cyberpet scan full`               | Full filesystem scan                        |
| `cyberpet quarantine list`         | List all quarantined files                  |
| `cyberpet quarantine restore <id>` | Restore a quarantined file                  |
| `cyberpet quarantine delete <id>`  | Permanently delete a quarantined file       |
| `cyberpet model status`            | Show RL brain status and FP analysis (V3)   |
| `cyberpet model start`             | Start RL training — daemon begins learning (V3) |
| `cyberpet model stop`              | Pause RL training — progress preserved (V3) |
| `cyberpet model reset`             | Delete trained RL model (V3)                |
| `cyberpet model info`              | Display PPO architecture details (V3)       |
| `cyberpet fp list`                 | List false positive memory entries (V3)     |
| `cyberpet fp clear`                | Clear all FP memory entries (V3)            |
| `cyberpet autostart on`            | Start CyberPet automatically on boot        |
| `cyberpet autostart off`           | Disable autostart on boot                   |
| `cyberpet autostart status`        | Check if autostart is enabled               |

---

## ⚙️ Configuration

Edit `/etc/cyberpet/config.toml`:

```toml
[general]
pet_name = "Byte"
log_level = "INFO"

[terminal_guard]
enabled = true
block_threshold = 61
hard_block_threshold = 86
allow_override_phrase = "CYBERPET ALLOW"

[scanner]
quick_scan_interval_minutes = 30
full_scan_time = "03:00"
max_file_size_mb = 50
auto_quarantine = false
auto_quarantine_threshold = 80

[file_monitor]
enabled = true
monitored_paths = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib"]

[yara]
rules_dir = "/etc/cyberpet/rules/"
scan_timeout_seconds = 30

[quarantine]
vault_path = "/var/lib/cyberpet/quarantine/"

# V3: RL Brain
[rl]
enabled = true
model_path = "/var/lib/cyberpet/models/"
decision_interval_seconds = 30
checkpoint_interval_steps = 3600
warmup_steps_no_priors = 100
warmup_steps_with_priors = 50
warmup_steps_deep_priors = 25
deep_prior_threshold = 20
```

### Key Config Options

- **auto_quarantine** — Set to `true` to enable automatic quarantine of high-score threats (defaults to `false` for safety)
- **block_threshold** — Minimum danger score to block a command (0-100)
- **quick_scan_interval_minutes** — How often the daemon runs background quick scans
- **full_scan_time** — Time of day for the automatic full scan (HH:MM format)
- **rl.enabled** — Enable/disable the RL brain (V3; defaults to `true`)
- **rl.decision_interval_seconds** — How often the RL brain makes decisions (V3; default: 30s)
- **rl.warmup_steps_no_priors** — Warmup steps when no prior knowledge exists (V3; default: 100)

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────┐
│              Shell Hook (bash/zsh)                   │
│              ↕ Unix Socket                           │
├──────────────────────────────────────────────────────┤
│           Terminal Guard (Scorer)                    │
│                ↕ EventBus                            │
├────────┬──────────┬──────────┬───────────────────────┤
│ Logger │  Pet UI  │  Stats   │   Scan Scheduler      │
│        │  [S]Scan │  Brain   │                       │
├────────┴──────────┴──────────┴───────────────────────┤
│              V3: RL Brain                            │
├─────────────────────┬────────────────────────────────┤
│ RLEngine (PPO)      │  ActionExecutor (8 actions)    │
│ RLExplainer         │  RLPriorKnowledge              │
│ CyberPetEnv (Gym)   │  SystemStateCollector (44-dim) │
├─────────────────────┴────────────────────────────────┤
│           Kernel Monitoring Layer                    │
├─────────────┬──────────────┬─────────────────────────┤
│ eBPF Exec   │  Syscall     │  fanotify File Monitor  │
│ Monitor     │  Anomaly (V3)│  (FAN_OPEN_PERM)        │
├─────────────┴──────────────┴─────────────────────────┤
│         File Scanner (11-stage pipeline)             │
│ Pre-filter → Hash → Pkg Trust → YARA → Entropy       │
│          → Magic → ELF → Combine → Context           │
├──────────────────────────────────────────────────────┤
│  Quarantine Vault  │  Hash DB  │  PackageManagerTrust│
│  Scan History      │  FP Memory│                     │
└──────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
cyberpet/
├── __init__.py               # Package init
├── events.py                 # EventType, Event, EventBus
├── config.py                 # TOML config loader
├── logger.py                 # Structured rotating logger
├── state.py                  # PetState dataclass
├── cmd_scorer.py             # Danger scoring engine
├── terminal_guard.py         # Unix socket server
├── daemon.py                 # Main daemon orchestrator
├── cli.py                    # Click CLI
├── scanner.py                # 11-stage file scanner
├── pkg_trust.py              # Package integrity verification
├── quarantine.py             # Quarantine vault (SQLite)
├── hash_db.py                # SHA256 hash database
├── yara_engine.py            # YARA rule compiler
├── scan_scheduler.py         # Scheduled scanning
├── scan_history.py           # Scan history store
├── false_positive_memory.py  # FP decisions + RL export
├── rl_prior.py               # V3: Prior knowledge bootstrap
├── state_collector.py        # V3: 44-feature state vector
├── rl_env.py                 # V3: Custom Gymnasium environment
├── rl_engine.py              # V3: PPO engine with persistence
├── action_executor.py        # V3: 8-action executor + FP protection
├── rl_explainer.py           # V3: Decision explainability
├── ebpf/
│   ├── exec_monitor.py       # eBPF process monitor
│   ├── file_monitor.py       # fanotify file access monitor
│   └── syscall_monitor.py    # V3: eBPF syscall anomaly detector
└── ui/
    ├── ascii_art.py           # 7 mood faces
    ├── pet.py                 # Main TUI screen + BrainStatsWidget
    ├── scan_menu.py           # Scan type selection modal
    ├── scan_screen.py         # Live scan progress screen
    └── threat_action.py       # Per-threat action modal

config/
└── default_config.toml
rules/                         # YARA rules
├── ransomware.yar
├── miners.yar
├── webshells.yar
└── generic_malware.yar
scripts/
├── socket_client.py
└── shell_hook.sh
tests/
├── test_rl_prior.py           # V3
├── test_state_collector.py    # V3
├── test_rl_env.py             # V3
├── test_action_executor.py    # V3
├── test_rl_engine.py          # V3
└── ...
```

---

## 📦 Dependencies

### System Packages

| Package                     | Required    | Purpose                              |
| --------------------------- | ----------- | ------------------------------------ |
| `libmagic1`                 | Recommended | MIME type detection                  |
| `libyara-dev`               | Recommended | YARA rule compilation                |
| `bcc` / `python3-bpfcc`     | Optional    | eBPF kernel monitoring               |
| `linux-headers-$(uname -r)` | Optional    | eBPF compilation                     |

### Python Packages

| Package         | Required    | Purpose                    |
| --------------- | ----------- | -------------------------- |
| `textual`       | ✅          | Terminal UI framework      |
| `psutil`        | ✅          | System stats               |
| `toml`          | ✅          | Configuration parsing      |
| `click`         | ✅          | CLI framework              |
| `python-daemon` | ✅          | Daemon management          |
| `aiosqlite`     | ✅          | Async SQLite               |
| `yara-python`   | Recommended | YARA scanning              |
| `python-magic`  | Recommended | File type detection        |
| `pyelftools`    | Recommended | ELF binary analysis        |
| `stable-baselines3` | V3      | PPO reinforcement learning |
| `torch` (CPU)   | V3          | Neural network backend     |
| `gymnasium`     | V3          | RL environment framework   |
| `numpy`         | V3          | Numerical computation      |
| `shimmy`        | V3          | Gym compatibility layer    |

---

## 🧪 Testing

```bash
# Run all tests
sudo /opt/cyberpet/venv/bin/python -m pytest tests/ -v
```

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or submit pull requests.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Ankit Bharti** — [@0Ankitexe](https://github.com/0Ankitexe)
