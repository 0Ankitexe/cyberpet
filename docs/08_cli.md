# 08 — CLI Reference

> Every `cyberpet` command, what it does, and when to use it.

---

## Global Usage

```bash
cyberpet <command> [subcommand] [args]
```

Most commands that interact with the daemon require it to be running. Commands that read from files (e.g. `cyberpet log`) work even when the daemon is stopped.

Commands that need root (via `sudo`) are marked **[sudo]**.

---

## Daemon Control

### `cyberpet start`
Start the daemon in the background (writes PID to `/var/run/cyberpet.pid`).

```bash
sudo cyberpet start
# Equivalent to: sudo systemctl start cyberpet
```

### `cyberpet stop`
Stop the running daemon cleanly (saves PPO checkpoint on shutdown).

```bash
sudo cyberpet stop
```

### `cyberpet status`
Check daemon status, uptime, and high-level stats.

```bash
cyberpet status
# Output example:
# ● CyberPet daemon: running (PID 1234, uptime 4h 12m)
#   Threats blocked:    3
#   Commands guarded:   421
#   Files scanned:      12,847
#   RL steps:           83
#   Model checkpoint:   2026-02-28 06:14
```

---

## TUI

### `cyberpet pet`
Launch the interactive terminal pet UI. Connects to the daemon's event stream socket.

```bash
cyberpet pet
```

The TUI refreshes live while the daemon runs. Press `Q` to exit (daemon keeps running).

---

## Scanning

### `cyberpet scan quick`
Trigger a quick scan of high-risk locations only (`/tmp`, `/dev/shm`, recently modified executables, etc.).

```bash
sudo cyberpet scan quick
# Writes "quick" to /var/run/cyberpet_scan_trigger
# Daemon picks it up within 2 seconds and starts scanning
# Progress visible in TUI or daemon log
```

### `cyberpet scan full`
Trigger a full filesystem scan (skips `/proc`, `/sys`, `/dev`, and the vault itself).

```bash
sudo cyberpet scan full
# Writes "full" to /var/run/cyberpet_scan_trigger
```

> **Note:** Both scan commands return immediately. The actual scan runs inside the daemon. Watch progress with `cyberpet pet` or `cyberpet log`.

---

## Quarantine

### `cyberpet quarantine list`
List all files currently in the quarantine vault.

```bash
cyberpet quarantine list
# Output example:
# ID                           | File                  | Score | Date
# 1709123456_abc12345_miner.sh | /tmp/miner.sh         |  91   | 2026-02-27 22:14
# 1709100000_def67890_evil.py  | /home/zer0/evil.py    |  73   | 2026-02-26 18:30
```

### `cyberpet quarantine restore <id>`
Restore a quarantined file back to its original location.

```bash
sudo cyberpet quarantine restore 1709123456_abc12345_miner.sh

# Short prefix works too (first 8+ unique chars):
sudo cyberpet quarantine restore 17091234
```

If the original location is now occupied, the restore will fail to prevent overwrite.

### `cyberpet quarantine delete <id>`
Permanently delete a file from the vault. **This cannot be undone.**

```bash
sudo cyberpet quarantine delete 1709123456_abc12345_miner.sh
```

---

## RL Brain Control

### `cyberpet model start`
Start RL training. The daemon begins making decisions every 30 seconds and learning from them.

```bash
cyberpet model start
# Writes "start" to /var/run/cyberpet_rl_control
# Output:
# ▶  RL training STARTED
#   The model will begin learning from the next decision cycle.
#   Brain UI will show state: TRAINING
#   To pause: cyberpet model stop
```

### `cyberpet model stop`
Pause RL training. The model and all progress are preserved — training resumes exactly where it left off on `model start`.

```bash
cyberpet model stop
# Writes "paused" to /var/run/cyberpet_rl_control
# Output:
# ⏸  RL training PAUSED
#   The model and progress are preserved.
#   Brain UI will show state: PAUSED
#   To resume: cyberpet model start
```

### `cyberpet model status`
Show the current RL brain state, training progress, FP analysis, and prior knowledge summary.

```bash
cyberpet model status
# Output example:
# RL Brain Status
# ═══════════════
# State:        TRAINING
# Steps:        498
# IQ Score:     24 / 100  (Smart 🦊)
# Avg Reward:   +2.34 (last 100 steps)
# FP Rate:      3.2%  ✓ Good
#
# Training Phase: LEARNING_SAFE (2 steps to full mode)
# Model file:   /var/lib/cyberpet/models/cyberpet_ppo.zip  (1.2 MB)
# Last checkpoint: 2026-02-28 03:14:22
#
# Prior Knowledge
# ───────────────
# Confirmed threats:  12  (avg score: 78)
# FP categories:       5
# Safe hashes:        34
# Action bias:        QUARANTINE ×1.3  (biased toward caution)
#
# False Positive Analysis
# ───────────────────────
# Total FP entries:   5
# Recent FP rate:     3.2%
# Last FP:            2026-02-27 (marked safe by user)
```

### `cyberpet model reset`
Delete the trained PPO model. The next `model start` will create a fresh model from scratch. **All training progress is lost.**

```bash
sudo cyberpet model reset
# Deletes /var/lib/cyberpet/models/cyberpet_ppo.zip
# Resets rl_state.json to {steps: 0, reward: 0, state: READY}
```

### `cyberpet model info`
Display the PPO neural network architecture and hyperparameters.

```bash
cyberpet model info
# Output:
# PPO Architecture
# ════════════════
# Policy:    MlpPolicy
# Input:     44 neurons  (system state vector)
# Hidden 1:  256 neurons (ReLU)
# Hidden 2:  256 neurons (ReLU)
# Actor:     8 neurons   (softmax — action probabilities)
# Critic:    1 neuron    (value estimate)
#
# Hyperparameters
# ───────────────
# learning_rate:    3e-4
# n_steps:          512
# batch_size:       64
# n_epochs:         10
# gamma:            0.99
# gae_lambda:       0.95
# clip_range:       0.2
# ent_coef:         0.01
# vf_coef:          0.5
# max_grad_norm:    0.5
```

---

## False Positive Memory

### `cyberpet fp list`
List all files in the false positive memory database.

```bash
cyberpet fp list
# Output:
# SHA256            | File                          | Category     | Marked
# abc123...def456   | /home/zer0/tools/nmap         | network_tool | 2026-02-27
# 789xyz...123abc   | /usr/local/bin/custom_script  | script       | 2026-02-25
```

### `cyberpet fp clear`
Clear **all** false positive memory entries. The RL brain will forget what it previously learned is safe.

```bash
sudo cyberpet fp clear
# Confirmation required:
# Are you sure? This removes all 5 FP entries. [y/N]:
```

---

## Logs

### `cyberpet log`
Tail the CyberPet daemon log in real time.

```bash
cyberpet log
# Tails /var/log/cyberpet/cyberpet.log
# Ctrl+C to stop
```

### `cyberpet log --lines <n>`
Show the last N lines of the log.

```bash
cyberpet log --lines 50
```

---

## Shell Hook

### `cyberpet hook install`
Print instructions for installing the shell hook manually.

```bash
cyberpet hook install
# Output:
# To install the CyberPet shell hook, add this line to ~/.bashrc or ~/.zshrc:
#   source /etc/cyberpet/shell_hook.sh
#
# Or for all users (already done by installer):
#   /etc/profile.d/cyberpet.sh → sources the hook globally
```

---

## Data Reset

To wipe all CyberPet data and start fresh (like a clean install):

```bash
sudo bash -c '
systemctl stop cyberpet
rm -f /var/lib/cyberpet/hashes.db
rm -f /var/lib/cyberpet/false_positives.db
rm -f /var/lib/cyberpet/scan_history.db
rm -f /var/lib/cyberpet/rl_feedback.json
rm -rf /var/lib/cyberpet/quarantine/*
rm -rf /var/lib/cyberpet/models/*
rm -rf /var/log/cyberpet/*
systemctl start cyberpet
'
```

---

## Testing

Run the full test suite (requires venv):

```bash
sudo /opt/cyberpet/venv/bin/python -m pytest tests/ -v
```

145 tests covering: action executor, scanner, quarantine, RL engine, RL environment, RL environment, state collector, terminal guard, shell hook, UI event parsing, scan scheduler, YARA engine, hash DB, config, and more.

---

## Quick Reference Card

| Command | What It Does |
|---------|-------------|
| `sudo cyberpet start` | Start daemon |
| `sudo cyberpet stop` | Stop daemon |
| `cyberpet status` | Daemon health check |
| `cyberpet pet` | Launch TUI |
| `cyberpet log` | Tail log |
| `sudo cyberpet scan quick` | Quick scan |
| `sudo cyberpet scan full` | Full scan |
| `cyberpet quarantine list` | List vault contents |
| `sudo cyberpet quarantine restore <id>` | Restore file |
| `sudo cyberpet quarantine delete <id>` | Permanently delete |
| `cyberpet model start` | Start RL training |
| `cyberpet model stop` | Pause RL training |
| `cyberpet model status` | RL status + FP analysis |
| `cyberpet model reset` | Wipe trained model |
| `cyberpet model info` | PPO architecture details |
| `cyberpet fp list` | List false positives |
| `sudo cyberpet fp clear` | Clear FP memory |
| `cyberpet hook install` | Shell hook instructions |
