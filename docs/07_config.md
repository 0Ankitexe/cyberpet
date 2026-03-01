# 07 — Configuration Reference

> Every setting in `/etc/cyberpet/config.toml` explained.

---

## File Location

```
/etc/cyberpet/config.toml     ← system config (requires sudo to edit)
```

After editing, restart the daemon for changes to take effect:
```bash
sudo systemctl restart cyberpet
```

---

## Full Configuration Reference

```toml
# ════════════════════════════════════════════════
# [general] — Core daemon settings
# ════════════════════════════════════════════════
[general]

# Name used in TUI pet display and log entries
pet_name = "Byte"

# Log directory (must be writable by root)
log_path = "/var/log/cyberpet/"

# PID file location
pid_file = "/var/run/cyberpet.pid"

# Unix socket for event stream (TUI connects here)
event_stream_socket = "/var/run/cyberpet_events.sock"


# ════════════════════════════════════════════════
# [terminal_guard] — Shell hook & command scoring
# ════════════════════════════════════════════════
[terminal_guard]

# Unix socket for terminal guard (shell hook connects here)
socket_path = "/var/run/cyberpet.sock"

# Socket permissions: "660" = group-accessible, "600" = root only
socket_mode = "660"

# Group that can access the terminal guard socket (shell users)
socket_group = "cyberpet"

# Score threshold for BLOCKING a command (70–100 = blocked)
block_threshold = 70

# Score threshold for WARNING (40–69 = warn but allow)
warn_threshold = 40

# Override token expiry in seconds (how long the user has to type it)
override_token_ttl = 30

# Max wrong override attempts before lockout
override_max_failures = 3

# Lockout duration in seconds after too many wrong overrides
override_lockout_seconds = 300


# ════════════════════════════════════════════════
# [quarantine] — Vault settings
# ════════════════════════════════════════════════
[quarantine]

# Directory where quarantined files are stored
# Must be on the same filesystem as most files you'll quarantine
vault_path = "/var/lib/cyberpet/quarantine/"

# Optional: encrypt vault files at rest (AES-256, requires setup)
# encrypt = true
# encrypt_key_path = "/etc/cyberpet/vault.key"


# ════════════════════════════════════════════════
# [hash_db] — Known hash database
# ════════════════════════════════════════════════
[hash_db]

# SQLite database of clean + malware file hashes
db_path = "/var/lib/cyberpet/hashes.db"


# ════════════════════════════════════════════════
# [scanner] — File scanning settings
# ════════════════════════════════════════════════
[scanner]

# Worker threads for parallel file scanning
scan_workers = 4

# Threat score threshold for reporting (0–100)
# Files below this score are considered clean
threat_threshold = 30

# Threshold for auto-quarantine (ONLY applies to /tmp, /dev/shm, /var/tmp)
auto_quarantine_threshold = 80

# Maximum file size to scan in bytes (files larger than this are skipped)
max_file_size = 104857600   # 100 MB

# YARA rules directory
rules_path = "/etc/cyberpet/rules/"

# Additional paths to include in quick scan (on top of defaults)
# quick_scan_extra_paths = ["/opt/myapp/"]

# Paths to exclude from all scans
scan_exclude_paths = [
    "/proc",
    "/sys",
    "/dev",
    "/var/lib/cyberpet",   # don't scan our own vault
]


# ════════════════════════════════════════════════
# [rl] — Reinforcement learning brain
# ════════════════════════════════════════════════
[rl]

# Enable or disable the RL brain entirely
enabled = true

# Path where PPO model checkpoint is saved
model_path = "/var/lib/cyberpet/models/"

# How often to save a checkpoint (in steps, not seconds)
# At 30s per step: 3600 steps = ~30 hours of runtime
checkpoint_interval_steps = 3600

# Seconds between each RL decision cycle
decision_interval_seconds = 30

# Warmup steps with NO prior threat history
# During warmup, only ALLOW and LOG_WARN are used
warmup_steps_no_priors = 100

# Warmup steps when prior history has some confirmed threats
warmup_steps_with_priors = 50

# Warmup steps when prior history has deep threat knowledge (20+ threats)
warmup_steps_deep_priors = 25

# Threshold of confirmed threats to use "deep priors" warmup
deep_prior_threshold = 20

# Steps before destructive actions are allowed (learning-safe mode)
learning_safe_steps = 500
```

---

## Key Values to Tune

### If you're getting too many false positives

```toml
[rl]
learning_safe_steps = 1000   # Keep restrictive mode longer
warmup_steps_no_priors = 200  # Longer warmup

[scanner]
threat_threshold = 45        # Only flag higher-confidence threats
auto_quarantine_threshold = 90  # Only auto-quarantine very high-score files
```

### If scans are too slow

```toml
[scanner]
scan_workers = 8             # More parallel workers (if you have CPU cores)
max_file_size = 52428800     # Skip files > 50MB
```

### If the RL brain uses too much CPU

```toml
[rl]
decision_interval_seconds = 60  # Check every 60s instead of 30s
```

### If terminal guard is too aggressive

```toml
[terminal_guard]
block_threshold = 80    # Raise block threshold (was 70)
warn_threshold = 50     # Raise warn threshold (was 40)
```

---

## Default Values Summary

| Setting | Default | Range |
|---------|---------|-------|
| `block_threshold` | 70 | 50–100 |
| `warn_threshold` | 40 | 20–70 |
| `threat_threshold` | 30 | 0–100 |
| `auto_quarantine_threshold` | 80 | 60–100 |
| `scan_workers` | 4 | 1–16 |
| `decision_interval_seconds` | 30 | 10–300 |
| `learning_safe_steps` | 500 | 0–5000 |
| `warmup_steps_no_priors` | 100 | 25–500 |
| `checkpoint_interval_steps` | 3600 | 100–100000 |
