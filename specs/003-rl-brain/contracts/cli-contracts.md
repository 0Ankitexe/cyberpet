# CLI Contracts: RL Brain Commands

**Branch**: `001-rl-brain` | **Date**: 2026-02-27

## `cyberpet model status`

**Description**: Display RL brain statistics and FP impact analysis.

**Output Format**:
```
RL Brain Status
───────────────
  State:            TRAINING
  Steps trained:    1,247
  Last action:      QUARANTINE_FILE (confidence: 78%)
  Avg reward (100): +3.2
  Warmup:           Complete (used 50 steps)
  Model path:       /var/lib/cyberpet/models/cyberpet_ppo.zip
  Last checkpoint:  2026-02-27 14:30:12

Action Distribution (last 100 steps)
  ALLOW           ████████████████████   42%
  LOG_WARN        ████████               18%
  BLOCK_PROCESS   ████                    9%
  QUARANTINE_FILE ██████                 13%
  TRIGGER_SCAN    ████                    8%
  Other           ████                   10%

FP Memory Impact
  Files marked safe:     8
  Confirmed threats:     3 (loaded as priors)
  Repeat FPs avoided:    3 this session
  Current FP rate:       12%
  RL aggressiveness:     Moderate (FP rate < 30%)
```

**Exit codes**: 0 = success, 1 = RL not initialized / daemon not running

---

## `cyberpet model reset`

**Description**: Delete saved RL model and clear prior knowledge cache.

**Interaction**:
```
Are you sure? This will:
  - Delete saved model (/var/lib/cyberpet/models/cyberpet_ppo.zip)
  - Clear prior knowledge cache
  - RL will start fresh on next daemon restart
  
  FP memory and scan history are NOT affected.

Type 'yes' to confirm: yes
Model reset complete. Restart daemon to create fresh model.
```

**Exit codes**: 0 = reset done, 1 = cancelled / error

---

## `cyberpet model info`

**Description**: Display model architecture and hyperparameters.

**Output Format**:
```
RL Model Architecture
─────────────────────
  Algorithm:       PPO (Proximal Policy Optimization)
  Policy:          MlpPolicy
  Network:         [256, 256] ReLU
  Observation:     44 features (float32)
  Actions:         8 discrete
  Device:          CPU

Hyperparameters
  Learning rate:   3e-4
  Batch size:      64
  N steps:         512
  N epochs:        10
  Gamma:           0.99
  GAE lambda:      0.95
  Clip range:      0.2
  Entropy coef:    0.01
  VF coef:         0.5
  Max grad norm:   0.5
```

**Exit codes**: 0 = success

---

## `cyberpet fp list`

**Description**: Display all files in false positive memory.

**Output Format**:
```
SHA256     Filepath                                 Category      Score  Date
────────── ──────────────────────────────────────── ───────────── ────── ────────────────────
a1b2c3d4   /usr/bin/some_tool                       cryptominer   72     2026-02-26 14:30:00
e5f6g7h8   /home/user/.local/bin/script.py          webshell      65     2026-02-25 09:15:00

2 files marked safe
```

**Exit codes**: 0 = success (even if empty), 1 = DB error

---

## `cyberpet fp clear`

**Description**: Clear all false positive memory entries.

**Interaction**:
```
Are you sure? This will clear 8 false positive records.
The RL model will lose its safe-file knowledge on next restart.

Type 'yes' to confirm: yes
FP memory cleared (8 records removed).
```

**Exit codes**: 0 = cleared, 1 = cancelled / error

---

## New EventBus Event Types

| Event Type | Source | Data Fields |
|-----------|--------|-------------|
| `RL_DECISION` | rl_engine | `{action, action_name, confidence, state_summary, reward, step}` |
| `SYSCALL_ANOMALY` | syscall_monitor | `{pid, process_name, anomaly_type, details, severity}` |
| `LOCKDOWN_ACTIVATED` | action_executor | `{reason, trigger_action, threat_score}` |
| `LOCKDOWN_DEACTIVATED` | action_executor | `{duration_seconds, reason}` |
| `FP_MARKED_SAFE` | scan_screen / threat_action | `{filepath, sha256, threat_category, threat_score}` |
| `QUARANTINE_CONFIRMED` | scan_screen / action_executor | `{filepath, sha256, threat_category, threat_score}` |
