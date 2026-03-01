# 02 — The RL Brain

> How CyberPet's reinforcement learning brain works — from raw system metrics to security decisions.

---

## The Key Insight: It Does NOT Scan Files

The RL brain is **not a file scanner**. It never opens files, reads their bytes, or runs YARA rules. Instead it watches **system vital signs** — like a doctor monitoring a patient's heart rate and blood pressure rather than performing surgery.

The brain observes 44 numbers every 30 seconds, makes a decision from 8 possible actions, gets feedback on whether that was right, and learns over thousands of cycles.

---

## The Full Decision Loop

Every **30 seconds**, the daemon runs one full cycle:

```
┌─────────────────────────────────────────────────────────────┐
│  1. OBSERVE                                                 │
│     state_collector.collect()                               │
│     → 44 floats [0.0 – 1.0] from CPU, RAM, network, etc.  │
├─────────────────────────────────────────────────────────────┤
│  2. DECIDE                                                  │
│     ppo_model.predict(obs, deterministic=False)             │
│     → 1 of 8 actions (sampled from probability dist.)      │
├─────────────────────────────────────────────────────────────┤
│  3. ACT                                                     │
│     action_executor.execute(action)                         │
│     → FP checks → execute → ActionResult                   │
├─────────────────────────────────────────────────────────────┤
│  4. REWARD                                                  │
│     env.calculate_reward(action, new_state, result)         │
│     → scalar in [-20, +20]                                  │
│     → multiplied by action_bias from prior knowledge        │
├─────────────────────────────────────────────────────────────┤
│  5. ACCUMULATE                                              │
│     steps_since_train += 1                                  │
│     if steps_since_train >= 512:                           │
│         model.learn(total_timesteps=512)  ← PPO update     │
│         steps_since_train = 0                               │
├─────────────────────────────────────────────────────────────┤
│  6. PUBLISH                                                 │
│     EventBus → RL_DECISION event → TUI                     │
│     Write rl_state.json → CLI                               │
└─────────────────────────────────────────────────────────────┘
```

> **Note on training:** PPO is a *batch* algorithm. The model only updates its weights after collecting 512 observations. Calling `learn(1)` repeatedly (the old code) does nothing useful — the fix in V3 collects 512 steps before each batch update.

---

## Step 1: What the Brain Observes (44 Features)

The `state_collector.py` module gathers 44 normalised (0–1) floats:

### System Resources (indices 0–5)

| Index | Feature | Source | Why It Matters |
|-------|---------|--------|---------------|
| 0 | `cpu_load_1min` | `/proc/loadavg` | Sudden CPU spike → possible cryptominer |
| 1 | `cpu_load_5min` | `/proc/loadavg` | Sustained load trend |
| 2 | `cpu_load_15min` | `/proc/loadavg` | Long-term baseline |
| 3 | `ram_percent` | psutil | High RAM → large process hiding in memory |
| 4 | `swap_percent` | psutil | Swap pressure often precedes attacks |
| 5 | `disk_io_rate` | psutil | Mass file writes → ransomware signal |

### Process Activity (indices 6–11)

| Index | Feature | Source | Why It Matters |
|-------|---------|--------|---------------|
| 6 | `process_count` | `/proc` | Sudden new process burst |
| 7 | `new_proc_events` | EventBus | Rate of new process creation |
| 8 | `root_process_count` | `/proc` | Processes running as root |
| 9 | `unknown_process_count` | `/proc` | Processes not matching known binaries |
| 10 | `zombie_count` | `/proc` | Zombies can indicate crashed malware |
| 11 | `thread_count` | `/proc` | Abnormally high thread counts |

### Network Activity (indices 12–16)

| Index | Feature | Source | Why It Matters |
|-------|---------|--------|---------------|
| 12 | `connection_count` | psutil | Total active TCP/UDP connections |
| 13 | `outbound_bytes_rate` | psutil | Data exfiltration indicator |
| 14 | `new_conn_events` | EventBus | Rate of new connections being opened |
| 15 | `external_connections` | psutil | Connections to public IPs |
| 16 | `failed_connections` | psutil | Repeated failed connects → port scan |

### Filesystem Changes (indices 17–21)

| Index | Feature | Source | Why It Matters |
|-------|---------|--------|---------------|
| 17 | `etc_modifications` | inotify | Changes to `/etc/` = config tampering |
| 18 | `tmp_file_count` | `os.listdir("/tmp")` | Malware often drops files in `/tmp` |
| 19 | `tmp_executables` | `os.listdir("/tmp")` | Executable in `/tmp` = high suspicion |
| 20 | `cron_modified` | inotify | Cron changes = persistence mechanism |
| 21 | `home_modifications` | inotify | Mass home dir writes |

> **None of these open files.** They only count entries in directories or watch for modification events.

### Threat & Security History (indices 22–36)

| Index | Feature | Source |
|-------|---------|--------|
| 22–29 | `threat_history_0–7` | Sliding window of last 8 threat event scores |
| 30 | `cmds_blocked_rate` | Rate of terminal commands blocked |
| 31 | `cmds_warned_rate` | Rate of commands that triggered warnings |
| 32 | `files_quarantined` | Total files in quarantine vault |
| 33 | `exec_blocks_rate` | Rate of process execution blocks |
| 34 | `last_scan_threats` | Threat count from last scan |
| 35 | `anomaly_score` | Heuristic anomaly score (eBPF if available) |
| 36 | `scan_in_progress` | Whether a scan is currently running |

### Temporal Context (indices 37–41)

| Index | Feature | Why It Matters |
|-------|---------|---------------|
| 37–38 | `time_sin/cos_hour` | Time of day (encoded as sine/cosine for cyclical continuity) |
| 39–40 | `time_sin/cos_weekday` | Day of week |
| 41 | `business_hours` | 0 or 1 — processes running at 3am are more suspicious |

### Scan Quality (indices 42–43)

| Index | Feature | Source |
|-------|---------|--------|
| 42 | `pkg_verified_ratio` | Fraction of running binaries verified by package manager |
| 43 | `fp_rate_recent` | Recent false-positive rate (keeps model conservative if it's been wrong) |

---

## Step 2: The 8 Actions

The model picks exactly one action per cycle:

| # | Action | What Happens | Destructive? | Safety Level |
|---|--------|-------------|-------------|-------------|
| 0 | **ALLOW** | Do nothing — system is normal | No | Always safe |
| 1 | **LOG_WARN** | Write a warning to the log | No | Always safe |
| 2 | **BLOCK_PROCESS** | Send `SIGTERM` to a suspicious PID | ⚠️ Yes | Requires 500+ steps |
| 3 | **QUARANTINE_FILE** | Move file to `/var/lib/cyberpet/quarantine/` | ⚠️ Yes | Requires 500+ steps |
| 4 | **NETWORK_ISOLATE** | Drop outbound traffic for a process via iptables | ⚠️ Yes | Requires 500+ steps |
| 5 | **RESTORE_FILE** | Restore a file from quarantine | No | Always allowed |
| 6 | **TRIGGER_SCAN** | Write `quick` to trigger file → scanner starts | No | Requires 500+ steps |
| 7 | **ESCALATE_LOCKDOWN** | SIGKILL process + drop TCP outbound port 1–1023 | ⚠️ Yes | Requires 500+ steps |

### False Positive Protection (3 Layers)

Before any destructive action runs, three checks happen in order:

```
Layer 1: FP Memory database
         "Has this file (sha256) been manually marked safe?"
         → If yes: ABORT, return false_positive=True

Layer 2: Prior Knowledge safe set
         "Is this file's hash in the confirmed-safe set from prior history?"
         → If yes: ABORT, return false_positive=True

Layer 3: (Hash dedup)
         "Does any safe sha256 match this file's hash?"
         → If yes: ABORT, return false_positive=True

All checks pass → execute action
```

---

## Step 3: Safety Layers During Training

The brain goes through three training phases:

```
Steps 0–100:   WARMUP
               ├── Only ALLOW (0) and LOG_WARN (1) are allowed
               ├── If prior history has confirmed threats: also QUARANTINE (3)
               └── Destructive actions are silently redirected to ALLOW

Steps 100–500: LEARNING-SAFE MODE
               ├── Destructive actions redirected to safe fallbacks:
               │   BLOCK_PROCESS    → LOG_WARN
               │   QUARANTINE_FILE  → LOG_WARN
               │   NETWORK_ISOLATE  → ALLOW
               │   ESCALATE_LOCKDOWN → ALLOW
               └── Model is learning but can't hurt anything

Steps 500+:    FULL MODE
               ├── All 8 actions available
               ├── FP protection still runs on every blocking action
               └── High FP rate suppresses aggressive actions via reward penalty
```

The warmup period itself adapts to prior knowledge:
- **0 confirmed threats in history** → 100-step warmup
- **1–19 confirmed threats** → 50-step warmup
- **20+ confirmed threats** → 25-step warmup

---

## Step 4: The Reward Function

After each action the environment calculates a reward signal:

### Positive Rewards

| Reward | When |
|--------|------|
| `+10.0` | Confirmed threat neutralised (BLOCK/QUARANTINE/LOCKDOWN) |
| `+5.0` | Suspicious activity detected (LOG_WARN/BLOCK/SCAN) |
| `+2.0` | Bonus for a threat category seen before in prior history |
| `+1.0` | System is stable (anomaly < 0.2 AND threat history < 0.1) |
| `+0.5` | Correct ALLOW when system shows no threat |

### Negative Rewards

| Reward | When |
|--------|------|
| `-5.0` | False positive (blocked a safe file) |
| `-10.0` | Repeat false positive (file was already in FP memory) |
| `-3.0` | Unnecessary action (acted when no threat present) |
| `-3.0` | Missed threat (did ALLOW when threat was detected) |
| `-0.5` | Disruptive action (ISOLATE or LOCKDOWN always pay this) |
| up to `-3.0` | High FP rate (fp_rate_recent × 3 if fp_rate > 0.3) |

### Reward Scaling

```python
# Confidence scaling
reward *= action_result.confidence_scale   # 0.0 – 1.0

# Action bias from prior knowledge
# (e.g. many confirmed threats → quarantine bias > 1.0)
reward *= action_bias.get(action, 1.0)

# Final clamp
reward = clip(reward, -20.0, 20.0)
```

---

## Step 5: PPO — How the Neural Network Trains

### Architecture

```
Input:   44 neurons  (system state vector)
         ↓
Hidden:  256 neurons (ReLU activation)
         ↓
Hidden:  256 neurons (ReLU activation)
         ↓
Actor:   8 neurons   (action probabilities, softmax)
Critic:  1 neuron    (expected future reward estimate)
```

Two networks share the hidden layers. The **Actor** decides what to do. The **Critic** estimates how good each situation is, which helps calculate the **advantage** (was this action better or worse than expected?).

### Training Batch (every 512 steps)

After 512 observations, PPO runs a batch update:

```
For each mini-batch of 64 samples from the 512:
    advantage = actual_reward - critic_estimate
    ratio = new_policy(action) / old_policy(action)
    
    loss = -min(ratio × advantage,
                clip(ratio, 0.8, 1.2) × advantage)  ← clip_range = 0.2
    
    loss += 0.5 × value_loss  ← vf_coef
    loss -= 0.01 × entropy    ← ent_coef (encourages exploration)
    
    backprop → update weights
    clip gradients at 0.5     ← max_grad_norm

Run this 10 times over the 512 samples (n_epochs = 10)
```

The clip prevents the policy from changing too drastically in one update — this is PPO's key safety property.

### Hyperparameters

| Parameter | Value | What It Controls |
|-----------|-------|-----------------|
| `learning_rate` | `3e-4` | Step size for weight updates — 0.0003 is the standard |
| `n_steps` | `512` | Observations before each weight update |
| `batch_size` | `64` | Mini-batch size within each update |
| `n_epochs` | `10` | How many passes over the batch |
| `gamma` | `0.99` | Discount factor — 0.99 means long-term reward matters |
| `gae_lambda` | `0.95` | Smooths advantage estimates (bias/variance tradeoff) |
| `clip_range` | `0.2` | Max policy change per update (the "Proximal" in PPO) |
| `ent_coef` | `0.01` | Entropy bonus — prevents the model from being too certain |
| `vf_coef` | `0.5` | Weight of critic loss vs actor loss |
| `max_grad_norm` | `0.5` | Gradient clipping — prevents exploding gradients |

---

## Prior Knowledge Bootstrapping

Before training begins, the brain reads all past human decisions:

```
FalsePositiveMemory DB   →   safe file hashes, FP categories
ScanHistory DB           →   confirmed threats, threat categories, scores
```

This gives the model three advantages:

1. **Appropriate warmup** — shorter if you've been using CyberPet a while
2. **Action bias** — if you've confirmed many threats, it biases towards QUARANTINE; if many FPs, biases towards ALLOW
3. **Safe set** — files you've marked safe will never be blocked, even from day one

---

## IQ Score = How Smart Is the AI?

The pet's IQ (shown in the TUI) is calculated:

```python
step_fraction = min(1.0, total_steps / 2000)   # 0.0 → 1.0
step_ceiling  = step_fraction * 100              # 0 → 100

norm_reward   = clip(avg_reward / 20.0, -1, 1)  # -1 → +1
reward_bonus  = norm_reward × 0.20 × step_ceiling  # ±20% of ceiling

iq = clip(step_ceiling + reward_bonus, 0, 100)
```

**Why steps drive the ceiling:** At step 1, even a +10 reward gives IQ ≈ 0. At step 2000 with excellent rewards, IQ reaches 100. This prevents the wild oscillations (40→35→32) that happened when reward alone dominated the score.

### Intelligence Levels

| Steps | Avg Reward | Level | Meaning |
|-------|-----------|-------|---------|
| 0 | any | 🥒 Newborn | Just started, acting randomly |
| 50 | -1.0+ | 🐣 Learning | Starting to see patterns |
| 100 | 0.0+ | 🐥 Aware | Recognising normal system state |
| 200 | 1.0+ | 🐹 Curious | Noticing anomalies |
| 500 | 2.0+ | 🦊 Smart | Making intentional decisions |
| 1000 | 3.0+ | 🐺 Clever | Predicting threat patterns |
| 2000 | 4.0+ | 🦁 Brilliant | Expert-level cybersecurity decisions |

---

## Model Persistence

The PPO model is saved to `/var/lib/cyberpet/models/cyberpet_ppo.zip` every:
- `checkpoint_interval_steps` steps (default: 3600 = every ~30 hours of runtime)
- On clean daemon shutdown (`SIGTERM`)

On restart, the model is loaded and training continues from where it left off.

---

## Control Commands

```bash
cyberpet model start     # Write "start" to /var/run/cyberpet_rl_control
cyberpet model stop      # Write "paused" to /var/run/cyberpet_rl_control
cyberpet model status    # Read rl_state.json + FP analysis
cyberpet model reset     # Delete cyberpet_ppo.zip (fresh model on next start)
cyberpet model info      # Show PPO architecture details
```
