# CyberPet V3 — RL Brain Documentation

> Complete reference for CyberPet's reinforcement learning system.
> Last updated: 2026-02-28

---

## Table of Contents
1. [Architecture Overview](#1-architecture-overview)
2. [The RL Loop](#2-the-rl-loop)
3. [State Vector (44 Features)](#3-state-vector-44-features)
4. [The 8 Actions](#4-the-8-actions)
5. [Reward System](#5-reward-system)
6. [PPO Algorithm](#6-ppo-algorithm)
7. [Prior Knowledge Bootstrapping](#7-prior-knowledge-bootstrapping)
8. [Safety Mechanisms](#8-safety-mechanisms)
9. [Intelligence Levels](#9-intelligence-levels)
10. [Brain UI](#10-brain-ui)
11. [CLI Commands](#11-cli-commands)
12. [Configuration](#12-configuration)
13. [File Map](#13-file-map)
14. [Future Improvements](#14-future-improvements)

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    CyberPet Daemon                          │
│                                                             │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐ │
│   │ State        │    │ PPO Model    │    │ Action       │ │
│   │ Collector    │───▶│ (256×256)    │───▶│ Executor     │ │
│   │ 44 features  │    │ predict()    │    │ 3-layer FP   │ │
│   └──────┬───────┘    └──────┬───────┘    └──────┬───────┘ │
│          │                   │                   │         │
│          │            ┌──────┴───────┐           │         │
│          │            │ RL Engine    │           │         │
│          │            │ warmup/train │           │         │
│          │            │ checkpoint   │           │         │
│          │            └──────┬───────┘           │         │
│          │                   │                   │         │
│   ┌──────┴───────┐    ┌──────┴───────┐    ┌─────┴────────┐│
│   │ Gym Env      │    │ Explainer    │    │ Prior        ││
│   │ reward calc  │    │ human text   │    │ Knowledge    ││
│   └──────────────┘    └──────────────┘    └──────────────┘│
│                                                             │
│   Outputs:                                                  │
│   ├── RL_DECISION events → TUI (Brain Widget + Brain Screen)│
│   ├── rl_state.json → CLI (cyberpet model status)          │
│   └── cyberpet_ppo.zip → Model checkpoint                  │
└─────────────────────────────────────────────────────────────┘
```

### Modules

| Module | File | Purpose |
|--------|------|---------|
| State Collector | `cyberpet/state_collector.py` | Collects 44-feature normalised state vector from system |
| RL Environment | `cyberpet/rl_env.py` | Gymnasium environment: obs space, action space, reward function |
| RL Engine | `cyberpet/rl_engine.py` | PPO lifecycle: warmup, predict, train, checkpoint |
| Action Executor | `cyberpet/action_executor.py` | Executes chosen action with 3-layer false positive protection |
| Prior Knowledge | `cyberpet/rl_prior.py` | Bootstraps model from past human decisions (FP memory + scan history) |
| Explainer | `cyberpet/rl_explainer.py` | Generates human-readable explanations for RL decisions |
| Daemon Loop | `cyberpet/daemon.py` (`_rl_loop`) | Runs the RL cycle every 30s, writes `rl_state.json`, publishes events |
| Brain Screen | `cyberpet/ui/brain_screen.py` | Full-screen TUI with reward graph, action distribution, decision log |

---

## 2. The RL Loop

Every **30 seconds** (configurable via `decision_interval_seconds`), the daemon executes one cycle:

### Step 1: Observe
```python
obs = state_collector.collect()  # → numpy array of 44 floats [0.0 – 1.0]
```
The state collector reads CPU, RAM, network, processes, file changes, threat history, time of day, scan quality metrics, and compresses them into a 44-dimensional float32 vector normalised to [0, 1].

### Step 2: Decide
```python
action, _ = ppo_model.predict(obs, deterministic=False)
```
The PPO neural network processes the 44-feature vector through 2 hidden layers (256 neurons each, ReLU activation) and outputs a probability distribution over 8 actions. One action is sampled from this distribution.

**During warmup** (first 25–100 steps), actions are restricted:
- No prior threats: only ALLOW (0) and LOG_WARN (1)
- With prior threats: also QUARANTINE_FILE (3)

**During learning-safe mode** (steps 0–500), destructive actions are blocked:
- BLOCK_PROCESS, QUARANTINE_FILE, NETWORK_ISOLATE, ESCALATE_LOCKDOWN → fallback to ALLOW

### Step 3: Act
```python
result = action_executor.execute(action)
```
The action executor runs the chosen action. Before any blocking action (BLOCK/QUARANTINE/ISOLATE/LOCKDOWN), it checks:
1. **Whitelist** — Is the target in the user's configured whitelist?
2. **FP Memory** — Has this file been previously marked as a false positive?
3. **Prior Safe Set** — Is this file hash in the prior knowledge safe set?

If any check matches → action is **aborted** and returns `false_positive=True`.

### Step 4: Learn
```python
reward = env.calculate_reward(action, new_state, result)
model.learn(total_timesteps=1, reset_num_timesteps=False)
```
The reward is calculated (see Section 5), and PPO updates its neural network weights. Over time, the network learns to associate certain system states with appropriate actions.

---

## 3. State Vector (44 Features)

| Index | Feature | Source | Range | Category |
|-------|---------|--------|-------|----------|
| 0 | cpu_load_1min | `/proc/loadavg` | 0–1 | System |
| 1 | cpu_load_5min | `/proc/loadavg` | 0–1 | System |
| 2 | cpu_load_15min | `/proc/loadavg` | 0–1 | System |
| 3 | ram_percent | psutil | 0–1 | System |
| 4 | swap_percent | psutil | 0–1 | System |
| 5 | disk_io_rate | psutil | 0–1 | System |
| 6 | process_count | `/proc` | 0–1 | Processes |
| 7 | new_proc_events | EventBus | 0–1 | Processes |
| 8 | root_process_count | `/proc` | 0–1 | Processes |
| 9 | unknown_process_count | `/proc` | 0–1 | Processes |
| 10 | zombie_count | `/proc` | 0–1 | Processes |
| 11 | thread_count | `/proc` | 0–1 | Processes |
| 12 | connection_count | psutil | 0–1 | Network |
| 13 | outbound_bytes_rate | psutil | 0–1 | Network |
| 14 | new_conn_events | EventBus | 0–1 | Network |
| 15 | external_connections | psutil | 0–1 | Network |
| 16 | failed_connections | psutil | 0–1 | Network |
| 17 | etc_modifications | inotify | 0–1 | Filesystem |
| 18 | tmp_file_count | os.listdir | 0–1 | Filesystem |
| 19 | tmp_executables | os.listdir | 0–1 | Filesystem |
| 20 | cron_modified | inotify | 0–1 | Filesystem |
| 21 | home_modifications | inotify | 0–1 | Filesystem |
| 22–29 | threat_history_0–7 | EventBus | 0–1 | Threats |
| 30 | cmds_blocked_rate | EventBus | 0–1 | Security |
| 31 | cmds_warned_rate | EventBus | 0–1 | Security |
| 32 | files_quarantined | QuarantineVault | 0–1 | Security |
| 33 | exec_blocks_rate | EventBus | 0–1 | Security |
| 34 | last_scan_threats | ScanHistory | 0–1 | Security |
| 35 | anomaly_score | Heuristic | 0–1 | Security |
| 36 | scan_in_progress | State | 0 or 1 | Security |
| 37 | time_sin_hour | `time.time()` | 0–1 | Temporal |
| 38 | time_cos_hour | `time.time()` | 0–1 | Temporal |
| 39 | time_sin_weekday | `time.time()` | 0–1 | Temporal |
| 40 | time_cos_weekday | `time.time()` | 0–1 | Temporal |
| 41 | business_hours | `time.time()` | 0 or 1 | Temporal |
| 42 | pkg_verified_ratio | PkgTrust | 0–1 | Quality |
| 43 | fp_rate_recent | FP Memory | 0–1 | Quality |

---

## 4. The 8 Actions

| Index | Name | What It Does | Reward When Correct | Penalty When Wrong |
|-------|------|-------------|--------------------|--------------------|
| 0 | ALLOW | Do nothing | +0.5 | -3.0 (missed threat) |
| 1 | LOG_WARN | Log a warning | +5.0 | minimal |
| 2 | BLOCK_PROCESS | Kill process (SIGKILL) | +10.0 | -3.0 (unnecessary) |
| 3 | QUARANTINE_FILE | Move to vault | +10.0 | -5.0 to -10.0 (FP) |
| 4 | NETWORK_ISOLATE | Block outbound | +10.0 | -0.5 (disruptive) |
| 5 | RESTORE_FILE | Restore from quarantine | context | context |
| 6 | TRIGGER_SCAN | Start a quick scan | +5.0 | -3.0 (unnecessary) |
| 7 | ESCALATE_LOCKDOWN | Full lockdown | +10.0 | -0.5 (disruptive) |

### False Positive Protection (3-Layer)

Before executing BLOCK/QUARANTINE/ISOLATE/LOCKDOWN:
1. Check user whitelist → abort if match
2. Check FP Memory database → abort if hash matches
3. Check Prior Knowledge safe set → abort if match

If aborted: action returns `false_positive=True`, reward = -5 or -10.

---

## 5. Reward System

### Positive Rewards

| Reward | Condition |
|--------|-----------|
| +10.0 | Confirmed threat neutralised (BLOCK/QUARANTINE/LOCKDOWN) |
| +5.0 | Suspicious activity caught (LOG_WARN/BLOCK/SCAN) |
| +2.0 | Category bonus (threat type seen before in priors) |
| +1.0 | System stability (anomaly < 0.2 AND threat_history < 0.1) |
| +0.5 | Correct inaction (ALLOW when threat_history < 0.1) |

### Negative Rewards

| Reward | Condition |
|--------|-----------|
| -5.0 | False positive (acted on safe file) |
| -10.0 | Repeat FP (file was already in FP memory) |
| -3.0 | Unnecessary action (no threat, but acted) |
| -3.0 | Missed threat (threat existed, did ALLOW) |
| -0.5 | Disruptive action penalty (ISOLATE/LOCKDOWN always) |
| -0.9 to -3.0 | High FP rate + aggressive action (fp_rate > 0.3) |

### Scaling

- All rewards multiplied by `confidence_scale` (0.0–1.0) from action result
- Final reward clamped to [-20, +20]

---

## 6. PPO Algorithm

### What is PPO?

Proximal Policy Optimization (PPO) is a policy gradient reinforcement learning algorithm. It maintains two neural networks:

1. **Policy Network (Actor)** — Maps observations → action probabilities
2. **Value Network (Critic)** — Estimates expected future reward from current state

PPO updates the policy by maximising a "clipped" objective that prevents large, unstable changes:

```
L = min(ratio * advantage, clip(ratio, 1-ε, 1+ε) * advantage)
```

Where:
- `ratio` = new_policy / old_policy (how much the action probability changed)
- `advantage` = actual_reward - estimated_reward (was the action better than expected?)
- `ε = 0.2` (clip range — limits how much the policy can change per update)

### Network Architecture

```
Input Layer:   44 neurons (state vector)
    ↓
Hidden Layer 1: 256 neurons (ReLU activation)
    ↓
Hidden Layer 2: 256 neurons (ReLU activation)
    ↓
Output Layer:  8 neurons (action probabilities, softmax)
```

### Hyperparameters

| Parameter | Value | Purpose |
|-----------|-------|---------|
| `learning_rate` | 3e-4 | How fast the network learns |
| `n_steps` | 512 | Steps collected before each weight update |
| `batch_size` | 64 | Mini-batch size for SGD updates |
| `n_epochs` | 10 | Passes over data per update |
| `gamma` | 0.99 | Discount factor (values long-term reward) |
| `gae_lambda` | 0.95 | Advantage estimation smoothing |
| `clip_range` | 0.2 | Policy change limit per update |
| `ent_coef` | 0.01 | Entropy bonus (encourages exploration) |
| `vf_coef` | 0.5 | Value function loss weight |
| `max_grad_norm` | 0.5 | Gradient clipping for stability |

### Why PPO for CyberPet?

| Requirement | PPO Fit |
|------------|---------|
| Continuous environment (no game over) | ✅ Designed for infinite-horizon |
| Discrete actions (8 choices) | ✅ Works with Discrete spaces |
| Stable learning (no wild swings) | ✅ Clipped objective prevents catastrophic updates |
| Sample efficient (30s intervals) | ✅ Learns from every observation |
| Online learning (no replay buffer) | ✅ On-policy algorithm |

---

## 7. Prior Knowledge Bootstrapping

Before training, the RL engine loads **prior knowledge** from human decisions:

### Sources

| Source | What It Provides |
|--------|-----------------|
| FP Memory DB | Safe file hashes, FP categories, mark counts |
| Scan History DB | Confirmed threats, threat categories, threat scores |

### How It Affects Training

| Prior Data | Effect |
|-----------|--------|
| 0 confirmed threats | Warmup = 100 steps (no threat context) |
| 1–19 confirmed threats | Warmup = 50 steps (some context) |
| 20+ confirmed threats | Warmup = 25 steps (deep prior knowledge) |

### Action Bias

Prior knowledge creates an **action bias**:
- Many confirmed threats → bias towards QUARANTINE/BLOCK
- Many FPs → bias towards ALLOW (conservative)
- Balanced → neutral bias

---

## 8. Safety Mechanisms

### Layer 1: Warmup Phase (Steps 0 to 25–100)
- Only ALLOW and LOG_WARN allowed
- QUARANTINE allowed only if prior threats > 0
- All other actions → fallback to ALLOW

### Layer 2: Learning-Safe Mode (Steps 0 to 500)
- BLOCK_PROCESS → fallback to LOG_WARN
- QUARANTINE_FILE → fallback to LOG_WARN
- NETWORK_ISOLATE → fallback to ALLOW
- ESCALATE_LOCKDOWN → fallback to ALLOW
- Only safe actions: ALLOW, LOG_WARN, RESTORE_FILE, TRIGGER_SCAN

### Layer 3: FP Protection (Always Active)
Before any blocking action:
1. Check user whitelist
2. Check FP Memory database
3. Check Prior Knowledge safe set
If match → abort action, return `false_positive=True`

### Layer 4: Reward Penalties (Always Active)
- FP penalty: -5 to -10 (teaches model to avoid)
- Unnecessary action: -3 (teaches model to be conservative)
- Disruptive action: -0.5 (slight bias against heavy actions)

### Layer 5: Model Checkpointing
- Saves to `/var/lib/cyberpet/models/cyberpet_ppo.zip` every 3600 steps
- Also saves on graceful daemon shutdown
- Survives daemon restarts

---

## 9. Intelligence Levels

| Level | Emoji | Steps | Reward | Description |
|-------|-------|-------|--------|-------------|
| Newborn | 🥒 | 0+ | any | Just started. Makes random choices, restricted by warmup and learning-safe mode. |
| Curious | 🐣 | 50+ | > -1.0 | Survived warmup. Starting to notice patterns. Still exploring. |
| Learning | 🧠 | 200+ | > 0.0 | Making real connections. Knows ALLOW is good when quiet. |
| Smart | ⚡ | 500+ | > +1.5 | First level with full action access. Solid decisions, rare FPs. |
| Expert | 🎓 | 2000+ | > +3.0 | Battle-hardened. Consistently positive rewards. Context-aware. |

### IQ Score (0–100)

Formula: `IQ = min(60, steps/2000 × 60) + min(40, max(0, (reward+5)/10) × 40)`

- 60% from experience (training steps)
- 40% from quality (average reward)

### Time to Each Level

| Level | Steps | Time (at 30s/step) |
|-------|-------|--------------------|
| Curious | 50 | ~25 minutes |
| Learning | 200 | ~1h 40m |
| Smart | 500 | ~4h 10m |
| Expert | 2000 | ~16h 40m |

---

## 10. Brain UI

### Compact Brain Widget (Main TUI)

Always visible in the top-right of the main TUI. Shows:
- Intelligence level + emoji
- IQ score with progress bar
- ETA to next milestone
- State (DISABLED / WARMUP / TRAINING)
- Steps trained (comma-formatted)
- Average reward
- Warmup progress bar (during warmup)
- Last action name
- Last decision explanation
- Action distribution chart (all 8 actions with bars)

### Brain Screen (Press `b`)

Full-screen detail view with 4 quadrants:

| Quadrant | Widget | Content |
|----------|--------|---------|
| Top-left | Reward Graph | ASCII sparkline of last 50 rewards. █=positive, ▒=negative |
| Top-right | Action Distribution | All 8 actions with proportional bars and percentages |
| Bottom-left | Decision Log | Scrollable log of recent decisions with step#, action, reward, explanation |
| Bottom-right | Brain Status | Intelligence level, IQ, ETA, model info, FP impact, state, steps, reward |

Keybindings: `Esc`/`b` = back to main TUI.

---

## 11. CLI Commands

```bash
cyberpet model status    # Show brain state, steps, reward, model info
cyberpet model info      # Display PPO architecture and hyperparameters
cyberpet model reset     # Delete trained model (fresh start)
cyberpet fp list         # List all false positive entries
cyberpet fp clear        # Clear all FP entries
```

---

## 12. Configuration

In `/etc/cyberpet/config.toml`:

```toml
[rl]
enabled = true                        # Master switch for RL brain
decision_interval_seconds = 30        # How often the brain makes a decision
model_path = "/var/lib/cyberpet/models/"  # Where to save the PPO model
checkpoint_interval_steps = 3600      # Save model every N steps
warmup_steps_no_priors = 100          # Warmup with no prior knowledge
warmup_steps_with_priors = 50         # Warmup with some priors
warmup_steps_deep_priors = 25         # Warmup with 20+ prior threats
deep_prior_threshold = 20            # Threats needed for "deep" priors
learning_safe_steps = 500             # Steps before destructive actions unlock
```

---

## 13. File Map

```
cyberpet/
├── rl_engine.py          # PPO training loop, warmup, checkpointing
├── rl_env.py             # Gymnasium env (obs/action spaces, reward calc)
├── rl_prior.py           # Prior knowledge from FP memory + scan history
├── rl_explainer.py       # Human-readable decision explanations
├── state_collector.py    # 44-feature system state vector
├── action_executor.py    # Execute 8 RL actions with FP protection
├── daemon.py             # _rl_loop (30s cycle), rl_state.json writer
├── state.py              # PetState with RL fields
├── ui/
│   ├── pet.py            # BrainStatsWidget, RL_DECISION handler, b keybind
│   └── brain_screen.py   # Full-screen brain detail view
└── cli.py                # model status/info/reset, fp list/clear

tests/
├── test_rl_engine.py     # Model creation, warmup, save/load, FP events
├── test_rl_env.py        # Observation/action spaces, reward function
├── test_rl_prior.py      # Prior loading, action bias, corruption handling
└── test_state_collector.py  # 44-feature shape, normalisation, event updates

config/
└── default_config.toml   # Default [rl] section with all parameters

/var/lib/cyberpet/models/
├── cyberpet_ppo.zip      # Saved PPO model weights
└── rl_state.json         # Live brain state (steps, reward, action)
```

---

## 14. Future Improvements

### Short-Term (V3.1)

| Improvement | Description | Priority |
|------------|-------------|----------|
| **Reward shaping** | Add time-decay to threat rewards (faster response = higher reward) | Medium |
| **Action confidence threshold** | Only execute non-safe actions if model confidence > 70% | Medium |
| **Per-action cooldown** | Prevent rapid repeated scans or blocks (rate limiting) | Medium |
| **Reward trend alerting** | Pet speech bubble changes when reward drops suddenly | Low |

### Medium-Term (V4)

| Improvement | Description | Priority |
|------------|-------------|----------|
| **Multi-agent** | Separate models for network threats vs file threats vs process threats | High |
| **Curiosity-driven exploration** | Intrinsic reward for novel observations (Random Network Distillation) | Medium |
| **Curriculum learning** | Increasingly complex threat scenarios during training | Medium |
| **Transfer learning** | Pre-trained model shared across installations | Medium |
| **Explainable attention** | Visualise which of the 44 features most influenced each decision | Low |

### Long-Term (V5+)

| Improvement | Description | Priority |
|------------|-------------|----------|
| **Federated learning** | Learn from multiple CyberPet instances without sharing raw data | High |
| **Natural language reasoning** | LLM-powered threat analysis layer on top of RL decisions | Medium |
| **Adversarial training** | Train against simulated attacks to build robustness | Medium |
| **Custom reward functions** | User-defined reward weights via config | Low |
| **A/B model testing** | Run two models simultaneously, compare performance | Low |
