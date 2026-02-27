# Data Model: RL Brain for CyberPet V3

**Branch**: `001-rl-brain` | **Date**: 2026-02-27

## Entities

### StateVector

A 44-dimensional float32 array representing the system's current state.

| Index | Name | Group | Source | Normalization |
|-------|------|-------|--------|---------------|
| 0 | cpu_percent_1min | CPU/Memory | psutil | /100 |
| 1 | cpu_percent_5min | CPU/Memory | psutil | /100 |
| 2 | cpu_percent_15min | CPU/Memory | psutil | /100 |
| 3 | ram_percent | CPU/Memory | psutil | /100 |
| 4 | swap_percent | CPU/Memory | psutil | /100 |
| 5 | disk_io_rate | CPU/Memory | psutil | clip /1e8 |
| 6 | process_count | Process | psutil | /1000 |
| 7 | new_process_rate | Process | EventBus accum | /100 |
| 8 | root_process_count | Process | psutil | /200 |
| 9 | unknown_process_count | Process | psutil | /100 |
| 10 | zombie_count | Process | psutil | /50 |
| 11 | thread_count | Process | psutil | /5000 |
| 12 | connection_count | Network | psutil | /1000 |
| 13 | outbound_bytes_rate | Network | psutil | clip /1e8 |
| 14 | new_connection_rate | Network | EventBus accum | /100 |
| 15 | external_connection_count | Network | psutil | /500 |
| 16 | failed_connection_count | Network | psutil | /100 |
| 17 | etc_modification_rate | FileSystem | EventBus accum | /50 |
| 18 | tmp_file_count | FileSystem | os.listdir | /1000 |
| 19 | tmp_executable_count | FileSystem | os.listdir | /100 |
| 20 | cron_modification_flag | FileSystem | EventBus accum | 0 or 1 |
| 21 | home_modification_rate | FileSystem | EventBus accum | /100 |
| 22-29 | threat_score_t0..t7 | Threat History | sliding window | /100 |
| 30 | commands_blocked_last_hour | Security | EventBus accum | /50 |
| 31 | commands_warned_last_hour | Security | EventBus accum | /100 |
| 32 | files_quarantined_total | Security | PetState | /50 |
| 33 | exec_blocks_last_hour | Security | EventBus accum | /50 |
| 34 | scan_threat_count_last_scan | Security | EventBus accum | /20 |
| 35 | anomaly_score | Security | SyscallMonitor | clip 0-1 |
| 36 | quarantine_count_active | Security | QuarantineVault | /50 |
| 37 | hour_sin | Time | math | sin(2π·h/24) mapped [0,1] |
| 38 | hour_cos | Time | math | cos(2π·h/24) mapped [0,1] |
| 39 | day_of_week_sin | Time | math | sin(2π·d/7) mapped [0,1] |
| 40 | day_of_week_cos | Time | math | cos(2π·d/7) mapped [0,1] |
| 41 | is_business_hours | Time | datetime | 0 or 1 |
| 42 | pkg_verified_ratio | Scan Quality | SCAN_COMPLETE event | 0-1 ratio |
| 43 | fp_rate_recent | Scan Quality | FP tracking | 0-1 ratio |

### ActionResult

Outcome of executing an RL action.

| Field | Type | Description |
|-------|------|-------------|
| action | int | Action index (0-7) |
| success | bool | Whether execution succeeded |
| confirmed_threat | bool | True if action neutralized a real threat |
| suspicious_detected | bool | True if suspicious activity was caught |
| false_positive | bool | True if target was actually safe |
| target_in_fp_memory | bool | True if target was in FP memory safe set |
| threat_category | str | Category from ThreatRecord (e.g., "cryptominer") |
| missed_threat | bool | True if scanner confirmed threat but RL allowed it |
| confidence_scale | float | 0.0-1.0, scales reward magnitude |
| details | str | Human-readable description of what happened |

### PriorKnowledge

Pre-loaded human decision data.

| Field | Type | Description |
|-------|------|-------------|
| safe_hashes | set[str] | SHA256s user marked safe |
| threat_hashes | set[str] | SHA256s user quarantined |
| safe_paths | set[str] | Paths user marked safe |
| fp_by_category | dict[str, int] | FP count per threat category |
| fp_by_rule | dict[str, int] | FP count per YARA rule |
| confirmed_threat_categories | dict[str, int] | Quarantine confirmations per category |
| total_fp_count | int | Total false positives recorded |
| total_confirmed_threats | int | Total confirmed threats recorded |
| avg_threat_score_at_quarantine | float | Average score when user chose quarantine |

### RLCheckpoint

Serialized model state.

| Field | Type | Description |
|-------|------|-------------|
| model_path | str | Path to saved PPO .zip file |
| total_steps | int | Total training steps completed |
| last_saved | datetime | Timestamp of last save |
| avg_reward_100 | float | Average reward over last 100 steps |
| action_distribution | dict[int, int] | Action selection counts |

## Relationships

```
FalsePositiveMemory ──reads──▸ RLPriorKnowledge ──informs──▸ CyberPetEnv (reward function)
                                                ──informs──▸ ActionExecutor (safe set)
                                                ──informs──▸ RLEngine (warmup period)

SystemStateCollector ──observes──▸ EventBus (all event types)
                     ──snapshot──▸ CyberPetEnv.reset() / step()

RLEngine ──trains──▸ PPO model ──acts──▸ ActionExecutor
         ──publishes──▸ EventBus (RL_DECISION)
         ──saves──▸ RLCheckpoint (to disk)

ActionExecutor ──uses──▸ QuarantineVault (quarantine action)
               ──uses──▸ FalsePositiveMemory (FP check + confirmation)
               ──publishes──▸ EventBus (QUARANTINE_CONFIRMED, FP_MARKED_SAFE)

SyscallAnomalyMonitor ──publishes──▸ EventBus (SYSCALL_ANOMALY)
                      ──updates──▸ SystemStateCollector (anomaly_score)
```

## State Transitions

### RL Engine Lifecycle

```
UNINITIALIZED ──initialize()──▸ WARMUP ──warmup_done──▸ TRAINING ──shutdown()──▸ SAVED
     │                           │                        │
     │                    (only ALLOW,LOG_WARN)     (all 8 actions)
     │                                                    │
     │                                            ──checkpoint()──▸ TRAINING
     │
     └── load_failed ──▸ DISABLED (daemon continues without RL)
```

### Action Execution Flow

```
RL selects action
  └──▸ Check FP memory/safe set
       ├── target is safe ──▸ ABORT (false_positive=True, -10 reward)
       └── target not safe ──▸ EXECUTE action
            ├── success ──▸ reward based on result
            └── failure ──▸ log error, 0 reward
```
