# Implementation Plan: RL Brain for CyberPet V3

**Branch**: `001-rl-brain` | **Date**: 2026-02-27 | **Spec**: [spec.md](file:///home/soham/cyberpet/specs/001-rl-brain/spec.md)  
**Input**: Feature specification from `/specs/001-rl-brain/spec.md`

## Summary

Add a Reinforcement Learning brain to CyberPet using PPO (stable-baselines3) that learns from real system events and human-confirmed decisions. The RL model observes a 44-feature state vector, selects from 8 actions, and is rewarded/penalized based on confirmed threats vs false positives. It bootstraps with prior knowledge from FalsePositiveMemory and ScanHistory databases so it doesn't start blind. 7 new files, modifications to 7 existing files, 5 new pip dependencies.

## Technical Context

**Language/Version**: Python 3.12.3  
**Primary Dependencies**: stable-baselines3 2.3.2, torch 2.2.2 (CPU), gymnasium 0.29.1, numpy 1.26.4, shimmy 1.3.0  
**Storage**: SQLite (existing pattern — synchronous `sqlite3`), filesystem for model checkpoints  
**Testing**: unittest (16 existing test files, all in `tests/`)  
**Target Platform**: Linux server/desktop (kernel 5.4+, root for eBPF)  
**Project Type**: system daemon + TUI + CLI  
**Performance Goals**: RL inference < 100ms on CPU, decision cycle every 30s  
**Constraints**: CPU-only (no GPU), ~60MB additional memory, graceful degradation when dependencies missing  
**Scale/Scope**: Single-host daemon, 44-dim state, 8 discrete actions, PPO with [256,256] MLP

## Constitution Check

*GATE: Constitution is a blank template — no custom principles defined. No gates to check.*

**Status**: PASS (no violations possible)

## Project Structure

### Documentation (this feature)

```text
specs/001-rl-brain/
├── plan.md              # This file
├── research.md          # Phase 0: 8 research decisions
├── data-model.md        # Phase 1: entities, relationships, state transitions
├── quickstart.md        # Phase 1: install, config, verify
├── contracts/
│   └── cli-contracts.md # Phase 1: CLI command schemas, event types
└── checklists/
    └── requirements.md  # Spec quality checklist
```

### Source Code (repository root)

```text
cyberpet/
├── rl_prior.py              [NEW] RLPriorKnowledge class
├── state_collector.py       [NEW] SystemStateCollector (44-feature vector)
├── rl_env.py                [NEW] CyberPetEnv (gymnasium.Env)
├── action_executor.py       [NEW] ActionExecutor (8 RL actions with FP protection)
├── rl_engine.py             [NEW] RLEngine (PPO training loop + persistence)
├── rl_explainer.py          [NEW] RLExplainer (human-readable explanations)
├── events.py                [MODIFY] Add 6 new EventTypes
├── daemon.py                [MODIFY] Initialize RL stack, start rl_loop task
├── scan_scheduler.py        [MODIFY] Accept fp_memory parameter
├── state.py                 [MODIFY] Add RL fields to PetState
├── ui/pet.py                [MODIFY] Add Brain panel widget
├── cli.py                   [MODIFY] Add model + fp subcommands
├── ebpf/
│   └── syscall_monitor.py   [NEW] SyscallAnomalyMonitor

config/
└── default_config.toml      [MODIFY] Add [rl] section

requirements.txt             [MODIFY] Add 5 packages

tests/
├── test_rl_prior.py         [NEW]
├── test_state_collector.py  [NEW]
├── test_rl_env.py           [NEW]
├── test_action_executor.py  [NEW]
└── test_rl_engine.py        [NEW]
```

**Structure Decision**: All new RL modules are flat in the `cyberpet/` package, following the existing project convention. No sub-packages except the existing `ebpf/` directory which gets one new file. Tests follow the existing `tests/test_*.py` pattern with `unittest.TestCase`.

---

## Implementation Phases

### Phase A: Foundation (EventTypes + Config + State)

**Files**: `events.py`, `config/default_config.toml`, `state.py`, `requirements.txt`

1. Add 6 new EventTypes to `events.py`:
   - `RL_DECISION`, `SYSCALL_ANOMALY`, `LOCKDOWN_ACTIVATED`, `LOCKDOWN_DEACTIVATED`, `FP_MARKED_SAFE`, `QUARANTINE_CONFIRMED`

2. Add `[rl]` section to `config/default_config.toml`:
   - `enabled`, `model_path`, `decision_interval_seconds`, `checkpoint_interval_steps`, warmup values

3. Add RL fields to `PetState` in `state.py`:
   - `rl_steps_trained`, `rl_last_action`, `rl_last_confidence`, `rl_avg_reward`, `rl_state` (WARMUP/TRAINING/DISABLED)

4. Add 5 new packages to `requirements.txt`

**Depends on**: Nothing  
**Verification**: Existing tests should still pass after these changes

---

### Phase B: Data Layer (Prior Knowledge + State Collector)

**Files**: `cyberpet/rl_prior.py`, `cyberpet/state_collector.py`, `tests/test_rl_prior.py`, `tests/test_state_collector.py`

1. **`rl_prior.py`** — `RLPriorKnowledge(fp_memory, scan_history)`:
   - `load()` → reads FP memory + scan history, returns prior dict
   - `get_action_bias()` → computes action probability adjustments
   - `get_safe_file_penalty_set()` → returns set of (sha256, filepath)
   - `summarize()` → human-readable log string

2. **`state_collector.py`** — `SystemStateCollector(event_bus, pet_state)`:
   - Subscribes to EventBus, accumulates counters
   - `collect()` → returns numpy array shape (44,) normalized to [0, 1]
   - Groups: CPU/Memory, Process, Network, FileSystem, ThreatHistory, Security, Time, ScanQuality
   - Event handlers for SCAN_COMPLETE (pkg_verified_ratio), FP_MARKED_SAFE (fp_rate_recent), QUARANTINE_SUCCESS, CMD_BLOCKED, etc.

**Depends on**: Phase A  
**Verification**: `test_rl_prior.py` (empty/populated FP memory), `test_state_collector.py` (vector shape, normalization, event-driven updates)

---

### Phase C: RL Core (Environment + Action Executor + Engine)

**Files**: `cyberpet/rl_env.py`, `cyberpet/action_executor.py`, `cyberpet/rl_engine.py`, `tests/test_rl_env.py`, `tests/test_action_executor.py`, `tests/test_rl_engine.py`

1. **`action_executor.py`** — `ActionExecutor(event_bus, quarantine_vault, fp_memory, prior_knowledge, pet_state)`:
   - 8 action methods with FP protection on all blocking actions
   - Returns `ActionResult` dataclass
   - Pre-checks: whitelist → FP memory → prior safe hashes

2. **`rl_env.py`** — `CyberPetEnv(state_collector, action_executor, fp_memory, prior_knowledge, config)`:
   - `gymnasium.Env` subclass
   - `observation_space = Box(0, 1, shape=(44,), dtype=float32)`
   - `action_space = Discrete(8)`
   - `reset()` → call state_collector.collect()
   - `step(action)` → execute via action_executor, calculate reward, return (obs, reward, done, truncated, info)
   - Reward function with FP penalties, confirmed-threat bonuses, category-aware scaling, FP-rate self-regulation

3. **`rl_engine.py`** — `RLEngine(env, config, fp_memory, scan_history, event_bus)`:
   - `initialize()` → load priors, create/load PPO model, set warmup period
   - `run_step()` → one observation-action-reward cycle
   - `save_checkpoint()` → save model to disk
   - FP_MARKED_SAFE event subscription for real-time safe-set updates
   - Warmup period: restrict actions to ALLOW + LOG_WARN (+ QUARANTINE if deep priors)

**Depends on**: Phase B  
**Verification**: `test_rl_env.py` (spaces, reward calc, FP penalties), `test_action_executor.py` (FP abort, quarantine flow), `test_rl_engine.py` (init, save/load, warmup)

---

### Phase D: eBPF Syscall Monitor

**Files**: `cyberpet/ebpf/syscall_monitor.py`

1. **`syscall_monitor.py`** — `SyscallAnomalyMonitor(event_bus, config)`:
   - BCC tracepoint on raw_syscalls/sys_enter
   - Per-PID sliding window counters
   - Detections: PTRACE_ABUSE, FORK_BOMB, MEMFD_MALWARE, MMAP_EXEC, PERSONA_TRICK
   - Publishes SYSCALL_ANOMALY events
   - Graceful degradation (same pattern as ExecMonitor)

**Depends on**: Phase A  
**Verification**: Manual testing with root — difficult to unit test eBPF; test event publishing logic with mocked data

---

### Phase E: Integration (Daemon + ScanScheduler)

**Files**: `cyberpet/daemon.py`, `cyberpet/scan_scheduler.py`

1. **`daemon.py`** — modify `CyberPetDaemon.start()`:
   - Create shared `FalsePositiveMemory` + `ScanHistory` instances early
   - Pass `fp_memory` to `ScanScheduler`
   - Initialize `SystemStateCollector`, `RLPriorKnowledge`, `ActionExecutor`, `CyberPetEnv`, `RLEngine`
   - Start `SyscallAnomalyMonitor` (optional, after ExecMonitor)
   - `asyncio.create_task(self._rl_loop())` — runs `rl_engine.run_step()` every 30s
   - Save model in SIGTERM handler
   - Wrap all RL init in try/except for graceful degradation

2. **`scan_scheduler.py`** — modify `__init__`:
   - Accept optional `fp_memory` parameter
   - Pass to internal `FileScanner(config, event_bus, hash_db, yara_engine, fp_memory=fp_memory)`

**Depends on**: Phases B, C, D  
**Verification**: Existing `test_scan_scheduler.py` must still pass. Integration tested by running full daemon.

---

### Phase F: UI + CLI

**Files**: `cyberpet/rl_explainer.py`, `cyberpet/ui/pet.py`, `cyberpet/cli.py`

1. **`rl_explainer.py`** — `RLExplainer(rl_engine, state_collector, fp_memory)`:
   - `explain(action, state, result)` → human-readable decision explanation
   - `explain_fp_impact()` → FP rate analysis string

2. **`ui/pet.py`** — add `BrainStatsWidget`:
   - Shows: steps trained, last action + confidence, avg reward, action distribution, FP memory size, loaded priors
   - Add to main TUI layout alongside existing panels
   - Refreshes with existing timer cycle

3. **`cli.py`** — add subcommand groups:
   - `cyberpet model status/reset/info` (3 commands)
   - `cyberpet fp list/clear` (2 commands)
   - See [contracts/cli-contracts.md](file:///home/soham/cyberpet/specs/001-rl-brain/contracts/cli-contracts.md) for exact output formats

**Depends on**: Phase E  
**Verification**: CLI commands tested manually; TUI tested visually

---

## Verification Plan

### Automated Tests

All tests use `unittest.TestCase` matching the existing project pattern.

```bash
# Run ALL tests (existing + new) to ensure no regressions
python3 -m unittest discover tests/ -v

# Run only new V3 tests
python3 -m unittest tests/test_rl_prior.py tests/test_state_collector.py tests/test_rl_env.py tests/test_action_executor.py tests/test_rl_engine.py -v
```

| Test File | What It Covers |
|-----------|---------------|
| `test_rl_prior.py` | Prior loading from empty DB, populated DB, corrupted DB; action bias calculation; safe file penalty set; summarize output |
| `test_state_collector.py` | Vector shape is (44,), all values in [0,1], event-driven counter updates, SCAN_COMPLETE handling, FP rate calculation |
| `test_rl_env.py` | Observation/action space shapes, reset returns valid obs, step returns valid tuple, reward positive for confirmed threats, reward -10 for FP in memory, FP rate self-regulation penalty |
| `test_action_executor.py` | FP memory abort on quarantine, safe-set abort on block, successful quarantine flow calls record_quarantine_confirmation, whitelist bypass |
| `test_rl_engine.py` | Fresh model creation, model save/load roundtrip, warmup period (100 vs 50 vs 25), FP_MARKED_SAFE event adds to safe set |

### Regression Check

```bash
# Ensure all 16 existing tests still pass after modifications
python3 -m unittest discover tests/ -v 2>&1 | tail -5
```

### Manual Verification

1. **Daemon start with RL**: `sudo cyberpet start` → check logs for "RL engine initialized" and "Loaded RL priors: ..." messages
2. **CLI commands**: Run `cyberpet model status`, `cyberpet model info`, `cyberpet fp list` and verify output matches contracts
3. **TUI Brain panel**: Run `cyberpet pet` and verify the Brain panel appears with RL stats
4. **Graceful degradation**: Uninstall torch (`pip uninstall torch`), restart daemon, verify it starts without RL and logs a warning

## Complexity Tracking

No constitution violations to justify — constitution is a blank template.

## References

- [spec.md](file:///home/soham/cyberpet/specs/001-rl-brain/spec.md) — Feature specification
- [research.md](file:///home/soham/cyberpet/specs/001-rl-brain/research.md) — Phase 0 research decisions
- [data-model.md](file:///home/soham/cyberpet/specs/001-rl-brain/data-model.md) — Entity definitions and relationships
- [quickstart.md](file:///home/soham/cyberpet/specs/001-rl-brain/quickstart.md) — Installation and verification
- [cli-contracts.md](file:///home/soham/cyberpet/specs/001-rl-brain/contracts/cli-contracts.md) — CLI command and event schemas
- [project_state.md](file:///home/soham/.gemini/antigravity/brain/d147fef9-1352-4f88-b192-f75e8cf31fe3/project_state.md) — Full V2 project state analysis
