# Tasks: RL Brain for CyberPet V3

**Input**: Design documents from `/specs/001-rl-brain/`  
**Prerequisites**: plan.md ✓, spec.md ✓, research.md ✓, data-model.md ✓, contracts/ ✓, quickstart.md ✓

**Tests**: Included — the spec references test verification for each component.

**Organization**: Tasks grouped by user story to enable independent implementation and testing.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Add new dependencies and extend shared infrastructure before any RL code.

- [x] T001 Add RL dependencies to requirements.txt (stable-baselines3==2.3.2, torch==2.2.2, gymnasium==0.29.1, numpy==1.26.4, shimmy==1.3.0)
- [x] T002 Add 6 new EventTypes to cyberpet/events.py (RL_DECISION, SYSCALL_ANOMALY, LOCKDOWN_ACTIVATED, LOCKDOWN_DEACTIVATED, FP_MARKED_SAFE, QUARANTINE_CONFIRMED)
- [x] T003 [P] Add `[rl]` config section to config/default_config.toml (enabled, model_path, decision_interval_seconds, checkpoint_interval_steps, warmup thresholds)
- [x] T004 [P] Add RL fields to PetState dataclass in cyberpet/state.py (rl_steps_trained, rl_last_action, rl_last_confidence, rl_avg_reward, rl_state)

**Checkpoint**: Shared infrastructure updated — existing tests must still pass.

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Create the two foundational modules that ALL RL user stories depend on.

**⚠️ CRITICAL**: No RL user story work can begin until this phase is complete.

- [x] T005 Create cyberpet/rl_prior.py — implement RLPriorKnowledge class with __init__(fp_memory, scan_history), load(), get_action_bias(), get_safe_file_penalty_set(), summarize() methods per data-model.md PriorKnowledge entity
- [x] T006 Create tests/test_rl_prior.py — test prior loading from empty DB, populated DB with 8 safe + 3 threats, corrupted DB graceful handling, action bias calculation, safe file penalty set contents, summarize() output format
- [x] T007 Create cyberpet/state_collector.py — implement SystemStateCollector class with __init__(event_bus, pet_state), collect() returning numpy array shape (44,) per data-model.md StateVector entity (all 44 features across 8 groups with normalization)
- [x] T008 Create tests/test_state_collector.py — test vector shape is (44,), all values in [0.0, 1.0], event-driven counter updates for CMD_BLOCKED/QUARANTINE_SUCCESS/SCAN_COMPLETE, pkg_verified_ratio calculation, fp_rate_recent calculation

**Checkpoint**: Foundation ready — rl_prior and state_collector independently testable. User story implementation can begin.

---

## Phase 3: User Story 1 — RL Brain Makes Automated Threat Decisions (Priority: P1) 🎯 MVP

**Goal**: The RL brain observes system state, selects actions via PPO, and executes them every 30 seconds.

**Independent Test**: Start daemon with RL enabled, trigger system events, verify RL_DECISION events appear on EventBus with action, confidence, and reward.

### Tests for User Story 1

- [x] T009 [P] [US1] Create tests/test_rl_env.py — test observation_space shape (44,), action_space (Discrete 8), reset() returns valid obs, step() returns valid (obs, reward, done, truncated, info) tuple, reward positive (+10) for confirmed_threat with blocking action, reward negative (-3) for unnecessary action when no threat
- [x] T010 [P] [US1] Create tests/test_action_executor.py — test ALLOW returns success, QUARANTINE_FILE calls quarantine_vault.quarantine_file(), BLOCK_PROCESS sends SIGTERM to target PID, action on whitelisted process returns false_positive=True, ActionResult has all required fields per data-model.md
- [x] T011 [P] [US1] Create tests/test_rl_engine.py — test fresh model creation (no saved file), model save creates .zip file, model load restores from .zip, warmup period defaults to 100 steps with no priors, run_step() produces RL_DECISION event, checkpoint saves every N steps

### Implementation for User Story 1

- [x] T012 [US1] Create cyberpet/action_executor.py — implement ActionExecutor class with __init__(event_bus, quarantine_vault, fp_memory, prior_knowledge, pet_state) and 8 action methods (action_allow, action_log_warn, action_block_process, action_quarantine_file, action_network_isolate, action_restore_file, action_trigger_scan, action_escalate_lockdown), each returning ActionResult dataclass per data-model.md
- [x] T013 [US1] Create cyberpet/rl_env.py — implement CyberPetEnv(gymnasium.Env) with __init__(state_collector, action_executor, fp_memory, prior_knowledge, config), observation_space=Box(0,1,(44,)), action_space=Discrete(8), reset(), step(action), calculate_reward() per spec reward function
- [x] T014 [US1] Create cyberpet/rl_engine.py — implement RLEngine class with __init__(env, config, fp_memory, scan_history, event_bus), initialize() (load priors, create/load PPO model, set warmup), run_step() (observe, act, reward, train), save_checkpoint(), shutdown_save(); PPO config: net_arch=[256,256], ReLU, lr=3e-4, n_steps=512, batch_size=64, device=cpu
- [x] T015 [US1] Modify cyberpet/daemon.py — add RL initialization block: create shared FalsePositiveMemory + ScanHistory instances, initialize SystemStateCollector, RLPriorKnowledge, ActionExecutor, CyberPetEnv, RLEngine; add asyncio.create_task(_rl_loop) running run_step() every 30s; add model save to SIGTERM handler; wrap all in try/except for graceful degradation
- [x] T016 [US1] Modify cyberpet/scan_scheduler.py — add optional fp_memory parameter to __init__(), pass to internal FileScanner constructor as fp_memory=fp_memory

**Checkpoint**: RL brain is functional — daemon starts, RL makes decisions every 30s, model persists across restarts. MVP complete.

---

## Phase 4: User Story 2 — Prior Knowledge Bootstrap (Priority: P1)

**Goal**: RL bootstraps from human-confirmed decisions so it doesn't start blind.

**Independent Test**: Pre-populate FP memory with safe files and threats, start daemon, verify prior summary in logs and shortened warmup.

### Implementation for User Story 2

- [x] T017 [US2] Enhance cyberpet/action_executor.py — add FP protection checks before every blocking action: check fp_memory.is_known_false_positive(), check prior.get_safe_file_penalty_set(), abort with false_positive=True and target_in_fp_memory=True if target is safe; after successful quarantine call fp_memory.record_quarantine_confirmation()
- [x] T018 [US2] Enhance cyberpet/rl_env.py — update calculate_reward() to apply -10 penalty when action_result.target_in_fp_memory is True, add category_bonus from prior confirmed_threat_categories, add FP rate self-regulation (penalize aggressive actions when fp_rate_recent > 0.3)
- [x] T019 [US2] Enhance cyberpet/rl_engine.py — implement dynamic warmup: 100 steps with 0 priors, 50 steps with 5+ confirmed threats, 25 steps with 20+ confirmed threats; subscribe to FP_MARKED_SAFE events and add to safe_file_set in real-time; apply _apply_prior_bias() from prior.get_action_bias() at initialization
- [x] T020 [US2] Add test cases to tests/test_action_executor.py — test FP memory abort on quarantine (file in FP memory → abort, false_positive=True), safe-set abort on block (hash in prior safe set → abort), successful quarantine calls record_quarantine_confirmation()
- [x] T021 [US2] Add test cases to tests/test_rl_engine.py — test warmup 50 steps with 5 priors, warmup 25 steps with 20 priors, FP_MARKED_SAFE event adds to safe_file_set immediately

**Checkpoint**: RL bootstraps from human decisions, respects FP memory, adjusts warmup dynamically.

---

## Phase 5: User Story 3 — System State Collection (Priority: P1)

**Goal**: 44-feature state vector correctly feeds the RL brain with scan quality metrics.

**Independent Test**: Run state collector, trigger SCAN_COMPLETE with audit stats, verify pkg_verified_ratio and fp_rate_recent update correctly.

### Implementation for User Story 3

- [x] T022 [US3] Enhance cyberpet/state_collector.py — implement SCAN_COMPLETE event handler extracting scan audit stats (skipped_pkg_verified, files_scanned) to compute pkg_verified_ratio (feature index 42); implement FP_MARKED_SAFE handler to increment fp_count_recent and recalculate fp_rate_recent (feature index 43)
- [x] T023 [US3] Enhance cyberpet/state_collector.py — implement QUARANTINE_SUCCESS handler to push threat score to threat_history sliding window (indices 22-29) and increment files_quarantined_total (index 32)
- [x] T024 [US3] Add test cases to tests/test_state_collector.py — test SCAN_COMPLETE updates pkg_verified_ratio to 0.5 when 500/1000 verified, test fp_rate_recent is 0.3 when 3/10 marked safe, test threat_history sliding window shifts correctly

**Checkpoint**: State vector accurately reflects system health + scan quality. All 44 features verified.

---

## Phase 6: User Story 4 — Action Execution with FP Protection (Priority: P2)

**Goal**: All 8 RL actions execute correctly with multi-layer FP checking.

**Independent Test**: Mark file safe in FP memory, request QUARANTINE_FILE, verify abort with false_positive=True.

### Implementation for User Story 4

- [x] T025 [US4] Implement action_network_isolate() in cyberpet/action_executor.py — use iptables to drop outbound connections for a flagged PID, publish LOCKDOWN_ACTIVATED event, return ActionResult
- [x] T026 [US4] Implement action_escalate_lockdown() in cyberpet/action_executor.py — block all non-essential network, kill suspicious processes, publish LOCKDOWN_ACTIVATED event; implement corresponding deactivation via action_restore_file() publishing LOCKDOWN_DEACTIVATED event
- [x] T027 [US4] Implement action_trigger_scan() in cyberpet/action_executor.py — write to /var/run/cyberpet_scan_trigger to trigger quick scan via existing ScanScheduler mechanism
- [x] T028 [US4] Add test cases to tests/test_action_executor.py — test all 8 actions return valid ActionResult, test network_isolate publishes LOCKDOWN_ACTIVATED, test escalate_lockdown with FP-protected target aborts

**Checkpoint**: All 8 actions work with FP protection. ActionExecutor is complete.

---

## Phase 7: User Story 5 — Syscall Anomaly Monitoring (Priority: P2)

**Goal**: eBPF syscall monitor detects anomalous patterns and updates anomaly_score.

**Independent Test**: Run as root, trigger ptrace attach, verify SYSCALL_ANOMALY event published.

### Implementation for User Story 5

- [x] T029 [US5] Create cyberpet/ebpf/syscall_monitor.py
- [x] T030 [US5] Implement PTRACE_ABUSE detection
- [x] T031 [P] [US5] Implement FORK_BOMB detection
- [x] T032 [P] [US5] Implement MEMFD_MALWARE and MMAP_EXEC detection
- [x] T033 [US5] Implement PERSONA_TRICK detection
- [x] T034 [US5] Add SyscallAnomalyMonitor initialization to daemon.py

**Checkpoint**: Syscall monitor detects 5 anomaly types and feeds anomaly_score to state vector.

---

## Phase 8: User Story 6 — RL Visibility in TUI and CLI (Priority: P3)

**Goal**: Users can see RL brain status in TUI and manage it via CLI commands.

**Independent Test**: Run TUI, verify Brain panel shows RL stats. Run `cyberpet model status`, verify output matches contract.

### Implementation for User Story 6

- [x] T035 [US6] Add `model` command group to cyberpet/cli.py
- [x] T036 [P] [US6] Add `cyberpet model reset` to cyberpet/cli.py
- [x] T037 [P] [US6] Add `cyberpet model info` to cyberpet/cli.py
- [x] T038 [P] [US6] Add `fp` command group to cyberpet/cli.py
- [x] T039 [US6] Add BrainStatsWidget to cyberpet/ui/pet.py

**Checkpoint**: Users can see and manage the RL brain via TUI and CLI.

---

## Phase 9: User Story 7 — RL Decision Explainability (Priority: P3)

**Goal**: Human-readable explanations for RL decisions.

**Independent Test**: Call explainer after an RL decision, verify non-empty string referencing state features.

### Implementation for User Story 7

- [x] T040 [US7] Create cyberpet/rl_explainer.py
- [x] T041 [US7] Integrate RLExplainer into cyberpet/cli.py `model status`
- [x] T042 [US7] Integrate RLExplainer into cyberpet/rl_engine.py

**Checkpoint**: RL decisions are explainable in CLI and event stream.

---

## Phase 10: Polish & Cross-Cutting Concerns

**Purpose**: Final integration, validation, and documentation.

- [x] T043 Run all existing tests to verify no regressions
- [x] T044 [P] Run all new V3 tests
- [x] T045 [P] Update cyberpet/ui/scan_screen.py — publish FP_MARKED_SAFE and QUARANTINE_CONFIRMED events
- [x] T046 Validate graceful degradation
- [x] T047 [P] Run quickstart.md validation steps
- [x] T048 Full integration test

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies — start immediately
- **Foundational (Phase 2)**: Depends on Phase 1 — BLOCKS all user stories
- **US1 (Phase 3)**: Depends on Phase 2 — MVP
- **US2 (Phase 4)**: Depends on Phase 3 (enhances action_executor, rl_env, rl_engine)
- **US3 (Phase 5)**: Depends on Phase 2 only (enhances state_collector)
- **US4 (Phase 6)**: Depends on Phase 3 (enhances action_executor)
- **US5 (Phase 7)**: Depends on Phase 1 only (new eBPF module)
- **US6 (Phase 8)**: Depends on Phase 3 (reads RL state)
- **US7 (Phase 9)**: Depends on Phase 3 (reads RL engine)
- **Polish (Phase 10)**: Depends on all desired user stories

### Dependency Graph

```
Phase 1 (Setup)
  ├──▸ Phase 2 (Foundation)
  │     ├──▸ Phase 3 (US1 — MVP) ──▸ Phase 4 (US2)
  │     │                         ──▸ Phase 6 (US4)
  │     │                         ──▸ Phase 8 (US6)
  │     │                         ──▸ Phase 9 (US7)
  │     └──▸ Phase 5 (US3) — can run parallel to Phase 3
  └──▸ Phase 7 (US5) — can run parallel to Phase 2
```

### User Story Dependencies

| Story | Depends On | Can Parallel With |
|-------|-----------|-------------------|
| US1 (P1) | Phase 2 | US3, US5 |
| US2 (P1) | US1 | US3, US4, US5 |
| US3 (P1) | Phase 2 | US1, US5 |
| US4 (P2) | US1 | US3, US5 |
| US5 (P2) | Phase 1 | US1, US2, US3, US4 |
| US6 (P3) | US1 | US5 |
| US7 (P3) | US1 | US5 |

### Parallel Opportunities

**Within Phase 1**: T003 ∥ T004

**Within Phase 3**: T009 ∥ T010 ∥ T011 (all tests in parallel)

**Across Phases**: US3 ∥ US1 (different files: state_collector vs rl_engine+action_executor); US5 ∥ everything (new standalone eBPF module)

---

## Parallel Example: User Story 1

```
# Launch all US1 tests in parallel:
Task T009: "test_rl_env.py"
Task T010: "test_action_executor.py"
Task T011: "test_rl_engine.py"

# Then implement sequentially:
Task T012: action_executor.py (no deps within phase)
Task T013: rl_env.py (depends on T007 state_collector, T012 action_executor)
Task T014: rl_engine.py (depends on T013 rl_env)
Task T015: daemon.py integration (depends on T014)
Task T016: scan_scheduler.py (independent of T014, can parallel with T015)
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Foundation (T005-T008)
3. Complete Phase 3: User Story 1 (T009-T016)
4. **STOP and VALIDATE**: Start daemon, verify RL_DECISION events on EventBus
5. Deploy/demo if ready — RL brain is making decisions

### Incremental Delivery

1. Phase 1 + 2 → Foundation ready
2. + US1 → RL brain active (MVP!)
3. + US2 → Prior knowledge bootstrap (no more blind starts)
4. + US3 → Accurate state vector with scan quality metrics
5. + US4 → All 8 actions complete with FP protection
6. + US5 → Syscall anomaly detection (deeper visibility)
7. + US6 → TUI + CLI visibility
8. + US7 → Explainability
9. + Polish → Production ready

### Suggested MVP Scope

**US1 only** (Phases 1-3, tasks T001-T016). This delivers a functional RL brain making real decisions. Everything else enhances it but the core value is immediately available.

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- All new files go in `cyberpet/` following existing flat package convention
- All tests use `unittest.TestCase` matching existing project pattern
- eBPF tasks (US5) require root for integration testing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
