# Research: RL Brain for CyberPet V3

**Branch**: `001-rl-brain` | **Date**: 2026-02-27

## R1: PPO on CPU — Performance & Memory Budget

**Decision**: Use stable-baselines3 PPO with `MlpPolicy`, net_arch=[256, 256], ReLU activation, CPU-only device.

**Rationale**:
- PPO is the standard on-policy algorithm for environments with discrete action spaces and low-dimensional observations (44 features).
- On CPU with a [256, 256] MLP, forward inference for 44-dim input is < 1ms. The 100ms budget the spec mandates is easily met.
- stable-baselines3 2.3.2 with torch 2.2.2 CPU wheel totals ~200MB installed. Memory footprint during training: ~50MB for the rollout buffer (512 steps × 44 features × float32) + model weights (~500K parameters × 4 bytes = 2MB).
- Total additional memory per daemon process: ~60MB.

**Alternatives Considered**:
- DQN: Simpler off-policy, but PPO's on-policy nature is better for non-stationary security environments where threat landscapes shift.
- SAC: Designed for continuous action spaces; not suitable for 8-discrete actions.
- Raw PyTorch: Lower overhead but requires implementing PPO from scratch with correct advantage estimation — high bug risk for no real benefit.

---

## R2: Gymnasium Environment Design

**Decision**: Custom `gymnasium.Env` subclass with `Box(0, 1, shape=(44,))` observation space and `Discrete(8)` action space.

**Rationale**:
- Gymnasium 0.29.1 is the standard interface stable-baselines3 expects.
- The 44-feature observation space maps directly to SystemStateCollector output.
- 8 discrete actions map to the existing system capabilities (quarantine, block, scan, etc.).
- `shimmy==1.3.0` is required by stable-baselines3 as a compatibility shim.

**Alternatives Considered**:
- Multi-discrete action space (separate actions per threat): Overcomplicated — the RL brain makes one system-level decision per cycle, not per-threat.
- Dict observation space: Would provide more semantic structure but stable-baselines3 MlpPolicy handles flat Box spaces most efficiently.

---

## R3: State Vector Refresh Strategy

**Decision**: Event-driven accumulation with snapshot on demand.

**Rationale**:
- The 44-feature vector is composed of 8 groups. Some (CPU/memory) are polled via psutil. Others (threat history, security events) are accumulated from EventBus events.
- The state collector subscribes to the EventBus and updates internal counters as events arrive. When the RL engine calls `collect()`, the collector takes a snapshot, normalizes everything to [0, 1], and returns a numpy array.
- This avoids expensive computation on every event; only the snapshot-on-demand requires the full 44-float build.

**Alternatives Considered**:
- Polling everything every 30 seconds: Would miss events between polls and require re-scanning EventBus history.
- Storing raw event lists and computing features at snapshot time: Higher latency at inference time.

---

## R4: FP Memory Integration Pattern

**Decision**: Shared instance passed by reference; in-memory safe set with event-driven updates.

**Rationale**:
- The V3 spec explicitly requires a single FalsePositiveMemory instance shared between RL engine, ActionExecutor, and FileScanner.
- The `safe_file_set` (set of (sha256, filepath) tuples) is loaded from FP memory at startup and updated in real-time via FP_MARKED_SAFE events.
- This avoids querying SQLite on every RL action check. The in-memory set provides O(1) lookup.

**Alternatives Considered**:
- Separate instances with periodic sync: Risk of stale data between components.
- Direct SQLite query on every check: Too slow (~1ms per query × potentially many checks per second).

---

## R5: ScanScheduler Refactoring

**Decision**: ScanScheduler will accept an optional `fp_memory` parameter. Its internal FileScanner already supports `fp_memory=None`.

**Rationale**:
- ScanScheduler currently creates its own HashDatabase, YaraEngine, FileScanner, and QuarantineVault internally. This is fine — the scanner's `fp_memory` parameter just needs to be plumbed through.
- The daemon will create the shared FalsePositiveMemory instance and pass it to ScanScheduler's constructor as a new optional parameter.
- ScanScheduler passes it to its internal FileScanner. No other changes needed — the scheduler's own QuarantineVault and HashDatabase remain internal.

**Alternatives Considered**:
- Externalizing all ScanScheduler dependencies: Over-engineering; only fp_memory needs sharing.
- Making ScanScheduler create its own fp_memory: Breaks shared-instance requirement.

---

## R6: daemon.py Initialization Order

**Decision**: Insert new V3 initialization between ScanScheduler.start() and the stats/uptime/logger tasks.

**Rationale**:
- FalsePositiveMemory and ScanHistory must be created BEFORE RLPriorKnowledge (which reads them).
- RLPriorKnowledge must be created BEFORE RLEngine/CyberPetEnv/ActionExecutor.
- ScanScheduler needs fp_memory, so the shared instance is created before the scheduler.
- The RL loop runs as an asyncio.create_task alongside existing tasks.

**Initialization order**:
1. Config, logging, PID (existing)
2. PetState, EventBus (existing)
3. **FalsePositiveMemory** (NEW)
4. **ScanHistory** (NEW)
5. TerminalGuard (existing)
6. ExecMonitor, FileAccessMonitor (existing)
7. ScanScheduler — now receives fp_memory (MODIFIED)
8. **SystemStateCollector** (NEW)
9. **RLPriorKnowledge** (NEW)
10. **ActionExecutor** (NEW)
11. **CyberPetEnv** (NEW)
12. **RLEngine** (NEW)
13. **SyscallAnomalyMonitor** (NEW — optional, eBPF)
14. Stats, uptime, event logger tasks (existing)
15. **RL loop task** (NEW)

---

## R7: eBPF Syscall Monitor Approach

**Decision**: Use BCC tracepoint on raw_syscalls/sys_enter with per-PID sliding window counters.

**Rationale**:
- PTRACE detection: Watch for SYS_PTRACE with PTRACE_ATTACH request.
- Fork bomb detection: Count SYS_CLONE per PID per second; threshold > 100.
- MEMFD detection: Watch for SYS_MEMFD_CREATE.
- MMAP_EXEC: Watch for SYS_MMAP with PROT_EXEC flag.
- PERSONA_TRICK: Watch for SYS_SETUID/SYS_SETGID from non-root processes.
- Uses the same BCC pattern as ExecMonitor: BPF perf buffer → background thread → asyncio event.
- Gracefully degrades when BCC unavailable or not root (exactly like ExecMonitor).

**Alternatives Considered**:
- audit subsystem: Requires auditd configuration, less control.
- seccomp-bpf: Designed for sandboxing, not monitoring.

---

## R8: Testing Strategy

**Decision**: Unit tests with unittest (matching existing project pattern). Mock all system dependencies.

**Rationale**:
- Project uses `unittest` (verified in 16 existing test files).
- RL components can be tested with synthetic state vectors and mocked action results.
- Gymnasium environment can be tested with `env.reset()` / `env.step()` loop.
- FP memory integration tested by pre-populating SQLite with test data.
- eBPF syscall monitor cannot be unit tested without root; test the event publishing logic with mocked BPF data.

**Test files to create**:
- `tests/test_state_collector.py` — verify 44-feature vector shape, normalization, event-driven updates
- `tests/test_rl_env.py` — verify observation/action spaces, reward calculation, FP penalty
- `tests/test_rl_prior.py` — verify prior loading from populated/empty FP memory
- `tests/test_action_executor.py` — verify FP protection, quarantine flow, safe-set checks
- `tests/test_rl_engine.py` — verify initialization, model save/load, warmup period adjustment
