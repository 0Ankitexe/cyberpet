# Feature Specification: Reinforcement Learning Brain for CyberPet V3

**Feature Branch**: `001-rl-brain`  
**Created**: 2026-02-27  
**Status**: Draft  
**Input**: User description: "Add the Reinforcement Learning brain. The pet now learns from real system events AND from human-confirmed decisions stored in FalsePositiveMemory and ScanHistory. The model bootstraps with prior knowledge from day one instead of starting blind."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - RL Brain Makes Automated Threat Decisions (Priority: P1)

The CyberPet daemon continuously monitors system events (process executions, file accesses, terminal commands, scan results). Every 30 seconds, the RL brain observes a 44-feature state vector describing the current system health, threat history, and scan quality metrics. Based on this observation, the RL engine selects one of 8 possible actions (ALLOW, LOG_WARN, BLOCK_PROCESS, QUARANTINE_FILE, NETWORK_ISOLATE, RESTORE_FILE, TRIGGER_SCAN, ESCALATE_LOCKDOWN) and executes it. Over time, the model improves its decisions through reward feedback based on whether actions were correct (confirmed threats neutralized) or incorrect (false positives penalized).

**Why this priority**: This is the core value proposition of V3 — the pet evolves from a static rule-based system to one that learns and adapts to the user's specific threat environment.

**Independent Test**: Can be fully tested by starting the daemon with the RL engine enabled, triggering system events (e.g., running commands, creating suspicious files), and verifying that the RL engine produces decisions logged to the event bus. Delivers immediate value by automating threat response.

**Acceptance Scenarios**:

1. **Given** the daemon starts with no prior model saved, **When** the RL engine initializes, **Then** a fresh PPO model is created with a (44,) observation space, 8-action discrete space, and a 100-step warmup period where only ALLOW and LOG_WARN actions are used.
2. **Given** the RL engine is running, **When** 30 seconds pass, **Then** the engine collects the current 44-feature state, runs PPO inference (under 100ms on CPU), selects an action, executes it via the ActionExecutor, receives a reward, and publishes an RL_DECISION event to the EventBus.
3. **Given** the model has been training, **When** the daemon receives SIGTERM, **Then** the current model checkpoint is saved to disk before shutdown.
4. **Given** a saved model exists on disk, **When** the daemon restarts, **Then** the model is loaded and training continues from where it left off.

---

### User Story 2 - Prior Knowledge Bootstrap from Human Decisions (Priority: P1)

When the daemon starts, the RL brain loads prior knowledge from human-confirmed decisions already stored in FalsePositiveMemory (files the user marked safe, files the user confirmed as threats) and ScanHistory (past scan results with per-threat actions). This prior knowledge adjusts the RL policy's initial action biases and pre-populates a safe-file penalty set, so the model does not waste its early training re-learning what the user already told it. For example, if the user previously quarantined 10 cryptominer files, the RL brain will bias QUARANTINE actions higher for threats in the cryptominer category from the start.

**Why this priority**: Without prior knowledge, the RL brain starts blind and may generate false positives on files the user already marked safe — causing frustration and distrust. This is essential to the user experience.

**Independent Test**: Can be tested by pre-populating the FalsePositiveMemory database with known-safe files and confirmed threats, then starting the daemon and verifying that the RL brain's summarize() output shows the loaded priors. Delivers value by eliminating repeat false positives from day one.

**Acceptance Scenarios**:

1. **Given** FalsePositiveMemory contains 8 safe files and 3 confirmed threats, **When** the RL engine initializes, **Then** the prior knowledge summary log shows "Loaded RL priors: 8 safe files, 3 confirmed threats" and the warmup period is shortened to 50 steps (or 25 if 20+ confirmed threats exist).
2. **Given** the user marked a file as safe in the TUI, **When** the RL engine next considers blocking that file, **Then** the ActionExecutor checks FalsePositiveMemory, aborts the block with false_positive=True, and the RL receives a -10 reward penalty.
3. **Given** FalsePositiveMemory and ScanHistory are both empty (first-ever run), **When** the RL engine initializes, **Then** prior knowledge loads empty dictionaries without errors, the warmup period is set to 100 steps, and the model starts training normally.
4. **Given** the FalsePositiveMemory SQLite database is corrupted, **When** the daemon starts, **Then** a warning is logged and FalsePositiveMemory initializes with a fresh database instead of crashing.

---

### User Story 3 - System State Collection (44-Feature Vector) (Priority: P1)

The system continuously collects a 44-dimensional state vector that feeds the RL brain's observations. This includes 8 groups: CPU/memory metrics (6 features), process activity (6 features), network connections (5 features), filesystem modifications (5 features), threat history sliding window (8 features), security event counters (7 features), time context (5 features), and scan quality metrics (2 new features — package-verified ratio and recent false positive rate). The state vector is normalized to [0, 1] range and refreshed every time the RL brain needs an observation.

**Why this priority**: The state vector is the RL brain's eyes — without it, the model cannot observe the system or make decisions. All other RL components depend on this.

**Independent Test**: Can be tested by running the state collector in isolation, printing the 44-feature vector, and verifying each group produces valid normalized values between 0 and 1.

**Acceptance Scenarios**:

1. **Given** the system is idle, **When** the state collector gathers a snapshot, **Then** all 44 features are populated as float32 values in [0.0, 1.0] range.
2. **Given** a SCAN_COMPLETE event is received with audit stats (skipped_pkg_verified=500, files_scanned=1000), **When** the state collector processes this event, **Then** pkg_verified_ratio is updated to 0.5.
3. **Given** the user marked 3 files safe out of 10 flagged threats in the last 5 scans, **When** the state collector calculates fp_rate_recent, **Then** the value is 0.3 (30%).

---

### User Story 4 - Action Execution with FP Protection (Priority: P2)

When the RL brain selects an action, the ActionExecutor carries it out while checking multiple layers of false-positive protection. Before any blocking action (BLOCK_PROCESS, QUARANTINE_FILE, ESCALATE_LOCKDOWN), the executor checks: (1) the existing process/file whitelist, (2) the FalsePositiveMemory safe set, and (3) the prior knowledge safe hashes. If any check identifies the target as safe, the action is aborted, the result is tagged as false_positive=True with target_in_fp_memory=True, and the RL receives a penalty. Successful quarantine actions call fp_memory.record_quarantine_confirmation() to keep the knowledge loop closed.

**Why this priority**: Without FP protection, the RL brain can repeatedly act on files the user already declared safe, destroying trust.

**Independent Test**: Can be tested by marking a file safe via FalsePositiveMemory, then asking the ActionExecutor to quarantine it, and verifying the action is aborted with false_positive=True.

**Acceptance Scenarios**:

1. **Given** a file is in FalsePositiveMemory as safe, **When** the RL selects QUARANTINE_FILE for it, **Then** the ActionExecutor aborts, returns false_positive=True and target_in_fp_memory=True, and does not move the file.
2. **Given** a file is genuinely malicious, **When** the RL selects QUARANTINE_FILE, **Then** the file is quarantined via QuarantineVault, fp_memory.record_quarantine_confirmation() is called, and a QUARANTINE_CONFIRMED event is published.
3. **Given** the RL selects BLOCK_PROCESS, **When** the process binary hash is in the prior safe set, **Then** the block is aborted with false_positive=True.

---

### User Story 5 - Syscall Anomaly Monitoring via eBPF (Priority: P2)

A new eBPF-based syscall monitor detects anomalous syscall patterns in real time: PTRACE abuse (debugger injection), fork bombs (excessive forking), MEMFD malware (memfd_create for fileless execution), MMAP_EXEC (mapping memory as executable), and persona tricks (unauthorized UID/GID manipulation). Each detection produces a SYSCALL_ANOMALY event and updates the anomaly_score feature in the RL state vector. This provides deeper visibility into host-level threats that file scanning alone cannot catch.

**Why this priority**: Syscall monitoring covers an entire class of attacks (fileless malware, privilege escalation, process injection) that the existing scanner cannot detect. Important but not blocking for the core RL loop.

**Independent Test**: Can be tested by running the syscall monitor in isolation (requires root), triggering a known anomaly pattern (e.g., rapid fork()), and verifying a SYSCALL_ANOMALY event is published.

**Acceptance Scenarios**:

1. **Given** the syscall monitor is running as root, **When** a process calls ptrace(PTRACE_ATTACH) on another process, **Then** a SYSCALL_ANOMALY event is published with category "PTRACE_ABUSE" and the anomaly_score increases.
2. **Given** BCC is not installed, **When** the daemon starts, **Then** the syscall monitor logs a warning and degrades gracefully without crashing.
3. **Given** a process forks more than 100 times in 1 second, **When** the monitor observes this, **Then** a SYSCALL_ANOMALY event with category "FORK_BOMB" is published.

---

### User Story 6 - RL Model Visibility in TUI and CLI (Priority: P3)

The CyberPet TUI pet screen gains a new "Brain" panel displaying: RL model steps trained, last action taken with confidence percentage, average reward over last 100 steps, an action distribution bar chart, number of files in FP memory marked safe, and number of confirmed threats loaded from priors. The CLI gains new subcommands: `cyberpet model status` (show RL stats + FP impact), `cyberpet model reset` (delete model + clear priors), `cyberpet model info` (architecture + hyperparameters), `cyberpet fp list` (show FP memory contents), and `cyberpet fp clear` (clear FP memory with confirmation).

**Why this priority**: Visibility and management commands are important for trust and usability, but the RL brain can function without them initially.

**Independent Test**: Can be tested by starting the TUI after the RL engine is initialized and verifying the Brain panel renders RL stats. CLI commands can be tested independently by running each subcommand and checking output.

**Acceptance Scenarios**:

1. **Given** the RL engine has completed 500 training steps, **When** the user opens the TUI, **Then** the Brain panel shows "Steps: 500", a last action label, and an average reward value.
2. **Given** the user runs `cyberpet model status`, **Then** the CLI outputs RL stats including steps trained, FP memory size, and the RL explainer's FP impact summary.
3. **Given** the user runs `cyberpet model reset`, **Then** the saved model file and priors are deleted (with confirmation prompt), and the next daemon start creates a fresh model.
4. **Given** the user runs `cyberpet fp list`, **Then** a table of all files marked safe is displayed with their sha256, filepath, category, and date.

---

### User Story 7 - RL Decision Explainability (Priority: P3)

An RL explainer module provides human-readable explanations for RL decisions. When queried (via CLI `cyberpet model status` or TUI), it explains which state features drove the decision, what the action was, the confidence level, and how false-positive history is affecting RL behavior. For example: "FP memory has 8 safe files. RL avoided 3 repeat FPs this session. Current FP rate: 12% (above 10% threshold, model is being more conservative on quarantine actions)."

**Why this priority**: Explainability builds user trust but is not required for the RL brain to function.

**Independent Test**: Can be tested by calling the explainer's explain() method after an RL decision and verifying it returns a non-empty, human-readable string referencing the actual state features and action taken.

**Acceptance Scenarios**:

1. **Given** the RL engine just made a QUARANTINE_FILE decision, **When** the explainer is called, **Then** it returns a string explaining which features were elevated (e.g., "threat_score_t0 = 0.85, anomaly_score = 0.6") and why quarantine was chosen.
2. **Given** the FP rate is above 30%, **When** the explainer's explain_fp_impact() is called, **Then** it returns a message indicating the model is being more conservative on quarantine actions.

---

### Edge Cases

- What happens when the RL model file on disk becomes corrupted? → The system detects the load failure, logs a warning, creates a fresh model, and continues without crashing.
- How does the system handle running without root privileges? → eBPF monitors (exec, file, syscall) degrade gracefully; the RL brain still functions with reduced state features (anomaly_score stays at 0).
- What happens when the EventBus queue overflows with events? → The RL engine processes events at its own 30-second cadence; unprocessed events are integrated into cumulative state counters rather than individual event processing.
- What happens if PyTorch or stable-baselines3 fails to import? → The RL engine logs an error, publishes no RL_DECISION events, and the daemon continues with rule-based operation only.
- What happens during system shutdown if a training step is mid-execution? → The SIGTERM handler waits for the current step to complete (with a timeout), then saves the model.
- What happens if FP memory and scan history have conflicting data? → FP memory takes precedence — if a file is marked safe, the RL will not quarantine it regardless of scan history.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST collect a 44-dimensional state vector every 30 seconds, normalized to [0.0, 1.0] range, covering CPU/memory, process activity, network, filesystem, threat history, security events, time context, and scan quality metrics.
- **FR-002**: System MUST support 8 discrete RL actions: ALLOW, LOG_WARN, BLOCK_PROCESS, QUARANTINE_FILE, NETWORK_ISOLATE, RESTORE_FILE, TRIGGER_SCAN, ESCALATE_LOCKDOWN.
- **FR-003**: System MUST execute RL inference within 100ms on CPU hardware.
- **FR-004**: System MUST load prior knowledge from FalsePositiveMemory and ScanHistory databases at startup, before RL training begins.
- **FR-005**: System MUST adjust warmup period based on prior knowledge depth: 100 steps with 0 priors, 50 steps with 5+ confirmed threats, 25 steps with 20+ confirmed threats.
- **FR-006**: System MUST check FalsePositiveMemory before every blocking action (BLOCK_PROCESS, QUARANTINE_FILE, ESCALATE_LOCKDOWN) and abort if the target is known safe, assigning a -10 penalty.
- **FR-007**: System MUST persist the RL model to disk on clean shutdown (SIGTERM) and restore it on next startup.
- **FR-008**: System MUST save model checkpoints every 3600 training steps.
- **FR-009**: System MUST detect syscall anomalies (PTRACE_ABUSE, FORK_BOMB, MEMFD_MALWARE, MMAP_EXEC, PERSONA_TRICK) via eBPF and publish SYSCALL_ANOMALY events.
- **FR-010**: System MUST publish 6 new event types: RL_DECISION, SYSCALL_ANOMALY, LOCKDOWN_ACTIVATED, LOCKDOWN_DEACTIVATED, FP_MARKED_SAFE, QUARANTINE_CONFIRMED.
- **FR-011**: System MUST update the scan quality metrics (pkg_verified_ratio, fp_rate_recent) in the state vector on SCAN_COMPLETE events.
- **FR-012**: System MUST synchronize FP memory with the RL safe-file set in real time — when a user marks a file safe, the RL engine adds it to the in-memory safe set immediately via FP_MARKED_SAFE events.
- **FR-013**: System MUST degrade gracefully when RL dependencies (PyTorch, stable-baselines3) are unavailable — the daemon continues with rule-based operation only.
- **FR-014**: System MUST provide CLI commands for model management: `model status`, `model reset`, `model info`, `fp list`, `fp clear`.
- **FR-015**: System MUST display RL brain stats in the TUI (steps trained, last action, average reward, action distribution, FP memory size, loaded priors count).
- **FR-016**: System MUST run the RL model on CPU only (no GPU requirement).
- **FR-017**: System MUST record quarantine confirmations from RL actions back into FalsePositiveMemory to maintain the learning feedback loop.
- **FR-018**: System MUST share FalsePositiveMemory by reference between the RL engine, ActionExecutor, and FileScanner — all components use the same instance.

### Key Entities

- **State Vector**: 44-dimensional float32 array representing current system health. Groups: CPU/Memory (6), Process Activity (6), Network (5), File System (5), Threat History (8), Security Events (7), Time Context (5), Scan Quality (2).
- **RL Action**: One of 8 discrete actions the RL brain can select, each with specific execution semantics and reward implications.
- **Action Result**: Outcome of executing an RL action, including whether a threat was confirmed, whether it was a false positive, the target's FP memory status, the threat category, and a confidence scale.
- **Prior Knowledge**: Pre-loaded human decision data (safe hashes, threat hashes, safe paths, FP patterns by category/rule, quarantine statistics) used to bias the RL policy at startup.
- **Safe File Set**: In-memory set of (sha256, filepath) tuples from FP memory that trigger -5 reward penalty if the RL attempts blocking actions on them.
- **Syscall Anomaly**: A detected anomalous syscall pattern (ptrace abuse, fork bomb, memfd malware, mmap exec, persona trick) that updates the anomaly_score in the state vector.
- **RL Checkpoint**: Serialized PPO model state saved to disk, restorable across daemon restarts.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: RL inference completes in under 100ms per decision cycle on standard CPU hardware.
- **SC-002**: The system makes one autonomous threat decision every 30 seconds while the daemon is running.
- **SC-003**: When prior knowledge includes files previously marked safe, the RL brain produces zero repeat false positives on those files within the same session.
- **SC-004**: The RL brain bootstraps from prior knowledge and begins making informed decisions within the first 50 training steps (when prior data exists), versus 100 steps when starting from scratch.
- **SC-005**: Model checkpoint persistence ensures zero loss of training progress across planned daemon restarts.
- **SC-006**: Corrupted FP memory database or missing RL dependencies result in graceful degradation — the daemon stays operational with logged warnings, never crashes.
- **SC-007**: All 6 new event types are correctly published and receivable by any EventBus subscriber.
- **SC-008**: The false positive rate for RL-driven quarantine actions trends downward over 500+ training steps as the model learns from FP penalties.
- **SC-009**: CLI model management commands each complete within 2 seconds and return parseable output.
- **SC-010**: TUI Brain panel refreshes RL stats at the same interval as other dashboard panels without impacting UI responsiveness.

## Assumptions

- The host machine runs Linux with kernel 5.4+ (required for existing eBPF and fanotify features).
- PyTorch CPU-only wheel and stable-baselines3 are installable via pip on the target system.
- SQLite databases are stored on local filesystem with adequate write permissions (existing V2 pattern).
- The daemon runs as root (existing requirement for eBPF and fanotify).
- FalsePositiveMemory and ScanHistory databases already exist from V2; V3 reads from them without schema changes.
- The existing EventBus fan-out model (all subscribers receive all events) is adequate; RL will filter events internally.
- The `aiosqlite` dependency in requirements.txt is unused; all new modules follow the existing synchronous `sqlite3` pattern for consistency.
