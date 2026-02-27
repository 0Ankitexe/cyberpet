# Quickstart: RL Brain for CyberPet V3

**Branch**: `001-rl-brain` | **Date**: 2026-02-27

## Prerequisites

- Python 3.12+
- Existing CyberPet V2 installed and functional
- Root access (for eBPF monitors)

## Install New Dependencies

```bash
pip install stable-baselines3[extra]==2.3.2 \
            torch==2.2.2 --index-url https://download.pytorch.org/whl/cpu \
            gymnasium==0.29.1 \
            numpy==1.26.4 \
            shimmy==1.3.0
```

## New Files Overview

| File | Purpose |
|------|---------|
| `cyberpet/rl_prior.py` | Load human decisions from FP memory and scan history |
| `cyberpet/state_collector.py` | Build 44-feature state vector from system metrics + events |
| `cyberpet/rl_env.py` | Gymnasium environment wrapping CyberPet |
| `cyberpet/action_executor.py` | Execute RL actions with FP protection |
| `cyberpet/rl_engine.py` | PPO training loop + model persistence |
| `cyberpet/rl_explainer.py` | Human-readable RL decision explanations |
| `cyberpet/ebpf/syscall_monitor.py` | eBPF syscall anomaly detection |

## Modified Files

| File | Change |
|------|--------|
| `cyberpet/events.py` | Add 6 new EventTypes |
| `cyberpet/daemon.py` | Initialize RL components, start rl_loop task |
| `cyberpet/scan_scheduler.py` | Accept fp_memory parameter |
| `cyberpet/ui/pet.py` | Add Brain panel to TUI |
| `cyberpet/cli.py` | Add `model` and `fp` subcommands |
| `requirements.txt` | Add 5 new packages |
| `config/default_config.toml` | Add `[rl]` config section |

## Verify Installation

```bash
# Check RL dependencies
python3 -c "import stable_baselines3; import gymnasium; import torch; print('OK')"

# Run existing tests (should still pass)
python3 -m pytest tests/ -v

# Run new V3 tests
python3 -m pytest tests/test_rl_prior.py tests/test_state_collector.py tests/test_rl_env.py -v

# Start daemon with RL (as root)
sudo cyberpet start

# Check RL status
cyberpet model status
```

## Config

Add to `config/default_config.toml` or `/etc/cyberpet/config.toml`:

```toml
[rl]
enabled = true
model_path = "/var/lib/cyberpet/models/"
decision_interval_seconds = 30
checkpoint_interval_steps = 3600
warmup_steps_no_priors = 100
warmup_steps_with_priors = 50
warmup_steps_deep_priors = 25
deep_prior_threshold = 20
```
