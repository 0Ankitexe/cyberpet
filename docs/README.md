# CyberPet — Full Technical Documentation

> Complete internals reference for every system in CyberPet V3.
> Last updated: 2026-02-28

---

## Documents

| File | Covers |
|------|--------|
| [01_architecture.md](01_architecture.md) | System overview, module map, daemon lifecycle |
| [02_rl_brain.md](02_rl_brain.md) | How the RL brain learns — observation loop, PPO, rewards, safety |
| [03_scanner.md](03_scanner.md) | File scanner, YARA rules, hash DB, scan pipeline |
| [04_shell_hook.md](04_shell_hook.md) | Shell hook, command scoring, terminal guard |
| [05_quarantine.md](05_quarantine.md) | Quarantine vault, false positive memory |
| [06_ui.md](06_ui.md) | TUI pet widget, brain screen, scan screen |
| [07_config.md](07_config.md) | Full configuration reference |
| [08_cli.md](08_cli.md) | Complete CLI command reference |

---

> The original `doc.md` at the project root focuses exclusively on the RL brain.
> These docs cover the entire codebase.
