"""CyberPet CLI — command-line interface.

Provides subcommands for daemon management, TUI launch, log tailing,
and shell hook installation.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import click  # type: ignore[import]
import psutil  # type: ignore[import]


@click.group()
def main() -> None:
    """CyberPet — a terminal-based cybersecurity daemon that behaves like a virtual pet."""
    pass


@main.command()
def start() -> None:
    """Start the CyberPet daemon in the background."""
    # Check root (needed for system paths)
    if os.getuid() != 0:
        click.echo("Error: Root privileges required to start CyberPet daemon", err=True)
        sys.exit(1)

    # Check if already running
    pid = _get_running_pid()
    if pid:
        click.echo(f"Error: CyberPet daemon is already running (PID: {pid})", err=True)
        sys.exit(1)

    # Daemonize via double-fork
    try:
        # First fork
        pid = os.fork()
        if pid > 0:
            # Parent — wait briefly for child to start
            time.sleep(0.5)
            child_pid = _get_running_pid()
            if child_pid:
                click.echo(f"CyberPet daemon started (PID: {child_pid})")
            else:
                click.echo("CyberPet daemon started")
            sys.exit(0)
    except OSError as exc:
        click.echo(f"Error: Failed to start daemon: {exc}", err=True)
        sys.exit(1)

    # Decouple from parent
    os.setsid()
    os.umask(0o077)

    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        sys.exit(1)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    devnull = open(os.devnull, "r")
    os.dup2(devnull.fileno(), sys.stdin.fileno())

    # Run the daemon
    import asyncio
    from cyberpet.daemon import CyberPetDaemon  # type: ignore[import]

    daemon = CyberPetDaemon()
    try:
        asyncio.run(daemon.start())
    except Exception:
        sys.exit(1)


@main.command()
def stop() -> None:
    """Stop the running CyberPet daemon."""
    pid = _get_running_pid()
    if not pid:
        click.echo("Error: CyberPet daemon is not running", err=True)
        sys.exit(1)

    try:
        # Send SIGTERM — pid is confirmed non-None by the check above
        assert pid is not None
        os.kill(pid, signal.SIGTERM)
        click.echo(f"Stopping CyberPet daemon (PID: {pid})...")

        # Wait up to 5 seconds for graceful shutdown
        for _ in range(50):
            if not psutil.pid_exists(pid):
                break
            time.sleep(0.1)
        else:
            # Force kill if still running
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass

        # Clean up stale PID file
        _cleanup_pid_file()
        click.echo("CyberPet daemon stopped")

    except ProcessLookupError:
        _cleanup_pid_file()
        click.echo("CyberPet daemon stopped (was not running)")
    except PermissionError:
        click.echo("Error: Permission denied. Try running with sudo.", err=True)
        sys.exit(1)


@main.command()
def status() -> None:
    """Check if the daemon is running and show basic stats."""
    pid = _get_running_pid()
    if not pid:
        click.echo("CyberPet daemon is not running")
        sys.exit(1)

    try:
        proc = psutil.Process(pid)
        uptime = time.time() - proc.create_time()
        uptime_str = _format_uptime(int(uptime))

        click.echo(f"CyberPet daemon is running (PID: {pid})")
        click.echo(f"  Uptime: {uptime_str}")
        click.echo(f"  CPU: {proc.cpu_percent(interval=0.1):.1f}%")
        click.echo(f"  Memory: {proc.memory_info().rss / 1024 / 1024:.1f} MB")
    except psutil.NoSuchProcess:
        _cleanup_pid_file()
        click.echo("CyberPet daemon is not running (stale PID file cleaned)")
        sys.exit(1)


@main.command()
def pet() -> None:
    """Launch the terminal pet UI (TUI).

    Automatically re-executes with sudo if not running as root,
    so the scanner can access system paths and /var/lib/cyberpet/.
    """
    import signal

    # Suppress threading shutdown traceback on Ctrl+C
    def _clean_exit(signum, frame):
        os._exit(0)

    signal.signal(signal.SIGINT, _clean_exit)

    if os.geteuid() != 0:
        print("[cyberpet] Starting with sudo for system access...")
        args = ["sudo", sys.executable, "-m", "cyberpet", "pet"] + sys.argv[2:]
        os.execvp("sudo", args)
        return  # pragma: no cover

    from cyberpet.daemon import start_ui  # type: ignore[import]
    start_ui()


@main.command()
def log() -> None:
    """Tail the main CyberPet log file."""
    from cyberpet.config import Config  # type: ignore[import]

    config = Config.load()
    log_path = config.general.get("log_path", "/var/log/cyberpet/")
    log_file = os.path.join(log_path, "cyberpet.log")

    if not os.path.exists(log_file):
        click.echo(f"Error: Log file not found at {log_file}", err=True)
        sys.exit(1)

    try:
        # Use tail -f for log tailing
        subprocess.run(["tail", "-f", log_file], check=False)
    except PermissionError:
        click.echo(f"Error: Permission denied reading {log_file}", err=True)
        sys.exit(1)
    except KeyboardInterrupt:
        pass


@main.group()
def hook() -> None:
    """Shell hook management commands."""
    pass


@hook.command("install")
def hook_install() -> None:
    """Print instructions for installing the shell hook."""
    click.echo("Installer already sets global hooks via /etc/profile.d and shell rc files.\n")
    click.echo("If you need manual setup, add the following line to your shell configuration:\n")
    click.echo("  For bash (~/.bashrc):")
    click.echo("    source /etc/cyberpet/shell_hook.sh\n")
    click.echo("  For zsh (~/.zshrc):")
    click.echo("    source /etc/cyberpet/shell_hook.sh\n")
    click.echo("Then reload your shell:")
    click.echo("    source ~/.bashrc    # or source ~/.zshrc")


# --- Helper functions ---

def _get_pid_file() -> str:
    """Get the PID file path from config."""
    try:
        from cyberpet.config import Config  # type: ignore[import]
        config = Config.load()
        return config.general.get("pid_file", "/var/run/cyberpet.pid")
    except Exception:
        return "/var/run/cyberpet.pid"


def _get_running_pid() -> int | None:
    """Get the PID of the running daemon, or None."""
    pid_file = _get_pid_file()
    if not os.path.exists(pid_file):
        return None
    try:
        with open(pid_file, "r") as f:
            pid = int(f.read().strip())
        if psutil.pid_exists(pid):
            return pid
        return None
    except (ValueError, OSError):
        return None


def _cleanup_pid_file() -> None:
    """Remove the PID file if it exists."""
    pid_file = _get_pid_file()
    try:
        if os.path.exists(pid_file):
            os.unlink(pid_file)
    except OSError:
        pass


def _format_uptime(seconds: int) -> str:
    """Format seconds into a human-readable uptime string."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        return f"{seconds // 60}m {seconds % 60}s"
    else:
        h = seconds // 3600
        m = (seconds % 3600) // 60
        return f"{h}h {m}m"


# ── V2 Scan Commands ──────────────────────────────────────────────


@main.group()
def scan() -> None:
    """Manage file scanning."""
    pass


@scan.command("quick")
def scan_quick() -> None:
    """Trigger a quick scan of high-risk locations."""
    trigger_file = "/var/run/cyberpet_scan_trigger"
    try:
        with open(trigger_file, "w") as f:
            f.write("quick")
        click.echo("Quick scan triggered")
    except PermissionError:
        click.echo(
            "Error: Permission denied writing scan trigger.\n"
            "The daemon creates this file on startup — make sure the daemon is running:\n"
            "  sudo systemctl start cyberpet",
            err=True,
        )
        sys.exit(1)
    except OSError as exc:
        click.echo(f"Error: Failed to trigger scan: {exc}", err=True)
        sys.exit(1)


@scan.command("full")
def scan_full() -> None:
    """Trigger a full filesystem scan."""
    trigger_file = "/var/run/cyberpet_scan_trigger"
    try:
        with open(trigger_file, "w") as f:
            f.write("full")
        click.echo("Full scan triggered")
    except PermissionError:
        click.echo(
            "Error: Permission denied writing scan trigger.\n"
            "The daemon creates this file on startup — make sure the daemon is running:\n"
            "  sudo systemctl start cyberpet",
            err=True,
        )
        sys.exit(1)
    except OSError as exc:
        click.echo(f"Error: Failed to trigger scan: {exc}", err=True)
        sys.exit(1)


# ── V2 Quarantine Commands ────────────────────────────────────────


@main.group()
def quarantine() -> None:
    """Manage quarantined files."""
    pass


@quarantine.command("list")
def quarantine_list() -> None:
    """List all quarantined files."""
    import asyncio
    from cyberpet.config import Config
    from cyberpet.events import EventBus
    from cyberpet.quarantine import QuarantineVault

    config = Config.load()
    vault_path = config.quarantine.get("vault_path", "/var/lib/cyberpet/quarantine/")
    bus = EventBus()
    vault = QuarantineVault(bus, vault_path)

    records = asyncio.run(vault.list_quarantined())
    vault.close()

    if not records:
        click.echo("No quarantined files")
        return

    # Table header
    click.echo(f"{'ID':<10} {'Original Path':<40} {'Category':<18} {'Score':<6} {'Date':<20} {'Status':<12}")
    click.echo("─" * 106)
    for r in records:
        qid = r.quarantine_id[:8]
        path = r.original_path[:38] + ".." if len(r.original_path) > 40 else r.original_path
        date = r.quarantine_time[:19]
        click.echo(f"{qid:<10} {path:<40} {r.malware_name:<18} {r.threat_score:<6} {date:<20} {r.status:<12}")


@quarantine.command("restore")
@click.argument("quarantine_id")
def quarantine_restore(quarantine_id: str) -> None:
    """Restore a quarantined file to its original location."""
    import asyncio
    from cyberpet.config import Config
    from cyberpet.events import EventBus
    from cyberpet.quarantine import QuarantineVault

    config = Config.load()
    vault_path = config.quarantine.get("vault_path", "/var/lib/cyberpet/quarantine/")
    bus = EventBus()
    vault = QuarantineVault(bus, vault_path)

    restored = asyncio.run(vault.restore_file(quarantine_id))
    vault.close()

    if restored:
        click.echo(f"Restored: {quarantine_id}")
    else:
        click.echo(f"Error: Could not restore '{quarantine_id}' — not found or already restored", err=True)
        sys.exit(1)


@quarantine.command("delete")
@click.argument("quarantine_id")
def quarantine_delete(quarantine_id: str) -> None:
    """Permanently delete a quarantined file."""
    import asyncio
    from cyberpet.config import Config
    from cyberpet.events import EventBus
    from cyberpet.quarantine import QuarantineVault

    config = Config.load()
    vault_path = config.quarantine.get("vault_path", "/var/lib/cyberpet/quarantine/")
    bus = EventBus()
    vault = QuarantineVault(bus, vault_path)

    deleted = asyncio.run(vault.delete_quarantined(quarantine_id))
    vault.close()

    if deleted:
        click.echo(f"Deleted: {quarantine_id}")
    else:
        click.echo(f"Error: Could not delete '{quarantine_id}' — not found or already deleted", err=True)
        sys.exit(1)


# ── V3 RL Model Commands ─────────────────────────────────────────

@main.group()
def model():
    """Manage the RL brain model."""
    pass


@model.command("status")
def model_status():
    """Show RL brain status and recent activity."""
    try:
        from cyberpet.config import Config
        config = Config()
        rl_cfg = config.rl
        model_dir = rl_cfg.get("model_path", "/var/lib/cyberpet/models/")
        model_file = os.path.join(model_dir, "cyberpet_ppo.zip")

        click.echo("═══ CyberPet RL Brain Status ═══")
        click.echo()

        if os.path.exists(model_file):
            stat = os.stat(model_file)
            size_mb = stat.st_size / (1024 * 1024)
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(stat.st_mtime))
            click.echo(f"  Model:    {model_file}")
            click.echo(f"  Size:     {size_mb:.1f} MB")
            click.echo(f"  Updated:  {mtime}")
        else:
            click.echo("  Model:    Not found (will be created on first run)")

        click.echo()

        # Try to read state from shared state file
        state_file = os.path.join(model_dir, "rl_state.json")
        if os.path.exists(state_file):
            import json
            with open(state_file) as f:
                state = json.load(f)
            click.echo(f"  Steps:    {state.get('total_steps', 0)}")
            click.echo(f"  Reward:   {state.get('avg_reward', 0.0):.3f}")
            click.echo(f"  State:    {state.get('rl_state', 'UNKNOWN')}")
            click.echo(f"  Action:   {state.get('last_action', 'N/A')}")
        else:
            click.echo("  State:    No live state available (daemon may not be running)")

        click.echo()

        # Explainer integration (T041)
        try:
            from cyberpet.rl_explainer import RLExplainer
            explainer = RLExplainer()
            fp_analysis = explainer.explain_fp_impact()
            if fp_analysis:
                click.echo("  FP Analysis:")
                click.echo(f"    {fp_analysis}")
        except Exception:
            pass

        click.echo()
        click.echo(f"  Enabled:  {rl_cfg.get('enabled', False)}")
        click.echo(f"  Interval: {rl_cfg.get('decision_interval_seconds', 30)}s")

    except Exception as exc:
        click.echo(f"Error reading RL status: {exc}", err=True)
        sys.exit(1)


@model.command("reset")
@click.confirmation_option(
    prompt="This will delete the trained RL model. Are you sure?"
)
def model_reset():
    """Delete the trained RL model (forces fresh start)."""
    try:
        from cyberpet.config import Config
        config = Config()
        model_dir = config.rl.get("model_path", "/var/lib/cyberpet/models/")
        model_file = os.path.join(model_dir, "cyberpet_ppo.zip")

        if os.path.exists(model_file):
            os.remove(model_file)
            click.echo(f"Deleted: {model_file}")
            click.echo("A fresh model will be created on next daemon start.")
        else:
            click.echo("No model file found — nothing to reset.")

    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


@model.command("info")
def model_info():
    """Display PPO architecture and hyperparameters."""
    click.echo("═══ CyberPet RL Brain Configuration ═══")
    click.echo()
    click.echo("  Algorithm:     PPO (Proximal Policy Optimization)")
    click.echo("  Policy:        MlpPolicy [256, 256]")
    click.echo("  Activation:    ReLU")
    click.echo("  Learning Rate: 3e-4")
    click.echo("  Batch Size:    64")
    click.echo("  N Steps:       512")
    click.echo("  Gamma:         0.99")
    click.echo("  GAE Lambda:    0.95")
    click.echo("  Clip Range:    0.2")
    click.echo("  Entropy Coef:  0.01")
    click.echo("  Device:        CPU")
    click.echo()
    click.echo("  Observation:   Box(0, 1, shape=(44,))")
    click.echo("  Action Space:  Discrete(8)")
    click.echo("  Actions:")
    actions = [
        "0: ALLOW", "1: LOG_WARN", "2: BLOCK_PROCESS", "3: QUARANTINE_FILE",
        "4: NETWORK_ISOLATE", "5: RESTORE_FILE", "6: TRIGGER_SCAN",
        "7: ESCALATE_LOCKDOWN",
    ]
    for a in actions:
        click.echo(f"    {a}")


# ── V3 FP Memory Commands ────────────────────────────────────────

@main.group()
def fp():
    """Manage false positive memory."""
    pass


@fp.command("list")
def fp_list():
    """List all entries in false positive memory."""
    try:
        from cyberpet.false_positive_memory import FalsePositiveMemory
        mem = FalsePositiveMemory()
        entries = mem.get_all_false_positives()

        if not entries:
            click.echo("No entries in false positive memory.")
            return

        click.echo(f"{'SHA256':<16} {'File Path':<50} {'Added':<20}")
        click.echo("─" * 86)
        for entry in entries:
            sha = entry.get("sha256", "")[:16]
            path = entry.get("filepath", "")[:50]
            added = entry.get("added_at", "")[:20]
            click.echo(f"{sha:<16} {path:<50} {added:<20}")
        click.echo(f"\nTotal: {len(entries)} entries")

    except Exception as exc:
        click.echo(f"Error reading FP memory: {exc}", err=True)
        sys.exit(1)


@fp.command("clear")
@click.confirmation_option(
    prompt="This will clear all false positive entries. Are you sure?"
)
def fp_clear():
    """Clear all entries from false positive memory."""
    try:
        from cyberpet.false_positive_memory import FalsePositiveMemory
        mem = FalsePositiveMemory()
        count = mem.clear_all()
        click.echo(f"Cleared {count} entries from false positive memory.")
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
