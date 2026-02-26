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


if __name__ == "__main__":
    main()
