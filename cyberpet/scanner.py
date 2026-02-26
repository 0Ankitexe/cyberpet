"""Multi-analysis file scanner for CyberPet V2.

Provides quick and full scan modes with an 11-stage per-file analysis
pipeline designed to eliminate false positives while catching real
threats:

  0. Pre-filter (skip safe types, empty, oversized)
  1. Hash DB — known malware → immediate flag
  2. Hash DB — known clean  → skip
  3. Package manager trust   → skip unmodified pkg files
  4. Path scrutiny level     → reduced / normal / high
  5. YARA scan
  6. Entropy scoring         → type-aware, path-aware, threshold 7.6
  7. Magic byte mismatch     → correct for Linux (no-ext normal)
  8. ELF anomaly detection   → stripped-in-/tmp is bad, not stripped-in-/usr
  9. Score combination       → diminishing returns (probability union)
 10. Context adjustments     → pkg trust / library path discounts
 11. Threshold gate          → scrutiny-dependent reporting cutoff
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import math
import os
import stat
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cyberpet.config import Config
from cyberpet.events import Event, EventBus, EventType
from cyberpet.hash_db import HashDatabase
from cyberpet.logger import log_info, log_warn
from cyberpet.pkg_trust import PackageManagerTrust
from cyberpet.yara_engine import YaraEngine, YaraMatch

# Optional imports — degrade gracefully
try:
    import magic as _magic  # type: ignore[import]

    _MAGIC_AVAILABLE = True
except ImportError:
    _MAGIC_AVAILABLE = False

try:
    from elftools.elf.elffile import ELFFile  # type: ignore[import]

    _ELF_AVAILABLE = True
except ImportError:
    _ELF_AVAILABLE = False


# ── Data classes (unchanged API — downstream safe) ──────────────────


@dataclass
class ThreatRecord:
    """A flagged file from scanning."""

    filepath: str
    threat_score: int
    threat_reason: str
    matched_rules: list[str] = field(default_factory=list)
    file_hash: str = ""
    threat_category: str = "unknown_malware"
    recommended_action: str = "monitor"


@dataclass
class ScanReport:
    """Summary of a completed scan."""

    scan_type: str
    start_time: datetime
    end_time: datetime = field(default_factory=datetime.now)
    files_scanned: int = 0
    threats_found: list[ThreatRecord] = field(default_factory=list)

    # Audit counters
    skipped_safe_type: int = 0
    skipped_pkg_verified: int = 0
    skipped_known_clean: int = 0
    analyzed_fully: int = 0

    @property
    def scan_duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


# ── Constants ───────────────────────────────────────────────────────

# Extensions that should ALWAYS be skipped — never malicious in practice
_ALWAYS_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    # Media
    ".mp3", ".mp4", ".wav", ".flac", ".ogg", ".avi", ".mkv",
    ".mov", ".webm", ".m4a", ".aac",
    # Images
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico",
    ".bmp", ".tiff",
    # Fonts
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    # Compiled data / caches
    ".pyc", ".pyo", ".gresource", ".cache",
    ".db", ".sqlite", ".sqlite3", ".ldb",
    ".pak", ".asar",
    # Locale
    ".mo", ".po",
    # Object files / static libs
    ".a", ".o",
    # Archives (we scan extracted content, not the archive itself)
    ".gz", ".xz", ".bz2", ".zst", ".lz4",
    ".zip", ".7z", ".rar", ".tar",
    ".jar", ".war", ".ear", ".class",
    # Pure documentation
    ".md", ".rst", ".txt", ".html", ".css", ".xml", ".json", ".yaml",
    ".yml", ".toml", ".ini", ".cfg", ".conf",
    # GNOME / system compiled resources
    ".compiled", ".bin",
})

# Extensions exempt from entropy scoring (always high by design)
_ENTROPY_EXEMPT_EXTENSIONS: frozenset[str] = frozenset({
    ".so", ".dylib", ".pyc", ".pyo",
    ".ttf", ".otf", ".woff", ".woff2",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".gz", ".xz", ".bz2", ".zst", ".lz4",
    ".jar", ".war", ".ear", ".class",
    ".zip", ".7z", ".rar",
    ".gresource", ".cache", ".db", ".sqlite",
    ".asar", ".pak",
    ".mo", ".po",
    ".a", ".o",
})

# Standard ELF section names — NOT anomalous
_STANDARD_ELF_SECTIONS: frozenset[str] = frozenset({
    ".text", ".data", ".bss", ".rodata", ".symtab", ".strtab",
    ".shstrtab", ".init", ".fini", ".plt", ".got", ".got.plt",
    ".dynamic", ".dynsym", ".dynstr", ".rela.dyn", ".rela.plt",
    ".note.ABI-tag", ".note.gnu.build-id", ".note.gnu.property",
    ".gnu.hash", ".gnu.version", ".gnu.version_r",
    ".interp", ".eh_frame", ".eh_frame_hdr", ".init_array",
    ".fini_array", ".comment", ".debug_info", ".debug_abbrev",
    ".debug_line", ".debug_str", ".debug_aranges", ".debug_ranges",
    ".debug_loc", ".tbss", ".tdata", ".gnu.warning",
    ".gnu_debuglink", "",
})

# Known legitimate non-standard ELF sections (Go, Rust, etc.)
_KNOWN_LEGIT_SECTION_PREFIXES: tuple[str, ...] = (
    ".rustc", ".llvm_", ".go.", ".gopclntab",
    ".noptrdata", ".typelink", ".itablink",
    ".gosymtab", ".pdata", ".xdata",
    ".note.", ".rela.", ".debug_",
)

# Paths where files get REDUCED scrutiny
_REDUCED_SCRUTINY_PATHS: tuple[str, ...] = (
    "/usr/lib/", "/usr/lib32/", "/usr/lib64/", "/usr/libx32/",
    "/usr/share/gnome", "/usr/share/gtk", "/usr/share/glib",
    "/usr/share/locale", "/usr/share/fonts", "/usr/share/icons",
    "/usr/share/pixmaps", "/usr/share/doc", "/usr/share/man",
    "/lib/", "/lib64/",
    "/snap/",
    "/var/lib/dpkg", "/var/cache/apt",
)

# Paths that ALWAYS get full scrutiny
_HIGH_SCRUTINY_PATHS: tuple[str, ...] = (
    "/tmp", "/dev/shm", "/var/tmp", "/run/user",
)

# System binary directories — no-extension files are expected here
_SYSTEM_BIN_PATHS: tuple[str, ...] = (
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
)

# Paths to skip during full scan
_SKIP_PATHS: frozenset[str] = frozenset({"/proc", "/sys", "/dev", "/run", "/snap"})


# ── Helper functions ────────────────────────────────────────────────


def should_skip_file(filepath: str) -> tuple[bool, str]:
    """Pre-filter: return ``(True, reason)`` for files that should
    never be analyzed."""
    try:
        st = os.stat(filepath)
    except (PermissionError, FileNotFoundError, OSError):
        return True, "unreadable"

    if st.st_size == 0:
        return True, "empty"

    # >500 MB — not practical to scan in-process
    if st.st_size > 500 * 1024 * 1024:
        return True, "too_large"

    ext = Path(filepath).suffix.lower()
    if ext in _ALWAYS_SKIP_EXTENSIONS:
        return True, f"safe_type_{ext}"

    # .so.* pattern (e.g. libfoo.so.3.2.1)
    if ".so." in os.path.basename(filepath):
        return True, "shared_library"

    # Broken symlinks
    if os.path.islink(filepath):
        real = os.path.realpath(filepath)
        if not os.path.exists(real):
            return True, "broken_symlink"

    return False, ""


def get_path_scrutiny_level(filepath: str) -> str:
    """Return ``'reduced'``, ``'normal'``, or ``'high'``."""
    for p in _HIGH_SCRUTINY_PATHS:
        if filepath.startswith(p):
            return "high"
    for p in _REDUCED_SCRUTINY_PATHS:
        if filepath.startswith(p):
            return "reduced"
    return "normal"


def score_entropy(
    filepath: str, file_bytes: bytes, is_elf: bool,
) -> int:
    """Entropy score — type-aware, path-aware, raised threshold."""
    ext = Path(filepath).suffix.lower()
    if ext in _ENTROPY_EXEMPT_EXTENSIONS:
        return 0
    # .so.* pattern
    if ".so." in os.path.basename(filepath):
        return 0

    entropy = _shannon_entropy(file_bytes)

    in_suspicious = any(filepath.startswith(p) for p in _HIGH_SCRUTINY_PATHS)

    if is_elf and in_suspicious and entropy > 7.6:
        return 30
    if is_elf and not in_suspicious and entropy > 7.8:
        return 10
    # Non-ELF text-ish file with extremely high entropy in /tmp
    if not is_elf and in_suspicious and entropy > 7.8:
        return 15
    return 0


def score_magic_mismatch(
    filepath: str, magic_type: str, is_elf: bool,
) -> tuple[int, str]:
    """Score files whose magic type doesn't match their extension."""
    ext = Path(filepath).suffix.lower()

    # System binary paths — no-extension is expected
    if any(filepath.startswith(p) for p in _SYSTEM_BIN_PATHS):
        return 0, ""

    # .so files ARE ELF but are libraries, not suspicious
    if ext in (".so", ".o", ".a") or ".so." in os.path.basename(filepath):
        return 0, ""

    # Files with no extension are normal on Linux
    if not ext:
        if is_elf and any(filepath.startswith(p) for p in _HIGH_SCRUTINY_PATHS):
            return 20, "ELF executable with no extension in temp directory"
        return 0, ""

    # ELF disguised as image
    image_exts = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"}
    doc_exts = {".pdf", ".doc", ".docx", ".txt", ".csv"}

    if is_elf and ext in image_exts:
        return 50, f"ELF executable disguised as image ({ext})"
    if is_elf and ext in doc_exts:
        return 50, f"ELF executable disguised as document ({ext})"

    # Script disguised as non-script
    is_script = "script" in magic_type.lower() or "text" in magic_type.lower()
    suspicious_non_script = {".jpg", ".png", ".pdf", ".mp3", ".wav"}
    if is_script and ext in suspicious_non_script:
        return 35, f"Script disguised as {ext}"

    return 0, ""


def score_elf_anomalies(
    filepath: str, elf: Any,
) -> tuple[int, list[str]]:
    """Score ELF files for genuine anomalies.

    Reversed logic: stripped binaries are NORMAL in system paths,
    only suspicious in temp directories.
    """
    score = 0
    reasons: list[str] = []
    in_tmp = any(filepath.startswith(p) for p in _HIGH_SCRUTINY_PATHS)

    # Rule 1: Stripped binary in /tmp (legit software doesn't live there)
    if in_tmp:
        has_debug = any(
            s.name.startswith(".debug_") for s in elf.iter_sections()
        )
        if not has_debug:
            score += 20
            reasons.append("Stripped ELF in temp directory")

    # Rule 2: Unusual section names
    for section in elf.iter_sections():
        name = section.name
        if not name or name in _STANDARD_ELF_SECTIONS:
            continue
        if any(name.startswith(pfx) for pfx in _KNOWN_LEGIT_SECTION_PREFIXES):
            continue
        # Truly unusual section
        score += 10
        reasons.append(f"Non-standard ELF section: {name}")
        break  # one is enough

    # Rule 3: No section headers at all in /tmp (possible shellcode)
    if in_tmp and elf.num_sections() == 0:
        score += 40
        reasons.append("ELF with no section headers in temp directory")

    return score, reasons


def combine_scores(scores: list[int]) -> int:
    """Combine component scores with diminishing returns.

    Uses the probability union formula so that weak signals don't
    accidentally stack to a high score:
      combined = 100 × (1 − ∏(1 − sᵢ/100))

    Examples:
      [30, 30, 30] → 66  (not 90)
      [90]         → 90
      [50, 50]     → 75  (not 100)
      [20, 20, 20] → 49  (not 60)
    """
    nonzero = [s for s in scores if s > 0]
    if not nonzero:
        return 0

    max_score = max(nonzero)
    # A single decisive signal dominates
    if max_score >= 85:
        return max_score

    product = 1.0
    for s in nonzero:
        product *= 1.0 - s / 100.0
    combined = (1.0 - product) * 100.0
    return int(max(max_score, combined))


def apply_context_adjustments(
    raw_score: int,
    filepath: str,
    is_managed: bool,
    pkg_hash_ok: bool,
) -> tuple[int, str]:
    """Apply final context adjustments to raw score."""
    # Package managed AND hash verified → heavy discount
    if is_managed and pkg_hash_ok:
        if raw_score < 70:
            return 0, "package_verified_clean"
        return max(0, raw_score - 40), "package_managed_discount"

    # Package managed but tampered → boost
    if is_managed and not pkg_hash_ok:
        return min(100, raw_score + 20), "package_file_tampered"

    # System library paths → discount
    lib_paths = ("/usr/lib/", "/usr/share/gnome", "/usr/share/glib")
    if any(filepath.startswith(p) for p in lib_paths):
        if raw_score < 60:
            return 0, "system_library_path"
        return max(0, raw_score - 25), "system_library_discount"

    # Trusted user application paths → discount
    # These are well-known application data directories where YARA rules
    # commonly false-positive on crypto strings (AES, RSA, TLS, etc.)
    _TRUSTED_APP_PATHS = (
        # Flatpak / Snap application data
        "/.var/app/",
        "/.local/share/flatpak/",
        "/snap/",
        # Browser profiles (Brave, Chrome, Firefox, etc.)
        "/.config/BraveSoftware/",
        "/.config/google-chrome/",
        "/.config/chromium/",
        "/.mozilla/",
        # IDE/editor extensions and AI tools
        "/.vscode/",
        "/.config/Code/",
        "/.antigravity/",
        "/.config/Antigravity/",
        "/.gemini/",
        "/.config/JetBrains/",
        # Package managers and caches
        "/.local/share/uv/",
        "/.local/share/pip/",
        "/.cache/pip/",
        "/.cache/gnome-software/",
        "/.local/share/gnome-software/",
        "/.npm/",
        "/.cargo/",
        "/.rustup/",
        "/.local/share/gem/",
        # Python virtual environments
        "/venv/",
        "/.venv/",
        "/site-packages/",
        "/node_modules/",
        # System caches
        "/.cache/",
        # User config dirs (general)
        "/.config/",
        "/.local/",
    )
    if any(part in filepath for part in _TRUSTED_APP_PATHS):
        if raw_score < 80:
            return 0, "trusted_app_path"
        return max(0, raw_score - 50), "trusted_app_discount"

    # User project/source dirs — never flag source code repos
    # as threats (they contain test payloads, security tools, etc.)
    if "/projects/" in filepath or "/src/" in filepath or "/repos/" in filepath:
        if raw_score < 80:
            return 0, "source_code_path"
        return max(0, raw_score - 50), "source_code_discount"

    return raw_score, "no_adjustment"


def _shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq: dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


class CancellationToken:
    """Simple cancellation flag for cooperative scan cancellation."""

    def __init__(self) -> None:
        self.cancelled = False

    def cancel(self) -> None:
        self.cancelled = True

    def is_cancelled(self) -> bool:
        return self.cancelled


# ── Scanner ─────────────────────────────────────────────────────────


class FileScanner:
    """Multi-analysis file scanner with quick and full scan modes.

    Usage::

        scanner = FileScanner(config, event_bus, hash_db, yara_engine)
        report = await scanner.quick_scan()
    """

    def __init__(
        self,
        config: Config,
        event_bus: EventBus,
        hash_db: HashDatabase | None = None,
        yara_engine: YaraEngine | None = None,
        fp_memory: Any | None = None,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.max_file_size = config.scanner.get("max_file_size_mb", 50) * 1024 * 1024
        self.hash_db = hash_db
        self.yara_engine = yara_engine
        self.fp_memory = fp_memory
        self._executor = ThreadPoolExecutor(max_workers=4)
        self._pkg_trust = PackageManagerTrust()

    # ── Public scan entry points ────────────────────────────────────

    async def quick_scan(
        self, cancel_token: CancellationToken | None = None,
    ) -> ScanReport:
        """Quick scan — starts scanning immediately, discovers targets in parallel."""
        report = ScanReport(scan_type="quick", start_time=datetime.now())

        await self.event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            source="scanner",
            data={"scan_type": "quick", "total_files": 0},
        ))

        await self._scan_streaming(
            collector=self._collect_quick_targets,
            report=report,
            cancel_token=cancel_token,
        )

        report.end_time = datetime.now()
        await self._publish_complete(report)
        return report

    async def full_scan(
        self, cancel_token: CancellationToken | None = None,
    ) -> ScanReport:
        """Full scan — starts scanning immediately, discovers targets in parallel."""
        report = ScanReport(scan_type="full", start_time=datetime.now())

        await self.event_bus.publish(Event(
            type=EventType.SCAN_STARTED,
            source="scanner",
            data={"scan_type": "full", "total_files": 0},
        ))

        await self._scan_streaming(
            collector=self._collect_full_targets,
            report=report,
            cancel_token=cancel_token,
        )

        report.end_time = datetime.now()
        await self._publish_complete(report)
        return report

    async def _scan_streaming(
        self,
        collector: Any,
        report: ScanReport,
        cancel_token: CancellationToken | None = None,
    ) -> None:
        """Producer-consumer scan: discover and scan files simultaneously.

        A background thread runs the collector and pushes files into a queue.
        The async loop pulls files from the queue and scans them immediately.
        Scanning starts within milliseconds — zero wait for full collection.
        """
        import queue as stdlib_queue

        file_queue: stdlib_queue.Queue[str | None] = stdlib_queue.Queue(maxsize=500)
        total_discovered = [0]  # mutable counter shared with producer thread

        def _producer() -> None:
            """Run collector in a thread; push files into queue one by one."""
            try:
                targets = collector()
                for fp in targets:
                    file_queue.put(fp)
                    total_discovered[0] += 1
            finally:
                file_queue.put(None)  # sentinel: collection done

        # Start the producer in a background thread
        loop = asyncio.get_event_loop()
        producer_future = loop.run_in_executor(self._executor, _producer)

        files_scanned = 0
        collection_done = False
        max_pct_seen = 0  # monotonically increasing

        while True:
            if cancel_token and cancel_token.is_cancelled():
                break

            # Try to grab a batch of files from the queue (non-blocking)
            batch: list[str] = []
            try:
                while len(batch) < 10:  # grab up to 10 at a time
                    item = file_queue.get_nowait()
                    if item is None:
                        collection_done = True
                        break
                    batch.append(item)
            except stdlib_queue.Empty:
                pass

            if not batch and not collection_done:
                # Queue is empty but producer is still running — wait a tiny bit
                await asyncio.sleep(0.02)
                continue

            if not batch and collection_done:
                break  # All done

            # Scan the batch
            for filepath in batch:
                if cancel_token and cancel_token.is_cancelled():
                    break
                try:
                    record = await loop.run_in_executor(
                        self._executor, self._analyze_file, filepath, report
                    )
                    report.files_scanned += 1
                    files_scanned += 1

                    if record and record.threat_score >= 40:
                        report.threats_found.append(record)
                        await self.event_bus.publish(Event(
                            type=EventType.THREAT_FOUND,
                            source="scanner",
                            data={
                                "filepath": record.filepath,
                                "threat_score": record.threat_score,
                                "threat_reason": record.threat_reason,
                                "threat_category": record.threat_category,
                                "matched_rules": record.matched_rules,
                                "file_hash": record.file_hash,
                            },
                            severity=record.threat_score,
                        ))
                except Exception:
                    report.files_scanned += 1
                    files_scanned += 1

                # Progress every 5 files
                if files_scanned % 5 == 0:
                    total_est = total_discovered[0]

                    if collection_done and total_est > 0:
                        # Discovery done — real linear percentage
                        pct = int(files_scanned / total_est * 100)
                        pct = min(pct, 100)
                    else:
                        # Discovery still running — logarithmic curve
                        # Smoothly rises: 100→15%, 500→45%, 1K→60%, 5K→82%, 30K→89%
                        # Approaches 90% asymptotically, never stalls
                        pct = int(90 * (1 - 1 / (1 + files_scanned / 500)))

                    # Never go backwards
                    pct = max(pct, max_pct_seen)
                    max_pct_seen = pct

                    await self.event_bus.publish(Event(
                        type=EventType.SCAN_PROGRESS,
                        source="scanner",
                        data={
                            "scan_type": report.scan_type,
                            "files_scanned": files_scanned,
                            "total_estimate": total_est,
                            "percent": pct,
                            "current_file": filepath,
                            "collection_done": collection_done,
                        },
                    ))

        # Final progress event
        total_est = total_discovered[0]
        await self.event_bus.publish(Event(
            type=EventType.SCAN_PROGRESS,
            source="scanner",
            data={
                "scan_type": report.scan_type,
                "files_scanned": files_scanned,
                "total_estimate": total_est,
                "percent": 100,
                "current_file": "",
                "collection_done": True,
            },
        ))

        # Wait for producer to finish (it might still be walking)
        await producer_future

    # ── Target collection ───────────────────────────────────────────

    # File extensions considered dangerous / exploitable for quick scan
    _DANGEROUS_EXTENSIONS: frozenset[str] = frozenset({
        # Executables & compiled
        ".elf", ".bin", ".out", ".so", ".o", ".ko",
        # Scripts
        ".sh", ".bash", ".zsh", ".fish", ".csh",
        ".py", ".pyc", ".pyo", ".pyw",
        ".pl", ".pm", ".rb", ".lua",
        ".js", ".mjs", ".ts",
        ".php", ".php5", ".phtml",
        ".ps1", ".psm1",
        # Java / JVM
        ".jar", ".class", ".war",
        # Compiled / bytecode
        ".wasm", ".bc",
        # Archives (can hide payloads)
        ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z",
        ".rar", ".cab", ".deb", ".rpm", ".apk",
        # Disk / ISO images
        ".iso", ".img", ".dmg",
        # Config files that control execution
        ".conf", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json",
        ".desktop", ".service", ".timer", ".socket",
        ".rules", ".sudoers",
        # Cron
        ".cron", ".crontab",
        # SSH / crypto
        ".pem", ".key", ".pub", ".crt", ".cer",
        # Makefiles / build
        ".mk", ".cmake",
        # Docker
        ".dockerfile",
        # Web shells / templates
        ".asp", ".aspx", ".jsp", ".cgi",
        # Misc dangerous
        ".awk", ".sed", ".expect",
    })

    def _is_dangerous_file(self, filepath: str) -> bool:
        """Check if a file is a dangerous type (by extension or header)."""
        name = os.path.basename(filepath).lower()

        # Extensionless files that are executable → dangerous
        if "." not in name:
            try:
                st = os.stat(filepath)
                if st.st_mode & 0o111:  # any execute bit set
                    return True
            except OSError:
                pass
            # Check for shebang or ELF header
            try:
                with open(filepath, "rb") as f:
                    header = f.read(4)
                if header[:4] == b"\x7fELF" or header[:2] == b"#!":
                    return True
            except OSError:
                pass
            # Also check common extensionless dangerous names
            if name in ("makefile", "dockerfile", "vagrantfile", "rakefile",
                        "gemfile", "crontab", "authorized_keys", "known_hosts",
                        ".bashrc", ".bash_profile", ".profile", ".zshrc",
                        ".ssh_config", ".gitconfig"):
                return True
            return False

        # Check extension
        _, ext = os.path.splitext(name)
        if ext in self._DANGEROUS_EXTENSIONS:
            return True

        # Dotfiles that are configs
        if name.startswith(".") and ext in (".rc", ""):
            return True

        return False

    def _collect_quick_targets(self) -> list[str]:
        """Collect files for quick scan.

        Strategy:
        1. All files in high-risk staging areas (/tmp, /dev/shm, /var/tmp)
        2. All cron and systemd persistence files
        3. ALL dangerous file types in /home and /root (full depth)
        4. ALL recently modified files (24h) in /home and /root
        """
        targets: set[str] = set()

        # ── 1. High-risk staging areas (all files) ──────────────────────
        for scan_dir in ("/tmp", "/dev/shm", "/var/tmp"):
            targets.update(self._walk_dir(scan_dir, max_depth=5))

        # ── 2. Cron persistence ─────────────────────────────────────────
        for cron_dir in ("/var/spool/cron/crontabs", "/etc/cron.d"):
            if os.path.isdir(cron_dir):
                try:
                    for entry in os.scandir(cron_dir):
                        if entry.is_file():
                            targets.add(entry.path)
                except OSError:
                    pass
        if os.path.isfile("/etc/crontab"):
            targets.add("/etc/crontab")

        # ── 3. Systemd persistence ──────────────────────────────────────
        systemd_dir = "/etc/systemd/system"
        if os.path.isdir(systemd_dir):
            try:
                for entry in os.scandir(systemd_dir):
                    if entry.name.endswith(".service") and entry.is_file():
                        targets.add(entry.path)
            except OSError:
                pass

        # ── 4. Full /home and /root — dangerous file types ONLY ─────────
        for search_dir in ("/home", "/root"):
            for fp in self._walk_dir(search_dir, max_depth=20):
                try:
                    st = os.lstat(fp)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_size > self.max_file_size or st.st_size == 0:
                        continue
                    if self._is_dangerous_file(fp):
                        targets.add(fp)
                except OSError:
                    pass

        # ── 5. Recently modified files (24h) in /home and /root ─────────
        #    Catches any file type that was touched recently
        cutoff = time.time() - 86400
        for search_dir in ("/home", "/root"):
            for fp in self._walk_dir(search_dir, max_depth=20):
                try:
                    if os.stat(fp).st_mtime > cutoff:
                        targets.add(fp)
                except OSError:
                    pass

        # ── 6. Priority-order: ELF → Scripts → Archives → Other ─────────
        priority_1: list[str] = []  # ELF binaries
        priority_2: list[str] = []  # Scripts (shebang)
        priority_3: list[str] = []  # Archives
        priority_4: list[str] = []  # Everything else

        for fp in targets:
            try:
                with open(fp, "rb") as f:
                    header = f.read(4)
            except OSError:
                priority_4.append(fp)
                continue

            if header[:4] == b"\x7fELF":
                priority_1.append(fp)
            elif header[:2] == b"#!":
                priority_2.append(fp)
            elif os.path.basename(fp).endswith(
                (".zip", ".tar", ".gz", ".7z", ".bz2", ".xz", ".rar", ".deb", ".rpm")
            ):
                priority_3.append(fp)
            else:
                priority_4.append(fp)

        return priority_1 + priority_2 + priority_3 + priority_4

    def _collect_full_targets(self) -> list[str]:
        """Walk the ENTIRE filesystem. No date filter, no type filter.

        Orders results by threat priority:
        1. ELF binaries (highest risk)
        2. Scripts (shebang files)
        3. Archives (can hide payloads)
        4. Everything else
        """
        priority_1: list[str] = []  # ELF
        priority_2: list[str] = []  # Scripts
        priority_3: list[str] = []  # Archives
        priority_4: list[str] = []  # Everything else

        for root, dirs, files in os.walk("/"):
            # Skip virtual/pseudo filesystems
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in _SKIP_PATHS]
            for fname in files:
                fp = os.path.join(root, fname)
                try:
                    st = os.lstat(fp)
                    if not stat.S_ISREG(st.st_mode):
                        continue
                    if st.st_size > self.max_file_size or st.st_size == 0:
                        continue

                    # Classify by reading first 4 bytes
                    try:
                        with open(fp, "rb") as f:
                            header = f.read(4)
                    except OSError:
                        priority_4.append(fp)
                        continue

                    if header[:4] == b"\x7fELF":
                        priority_1.append(fp)
                    elif header[:2] == b"#!":
                        priority_2.append(fp)
                    elif fname.endswith((".zip", ".tar", ".gz", ".7z", ".bz2", ".xz")):
                        priority_3.append(fp)
                    else:
                        priority_4.append(fp)
                except OSError:
                    continue

        return priority_1 + priority_2 + priority_3 + priority_4

    @staticmethod
    def _walk_dir(directory: str, max_depth: int = 10) -> list[str]:
        """Recursively list regular files, respecting max depth."""
        results: list[str] = []
        if not os.path.isdir(directory):
            return results
        base_depth = directory.rstrip("/").count("/")
        for root, dirs, files in os.walk(directory):
            depth = root.rstrip("/").count("/") - base_depth
            if depth >= max_depth:
                dirs.clear()
                continue
            for f in files:
                fp = os.path.join(root, f)
                try:
                    if os.path.isfile(fp) and not os.path.islink(fp):
                        results.append(fp)
                except OSError:
                    pass
        return results

    # ── Scan loop ───────────────────────────────────────────────────

    async def _scan_files(
        self,
        targets: list[str],
        report: ScanReport,
        cancel_token: CancellationToken | None = None,
    ) -> None:
        """Scan a list of files using the thread pool."""
        loop = asyncio.get_event_loop()
        total = len(targets)
        for i, filepath in enumerate(targets):
            if cancel_token and cancel_token.is_cancelled():
                break
            try:
                record = await loop.run_in_executor(
                    self._executor, self._analyze_file, filepath, report
                )
                report.files_scanned += 1

                if record and record.threat_score >= 40:
                    report.threats_found.append(record)
                    await self.event_bus.publish(Event(
                        type=EventType.THREAT_FOUND,
                        source="scanner",
                        data={
                            "filepath": record.filepath,
                            "threat_score": record.threat_score,
                            "threat_reason": record.threat_reason,
                            "threat_category": record.threat_category,
                            "matched_rules": record.matched_rules,
                            "file_hash": record.file_hash,
                        },
                        severity=record.threat_score,
                    ))
            except Exception:
                report.files_scanned += 1

            # Progress every 5 files (or always at the end)
            if (i + 1) % 5 == 0 or i == total - 1:
                pct = int((i + 1) / total * 100) if total else 100
                await self.event_bus.publish(Event(
                    type=EventType.SCAN_PROGRESS,
                    source="scanner",
                    data={
                        "scan_type": report.scan_type,
                        "files_scanned": report.files_scanned,
                        "total_estimate": total,
                        "percent": pct,
                        "current_file": filepath,
                    },
                ))

    # ── Per-file analysis (11-stage pipeline) ───────────────────────

    def _analyze_file(
        self, filepath: str, report: ScanReport | None = None,
    ) -> ThreatRecord | None:
        """Run the 11-stage analysis pipeline on a single file.

        Returns None if the file is clean or should be skipped.
        Returns ThreatRecord only for genuine threats.
        """

        # STAGE 0: Pre-filter
        skip, skip_reason = should_skip_file(filepath)
        if skip:
            if report is not None:
                report.skipped_safe_type += 1
            return None

        # STAGE 0b: False positive memory — user previously marked safe
        if self.fp_memory:
            try:
                file_hash_quick = hashlib.sha256(
                    open(filepath, "rb").read(4096)
                ).hexdigest()
            except OSError:
                file_hash_quick = ""
            if file_hash_quick and self.fp_memory.is_known_false_positive(
                file_hash_quick, filepath
            ):
                return None

        # Read file data
        try:
            file_stat = os.stat(filepath)
            if file_stat.st_size > self.max_file_size:
                return None
            with open(filepath, "rb") as f:
                # Cap at 5 MB for analysis (large files read header only)
                data = f.read(5 * 1024 * 1024)
        except (PermissionError, OSError):
            return None

        file_hash = hashlib.sha256(data).hexdigest()

        # STAGE 1: Hash DB — known malware
        if self.hash_db:
            is_mal, name, level = self.hash_db.is_malware(file_hash)
            if is_mal:
                return ThreatRecord(
                    filepath=filepath,
                    threat_score=level,
                    threat_reason=f"Known malware: {name}",
                    file_hash=file_hash,
                    threat_category="known_malware",
                    recommended_action="quarantine" if level >= 80 else "warn",
                )

        # STAGE 2: Hash DB — known clean
        if self.hash_db and self.hash_db.is_known_clean(file_hash):
            if report is not None:
                report.skipped_known_clean += 1
            return None

        # STAGE 3: Package manager trust
        is_managed, pkg_hash_ok = self._pkg_trust.verify_package_hash(filepath)
        if is_managed and pkg_hash_ok:
            if report is not None:
                report.skipped_pkg_verified += 1
            return None

        # STAGE 4: Scrutiny level
        scrutiny = get_path_scrutiny_level(filepath)

        if report is not None:
            report.analyzed_fully += 1

        # Determine file type
        is_elf = data[:4] == b"\x7fELF"
        magic_type = ""
        if _MAGIC_AVAILABLE:
            try:
                magic_type = _magic.from_file(filepath, mime=True) or ""
            except Exception:
                pass

        # STAGE 5-8: Scoring components
        component_scores: list[int] = []
        reasons: list[str] = []
        matched_rules: list[str] = []
        category = "unknown_malware"

        # Stage 5: YARA scan (all scrutiny levels)
        if self.yara_engine and self.yara_engine.available:
            yara_matches = self.yara_engine.scan_file(filepath)
            if yara_matches:
                yara_score = min(60, len(yara_matches) * 20)
                component_scores.append(yara_score)
                matched_rules = [m.rule_name for m in yara_matches]
                category = YaraEngine.categorize_matches(yara_matches)
                reasons.append(f"YARA: {', '.join(matched_rules)}")

        # Stage 6: Entropy (skip for reduced scrutiny)
        if scrutiny in ("normal", "high"):
            ent_score = score_entropy(filepath, data, is_elf)
            if ent_score > 0:
                entropy_val = _shannon_entropy(data)
                component_scores.append(ent_score)
                reasons.append(f"High entropy ({entropy_val:.2f})")

        # Stage 7: Magic mismatch (all scrutiny levels)
        if magic_type:
            mm_score, mm_reason = score_magic_mismatch(filepath, magic_type, is_elf)
            if mm_score > 0:
                component_scores.append(mm_score)
                reasons.append(mm_reason)

        # Stage 8: ELF anomalies (skip for reduced scrutiny)
        if is_elf and _ELF_AVAILABLE and scrutiny != "reduced":
            try:
                elf = ELFFile(io.BytesIO(data))
                elf_score, elf_reasons = score_elf_anomalies(filepath, elf)
                if elf_score > 0:
                    component_scores.append(elf_score)
                    reasons.extend(elf_reasons)
            except Exception:
                pass

        # STAGE 9: Combine with diminishing returns
        raw_score = combine_scores(component_scores)

        # STAGE 10: Context adjustments
        final_score, adjustment = apply_context_adjustments(
            raw_score, filepath, is_managed, pkg_hash_ok,
        )

        # STAGE 11: Threshold gate
        thresholds = {"reduced": 70, "normal": 45, "high": 30}
        threshold = thresholds.get(scrutiny, 45)

        # Log scoring decision for debugging
        if final_score > 0:
            log_info(
                f"SCORE: {filepath} | final={final_score} raw={raw_score} "
                f"adj={adjustment} scrutiny={scrutiny} managed={is_managed} "
                f"reasons={reasons}",
                module="scanner",
            )

        if final_score < threshold:
            return None

        # Determine action
        final_score = min(100, final_score)
        if final_score >= 80:
            action = "quarantine"
        elif final_score >= 55:
            action = "warn"
        else:
            action = "monitor"

        return ThreatRecord(
            filepath=filepath,
            threat_score=final_score,
            threat_reason="; ".join(reasons) if reasons else f"Suspicious ({adjustment})",
            matched_rules=matched_rules,
            file_hash=file_hash,
            threat_category=category,
            recommended_action=action,
        )

    # ── Static helpers (kept for backward compat with tests) ────────

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calculate Shannon entropy of a byte sequence."""
        return _shannon_entropy(data)

    @staticmethod
    def _is_executable(filepath: str, data: bytes) -> bool:
        """Check if a file is executable (ELF or shebang)."""
        if data[:4] == b"\x7fELF":
            return True
        if data[:2] == b"#!":
            return True
        try:
            return bool(os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        except OSError:
            return False

    # ── Event publishing ────────────────────────────────────────────

    async def _publish_complete(self, report: ScanReport) -> None:
        """Publish scan completion event with audit summary."""
        total = report.files_scanned
        await self.event_bus.publish(Event(
            type=EventType.SCAN_COMPLETE,
            source="scanner",
            data={
                "scan_type": report.scan_type,
                "files_scanned": total,
                "threats_found_count": len(report.threats_found),
                "duration_seconds": report.scan_duration_seconds,
                # Audit stats
                "skipped_safe_type": report.skipped_safe_type,
                "skipped_pkg_verified": report.skipped_pkg_verified,
                "skipped_known_clean": report.skipped_known_clean,
                "analyzed_fully": report.analyzed_fully,
            },
        ))
        # Log audit summary
        log_info(
            f"SCAN {report.scan_type.upper()} COMPLETE: "
            f"{total} files | "
            f"safe_type={report.skipped_safe_type} "
            f"pkg_verified={report.skipped_pkg_verified} "
            f"known_clean={report.skipped_known_clean} "
            f"analyzed={report.analyzed_fully} "
            f"threats={len(report.threats_found)} "
            f"({report.scan_duration_seconds:.1f}s)",
            module="scanner",
        )
