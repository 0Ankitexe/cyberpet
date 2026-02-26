"""Rule-based command danger scorer for CyberPet.

Scores terminal commands on a 0-100 danger scale using regex pattern
matching across three categories (HARD_BLOCK, HIGH_RISK, MEDIUM_RISK)
with additive context modifiers.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import NamedTuple
from urllib.parse import urlparse


class DangerResult(NamedTuple):
    """Result of scoring a command for danger.

    Attributes:
        score: Numeric danger score (0-100).
        reason: Human-readable explanation.
    """

    score: int
    reason: str


@dataclass
class ScoringContext:
    """Contextual information used to modify danger scores.

    Attributes:
        is_root: Whether the current user is root.
        cwd: Current working directory.
        hour_of_day: Current hour in local time (0-23).
    """

    is_root: bool = False
    cwd: str = "/"
    hour_of_day: int = 12


# Each rule: (compiled regex, base score, reason)
_Rule = tuple[re.Pattern[str], int, str]

TRUSTED_INSTALL_DOMAINS = {
    "opencode.ai",
    "raw.githubusercontent.com",
    "get.docker.com",
    "sh.rustup.rs",
    "deb.nodesource.com",
}

_URL_RE = re.compile(r"https?://[^\s\"'|)]+")
_PIPE_TO_SHELL_RE = re.compile(r"\b(curl|wget)\b.*\|.*\b(bash|sh)\b")
_TRUSTED_PIPE_RULE_REASONS = {
    "Piping remote content directly to shell",
    "Piping remote download directly to shell",
    "Piping wget output directly to shell",
}
_TRUSTED_PIPE_BASE_REASON = "Remote install script from trusted source (review before running)"


def _host_is_trusted(host: str) -> bool:
    """Return True when host is explicitly trusted or a trusted subdomain."""
    host = host.lower().strip(".")
    for trusted in TRUSTED_INSTALL_DOMAINS:
        trusted = trusted.lower()
        if host == trusted or host.endswith(f".{trusted}"):
            return True
    return False


def _segment_before_first_unquoted_pipe(command: str) -> str:
    """Return command text before the first unquoted pipe."""
    in_single = False
    in_double = False
    escape = False

    for idx, ch in enumerate(command):
        if escape:
            escape = False
            continue
        if ch == "\\":
            escape = True
            continue
        if ch == "'" and not in_double:
            in_single = not in_single
            continue
        if ch == '"' and not in_single:
            in_double = not in_double
            continue
        if ch == "|" and not in_single and not in_double:
            return command[:idx]

    return command


def _is_trusted_install_pipeline(command: str) -> bool:
    """Check for curl/wget pipe-to-shell where fetched URL hosts are trusted."""
    if not _PIPE_TO_SHELL_RE.search(command):
        return False

    fetch_segment = _segment_before_first_unquoted_pipe(command)
    urls = [m.group(0) for m in _URL_RE.finditer(fetch_segment)]
    if not urls:
        return False

    # Require every fetched URL in the network-fetch segment to be trusted.
    for url in urls:
        host = urlparse(url).hostname or ""
        if not host or not _host_is_trusted(host):
            return False

    return True


def _has_unquoted_control_operator(command: str) -> bool:
    """Return True when command has unquoted shell control operators."""
    in_single = False
    in_double = False
    escape = False
    i = 0

    while i < len(command):
        ch = command[i]

        if escape:
            escape = False
            i += 1
            continue

        if ch == "\\":
            escape = True
            i += 1
            continue

        if ch == "'" and not in_double:
            in_single = not in_single
            i += 1
            continue

        if ch == '"' and not in_single:
            in_double = not in_double
            i += 1
            continue

        if not in_single and not in_double:
            if ch in {"|", ">", "<", ";", "&", "`"}:
                return True
            if ch == "$" and i + 1 < len(command) and command[i + 1] == "(":
                return True

        i += 1

    return False


def _is_benign_shell_management_command(command: str) -> bool:
    """Detect common benign commands that should not be threat-scored."""
    stripped = command.strip()
    if not stripped:
        return True

    try:
        tokens = shlex.split(stripped, posix=True)
    except ValueError:
        tokens = stripped.split()

    if not tokens:
        return True

    head = tokens[0]

    # Display-only commands (printing text) should not match threat regexes
    # when they do not execute shell control operators.
    if head in {"echo", "printf"} and not _has_unquoted_control_operator(stripped):
        return True

    # Activating local virtualenvs and sourcing local rc files are common
    # shell-management actions; do not score these as threats.
    if head in {"source", "."} and len(tokens) >= 2 and not _has_unquoted_control_operator(stripped):
        source_target = tokens[1]
        if source_target.startswith(("~", "/", "./", "../")):
            return True

    return False

# ---------------------------------------------------------------------------
# HARD BLOCK patterns (score 90-100)
# ---------------------------------------------------------------------------
HARD_BLOCK_RULES: list[_Rule] = [
    # rm -rf / or rm -rf /*
    (re.compile(r"\brm\s+.*-\w*r\w*f\w*\s+/\s*\*?\s*$|rm\s+.*-\w*f\w*r\w*\s+/\s*\*?\s*$"),
     95, "Recursive delete of root filesystem"),

    # mkfs on /dev/sd* or /dev/nvme*
    (re.compile(r"\bmkfs\b.*\s+/dev/(sd|nvme)"),
     95, "Format disk device"),

    # dd if=/dev/zero or /dev/random to /dev/sd* or /dev/nvme*
    (re.compile(r"\bdd\b.*if=/dev/(zero|random|urandom).*of=/dev/(sd|nvme)"),
     95, "Overwrite disk device with zeros/random data"),

    # curl [url] | bash/sh
    (re.compile(r"\bcurl\b.*\|.*\b(bash|sh)\b"),
     95, "Piping remote content directly to shell"),

    # wget [url] | bash/sh
    (re.compile(r"\bwget\b.*\|.*\b(bash|sh)\b"),
     95, "Piping remote download directly to shell"),

    # wget -O- [url] | sh
    (re.compile(r"\bwget\b.*-O\s*-.*\|.*\b(bash|sh)\b"),
     95, "Piping wget output directly to shell"),

    # Any command piping to bash/sh from network tools (nc, ncat)
    (re.compile(r"\b(nc|ncat)\b.*\|.*\b(bash|sh)\b"),
     95, "Piping network tool output to shell"),

    # cat/echo > /etc/passwd
    (re.compile(r"\b(cat|echo)\b.*>\s*/etc/passwd"),
     100, "Overwriting /etc/passwd"),

    # cat/echo > /etc/shadow
    (re.compile(r"\b(cat|echo)\b.*>\s*/etc/shadow"),
     100, "Overwriting /etc/shadow"),

    # echo >> /etc/sudoers
    (re.compile(r"\becho\b.*>>\s*/etc/sudoers"),
     95, "Appending to /etc/sudoers"),

    # nc -e /bin/bash or /bin/sh (reverse shell)
    (re.compile(r"\bnc\b.*-e\s+/bin/(bash|sh)"),
     100, "Reverse shell via netcat"),

    # /dev/tcp reverse shell patterns
    (re.compile(r"/dev/tcp/"),
     95, "Reverse shell via /dev/tcp"),

    # python -c with base64 decode and exec
    (re.compile(r"\bpython[23]?\b\s+-c\s+.*base64.*exec"),
     95, "Encoded Python payload execution"),

    # perl -e with system/exec
    (re.compile(r"\bperl\b\s+-e\s+.*\b(system|exec)\b"),
     90, "Perl payload with system/exec"),
]

# ---------------------------------------------------------------------------
# HIGH RISK patterns (score 65-89)
# ---------------------------------------------------------------------------
HIGH_RISK_RULES: list[_Rule] = [
    # chmod 777 on system paths
    (re.compile(r"\bchmod\b\s+777\s+/(bin|sbin|usr|etc|boot)"),
     75, "Setting world-writable permissions on system directory"),

    # chown on system paths
    (re.compile(r"\bchown\b\s+.*\s+/etc/|chown\b\s+.*\s+/bin/|chown\b\s+.*\s+/sbin/"),
     70, "Changing ownership of system files"),

    # crontab -r
    (re.compile(r"\bcrontab\b\s+-r\b"),
     70, "Removing all cron jobs"),

    # iptables -F
    (re.compile(r"\biptables\b\s+-F\b"),
     80, "Flushing all firewall rules"),

    # ufw disable
    (re.compile(r"\bufw\b\s+disable\b"),
     80, "Disabling firewall"),

    # systemctl disable security services
    (re.compile(r"\bsystemctl\b\s+disable\b\s+.*(firewall|ufw|iptables|fail2ban|auditd)"),
     75, "Disabling security service"),

    # export LD_PRELOAD
    (re.compile(r"\bexport\b\s+LD_PRELOAD="),
     80, "Setting LD_PRELOAD (library injection)"),

    # mount --bind on system directories
    (re.compile(r"\bmount\b.*--bind\s+.*/(bin|sbin|usr|etc|boot|lib)"),
     75, "Bind-mounting over system directory"),

    # insmod or modprobe
    (re.compile(r"\b(insmod|modprobe)\b"),
     70, "Loading kernel module"),

    # base64 -d piped to bash/sh
    (re.compile(r"\bbase64\b\s+-d.*\|.*\b(bash|sh)\b"),
     85, "Executing base64-encoded payload"),

    # python/python3/perl/ruby with exec/system and suspicious args
    (re.compile(r"\b(python[23]?|perl|ruby)\b\s+-(c|e)\s+.*\b(exec|system|eval)\b"),
     75, "Scripting language executing suspicious payload"),

    # history -c or unset HISTFILE (log evasion)
    (re.compile(r"\bhistory\b\s+-c\b|\bunset\b\s+HISTFILE\b"),
     70, "Clearing command history (log evasion)"),
]

# ---------------------------------------------------------------------------
# MEDIUM RISK patterns (score 35-64)
# ---------------------------------------------------------------------------
MEDIUM_RISK_RULES: list[_Rule] = [
    # sudo su / sudo -i / sudo bash
    (re.compile(r"\bsudo\b\s+(su|bash|-i)\b"),
     45, "Escalating to root shell"),

    # passwd changing another user's password as root
    (re.compile(r"\bpasswd\b\s+\w+"),
     40, "Changing another user's password"),

    # find / with -exec and rm or chmod
    (re.compile(r"\bfind\b\s+/\s+.*-exec\s+.*(rm|chmod)\b"),
     55, "Recursive find with destructive exec"),

    # tar with --overwrite to system paths
    (re.compile(r"\btar\b.*--overwrite.*/(bin|sbin|usr|etc|boot|lib)"),
     50, "Extracting tar with overwrite to system path"),

    # mv of system binary to /tmp
    (re.compile(r"\bmv\b\s+/(bin|sbin|usr/bin|usr/sbin)/\S+\s+/tmp"),
     55, "Moving system binary to /tmp"),

    # cp into /bin /sbin /usr/bin
    (re.compile(r"\bcp\b\s+\S+\s+/(bin|sbin|usr/bin)/"),
     50, "Copying file into system binary directory"),

    # screen/tmux detach with suspicious command
    (re.compile(r"\b(screen|tmux)\b.*\b(nc|ncat|curl|wget|python|perl)\b"),
     45, "Running network/scripting tool in detached session"),

    # nohup with network tool in background
    (re.compile(r"\bnohup\b.*\b(nc|ncat|curl|wget|python|perl)\b.*&"),
     50, "Running network tool in background via nohup"),
]


class DangerScorer:
    """Rule-based command danger scorer.

    Evaluates terminal commands against a set of regex patterns across
    three severity categories. Context modifiers are applied additively,
    and the final score is capped at 100.

    Usage:
        scorer = DangerScorer()
        result = scorer.score("rm -rf /", ScoringContext(is_root=True))
        print(result.score, result.reason)
    """

    def score(self, command: str, context: ScoringContext | None = None) -> DangerResult:
        """Score a command for danger.

        Args:
            command: The full command string to evaluate.
            context: Optional context for score modifiers.

        Returns:
            A DangerResult with score (0-100) and reason string.
        """
        if context is None:
            context = ScoringContext()

        if _is_benign_shell_management_command(command):
            return DangerResult(score=0, reason="Benign shell management command")

        best_score = 0
        best_reason = "Command appears safe"
        trusted_install_pipeline = _is_trusted_install_pipeline(command)

        # Known install domains are still risky when piped to shell, but should
        # warn by default rather than hard-block.
        if trusted_install_pipeline:
            best_score = 55
            best_reason = _TRUSTED_PIPE_BASE_REASON

        # Check all rule categories, keeping highest score
        for rules in (HARD_BLOCK_RULES, HIGH_RISK_RULES, MEDIUM_RISK_RULES):
            for pattern, base_score, reason in rules:
                if trusted_install_pipeline and reason in _TRUSTED_PIPE_RULE_REASONS:
                    continue
                if pattern.search(command):
                    if base_score > best_score:
                        best_score = base_score
                        best_reason = reason

        if best_score == 0:
            return DangerResult(score=0, reason=best_reason)

        # Apply context modifiers
        modifier = 0

        if context.is_root:
            modifier += 15

        if context.hour_of_day < 6 or context.hour_of_day >= 22:
            modifier += 10

        if context.cwd in ("/tmp", "/dev/shm"):
            modifier += 10

        final_score = min(100, best_score + modifier)
        if trusted_install_pipeline and best_reason == _TRUSTED_PIPE_BASE_REASON:
            # Trusted install pipes should remain warn-level unless another
            # separate high-severity rule matched.
            final_score = min(final_score, 60)

        parts = [best_reason]
        if context.is_root:
            parts.append("running as root (+15)")
        if context.hour_of_day < 6 or context.hour_of_day >= 22:
            parts.append("unusual hour (+10)")
        if context.cwd in ("/tmp", "/dev/shm"):
            parts.append(f"suspicious CWD: {context.cwd} (+10)")

        full_reason = "; ".join(parts)
        return DangerResult(score=final_score, reason=full_reason)
