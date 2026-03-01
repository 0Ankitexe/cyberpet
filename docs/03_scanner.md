# 03 — File Scanner

> How CyberPet scans files, what it looks for, and how results are stored.

---

## What Is the Scanner?

The scanner is a **completely separate system from the RL brain**. It runs on-demand (never automatically) and examines actual file bytes using four detection methods stacked in order from fastest to slowest:

```
File submitted for scanning
        │
        ▼
1. Whitelist check      ← instant, skip known-clean files
        │
        ▼
2. Hash database        ← milliseconds, exact match against known malware
        │
        ▼
3. Entropy analysis     ← microseconds, detects encrypted/packed content
        │
        ▼
4. YARA rules           ← fast, pattern matching against file bytes
        │
        ▼
5. Heuristic scoring    ← combine all signals into a threat score 0–100
        │
        ▼
Threat? → Emit THREAT_DETECTED event → TUI shows alert
```

---

## Detection Methods

### 1. Hash Database (`hash_db.py`)

SQLite database at `/var/lib/cyberpet/hashes.db` containing:
- **Known clean hashes** — system binaries, package manager verified files
- **Known malware hashes** — EICAR test virus + imported threat intel

```python
db.is_known_clean(sha256)    # → True/False
db.is_known_malware(sha256)  # → True/False, threat_level 0–100
```

If a file matches a **clean hash** → scan skipped entirely (fast path).  
If it matches a **malware hash** → instant `THREAT_DETECTED` with score from DB.

### 2. Entropy Analysis

Files are read in chunks and their Shannon entropy is calculated:

```python
entropy = -sum(p * log2(p) for p in byte_freq if p > 0)
```

- **Entropy < 3.0** → mostly text/binary with patterns → normal
- **Entropy 6.0–7.9** → compressed/packed content → moderate suspicion
- **Entropy ≥ 7.5** in an executable → very likely packed/encrypted → high suspicion

High entropy in executables is a strong ransomware/packer indicator.

### 3. YARA Rules (`yara_engine.py`)

CyberPet ships with YARA rules in `/etc/cyberpet/rules/`:

| Rule File | What It Detects |
|-----------|----------------|
| `malware.yar` | Common malware patterns, shell command injection, reverse shells |
| `suspicious.yar` | Suspicious scripting patterns, unusual binary strings |
| `network.yar` | Hardcoded C2 endpoints, suspicious network strings |
| `crypto.yar` | Cryptocurrency mining strings, known miner signatures |

YARA matches on the raw bytes of the file. Each matched rule contributes to the threat score and provides a category label.

### 4. Heuristic Scoring

Beyond YARA, the scanner applies heuristic checks:

- **File location**: `/tmp`, `/dev/shm`, `/var/tmp` executables → +30 score
- **File name**: names matching malware patterns (`.crypted`, `.locked`) → +20
- **Permission bits**: SUID/SGID set unexpectedly → +15
- **File age vs modification**: recently modified old binaries → suspicious
- **String matching**: hardcoded IPs, base64-encoded payloads, known C2 patterns

All signals combine into a final **threat score 0–100**:
- Score < 30 → clean, no alert
- Score 30–59 → suspicious, logged but no quarantine
- Score 60–79 → threat, `THREAT_DETECTED` event, TUI alert
- Score ≥ 80 → high threat, auto-quarantine possible (only for `/tmp` paths)

---

## Quick Scan vs Full Scan

### Quick Scan (1–3 minutes)

Scans only **high-risk locations**:
```
/tmp/
/dev/shm/
/var/tmp/
~/.local/share/
~/.config/
/etc/cron* (cron files only)
/var/spool/cron/
Recently modified files in /home (last 24h, executables only)
```

### Full Scan (10–60 minutes)

Scans the **entire filesystem** with exclusions:
```
Excluded:
  /proc/, /sys/, /dev/    ← virtual filesystems
  /var/lib/cyberpet/      ← our own quarantine vault
  Network mounts          ← NFS, CIFS
  Symlinks                ← not followed (prevents loops)

Included:
  Everything else on the filesystem
```

---

## Scan Pipeline (Technical)

```python
class FileScanner:
    def scan_file(self, path) -> ThreatRecord | None:
        # 1. Skip if not a regular file or size 0
        # 2. Calculate sha256
        # 3. Check hash DB → clean? return None. Malware? return record.
        # 4. Read up to 1MB of file content
        # 5. Calculate entropy
        # 6. Run YARA rules against bytes
        # 7. Apply heuristics
        # 8. Combine scores
        # 9. If score >= threshold → return ThreatRecord
        return None  # clean
```

The scan runs in a thread pool (default: 4 workers) to scan multiple files in parallel without blocking the async event loop.

Progress events are published every N files:
```python
EventType.SCAN_PROGRESS  →  {files_scanned, threats_found, current_file, percent}
EventType.SCAN_FILE_SCANNED  →  {path, threat_score, is_threat}
```

---

## Scan Trigger Mechanism

```
CLI:          cyberpet scan quick/full
              → writes "quick"/"full" to /var/run/cyberpet_scan_trigger

TUI:          press 'S' → scan menu → select type
              → opens ScanScreen which directly calls scanner

RL action 6:  TRIGGER_SCAN
              → writes "quick" to /var/run/cyberpet_scan_trigger
              (only available after 500+ RL steps)

Daemon watcher: polls trigger file every 2s
              → if content is "quick" or "full" → start scan
              → truncates trigger file after reading
```

Auto-scans on a timer are **disabled** by default (startup scan, periodic scan, and daily scan are all commented out in `scan_scheduler.py`).

---

## Scan History (`scan_history.py`)

Every completed scan is recorded in SQLite at `/var/lib/cyberpet/scan_history.db`:

| Column | Type | Content |
|--------|------|---------|
| `scan_id` | TEXT | UUID |
| `scan_type` | TEXT | `quick` or `full` |
| `started_at` | REAL | Unix timestamp |
| `completed_at` | REAL | Unix timestamp |
| `files_scanned` | INTEGER | Total files examined |
| `threats_found` | TEXT | JSON list of ThreatRecord dicts |
| `duration_seconds` | REAL | Wall clock time |

The RL brain reads this database to bootstrap prior knowledge — confirmed threats inform action bias, and scan results feed into the state vector (`last_scan_threats` at index 34).

---

## Auto-Quarantine Safety Rules

When a threat is detected with score ≥ 80, the scanner **can** auto-quarantine — but with strict safety constraints:

```python
SAFE_AUTO_QUARANTINE_PATHS = {"/tmp", "/dev/shm", "/var/tmp"}

# Auto-quarantine ONLY if:
# 1. threat_score >= 80
# 2. File is inside one of the safe paths above
# 3. NOT a system binary (not in /usr, /bin, /sbin, /lib)
# 4. NOT in user home directory
```

Files in system paths, user home directories, or application data directories are **never** auto-quarantined. They trigger a TUI alert for manual review only.
