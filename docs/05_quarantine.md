# 05 — Quarantine & False Positive Memory

> How CyberPet isolates threats and remembers what's safe.

---

## Quarantine Vault (`quarantine.py`)

The quarantine vault at `/var/lib/cyberpet/quarantine/` is where suspicious files go when they're removed from their original location.

### What Happens When a File Is Quarantined

```
1. Calculate SHA256 of original file
2. Generate a unique quarantine ID: {timestamp}_{sha256[:8]}_{filename}
3. Move file to /var/lib/cyberpet/quarantine/{id}
4. Strip all permissions (chmod 000)
5. Record in vault manifest:
   - original path
   - sha256
   - quarantine timestamp
   - threat score + category
   - threat reason
6. Publish QUARANTINE_CONFIRMED event → TUI shows notification
7. FP memory records the quarantine (for anti-FP bias in RL)
```

The file is **moved** (not copied) from its original location. The original path is stored so it can be restored exactly where it was.

### Security Properties

- **Permissions stripped:** `chmod 000` prevents any process from reading/executing the file
- **Renamed:** original filename is not preserved at the vault path, preventing accidental execution
- **Root-only access:** vault directory is `chmod 700` owned by root
- **No auto-delete:** files stay in the vault indefinitely until manually deleted

### Quarantine Commands

```bash
# List all quarantined files with IDs
cyberpet quarantine list

# Restore a file to its original location
cyberpet quarantine restore <id>   # full ID or unique prefix

# Permanently delete from vault
cyberpet quarantine delete <id>

# Restore using a prefix (first 8 chars of ID is enough)
cyberpet quarantine restore 1709123
```

### Restore Process

When restoring:
1. Read original path from manifest
2. Restore permissions (from manifest or default 644)
3. Move file back to original path
4. If original path is occupied → error (prevents overwrite)
5. Remove vault record
6. Publish `LOCKDOWN_DEACTIVATED` event

---

## False Positive Memory (`false_positive_memory.py`)

The FP memory is a SQLite database at `/var/lib/cyberpet/false_positives.db` that remembers every file the user has confirmed is safe.

### What Gets Recorded

**When you click "Mark Safe" in the TUI or scan screen:**
```python
fp_memory.mark_safe(
    sha256="abc123...",
    filepath="/home/zer0/tools/nmap",
    category="network_tool",     # why it was originally flagged
    confidence=0.9,              # how confident we are it's safe
)
```

**When a quarantined file is confirmed as a real threat:**
```python
fp_memory.record_quarantine_confirmation(threat_record)
```

### How FP Memory Is Used

1. **3-layer FP protection** — before any blocking action, `action_executor.py` checks if the target file's hash is in FP memory. If yes → abort action.

2. **RL reward penalty** — the reward function applies:
   - `-5.0` for any false positive
   - `-10.0` if the file was **already in FP memory** (repeat FP)
   
3. **State vector** — `fp_rate_recent` (index 43) = fraction of recent detections that were FPs. High FP rate suppresses aggressive RL actions.

4. **RL prior knowledge** — safe file hashes seed the prior knowledge set, which the RL engine uses before it has learned enough to judge files on its own.

5. **CLI review** — `cyberpet fp list` shows all FP entries so you can audit them.

### FP Memory Schema

```sql
CREATE TABLE false_positives (
    sha256       TEXT NOT NULL,
    filepath     TEXT NOT NULL,
    category     TEXT DEFAULT '',
    marked_at    REAL NOT NULL,      -- Unix timestamp
    mark_count   INTEGER DEFAULT 1, -- how many times confirmed safe
    confidence   REAL DEFAULT 1.0,
    source       TEXT DEFAULT 'user' -- 'user' | 'prior' | 'auto'
);

CREATE TABLE quarantine_confirmations (
    sha256       TEXT NOT NULL,
    filepath     TEXT NOT NULL,
    threat_score INTEGER,
    threat_category TEXT,
    confirmed_at REAL NOT NULL
);
```

### RL Feedback Loop

```
User marks file safe
        │
        ├─► FP Memory DB updated
        │
        ├─► FP_MARKED_SAFE event published
        │
        ├─► RL Engine adds to live safe set (immediate effect)
        │
        └─► State collector increments fp_rate_recent
                │
                └─► Next RL observation sees higher FP rate
                        │
                        └─► Reward function penalises aggressive actions
                                │
                                └─► PPO learns to be more conservative
```

---

## Package Manager Trust (`pkg_trust.py`)

An additional verification layer that checks whether running binaries are owned by a known package:

```bash
# For each suspicious process, check:
rpm -qf /usr/bin/suspicious_binary
# or
dpkg -S /usr/bin/suspicious_binary
```

If the binary is owned by a package → trust score +1.  
If not found in any package → unknown binary, higher suspicion.

This feeds into state index 42 (`pkg_verified_ratio`):
```python
pkg_verified_ratio = pkg_trust_count / total_process_count
```

Low `pkg_verified_ratio` means many running processes aren't from known packages — a strong signal of compromise or custom tooling.

---

## CLI Commands

```bash
# List all false positive memory entries
cyberpet fp list

# Clear all FP memory (start fresh)
cyberpet fp clear

# List quarantined files
cyberpet quarantine list

# Restore by ID or prefix
cyberpet quarantine restore <id>

# Permanently delete from vault
cyberpet quarantine delete <id>
```
