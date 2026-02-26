#!/bin/bash
# CyberPet V2 Installer — extends V1
# Run with: sudo ./install_v2.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'
BOLD='\033[1m'

info()  { echo -e "${GREEN}[✓]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
error() { echo -e "${RED}[✗]${RESET} $1"; exit 1; }
step()  { echo -e "\n${CYAN}${BOLD}>>> $1${RESET}"; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════╗"
echo "║   CyberPet V2 — The Watcher          ║"
echo "║   Installer                          ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

# Check root
[ "$(id -u)" -eq 0 ] || error "This installer must be run as root"

# ── Step 1: V1 base ──────────────────────────────────────────────
step "Checking V1 installation"
if [ ! -d /opt/cyberpet/venv ]; then
    error "V1 not installed. Run install_v1.sh first."
fi
info "V1 installation found at /opt/cyberpet/"

# ── Step 2: System dependencies ──────────────────────────────────
step "Installing V2 system dependencies"

# Detect package manager
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq libmagic1 libyara-dev 2>/dev/null || warn "Some system packages failed"
    # BCC is optional
    apt-get install -y -qq bcc python3-bpfcc 2>/dev/null || warn "BCC not available — eBPF monitor will be disabled"
    # Linux headers (optional, needed for eBPF)
    apt-get install -y -qq "linux-headers-$(uname -r)" 2>/dev/null || warn "linux-headers not available — eBPF may not work"
elif command -v dnf &>/dev/null; then
    dnf install -y -q file-libs yara-devel 2>/dev/null || warn "Some system packages failed"
    dnf install -y -q bcc bcc-tools 2>/dev/null || warn "BCC not available"
elif command -v yum &>/dev/null; then
    yum install -y -q file-libs yara-devel 2>/dev/null || warn "Some system packages failed"
fi

# ── Step 3: Python dependencies ──────────────────────────────────
step "Installing V2 Python dependencies"
/opt/cyberpet/venv/bin/pip install --quiet yara-python python-magic pyelftools aiosqlite 2>/dev/null || warn "Some Python packages failed to install"
info "Python dependencies installed (yara-python, python-magic, pyelftools, aiosqlite)"

# ── Step 4: Create V2 directories ────────────────────────────────
step "Creating V2 directories"
mkdir -p /etc/cyberpet/rules
mkdir -p /var/lib/cyberpet/quarantine
chmod 700 /var/lib/cyberpet/quarantine
info "Created /etc/cyberpet/rules/"
info "Created /var/lib/cyberpet/quarantine/ (mode 700)"

# Scan history and false-positive memory (written by TUI — world-writable dir)
mkdir -p /var/lib/cyberpet
chmod 755 /var/lib/cyberpet
info "Created /var/lib/cyberpet/ (scan history, FP memory, RL feedback)"

# ── Step 5: Deploy YARA rules ────────────────────────────────────
step "Deploying YARA rules"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -d "$SCRIPT_DIR/rules" ]; then
    cp -f "$SCRIPT_DIR/rules/"*.yar /etc/cyberpet/rules/ 2>/dev/null
    info "YARA rules deployed to /etc/cyberpet/rules/ (overwriting existing)"
else
    warn "No rules/ directory found — YARA scanning will be limited"
fi

# ── Step 6: Initialize hash database ─────────────────────────────
step "Initializing hash database"
if [ -f "$SCRIPT_DIR/data/seed_hashes.csv" ]; then
    cp "$SCRIPT_DIR/data/seed_hashes.csv" /etc/cyberpet/seed_hashes.csv
    info "Seed hash file deployed to /etc/cyberpet/seed_hashes.csv"
else
    warn "No seed_hashes.csv found — hash database will start empty"
fi

# ── Step 7: Update config ────────────────────────────────────────
step "Updating configuration"
if [ -f /etc/cyberpet/config.toml ]; then
    # Check if V2 sections already exist
    if ! grep -q "\[scanner\]" /etc/cyberpet/config.toml 2>/dev/null; then
        cat >> /etc/cyberpet/config.toml <<'EOF'

[scanner]
quick_scan_interval_minutes = 30
full_scan_time = "03:00"
max_file_size_mb = 50
auto_quarantine = false
auto_quarantine_threshold = 80

[file_monitor]
enabled = true
monitored_paths = ["/etc", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/boot", "/lib"]
whitelist = ["apt", "apt-get", "dpkg", "dnf", "yum", "rpm", "pip", "pip3", "systemd", "systemctl", "sshd", "cron", "rsyslog"]

[exec_monitor]
enabled = true

[yara]
rules_dir = "/etc/cyberpet/rules/"
scan_timeout_seconds = 30

[quarantine]
vault_path = "/var/lib/cyberpet/quarantine/"

[hash_db]
db_path = "/var/lib/cyberpet/hashes.db"
seed_file = "/etc/cyberpet/seed_hashes.csv"
EOF
        info "V2 config sections added to /etc/cyberpet/config.toml"
    else
        info "V2 config sections already present"
    fi
fi

# ── Step 8: Install V2 code ──────────────────────────────────────
step "Installing V2 code"
/opt/cyberpet/venv/bin/pip install -q -e "$SCRIPT_DIR"
info "CyberPet package refreshed in /opt/cyberpet/venv"

if [ -f "$SCRIPT_DIR/scripts/shell_hook.sh" ]; then
    cp "$SCRIPT_DIR/scripts/shell_hook.sh" /etc/cyberpet/shell_hook.sh
    chmod 644 /etc/cyberpet/shell_hook.sh
    info "Updated shell hook at /etc/cyberpet/shell_hook.sh"
fi

if [ -f "$SCRIPT_DIR/scripts/socket_client.py" ]; then
    mkdir -p /usr/lib/cyberpet
    cp "$SCRIPT_DIR/scripts/socket_client.py" /usr/lib/cyberpet/socket_client.py
    chmod 755 /usr/lib/cyberpet/socket_client.py
    info "Updated socket client at /usr/lib/cyberpet/socket_client.py"
fi

# ── Step 9: Kernel check ─────────────────────────────────────────
step "Checking kernel compatibility"
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]; }; then
    info "Kernel $KERNEL_VERSION supports eBPF tracepoints ✓"
else
    warn "Kernel $KERNEL_VERSION — eBPF exec monitor requires ≥ 5.8"
    warn "File scanning and terminal guard will still work"
fi

if [ "$KERNEL_MAJOR" -gt 4 ] || { [ "$KERNEL_MAJOR" -eq 4 ] && [ "$KERNEL_MINOR" -ge 20 ]; }; then
    info "Kernel $KERNEL_VERSION supports fanotify filesystem marks ✓"
else
    warn "Kernel $KERNEL_VERSION — fanotify FAN_MARK_FILESYSTEM requires ≥ 4.20"
fi

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   CyberPet V2 installed!             ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Restart daemon:${RESET}  sudo systemctl restart cyberpet"
echo -e "  ${CYAN}Quick scan:${RESET}      cyberpet scan quick"
echo -e "  ${CYAN}Quarantine:${RESET}      cyberpet quarantine list"
echo -e "  ${CYAN}View TUI:${RESET}        cyberpet pet"
echo ""
