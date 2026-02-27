#!/bin/bash
# CyberPet V3 Installer — extends V2
# Run with: sudo ./install_v3.sh

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
echo "║   CyberPet V3 — The RL Brain         ║"
echo "║   Installer                          ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

# Check root
[ "$(id -u)" -eq 0 ] || error "This installer must be run as root"

# ── Step 1: V2 base ──────────────────────────────────────────────
step "Checking V2 installation"
if [ ! -d /opt/cyberpet/venv ]; then
    error "V1 not installed. Run install_v1.sh first."
fi

if ! /opt/cyberpet/venv/bin/pip show yara-python &>/dev/null; then
    error "V2 not installed. Run install_v2.sh first."
fi
info "V2 installation verified at /opt/cyberpet/"

# ── Step 2: System dependencies ──────────────────────────────────
step "Installing V3 system dependencies"

# BCC is required for syscall anomaly monitor (optional — degrades gracefully)
if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq bcc python3-bpfcc 2>/dev/null || warn "BCC not available — syscall anomaly monitor will be disabled"
    apt-get install -y -qq "linux-headers-$(uname -r)" 2>/dev/null || warn "linux-headers not available — eBPF may not work"
elif command -v dnf &>/dev/null; then
    dnf install -y -q bcc bcc-tools 2>/dev/null || warn "BCC not available"
elif command -v yum &>/dev/null; then
    yum install -y -q bcc bcc-tools 2>/dev/null || warn "BCC not available"
fi
info "System dependencies checked"

# ── Step 3: Python dependencies ──────────────────────────────────
step "Installing V3 Python dependencies (RL brain)"

# Install PyTorch CPU-only first (to avoid pulling CUDA)
/opt/cyberpet/venv/bin/pip install --quiet \
    torch==2.2.2 --index-url https://download.pytorch.org/whl/cpu \
    2>/dev/null || {
    warn "PyTorch CPU install failed, trying default index"
    /opt/cyberpet/venv/bin/pip install --quiet "torch>=2.0.0,<3.0.0" 2>/dev/null || warn "PyTorch installation failed — RL brain will be disabled"
}

# Install RL dependencies
/opt/cyberpet/venv/bin/pip install --quiet \
    "stable-baselines3[extra]==2.3.2" \
    "gymnasium==0.29.1" \
    "numpy==1.26.4" \
    "shimmy==1.3.0" \
    2>/dev/null || warn "Some RL packages failed to install"

info "Python dependencies installed (stable-baselines3, gymnasium, numpy, shimmy, torch)"

# ── Step 4: Create V3 directories ────────────────────────────────
step "Creating V3 directories"
mkdir -p /var/lib/cyberpet/models
chmod 755 /var/lib/cyberpet/models
info "Created /var/lib/cyberpet/models/ (RL model storage)"

# ── Step 5: Update config ────────────────────────────────────────
step "Updating configuration"
if [ -f /etc/cyberpet/config.toml ]; then
    # Check if V3 [rl] section already exists
    if ! grep -q "\[rl\]" /etc/cyberpet/config.toml 2>/dev/null; then
        cat >> /etc/cyberpet/config.toml <<'EOF'

[rl]
enabled = true
model_path = "/var/lib/cyberpet/models/"
decision_interval_seconds = 30
checkpoint_interval_steps = 3600
warmup_steps_no_priors = 100
warmup_steps_with_priors = 50
warmup_steps_deep_priors = 25
deep_prior_threshold = 20
EOF
        info "V3 [rl] config section added to /etc/cyberpet/config.toml"
    else
        info "V3 [rl] config section already present"
    fi
fi

# Also update default_config.toml if rl section is missing
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "$SCRIPT_DIR/config/default_config.toml" ]; then
    if ! grep -q "\[rl\]" "$SCRIPT_DIR/config/default_config.toml" 2>/dev/null; then
        cat >> "$SCRIPT_DIR/config/default_config.toml" <<'EOF'

[rl]
enabled = true
model_path = "/var/lib/cyberpet/models/"
decision_interval_seconds = 30
checkpoint_interval_steps = 3600
warmup_steps_no_priors = 100
warmup_steps_with_priors = 50
warmup_steps_deep_priors = 25
deep_prior_threshold = 20
EOF
        info "V3 [rl] section added to default_config.toml"
    fi
fi

# ── Step 6: Install V3 code ─────────────────────────────────────
step "Installing V3 code"
/opt/cyberpet/venv/bin/pip install -q -e "$SCRIPT_DIR"
info "CyberPet package refreshed in /opt/cyberpet/venv"

# ── Step 7: Verify RL dependencies ───────────────────────────────
step "Verifying RL brain dependencies"

DEPS_OK=true
for pkg in torch stable_baselines3 gymnasium numpy shimmy; do
    if /opt/cyberpet/venv/bin/python -c "import $pkg" 2>/dev/null; then
        info "$pkg ✓"
    else
        warn "$pkg not importable — RL brain will start in degraded mode"
        DEPS_OK=false
    fi
done

if $DEPS_OK; then
    info "All RL dependencies verified"
else
    warn "Some RL dependencies missing. The daemon will start but RL brain will be disabled."
    warn "The rest of CyberPet (terminal guard, scanner, quarantine) will work normally."
fi

# ── Step 8: Kernel check ────────────────────────────────────────
step "Checking kernel compatibility for syscall monitor"
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [ "$KERNEL_MAJOR" -gt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]; }; then
    info "Kernel $KERNEL_VERSION supports raw_syscalls tracepoint ✓"
else
    warn "Kernel $KERNEL_VERSION — syscall anomaly monitor requires ≥ 5.8"
    warn "RL brain will still work without syscall monitoring"
fi

# ── Step 9: Test RL brain initialization ─────────────────────────
step "Testing RL brain initialization"
if /opt/cyberpet/venv/bin/python -c "
from cyberpet.rl_prior import RLPriorKnowledge
from cyberpet.state_collector import SystemStateCollector
from cyberpet.rl_explainer import RLExplainer
print('RL modules loaded successfully')
" 2>/dev/null; then
    info "RL brain modules load successfully"
else
    warn "Some RL modules failed to load — check daemon logs on startup"
fi

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║   CyberPet V3 installed!             ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${CYAN}Restart daemon:${RESET}    sudo systemctl restart cyberpet"
echo -e "  ${CYAN}Brain status:${RESET}      cyberpet model status"
echo -e "  ${CYAN}Brain info:${RESET}        cyberpet model info"
echo -e "  ${CYAN}FP memory:${RESET}         cyberpet fp list"
echo -e "  ${CYAN}View TUI:${RESET}          cyberpet pet"
echo ""
echo -e "  ${YELLOW}Note:${RESET} The RL brain starts in WARMUP mode for"
echo -e "  100 steps (50 if you have scan history). During warmup,"
echo -e "  it only uses safe actions (ALLOW, LOG_WARN)."
echo ""
echo -e "  ${YELLOW}Graceful degradation:${RESET} If RL dependencies fail,"
echo -e "  all V1+V2 features continue working normally."
echo ""
