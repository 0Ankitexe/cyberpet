#!/bin/bash
# CyberPet V1 Installer
# Run with: sudo ./install_v1.sh

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
echo "║     CyberPet V1 Installer            ║"
echo "║     Terminal Security Daemon         ║"
echo "╚══════════════════════════════════════╝"
echo -e "${RESET}"

# -------------------------------------------------------------------
# 1. Prerequisites
# -------------------------------------------------------------------
step "Checking prerequisites..."

# Check Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    error "CyberPet requires Linux. Detected: $(uname -s)"
fi
info "Linux detected: $(uname -r)"

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This installer must be run as root (use sudo)"
fi
info "Running as root"

# Check Python 3.11+
if ! command -v python3 &>/dev/null; then
    error "Python 3 is not installed"
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PYTHON_MAJOR=$(echo "$PYTHON_VERSION" | cut -d. -f1)
PYTHON_MINOR=$(echo "$PYTHON_VERSION" | cut -d. -f2)

if [[ "$PYTHON_MAJOR" -lt 3 ]] || [[ "$PYTHON_MAJOR" -eq 3 && "$PYTHON_MINOR" -lt 11 ]]; then
    error "Python 3.11+ required. Found: Python $PYTHON_VERSION"
fi
info "Python $PYTHON_VERSION detected"

# -------------------------------------------------------------------
# 1b. Access group
# -------------------------------------------------------------------
step "Configuring socket access group..."

if ! getent group cyberpet >/dev/null 2>&1; then
    groupadd --system cyberpet
    info "Created system group: cyberpet"
else
    info "Group cyberpet already exists"
fi

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    usermod -aG cyberpet "$SUDO_USER" || warn "Could not add $SUDO_USER to cyberpet group"
    info "Added $SUDO_USER to cyberpet group (re-login may be required)"
fi

# Add all interactive local users so terminal hooks can reach the socket.
while IFS=: read -r username _ uid _ _ _ shell_path; do
    if [[ "$uid" -ge 1000 && "$username" != "nobody" ]]; then
        if [[ "$shell_path" != *"/nologin" && "$shell_path" != "/bin/false" ]]; then
            usermod -aG cyberpet "$username" || warn "Could not add $username to cyberpet group"
        fi
    fi
done < /etc/passwd
info "Ensured interactive local users have cyberpet group access"

# -------------------------------------------------------------------
# 2. System packages
# -------------------------------------------------------------------
step "Installing system packages..."

if command -v apt-get &>/dev/null; then
    apt-get update -qq
    apt-get install -y -qq python3-pip python3-dev python3-venv socat
    info "System packages installed (apt)"
elif command -v dnf &>/dev/null; then
    dnf install -y -q python3-pip python3-devel python3-virtualenv socat
    info "System packages installed (dnf)"
else
    warn "Package manager not detected. Please install python3-pip, python3-dev, socat manually."
fi

# -------------------------------------------------------------------
# 3. Create virtualenv
# -------------------------------------------------------------------
step "Creating virtualenv at /opt/cyberpet/venv..."

VENV=/opt/cyberpet/venv
mkdir -p /opt/cyberpet
python3 -m venv "$VENV"
info "Virtualenv created at $VENV"

# -------------------------------------------------------------------
# 4. Python dependencies
# -------------------------------------------------------------------
step "Installing Python dependencies into venv..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    "$VENV/bin/pip" install -q -r "$SCRIPT_DIR/requirements.txt"
    info "Python dependencies installed from requirements.txt"
else
    "$VENV/bin/pip" install -q textual psutil toml click python-daemon
    info "Python dependencies installed"
fi

# -------------------------------------------------------------------
# 5. Create directories
# -------------------------------------------------------------------
step "Creating directories..."

mkdir -p /etc/cyberpet
mkdir -p /var/log/cyberpet
mkdir -p /var/lib/cyberpet
mkdir -p /var/run

info "Directories created: /etc/cyberpet, /var/log/cyberpet, /var/lib/cyberpet"

# -------------------------------------------------------------------
# 5. Deploy config
# -------------------------------------------------------------------
step "Deploying configuration..."

if [[ -f "$SCRIPT_DIR/config/default_config.toml" ]]; then
    if [[ ! -f /etc/cyberpet/config.toml ]]; then
        cp "$SCRIPT_DIR/config/default_config.toml" /etc/cyberpet/config.toml
        info "Config deployed to /etc/cyberpet/config.toml"
    else
        warn "Config already exists at /etc/cyberpet/config.toml (preserved)"
    fi
else
    warn "Default config not found, skipping"
fi

# Terminal guard socket: 0666 so every user's shell can reach the daemon
# without needing to be in the cyberpet group (group membership requires a
# full re-login which breaks the out-of-the-box experience).
# Event stream socket stays 0660 (only the TUI process needs it).
if [[ -f /etc/cyberpet/config.toml ]]; then
    "$VENV/bin/python" - <<'PY'
import toml

path = "/etc/cyberpet/config.toml"
data = toml.load(path)

data.setdefault("general", {})
data.setdefault("terminal_guard", {})

data["general"]["event_stream_socket_mode"] = "0666"
data["terminal_guard"]["socket_mode"] = "0666"

with open(path, "w", encoding="utf-8") as f:
    toml.dump(data, f)
PY
    info "Configured socket permissions (terminal_guard=0666, event_stream=0660) in /etc/cyberpet/config.toml"
fi

# -------------------------------------------------------------------
# 6. Deploy shell hook
# -------------------------------------------------------------------
step "Deploying shell hook..."

if [[ -f "$SCRIPT_DIR/scripts/shell_hook.sh" ]]; then
    cp "$SCRIPT_DIR/scripts/shell_hook.sh" /etc/cyberpet/shell_hook.sh
    chmod 644 /etc/cyberpet/shell_hook.sh
    info "Shell hook deployed to /etc/cyberpet/shell_hook.sh"
fi

# Auto-source hook in login shells.
cat > /etc/profile.d/cyberpet.sh <<'PROFILE_HOOK'
# CyberPet global shell hook
if [ -n "${BASH_VERSION:-}" ] || [ -n "${ZSH_VERSION:-}" ]; then
    if [ -r /etc/cyberpet/shell_hook.sh ]; then
        . /etc/cyberpet/shell_hook.sh
    fi
fi
PROFILE_HOOK
chmod 644 /etc/profile.d/cyberpet.sh
info "Global profile hook installed at /etc/profile.d/cyberpet.sh"

# Auto-source hook in interactive non-login bash shells.
if [[ -f /etc/bash.bashrc ]]; then
    if ! grep -Fq "/etc/cyberpet/shell_hook.sh" /etc/bash.bashrc; then
        cat >> /etc/bash.bashrc <<'BASHRC_HOOK'

# CyberPet shell hook
[[ -f /etc/cyberpet/shell_hook.sh ]] && source /etc/cyberpet/shell_hook.sh
BASHRC_HOOK
        info "Added CyberPet hook to /etc/bash.bashrc"
    else
        info "CyberPet hook already present in /etc/bash.bashrc"
    fi
fi

# Auto-source hook in interactive zsh shells when available.
if [[ -f /etc/zsh/zshrc ]]; then
    if ! grep -Fq "/etc/cyberpet/shell_hook.sh" /etc/zsh/zshrc; then
        cat >> /etc/zsh/zshrc <<'ZSHRC_HOOK'

# CyberPet shell hook
[[ -f /etc/cyberpet/shell_hook.sh ]] && source /etc/cyberpet/shell_hook.sh
ZSHRC_HOOK
        info "Added CyberPet hook to /etc/zsh/zshrc"
    else
        info "CyberPet hook already present in /etc/zsh/zshrc"
    fi
fi

if [[ -f "$SCRIPT_DIR/scripts/socket_client.py" ]]; then
    mkdir -p /usr/lib/cyberpet
    cp "$SCRIPT_DIR/scripts/socket_client.py" /usr/lib/cyberpet/socket_client.py
    chmod 755 /usr/lib/cyberpet/socket_client.py
    info "Socket client deployed to /usr/lib/cyberpet/socket_client.py"
fi

# -------------------------------------------------------------------
# 7. Install package into venv
# -------------------------------------------------------------------
step "Installing CyberPet package into venv..."

"$VENV/bin/pip" install -q -e "$SCRIPT_DIR"
info "CyberPet package installed into venv"

# Create /usr/local/bin/cyberpet wrapper
# NOTE: 'cyberpet pet' auto-elevates to root via sudo internally (cli.py).
# The wrapper itself stays simple — Python handles privilege escalation.
cat > /usr/local/bin/cyberpet << WRAPPER
#!/bin/bash
exec $VENV/bin/python -m cyberpet "\$@"
WRAPPER
chmod 755 /usr/local/bin/cyberpet
info "CLI wrapper created at /usr/local/bin/cyberpet"

# -------------------------------------------------------------------
# 8. Deploy systemd service
# -------------------------------------------------------------------
step "Deploying systemd service..."

if [[ -f "$SCRIPT_DIR/cyberpet.service" ]]; then
    cp "$SCRIPT_DIR/cyberpet.service" /etc/systemd/system/cyberpet.service
    systemctl daemon-reload
    info "systemd service registered"
else
    warn "Service file not found, skipping"
fi

# -------------------------------------------------------------------
# Done
# -------------------------------------------------------------------
echo ""
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo -e "${GREEN}${BOLD}  CyberPet V1 installed successfully!  ${RESET}"
echo -e "${GREEN}${BOLD}════════════════════════════════════════${RESET}"
echo ""
echo -e "  ${CYAN}Next steps:${RESET}"
echo ""
echo -e "  1. Shell hook is auto-installed globally."
echo -e "     Manual fallback: ${BOLD}source /etc/cyberpet/shell_hook.sh${RESET}"
echo ""
echo -e "  2. Start the daemon:"
echo -e "     ${BOLD}systemctl start cyberpet${RESET}"
echo ""
echo -e "  3. View your pet:"
echo -e "     ${BOLD}cyberpet pet${RESET}"
echo ""
echo -e "  4. Activate monitoring in your current shell:"
echo -e "     ${BOLD}exec newgrp cyberpet${RESET}"
echo -e "     Or simply open a fresh terminal / login session."
echo ""
