#!/bin/bash
# CyberPet Shell Hook
# Source this in your .bashrc or .zshrc:
#   source /etc/cyberpet/shell_hook.sh

# Prevent duplicate installation when sourced multiple times.
if [[ -n "${_CYBERPET_HOOK_LOADED:-}" ]]; then
    return 0 2>/dev/null || exit 0
fi
_CYBERPET_HOOK_LOADED=1

CYBERPET_SOCKET="${CYBERPET_SOCKET:-/var/run/cyberpet.sock}"
CYBERPET_ENABLED="${CYBERPET_ENABLED:-true}"
CYBERPET_OVERRIDE_TIMEOUT="${CYBERPET_OVERRIDE_TIMEOUT:-30}"
_CYBERPET_PERMISSION_WARNED="${_CYBERPET_PERMISSION_WARNED:-false}"
_CYBERPET_LAST_CHECKED="${_CYBERPET_LAST_CHECKED:-}"
_CYBERPET_LAST_HISTORY_ID="${_CYBERPET_LAST_HISTORY_ID:-}"
_CYBERPET_SELECTED_CMD="${_CYBERPET_SELECTED_CMD:-}"
_CYBERPET_READY="${_CYBERPET_READY:-0}"

# Path to the Python socket client helper
CYBERPET_CLIENT="${CYBERPET_CLIENT:-/usr/lib/cyberpet/socket_client.py}"
CYBERPET_PYTHON="${CYBERPET_PYTHON:-/opt/cyberpet/venv/bin/python}"

# Prefer the packaged venv interpreter, but gracefully fall back.
if [[ ! -x "$CYBERPET_PYTHON" ]]; then
    if command -v python3 >/dev/null 2>&1; then
        CYBERPET_PYTHON="$(command -v python3)"
    elif command -v python >/dev/null 2>&1; then
        CYBERPET_PYTHON="$(command -v python)"
    fi
fi

# Fallback: check common locations
if [[ ! -f "$CYBERPET_CLIENT" ]]; then
    # Check relative to this script
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$_script_dir/socket_client.py" ]]; then
        CYBERPET_CLIENT="$_script_dir/socket_client.py"
    elif [[ -f "$_script_dir/../scripts/socket_client.py" ]]; then
        CYBERPET_CLIENT="$_script_dir/../scripts/socket_client.py"
    fi
fi

# Colors
_CP_RED='\033[0;31m'
_CP_YELLOW='\033[0;33m'
_CP_GREEN='\033[0;32m'
_CP_CYAN='\033[0;36m'
_CP_RESET='\033[0m'
_CP_BOLD='\033[1m'

_cyberpet_check_command() {
    local cmd="$1"

    # Skip if disabled
    [[ "$CYBERPET_ENABLED" != "true" ]] && return 0

    # Skip empty commands
    [[ -z "$cmd" ]] && return 0

    # Skip cyberpet's own commands
    [[ "$cmd" == cyberpet* ]] && return 0

    # Check if daemon is running (socket exists)
    if [[ ! -S "$CYBERPET_SOCKET" ]]; then
        return 0
    fi

    # Check if Python client exists
    if [[ ! -f "$CYBERPET_CLIENT" ]]; then
        return 0
    fi
    if [[ ! -x "$CYBERPET_PYTHON" ]]; then
        return 0
    fi

    # Send command to daemon via Python helper
    local response
    response=$(echo "$cmd" | CYBERPET_SOCKET="$CYBERPET_SOCKET" "$CYBERPET_PYTHON" "$CYBERPET_CLIENT" 2>/dev/null)

    # Handle response
    case "$response" in
        ALLOW*)
            # Command is safe, proceed
            return 0
            ;;
        WARN:CyberPet\ socket\ permission\ denied*)
            # Permission mismatch (usually new group membership not active yet).
            # Warn once per session. Do NOT disable monitoring — keep retrying so
            # that monitoring activates automatically once the user runs
            # 'newgrp cyberpet' or opens a fresh login shell.
            if [[ "$_CYBERPET_PERMISSION_WARNED" != "true" ]]; then
                echo -e "${_CP_YELLOW}${_CP_BOLD}⚠  CyberPet Warning:${_CP_RESET} ${_CP_YELLOW}socket permission denied; monitoring inactive in this shell.${_CP_RESET}" >&2
                echo -e "${_CP_CYAN}Run 'exec newgrp cyberpet' (or open a fresh login shell) to activate monitoring.${_CP_RESET}" >&2
                _CYBERPET_PERMISSION_WARNED="true"
            fi
            return 0
            ;;
        WARN:*)
            # Extract reason after "WARN:"
            local reason="${response#WARN:}"
            echo -e "${_CP_YELLOW}${_CP_BOLD}⚠  CyberPet Warning:${_CP_RESET} ${_CP_YELLOW}${reason}${_CP_RESET}" >&2
            # Allow command to proceed with warning
            return 0
            ;;
        BLOCK:*)
            # Extract reason after "BLOCK:"
            local block_payload="${response#BLOCK:}"
            local reason="$block_payload"
            local override_token=""
            if [[ "$block_payload" == *"|TOKEN:"* ]]; then
                reason="${block_payload%%|TOKEN:*}"
                override_token="${block_payload##*|TOKEN:}"
            fi
            echo -e "${_CP_RED}${_CP_BOLD}🛑 CyberPet BLOCKED:${_CP_RESET} ${_CP_RED}${reason}${_CP_RESET}" >&2
            echo -e "${_CP_CYAN}Type the override phrase to allow, or press Enter to cancel:${_CP_RESET}" >&2

            # Read override input
            local override
            if ! read -t "$CYBERPET_OVERRIDE_TIMEOUT" -r override; then
                echo -e "${_CP_RED}Override timed out. Command blocked.${_CP_RESET}" >&2
                return 1
            fi

            if [[ -n "$override" ]]; then
                local override_response
                if [[ -n "$override_token" ]]; then
                    # Preferred path: token-based override avoids replaying command.
                    override_response=$(
                        CYBERPET_SOCKET="$CYBERPET_SOCKET" "$CYBERPET_PYTHON" "$CYBERPET_CLIENT" \
                            --override-token "$override_token" \
                            --override-phrase "$override" 2>/dev/null
                    )
                else
                    # Backward-compatible fallback for older daemons.
                    override_response=$(
                        printf '%s\n%s\n' "$cmd" "$override" | CYBERPET_SOCKET="$CYBERPET_SOCKET" "$CYBERPET_PYTHON" "$CYBERPET_CLIENT" 2>/dev/null
                    )
                fi
                if [[ "$override_response" == "ALLOW"* ]]; then
                    echo -e "${_CP_GREEN}✓ Override accepted. Command allowed.${_CP_RESET}" >&2
                    return 0
                else
                    echo -e "${_CP_RED}✗ Override denied. Command blocked.${_CP_RESET}" >&2
                    return 1
                fi
            else
                echo -e "${_CP_RED}Command cancelled.${_CP_RESET}" >&2
                return 1
            fi
            ;;
        *)
            # Unknown response or error — allow through
            return 0
            ;;
    esac
}

_cyberpet_select_full_cmd() {
    # Args:
    #   $1 = current BASH_COMMAND
    #   $2 = output of `history 1`
    local current_cmd="$1"
    local history_line="$2"
    local history_id=""
    local history_cmd=""
    _CYBERPET_SELECTED_CMD=""

    history_id=$(printf '%s\n' "$history_line" | sed -n 's/^ *\([0-9]\+\).*/\1/p')
    history_cmd=$(printf '%s\n' "$history_line" | sed 's/^ *[0-9]\+[[:space:]]*//')

    # Prefer history row as authoritative for full pipelines. Evaluate once
    # per row id to avoid stale history reuse across subsequent trap calls.
    if [[ -n "$history_id" ]]; then
        if [[ "$history_id" == "$_CYBERPET_LAST_HISTORY_ID" ]]; then
            return 1
        fi
        _CYBERPET_LAST_HISTORY_ID="$history_id"
        if [[ -n "$history_cmd" ]]; then
            _CYBERPET_SELECTED_CMD="$history_cmd"
        else
            _CYBERPET_SELECTED_CMD="$current_cmd"
        fi
        return 0
    fi

    # Fallback for shells with history disabled.
    if [[ "$current_cmd" == "$_CYBERPET_LAST_CHECKED" ]]; then
        return 1
    fi
    _CYBERPET_LAST_CHECKED="$current_cmd"
    _CYBERPET_SELECTED_CMD="$current_cmd"
    return 0
}

# --------------------------------------------------------------------------
# Bash preexec hook (using DEBUG trap + history to capture full pipeline)
# --------------------------------------------------------------------------
if [[ -n "$BASH_VERSION" && $- == *i* ]]; then
    # Enable extdebug so the DEBUG trap can cancel commands (return 1 = skip command)
    shopt -s extdebug

    # Mark shell as ready only after first prompt to avoid checking rc/startup commands.
    _cyberpet_mark_ready() {
        _CYBERPET_READY=1
    }

    if declare -p PROMPT_COMMAND >/dev/null 2>&1; then
        if declare -p PROMPT_COMMAND 2>/dev/null | grep -q 'declare -a'; then
            _cp_has_ready=0
            for _cp_entry in "${PROMPT_COMMAND[@]}"; do
                if [[ "$_cp_entry" == "_cyberpet_mark_ready" ]]; then
                    _cp_has_ready=1
                    break
                fi
            done
            if [[ "$_cp_has_ready" -eq 0 ]]; then
                PROMPT_COMMAND+=("_cyberpet_mark_ready")
            fi
        elif [[ "$PROMPT_COMMAND" != *"_cyberpet_mark_ready"* ]]; then
            PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND; }_cyberpet_mark_ready"
        fi
    else
        PROMPT_COMMAND="_cyberpet_mark_ready"
    fi

    _cyberpet_debug_trap() {
        [[ "$_CYBERPET_READY" != "1" ]] && return 0
        [[ "${_CYBERPET_IN_CHECK:-0}" == "1" ]] && return 0

        # Skip our own internal functions
        [[ "$BASH_COMMAND" == _cyberpet_* ]] && return 0
        [[ "$BASH_COMMAND" == "_CYBERPET"* ]] && return 0

        # Get the FULL command line the user typed, including pipe operators.
        # Bash adds to the history list when the user presses Enter, BEFORE
        # the DEBUG trap fires, so history 1 always holds the full pipeline.
        local history_line
        local full_cmd
        history_line=$(HISTTIMEFORMAT='' history 1 2>/dev/null)
        _cyberpet_select_full_cmd "$BASH_COMMAND" "$history_line" || return 0
        full_cmd="$_CYBERPET_SELECTED_CMD"

        _CYBERPET_IN_CHECK=1
        _cyberpet_check_command "$full_cmd"
        local rc=$?
        _CYBERPET_IN_CHECK=0
        return $rc
    }

    trap '_cyberpet_debug_trap' DEBUG
fi

# --------------------------------------------------------------------------
# Zsh hook (ZLE accept-line widget override)
# --------------------------------------------------------------------------
if [[ -n "$ZSH_VERSION" ]]; then
    _cyberpet_accept_line() {
        local full_cmd="$BUFFER"
        _cyberpet_check_command "$full_cmd"
        local result=$?
        if [[ $result -eq 0 ]]; then
            zle .accept-line
        else
            # Keep command in buffer so the user can edit or cancel it.
            zle redisplay
        fi
    }

    # Override Enter handling only in interactive zsh with zle enabled.
    if [[ -o interactive ]] && command -v zle >/dev/null 2>&1; then
        zle -N accept-line _cyberpet_accept_line
    fi
fi
