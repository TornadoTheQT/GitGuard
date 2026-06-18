#!/usr/bin/env bash
#
# GitGuard installer — autodetects a suitable Python interpreter, creates a
# virtual environment, and installs GitGuard into it.
#
# Usage:
#   ./install.sh            # install the gitguard CLI
#   ./install.sh --dev      # also install dev/test extras (pytest)
#   ./install.sh --with-fix-agent
#                           # install GitGuard plus scan --fix dependencies
#   ./install.sh --without-fix-agent
#                           # skip optional scan --fix dependency setup
#   ./install.sh --no-fix-agent-auth
#                           # install fix-agent packages but skip Claude login
#   VENV=.venv ./install.sh # override the venv location (default: .venv)
#
set -euo pipefail

# Resolve the repo root so the script works from any working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

VENV="${VENV:-.venv}"
EXTRAS="."
INSTALL_FIX_AGENT="prompt"
FIX_AGENT_AUTH="1"
for arg in "$@"; do
    case "$arg" in
        --dev) EXTRAS=".[dev]" ;;
        --with-fix-agent) INSTALL_FIX_AGENT="yes" ;;
        --without-fix-agent|--no-fix-agent) INSTALL_FIX_AGENT="no" ;;
        --no-fix-agent-auth) FIX_AGENT_AUTH="0" ;;
        -h|--help)
            awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

# --- Determine the minimum Python version dynamically -----------------------
# Single source of truth: the `requires-python` field in pyproject.toml.
# e.g. ">=3.9"  ->  MIN_MAJOR=3 MIN_MINOR=9
REQUIRES="$(sed -n 's/^[[:space:]]*requires-python[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' pyproject.toml)"
MIN_VER="$(printf '%s' "$REQUIRES" | grep -oE '[0-9]+\.[0-9]+' | head -n1)"
if [ -z "$MIN_VER" ]; then
    MIN_VER="3.9"  # fallback if pyproject is unparseable
fi
MIN_MAJOR="${MIN_VER%%.*}"
MIN_MINOR="${MIN_VER##*.}"

echo "GitGuard requires Python >= ${MIN_VER}"

# --- Find qualifying interpreters -------------------------------------------
# Probe versioned binaries (newest first) plus the generic names, keeping every
# one that satisfies the minimum version. We collect a list rather than a single
# pick so we can fall through if the preferred interpreter can't build a venv.
candidates=()
for minor in $(seq 20 -1 "$MIN_MINOR"); do
    candidates+=("python${MIN_MAJOR}.${minor}")
done
candidates+=("python${MIN_MAJOR}" "python")

qualifying=()
seen=""
for cand in "${candidates[@]}"; do
    path="$(command -v "$cand" 2>/dev/null)" || continue
    case "$seen" in *"|$path|"*) continue ;; esac  # de-dupe by resolved path
    seen="${seen}|$path|"
    if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info[:2] >= ($MIN_MAJOR, $MIN_MINOR) else 1)" 2>/dev/null; then
        qualifying+=("$cand")
    fi
done

if [ "${#qualifying[@]}" -eq 0 ]; then
    echo "Error: no Python >= ${MIN_VER} found on PATH." >&2
    echo "Install a recent Python (e.g. from python.org or your package manager) and retry." >&2
    exit 1
fi

# --- Create the venv (trying each interpreter until one succeeds) -----------
PY=""
if [ -d "$VENV" ]; then
    echo "Reusing existing virtual environment in ${VENV}/"
    PY="reused"
else
    for cand in "${qualifying[@]}"; do
        ver="$("$cand" -c 'import sys; print("%d.%d.%d" % sys.version_info[:3])')"
        echo "Creating virtual environment with $(command -v "$cand") (Python ${ver})…"
        if "$cand" -m venv "$VENV" 2>/tmp/gitguard-venv.err; then
            PY="$cand"
            break
        fi
        echo "  ↳ that interpreter can't build a venv here; trying the next one." >&2
        rm -rf "$VENV"
    done
    if [ -z "$PY" ]; then
        echo "Error: found Python >= ${MIN_VER}, but none could create a virtualenv." >&2
        echo "Last error:" >&2
        cat /tmp/gitguard-venv.err >&2 || true
        exit 1
    fi
fi

VENV_PY="$VENV/bin/python"
[ -x "$VENV_PY" ] || VENV_PY="$VENV/Scripts/python.exe"  # Windows/Git-Bash

echo "Upgrading pip…"
"$VENV_PY" -m pip install --quiet --upgrade pip

echo "Installing GitGuard (${EXTRAS})…"
"$VENV_PY" -m pip install --quiet -e "$EXTRAS"

should_install_fix_agent() {
    case "$INSTALL_FIX_AGENT" in
        yes) return 0 ;;
        no) return 1 ;;
    esac
    if [ -t 0 ] && [ -t 1 ]; then
        printf "Install scan --fix support now? This installs the fix-agent runtime and checks Claude login. [Y/n] "
        read -r answer
        case "${answer:-Y}" in
            y|Y|yes|YES) return 0 ;;
            *) return 1 ;;
        esac
    fi
    return 1
}

if should_install_fix_agent; then
    echo
    echo "Setting up scan --fix support…"
    setup_args=(setup-fix-agent)
    if [ "$FIX_AGENT_AUTH" = "0" ]; then
        setup_args+=(--no-auth)
    fi
    "$VENV_PY" -m gitguard.cli "${setup_args[@]}"
fi

echo
echo "✓ GitGuard installed."
echo "  Activate the environment:  source ${VENV}/bin/activate"
echo "  Then run:                  gitguard --help"
echo "  Setup scan --fix later:    gitguard setup-fix-agent"
