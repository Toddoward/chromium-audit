#!/bin/sh
# ============================================================
#  chromium-audit launcher for Linux / macOS
#  - Finds python3, version 3.8 or newer
#  - Installs it with Homebrew on macOS, or with your package
#    manager on Linux, when it is missing
#  - Runs chromium-audit.py with any arguments you pass
#     ./run.sh            audit only
#     ./run.sh --update   audit and update what can be updated
#     ./run.sh --json     machine-readable output
# ============================================================
set -u
DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

have_python() {
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null
}

if ! have_python; then
    echo "Python 3 was not found, or is older than 3.8."
    OS=$(uname -s)
    if [ "$OS" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo "Installing Python with Homebrew..."
            brew install python || { echo "Homebrew install failed."; exit 1; }
        else
            echo "Please install Python 3 from https://www.python.org/downloads/"
            echo "or install Homebrew from https://brew.sh and run this file again."
            open "https://www.python.org/downloads/" 2>/dev/null || true
            exit 1
        fi
    else
        echo "Installing Python 3 with your package manager. sudo may ask for your password..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update && sudo apt-get install -y python3 || exit 1
        elif command -v dnf >/dev/null 2>&1; then
            sudo dnf install -y python3 || exit 1
        elif command -v yum >/dev/null 2>&1; then
            sudo yum install -y python3 || exit 1
        elif command -v pacman >/dev/null 2>&1; then
            sudo pacman -S --noconfirm python || exit 1
        elif command -v zypper >/dev/null 2>&1; then
            sudo zypper install -y python3 || exit 1
        elif command -v apk >/dev/null 2>&1; then
            sudo apk add python3 || exit 1
        else
            echo "No supported package manager was found."
            echo "Please install Python 3 manually and run this file again."
            exit 1
        fi
    fi
fi

if ! have_python; then
    echo "Python 3 is still not available. Please install it and try again."
    exit 1
fi

exec python3 "$DIR/chromium-audit.py" "$@"
