#!/usr/bin/env bash
# AEPTF installer (Linux). Creates a virtualenv and installs the package.
# Deliberately does NOT install nmap -- that's a separate, explicit step
# documented in README.md so it's never silently pulled in.
set -euo pipefail

PYTHON_BIN="${PYTHON_BIN:-python3}"
VENV_DIR="${VENV_DIR:-.venv}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  echo "error: $PYTHON_BIN not found. Install Python 3.10+ first." >&2
  exit 1
fi

echo "Creating virtual environment in $VENV_DIR ..."
"$PYTHON_BIN" -m venv "$VENV_DIR"

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Upgrading pip ..."
pip install --upgrade pip >/dev/null

echo "Installing AEPTF (editable) ..."
pip install -e .

echo
echo "Install complete."
echo "Next steps:"
echo "  source $VENV_DIR/bin/activate"
echo "  aeptf init-db"
echo "  aeptf serve --reload"
echo
echo "Nmap is required for the reconnaissance and scanning plugins and is"
echo "NOT installed by this script. Install it explicitly:"
echo "  sudo apt update && sudo apt install -y nmap"
