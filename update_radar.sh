#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "🔄 Updating CIVOPS-Radar..."
if [ -d .git ]; then
    git pull origin main || echo "⚠ Git pull failed, continuing..."
else
    echo "ℹ Not a git repository, skipping git pull"
fi

echo "📦 Reinstalling dependencies..."
if command -v pkg &>/dev/null; then
    pkg install -y python-numpy 2>/dev/null || true
fi

grep -vi '^numpy' requirements.txt > .requirements-termux.txt 2>/dev/null || true
if [ -s .requirements-termux.txt ]; then
    PYTHON_BIN="${PREFIX:-/data/data/com.termux/files/usr}/bin/python3"
    if [ ! -x "$PYTHON_BIN" ]; then
        PYTHON_BIN="python3"
    fi
    $PYTHON_BIN -m pip install -r .requirements-termux.txt || python3 -m pip install -r .requirements-termux.txt || true
    rm -f .requirements-termux.txt
fi

python3 -c "import numpy; print('numpy OK', numpy.__version__)" 2>/dev/null || true
echo "✅ Update complete!"
echo "Run ./start_mobile.sh to restart"
