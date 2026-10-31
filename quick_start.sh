#!/bin/bash
# Quick start for mobile users

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "🚀 Quick Start CIVOPS-Radar"
echo "1. Starting web server..."
python3 server/app.py --host 0.0.0.0 --port 5000 &
SERVER_PID=$!

trap 'kill $SERVER_PID 2>/dev/null || true; exit 0' INT TERM

echo "2. Web interface ready at: http://localhost:5000"
echo "3. Open browser and navigate to the URL above"
echo "4. Press Ctrl+C to stop"
wait
