#!/bin/bash
# CIVOPS-Radar Mobile Startup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR" || exit 1

echo "🛰️ Starting CIVOPS-Radar Mobile..."
echo "📱 Web interface: http://localhost:5000"
echo "📊 Demo interface: http://localhost:5000/demo"
echo "Press Ctrl+C to stop"

# Start the web server
python3 server/app.py --host 0.0.0.0 --port 5000 &
SERVER_PID=$!

# Start the scanner
./termux/radar_prototype.sh scan &
SCANNER_PID=$!

# Wait for user interrupt
trap 'kill $SERVER_PID $SCANNER_PID 2>/dev/null || true; echo ""; echo "🛑 CIVOPS-Radar stopped"; exit 0' INT TERM
wait
