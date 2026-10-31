#!/bin/bash
# CIVOPS-Radar: Main Wi-Fi Scanning Script
# Author: CIVOPS-Radar Contributors
# License: MIT
# 
# This script performs passive Wi-Fi scanning using Termux:API
# and stores results in SQLite database for radar visualization.

set -euo pipefail

# Configuration
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
elif [[ -d "$HOME/radar" ]]; then
    PROJECT_ROOT="$HOME/radar"
else
    PROJECT_ROOT="$(pwd)"
fi
RADAR_DIR="${RADAR_DIR:-$PROJECT_ROOT}"
DB_PATH="${RADAR_DIR}/data/scans.db"
SCAN_INTERVAL=5  # seconds between scans
MAX_SCANS=1000   # maximum scans to keep in database
LOG_FILE="${RADAR_DIR}/scan.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Error handling
error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

# Check if running in Termux
check_termux() {
    if [[ ! -d "/data/data/com.termux" ]]; then
        error_exit "This script must be run in Termux environment"
    fi
}

# Check Termux:API installation
check_termux_api() {
    if ! command -v termux-wifi-scaninfo &> /dev/null; then
        error_exit "Termux:API not installed. Run: pkg install termux-api"
    fi
}

# Create radar directory structure
setup_directories() {
    log "${BLUE}Setting up radar directories...${NC}"
    mkdir -p "$RADAR_DIR"/{data,exports,samples,server}
    mkdir -p "$RADAR_DIR"/server/{templates,static}
}

# Initialize SQLite database
init_database() {
    log "${BLUE}Initializing SQLite database...${NC}"
    
    # Create base table if it doesn't exist
    sqlite3 "$DB_PATH" << 'EOF'
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    bssid TEXT NOT NULL,
    ssid TEXT,
    capabilities TEXT,
    frequency INTEGER,
    level INTEGER,
    distance REAL,
    risk_score INTEGER DEFAULT 0,
    is_hidden BOOLEAN DEFAULT 0,
    is_open BOOLEAN DEFAULT 0,
    vendor TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    scan_count INTEGER DEFAULT 1,
    is_flock BOOLEAN DEFAULT 0,
    flock_type TEXT DEFAULT '',
    alpr_confidence TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_bssid ON scans(bssid);
CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp);
CREATE INDEX IF NOT EXISTS idx_level ON scans(level);
EOF

    # Migration for tables created before Flock detection
    sqlite3 "$DB_PATH" "ALTER TABLE scans ADD COLUMN is_flock BOOLEAN DEFAULT 0;" 2>/dev/null || true
    sqlite3 "$DB_PATH" "ALTER TABLE scans ADD COLUMN flock_type TEXT DEFAULT '';" 2>/dev/null || true
    sqlite3 "$DB_PATH" "ALTER TABLE scans ADD COLUMN alpr_confidence TEXT DEFAULT '';" 2>/dev/null || true
    sqlite3 "$DB_PATH" "CREATE INDEX IF NOT EXISTS idx_flock ON scans(is_flock);" 2>/dev/null || true
    sqlite3 "$DB_PATH" "DROP VIEW IF EXISTS latest_scans;" 2>/dev/null || true

    sqlite3 "$DB_PATH" << 'EOF'
CREATE VIEW IF NOT EXISTS latest_scans AS
SELECT 
    bssid,
    ssid,
    capabilities,
    frequency,
    level,
    distance,
    risk_score,
    is_hidden,
    is_open,
    vendor,
    first_seen,
    last_seen,
    scan_count,
    timestamp,
    is_flock,
    flock_type,
    alpr_confidence
FROM scans s1
WHERE timestamp = (
    SELECT MAX(timestamp) 
    FROM scans s2 
    WHERE s2.bssid = s1.bssid
);
EOF
}

# Perform single Wi-Fi scan
perform_scan() {
    local scan_output
    local scan_count=0
    
    log "${YELLOW}Performing Wi-Fi scan...${NC}"
    
    # Use termux-wifi-scaninfo to get scan results
    if ! scan_output=$(termux-wifi-scaninfo 2>/dev/null); then
        log "${RED}Failed to get scan results. This may be due to Android throttling.${NC}"
        return 1
    fi
    
    # Check if scan output is empty
    if [[ -z "$scan_output" || "$scan_output" == "[]" ]]; then
        log "${YELLOW}No networks detected in scan.${NC}"
        return 1
    fi
    
    # Process scan results with Python safely via stdin
    echo "$scan_output" | python3 -c "
import json
import sqlite3
import sys
import os
import math
from datetime import datetime

RADAR_DIR = '''$RADAR_DIR'''
DB_PATH = '''$DB_PATH'''

# Try importing RiskEngine and FlockDetector if available
risk_engine = None
flock_detector = None
try:
    sys.path.insert(0, os.path.join(RADAR_DIR, 'server'))
    from risk_engine import RiskEngine, NetworkProfile
    from flock_detector import detector as flock_detector
    risk_engine = RiskEngine()
except Exception:
    pass

# Common OUI prefix mapping for vendor detection
OUI_MAP = {
    '00:11:22': 'Cisco',
    '00:14:bf': 'Linksys',
    '00:1e:2a': 'Netgear',
    '00:26:f2': 'Netgear',
    '14:59:c0': 'TP-Link',
    '50:c7:bf': 'TP-Link',
    'ec:08:6b': 'TP-Link',
    '00:1a:2b': 'Ubiquiti',
    '78:8a:20': 'Ubiquiti',
    '00:0c:29': 'VMware',
    '00:1a:11': 'Google',
    '3c:5a:37': 'Google',
    'f4:f5:e8': 'Google',
    '00:17:88': 'Philips',
    '00:1f:f3': 'Apple',
    '10:40:f3': 'Apple',
    '3c:06:30': 'Apple',
    '70:ef:00': 'Apple',
    'bc:d1:1f': 'Apple',
    'f0:18:98': 'Apple',
    '00:12:fb': 'Samsung',
    '34:23:ba': 'Samsung',
    '60:af:6d': 'Samsung',
    '00:21:6a': 'Intel',
    '34:13:e8': 'Intel',
    '00:18:0a': 'Cisco-Meraki',
    '00:24:6c': 'Aruba',
    '24:de:c6': 'Aruba',
    'cc:40:d0': 'Amazon',
    'fc:65:de': 'Amazon'
}

def lookup_vendor(bssid):
    if not bssid:
        return 'Unknown'
    prefix = bssid.lower()[:8]
    return OUI_MAP.get(prefix, 'Unknown')

def calculate_distance(rssi, frequency=2412):
    '''Calculate approximate distance (in meters) from RSSI using log-distance model'''
    if rssi == 0 or rssi is None:
        return 999.0
    try:
        # Standard indoor log-distance model: RSSI = -30 - 10*n*log10(d), with n=2.8
        exp = (-30.0 - float(rssi)) / 28.0
        d = 10.0 ** exp
        return round(max(0.5, min(300.0, d)), 1)
    except Exception:
        return 50.0

def calculate_risk_score(ssid, capabilities, level, frequency, is_hidden, is_open, vendor, bssid):
    '''Calculate risk score using RiskEngine or fallback algorithm'''
    if risk_engine:
        try:
            profile = NetworkProfile(
                bssid=bssid,
                ssid=ssid or '',
                capabilities=capabilities or '',
                frequency=frequency or 2412,
                level=level,
                is_hidden=is_hidden,
                is_open=is_open,
                vendor=vendor
            )
            score, _ = risk_engine.calculate_risk_score(profile)
            return score
        except Exception:
            pass

    score = 0
    if is_open:
        score += 30
    if is_hidden:
        score += 20
    if level < -80:
        score += 5
    elif level > -30:
        score += 10
    return min(100, max(0, score))

def process_scan_data():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        scan_data = json.load(sys.stdin)
        current_time = datetime.now().isoformat()
        
        for network in scan_data:
            bssid = network.get('bssid', '').strip()
            if not bssid:
                continue
            
            ssid = network.get('ssid', '').strip()
            capabilities = network.get('capabilities', '').strip()
            # Support both termux-wifi-scaninfo keys and sample/generic keys
            frequency = network.get('frequency_mhz') or network.get('frequency', 2412)
            level = network.get('rssi') if 'rssi' in network else network.get('level', -100)
            
            is_hidden = (ssid == '' or ssid.lower() == '<unknown ssid>')
            is_open = ('WPA' not in capabilities and 'WEP' not in capabilities and 'RSN' not in capabilities and 'SAE' not in capabilities)
            
            vendor = lookup_vendor(bssid)
            distance = calculate_distance(level, frequency)
            risk_score = calculate_risk_score(ssid, capabilities, level, frequency, is_hidden, is_open, vendor, bssid)
            
            is_flock = 0
            flock_type = ''
            alpr_confidence = 'NONE'
            if flock_detector:
                try:
                    f_info = flock_detector.analyze(bssid, ssid, capabilities, level, frequency)
                    if f_info.is_flock or f_info.is_alpr:
                        is_flock = 1 if f_info.is_flock else 0
                        flock_type = f_info.device_type
                        alpr_confidence = f_info.confidence
                        if f_info.is_flock:
                            vendor = f_info.vendor
                            print(f'🚨 [ALERT] Flock Safety ALPR Detected: {ssid or \"Hidden\"} ({bssid}) - {flock_type} [Confidence: {alpr_confidence}]')
                except Exception:
                    pass
            
            cursor.execute('SELECT id, scan_count FROM scans WHERE bssid = ? ORDER BY timestamp DESC LIMIT 1', (bssid,))
            existing = cursor.fetchone()
            
            if existing:
                cursor.execute('''
                    UPDATE scans 
                    SET timestamp = ?, ssid = ?, capabilities = ?, frequency = ?,
                        level = ?, distance = ?, risk_score = ?, is_hidden = ?, 
                        is_open = ?, vendor = ?, last_seen = ?, scan_count = scan_count + 1,
                        is_flock = ?, flock_type = ?, alpr_confidence = ?
                    WHERE bssid = ?
                ''', (current_time, ssid, capabilities, frequency, level, distance, 
                      risk_score, is_hidden, is_open, vendor, current_time, 
                      is_flock, flock_type, alpr_confidence, bssid))
            else:
                cursor.execute('''
                    INSERT INTO scans (bssid, ssid, capabilities, frequency, level, 
                                    distance, risk_score, is_hidden, is_open, 
                                    vendor, first_seen, last_seen, scan_count,
                                    is_flock, flock_type, alpr_confidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                ''', (bssid, ssid, capabilities, frequency, level, distance, 
                      risk_score, is_hidden, is_open, vendor, current_time, current_time,
                      is_flock, flock_type, alpr_confidence))
        
        conn.commit()
        print(f'Processed {len(scan_data)} networks')
    except Exception as e:
        print(f'Error processing scan data: {e}', file=sys.stderr)
        sys.exit(1)
    finally:
        conn.close()

process_scan_data()
" || {
        log "${RED}Failed to process scan data${NC}"
        return 1
    }
    
    log "${GREEN}Scan completed successfully${NC}"
    return 0
}

# Clean old scans to prevent database bloat
cleanup_old_scans() {
    log "${BLUE}Cleaning up old scans...${NC}"
    sqlite3 "$DB_PATH" "DELETE FROM scans WHERE timestamp < datetime('now', '-24 hours');"
    sqlite3 "$DB_PATH" "VACUUM;"
}

# Display current scan statistics
show_stats() {
    local total_networks
    local active_networks
    local high_risk_networks
    local flock_cameras
    
    total_networks=$(sqlite3 -batch -noheader "$DB_PATH" "SELECT COUNT(DISTINCT bssid) FROM scans;")
    active_networks=$(sqlite3 -batch -noheader "$DB_PATH" "SELECT COUNT(*) FROM latest_scans;")
    high_risk_networks=$(sqlite3 -batch -noheader "$DB_PATH" "SELECT COUNT(*) FROM latest_scans WHERE risk_score > 50;")
    flock_cameras=$(sqlite3 -batch -noheader "$DB_PATH" "SELECT COUNT(*) FROM latest_scans WHERE is_flock = 1;")
    
    log "${GREEN}=== Scan Statistics ===${NC}"
    log "Total networks discovered: $total_networks"
    log "Currently active: $active_networks"
    log "High risk networks: $high_risk_networks"
    if [ "$flock_cameras" -gt 0 ]; then
        log "${RED}🚨 Flock / ALPR Cameras Detected: $flock_cameras${NC}"
    else
        log "${GREEN}Flock / ALPR Cameras: 0 (No surveillance cameras in range)${NC}"
    fi
}

# Main scanning loop
scan_loop() {
    local scan_count=0
    
    log "${GREEN}Starting CIVOPS-Radar scanning loop...${NC}"
    log "Scan interval: ${SCAN_INTERVAL} seconds"
    log "Press Ctrl+C to stop"
    
    while true; do
        scan_count=$((scan_count + 1))
        log "${BLUE}=== Scan #$scan_count ===${NC}"
        
        if perform_scan; then
            show_stats
        else
            log "${YELLOW}Scan failed, retrying in ${SCAN_INTERVAL} seconds...${NC}"
        fi
        
        # Cleanup every 10 scans
        if ((scan_count % 10 == 0)); then
            cleanup_old_scans
        fi
        
        sleep "$SCAN_INTERVAL"
    done
}

# Export scan data
export_data() {
    local format="${1:-json}"
    local output_file="${RADAR_DIR}/exports/scan_export_$(date +%Y%m%d_%H%M%S).${format}"
    
    case "$format" in
        json)
            sqlite3 -json "$DB_PATH" "SELECT * FROM latest_scans;" > "$output_file"
            ;;
        csv)
            sqlite3 -header -csv "$DB_PATH" "SELECT * FROM latest_scans;" > "$output_file"
            ;;
        *)
            log "${RED}Unsupported format: $format${NC}"
            return 1
            ;;
    esac
    
    log "${GREEN}Data exported to: $output_file${NC}"
}

# Main function
main() {
    log "${GREEN}=== CIVOPS-Radar Scanner ===${NC}"
    log "Initializing Wi-Fi scanning system..."
    
    # Pre-flight checks
    check_termux
    check_termux_api
    
    # Setup
    setup_directories
    init_database
    
    # Handle command line arguments
    case "${1:-scan}" in
        scan)
            scan_loop
            ;;
        once)
            perform_scan
            show_stats
            ;;
        export)
            export_data "${2:-json}"
            ;;
        stats)
            show_stats
            ;;
        init)
            log "${GREEN}Database initialized successfully${NC}"
            ;;
        *)
            echo "Usage: $0 {scan|once|export|stats|init}"
            echo "  scan   - Start continuous scanning (default)"
            echo "  once   - Perform a single scan and exit"
            echo "  export - Export data (json|csv)"
            echo "  stats  - Show current statistics"
            echo "  init   - Initialize database only"
            exit 1
            ;;
    esac
}

# Trap Ctrl+C for graceful shutdown
trap 'log "${YELLOW}Shutting down CIVOPS-Radar...${NC}"; exit 0' INT

# Run main function
main "$@"
