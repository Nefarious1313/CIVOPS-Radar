#!/usr/bin/env python3
"""
CIVOPS-Radar: Flask Web Server
Author: CIVOPS-Radar Contributors
License: MIT

Main Flask application for the radar web interface.
Provides real-time Wi-Fi network visualization and data export.
"""

import os
import json
import sqlite3
import math
import time
import hashlib
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify, request, send_file
from flask_cors import CORS
import threading
import queue

try:
    from flock_detector import detector as flock_detector
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from flock_detector import detector as flock_detector

try:
    from police_vehicle_detector import detector as police_vehicle_detector
except ImportError:
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from police_vehicle_detector import detector as police_vehicle_detector

# Configuration
RADAR_DIR = os.environ.get("RADAR_DIR") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(RADAR_DIR, "data", "scans.db")
EXPORT_DIR = os.path.join(RADAR_DIR, "exports")

# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Global variables for real-time updates
scan_queue = queue.Queue()
last_scan_time = None

class RadarData:
    """Handle radar data operations and calculations"""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.ensure_database()
    
    def ensure_database(self):
        """Ensure database exists and is properly initialized"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables if they don't exist
        cursor.execute('''
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
                alpr_confidence TEXT DEFAULT '',
                is_police_vehicle BOOLEAN DEFAULT 0,
                police_vehicle_type TEXT DEFAULT '',
                police_confidence TEXT DEFAULT ''
            )
        ''')
        
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_bssid ON scans(bssid)
        ''')
        cursor.execute('''
            CREATE INDEX IF NOT EXISTS idx_timestamp ON scans(timestamp)
        ''')
        
        # Ensure Flock / police-vehicle columns exist for older databases
        for col_def in [
            "is_flock BOOLEAN DEFAULT 0",
            "flock_type TEXT DEFAULT ''",
            "alpr_confidence TEXT DEFAULT ''",
            "is_police_vehicle BOOLEAN DEFAULT 0",
            "police_vehicle_type TEXT DEFAULT ''",
            "police_confidence TEXT DEFAULT ''"
        ]:
            try:
                cursor.execute(f"ALTER TABLE scans ADD COLUMN {col_def}")
            except sqlite3.OperationalError:
                pass
                
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_flock ON scans(is_flock)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_police_vehicle ON scans(is_police_vehicle)")
        
        conn.commit()
        conn.close()
    
    def get_latest_scans(self, limit=100):
        """Get latest scan results for radar display"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT 
                bssid, ssid, capabilities, frequency, level, distance, 
                risk_score, is_hidden, is_open, vendor, first_seen, last_seen,
                scan_count, timestamp, is_flock, flock_type, alpr_confidence,
                is_police_vehicle, police_vehicle_type, police_confidence
            FROM (
                SELECT *, ROW_NUMBER() OVER (PARTITION BY bssid ORDER BY timestamp DESC, id DESC) as rn
                FROM scans
            )
            WHERE rn = 1
            ORDER BY is_police_vehicle DESC, is_flock DESC, timestamp DESC
            LIMIT ?
        '''
        
        cursor.execute(query, (limit,))
        columns = [description[0] for description in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]
        
        # Retroactive on-the-fly Flock check for rows saved before detector was enabled
        for item in results:
            if not item.get('is_flock'):
                f_res = flock_detector.analyze(
                    item.get('bssid'),
                    item.get('ssid'),
                    item.get('capabilities'),
                    item.get('level'),
                    item.get('frequency')
                )
                if f_res.is_flock or f_res.is_alpr:
                    item['is_flock'] = 1 if f_res.is_flock else 0
                    item['flock_type'] = f_res.device_type
                    item['alpr_confidence'] = f_res.confidence
                    if f_res.is_flock and item.get('vendor') in ['Unknown', None, '']:
                        item['vendor'] = f_res.vendor

            # Retroactive police-vehicle check for rows saved before this detector existed
            if not item.get('is_police_vehicle'):
                p_res = police_vehicle_detector.analyze(
                    item.get('bssid'),
                    item.get('ssid'),
                    item.get('capabilities'),
                    item.get('level'),
                    item.get('frequency')
                )
                if p_res.confidence_score > 0:
                    item['police_confidence'] = p_res.confidence
                    if p_res.is_police_vehicle:
                        item['is_police_vehicle'] = 1
                        item['police_vehicle_type'] = p_res.device_type
                        if item.get('vendor') in ['Unknown', None, '']:
                            item['vendor'] = p_res.vendor
        
        conn.close()
        return results
    
    def get_scan_statistics(self):
        """Get overall scan statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        stats = {}
        
        # Total networks discovered
        cursor.execute("SELECT COUNT(DISTINCT bssid) FROM scans")
        stats['total_networks'] = cursor.fetchone()[0] or 0
        
        # Currently active networks (seen in last 15 minutes)
        cursor.execute("SELECT COUNT(*) FROM scans WHERE timestamp > datetime('now', '-15 minutes')")
        stats['active_networks'] = cursor.fetchone()[0] or 0
        
        # High risk networks
        cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_score > 50")
        stats['high_risk_networks'] = cursor.fetchone()[0] or 0
        
        # Open networks
        cursor.execute("SELECT COUNT(*) FROM scans WHERE is_open = 1")
        stats['open_networks'] = cursor.fetchone()[0] or 0
        
        # Hidden networks
        cursor.execute("SELECT COUNT(*) FROM scans WHERE is_hidden = 1")
        stats['hidden_networks'] = cursor.fetchone()[0] or 0
        
        # Flock & ALPR surveillance cameras
        cursor.execute("SELECT COUNT(DISTINCT bssid) FROM scans WHERE is_flock = 1")
        stats['flock_cameras'] = cursor.fetchone()[0] or 0
        
        cursor.execute("SELECT COUNT(DISTINCT bssid) FROM scans WHERE is_flock = 1 OR flock_type LIKE '%ALPR%'")
        stats['alpr_cameras'] = cursor.fetchone()[0] or 0
        
        # Police / law-enforcement vehicles
        cursor.execute("SELECT COUNT(DISTINCT bssid) FROM scans WHERE is_police_vehicle = 1")
        stats['police_vehicles'] = cursor.fetchone()[0] or 0
        
        conn.close()
        return stats
    
    def calculate_radar_position(self, bssid, level, distance):
        """Calculate radar position for network visualization"""
        # Use deterministic hash of BSSID for consistent angle across runs
        hash_bytes = hashlib.md5((bssid or '').encode('utf-8')).hexdigest()
        hash_val = int(hash_bytes[:4], 16) % 360
        angle = math.radians(hash_val)
        
        # Calculate position based on distance:
        # Stronger signals / closer networks appear closer to center (0, 0)
        # Weaker signals / distant networks appear closer to outer boundary
        max_distance = 250.0  # meters
        dist = float(distance) if distance is not None and distance >= 0 else 50.0
        normalized_distance = max(0.0, min(dist / max_distance, 1.0))
        # Keep radius between 0.12 (near center) and 0.88 (outer perimeter)
        radius = 0.12 + (normalized_distance * 0.76)
        
        x = radius * math.cos(angle)
        y = radius * math.sin(angle)
        
        return {
            'x': x,
            'y': y,
            'angle': hash_val,
            'radius': radius
        }
    
    def export_data(self, format_type='json'):
        """Export scan data in specified format"""
        scans = self.get_latest_scans(limit=1000)
        
        if format_type == 'json':
            return json.dumps(scans, indent=2, default=str)
        elif format_type == 'csv':
            import csv
            import io
            
            output = io.StringIO()
            if scans:
                writer = csv.DictWriter(output, fieldnames=scans[0].keys())
                writer.writeheader()
                writer.writerows(scans)
            return output.getvalue()
        elif format_type == 'kml':
            return self.generate_kml(scans)
        else:
            raise ValueError(f"Unsupported format: {format_type}")
    
    def generate_kml(self, scans):
        """Generate KML file for Google Earth visualization"""
        kml_header = '''<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
<Document>
    <name>CIVOPS-Radar Scan Results</name>
    <description>Wi-Fi network scan results</description>
'''
        
        kml_footer = '''
</Document>
</kml>'''
        
        kml_content = kml_header
        
        for scan in scans:
            if scan['ssid'] and scan['ssid'] != '':
                name = scan['ssid']
            else:
                name = f"Hidden Network ({scan['bssid']})"
            
            # Generate consistent coordinates for visualization based on BSSID
            # In real implementation, this would use GPS coordinates
            h_int = int(hashlib.md5((scan['bssid'] or '').encode('utf-8')).hexdigest()[:6], 16)
            lat = 37.7749 + ((h_int % 1000) - 500) / 100000
            lon = -122.4194 + (((h_int >> 10) % 1000) - 500) / 100000
            
            kml_content += f'''
    <Placemark>
        <name>{name}</name>
        <description>
            BSSID: {scan['bssid']}
            Signal: {scan['level']} dBm
            Risk Score: {scan['risk_score']}
            Security: {scan['capabilities']}
        </description>
        <Point>
            <coordinates>{lon},{lat},0</coordinates>
        </Point>
    </Placemark>'''
        
        kml_content += kml_footer
        return kml_content

# Initialize radar data handler
radar_data = RadarData(DB_PATH)

@app.route('/')
def index():
    """Main radar interface"""
    return render_template('radar.html')

@app.route('/demo')
def demo():
    """Interactive demo interface"""
    return render_template('demo.html')

@app.route('/api/signals')
def get_signals():
    """Get latest scan signals for radar display"""
    try:
        scans = radar_data.get_latest_scans(limit=50)
        
        # Process scans for radar display
        radar_signals = []
        for scan in scans:
            position = radar_data.calculate_radar_position(
                scan['bssid'], 
                scan['level'], 
                scan['distance']
            )
            
            signal = {
                'bssid': scan['bssid'],
                'ssid': scan['ssid'] or 'Hidden',
                'level': scan['level'],
                'distance': scan['distance'],
                'risk_score': scan['risk_score'],
                'is_hidden': scan['is_hidden'],
                'is_open': scan['is_open'],
                'capabilities': scan['capabilities'],
                'frequency': scan['frequency'],
                'vendor': scan['vendor'],
                'last_seen': scan['last_seen'],
                'scan_count': scan['scan_count'],
                'is_flock': bool(scan.get('is_flock')),
                'flock_type': scan.get('flock_type') or '',
                'alpr_confidence': scan.get('alpr_confidence') or 'NONE',
                'is_police_vehicle': bool(scan.get('is_police_vehicle')),
                'police_vehicle_type': scan.get('police_vehicle_type') or '',
                'police_confidence': scan.get('police_confidence') or 'NONE',
                'position': position
            }
            radar_signals.append(signal)
        
        # Check if any Flock cameras or police vehicles are active
        flock_found = any(s['is_flock'] for s in radar_signals)
        police_found = any(s['is_police_vehicle'] for s in radar_signals)
        
        return jsonify({
            'signals': radar_signals,
            'flock_detected': flock_found,
            'police_vehicle_detected': police_found,
            'timestamp': datetime.now().isoformat()
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/flock/status')
def get_flock_status():
    """Get active Flock Safety and ALPR surveillance status"""
    try:
        scans = radar_data.get_latest_scans(limit=100)
        flock_cameras = [s for s in scans if s.get('is_flock')]
        
        # Sort by distance (closest first)
        flock_cameras.sort(key=lambda s: s.get('distance') or 999.0)
        
        return jsonify({
            'status': 'alert' if flock_cameras else 'clear',
            'flock_detected': len(flock_cameras) > 0,
            'camera_count': len(flock_cameras),
            'nearest_camera': flock_cameras[0] if flock_cameras else None,
            'cameras': flock_cameras,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/flock/demo', methods=['POST', 'GET'])
def inject_flock_demo():
    """Inject realistic demo Flock Safety ALPR cameras for testing and validation"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        current_time = datetime.now().isoformat()
        
        demo_cameras = [
            (
                "b4:1e:52:84:a1:0b",
                "Flock-a10b",
                "[WPA2-PSK-CCMP][ESS]",
                2437,
                -48,
                4.5,
                95,
                0,
                0,
                "Flock Safety Inc.",
                current_time,
                current_time,
                12,
                1,
                "Flock Safety ALPR Camera (Falcon V2)",
                "CONFIRMED"
            ),
            (
                "70:c9:4e:32:19:f0",
                "fs ext battery",
                "[ESS]",
                2412,
                -55,
                7.8,
                90,
                0,
                1,
                "Flock Safety",
                current_time,
                current_time,
                8,
                1,
                "Flock Solar Power Telemetry",
                "CONFIRMED"
            ),
            (
                "00:03:7f:88:cd:e1",
                "",
                "[WPA2-PSK-CCMP][ESS]",
                2462,
                -64,
                16.2,
                85,
                1,
                0,
                "Qualcomm Atheros",
                current_time,
                current_time,
                5,
                1,
                "Suspected Flock Falcon ALPR (Stealth Probe)",
                "HIGH"
            )
        ]
        
        for cam in demo_cameras:
            # Delete any previous demo row with the same BSSID so re-running is idempotent.
            cursor.execute('DELETE FROM scans WHERE bssid = ?', (cam[0],))
            cursor.execute('''
                INSERT INTO scans (
                    bssid, ssid, capabilities, frequency, level, distance,
                    risk_score, is_hidden, is_open, vendor, first_seen,
                    last_seen, scan_count, is_flock, flock_type, alpr_confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', cam)
            
        conn.commit()
        conn.close()
        return jsonify({
            'status': 'demo_cameras_injected',
            'count': len(demo_cameras),
            'message': 'Sample Flock Safety cameras injected into database for testing'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/police-vehicle/status')
def get_police_vehicle_status():
    """Get active police / law-enforcement vehicle status"""
    try:
        scans = radar_data.get_latest_scans(limit=100)
        vehicles = [s for s in scans if s.get('is_police_vehicle')]

        # Sort by distance (closest first)
        vehicles.sort(key=lambda s: s.get('distance') or 999.0)

        return jsonify({
            'status': 'alert' if vehicles else 'clear',
            'police_vehicle_detected': len(vehicles) > 0,
            'vehicle_count': len(vehicles),
            'nearest_vehicle': vehicles[0] if vehicles else None,
            'vehicles': vehicles,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/police-vehicle/demo', methods=['POST', 'GET'])
def inject_police_vehicle_demo():
    """Inject realistic demo police-vehicle equipment for testing and validation"""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        current_time = datetime.now().isoformat()

        demo_vehicles = [
            (
                "70:1a:d5:12:34:56", "MPD-Fleet", "[WPA2-PSK-CCMP][ESS]",
                2437, -52, 6.1, 95, 0, 0, "Avigilon (Motorola Solutions)",
                current_time, current_time, 14, 1,
                "Police Department Vehicle", "CONFIRMED"
            ),
            (
                "00:30:44:ab:cd:ef", "", "[WPA2-PSK-CCMP][ESS]",
                5180, -61, 12.4, 70, 1, 0, "CradlePoint, Inc",
                current_time, current_time, 9, 1,
                "Suspected Police In-Car Router / Mobile Gateway (Hidden SSID)", "MEDIUM"
            ),
            (
                "00:04:7d:11:22:33", "Dispatch-1", "[WPA2-PSK-CCMP][ESS]",
                2412, -48, 4.2, 95, 0, 0, "Motorola Solutions Inc.",
                current_time, current_time, 21, 1,
                "Police Dispatch Vehicle", "CONFIRMED"
            ),
        ]

        for vehicle in demo_vehicles:
            cursor.execute('''
                INSERT INTO scans (
                    bssid, ssid, capabilities, frequency, level, distance,
                    risk_score, is_hidden, is_open, vendor, first_seen,
                    last_seen, scan_count, is_police_vehicle,
                    police_vehicle_type, police_confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', vehicle)

        conn.commit()
        conn.close()
        return jsonify({
            'status': 'demo_vehicles_injected',
            'count': len(demo_vehicles),
            'message': 'Sample police-vehicle equipment injected into database for testing'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics')
def get_statistics():
    """Get scan statistics"""
    try:
        stats = radar_data.get_scan_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/<format_type>')
def export_data(format_type):
    """Export scan data in specified format"""
    try:
        if format_type not in ['json', 'csv', 'kml']:
            return jsonify({'error': 'Unsupported format'}), 400
        
        data = radar_data.export_data(format_type)
        
        # Save to file
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"radar_export_{timestamp}.{format_type}"
        filepath = os.path.join(EXPORT_DIR, filename)
        
        os.makedirs(EXPORT_DIR, exist_ok=True)
        
        with open(filepath, 'w') as f:
            f.write(data)
        
        return send_file(filepath, as_attachment=True, download_name=filename)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/network/<bssid>')
def get_network_details(bssid):
    """Get detailed information about a specific network"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Get latest scan for this BSSID
        cursor.execute('''
            SELECT * FROM scans 
            WHERE bssid = ? 
            ORDER BY timestamp DESC 
            LIMIT 1
        ''', (bssid,))
        
        columns = [description[0] for description in cursor.description]
        result = cursor.fetchone()
        
        if result:
            network = dict(zip(columns, result))
            
            # Get historical data
            cursor.execute('''
                SELECT timestamp, level, distance, risk_score
                FROM scans 
                WHERE bssid = ? 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', (bssid,))
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'timestamp': row[0],
                    'level': row[1],
                    'distance': row[2],
                    'risk_score': row[3]
                })
            
            network['history'] = history
            return jsonify(network)
        else:
            return jsonify({'error': 'Network not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/clear', methods=['POST', 'GET'])
def clear_data():
    """Clear all scan data from the database"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans")
        conn.commit()
        return jsonify({'status': 'data_cleared'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/api/scan/start')
def start_scan():
    """Start manual scan (triggers radar_prototype.sh once in background if available)"""
    try:
        prototype_script = os.path.join(RADAR_DIR, "termux", "radar_prototype.sh")
        if os.path.exists(prototype_script):
            threading.Thread(
                target=lambda: os.system(f"bash {prototype_script} once >/dev/null 2>&1"),
                daemon=True
            ).start()
        return jsonify({'status': 'scan_started'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/stop')
def stop_scan():
    """Stop scanning"""
    try:
        return jsonify({'status': 'scan_stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def run_server(host='0.0.0.0', port=5000, debug=False):
    """Run the Flask server"""
    print(f"Starting CIVOPS-Radar web server...")
    print(f"Web interface: http://{host}:{port}")
    print(f"Database: {DB_PATH}")
    print("Press Ctrl+C to stop")
    
    app.run(host=host, port=port, debug=debug, threaded=True)

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='CIVOPS-Radar Web Server')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    
    args = parser.parse_args()
    
    run_server(host=args.host, port=args.port, debug=args.debug)
