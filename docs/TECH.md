# CIVOPS-Radar Technical Documentation

## Architecture Overview

CIVOPS-Radar is built as a modular, offline-first Wi-Fi scanning and visualization system. The architecture consists of several interconnected components that work together to provide comprehensive network analysis capabilities.

### System Architecture

```
┌─────────────────┐    ┌─────────────────────────────┐    ┌─────────────────┐
│   Termux API    │    │       Flask Server          │    │   Web Browser   │
│   (Wi-Fi Scan)  │───▶│       (Backend)             │◀───│   (Frontend)    │
└─────────────────┘    └─────────────────────────────┘    └─────────────────┘
         │               │         │           │                    │
         ▼               ▼         ▼           ▼                    ▼
┌──────────────┐  ┌──────────┐ ┌──────────┐ ┌────────────┐  ┌────────────┐
│  SQLite DB   │  │  Risk    │ │  Flock   │ │   Export   │  │HTML5 Canvas│
│ (Data Store) │  │  Engine  │ │ Detector │ │  Engine    │  │ (Radar UI) │
└──────────────┘  └──────────┘ └──────────┘ └────────────┘  └────────────┘
```

Detection engines (all passive, OUI + SSID heuristics):

| Engine | Module | Flags |
|--------|--------|-------|
| Flock / ALPR | `server/flock_detector.py` | `is_flock`, `flock_type`, `alpr_confidence` |
| Police vehicle | `server/police_vehicle_detector.py` | `is_police_vehicle`, `police_vehicle_type`, `police_confidence` |
| Drone / UAV | `server/drone_detector.py` | `is_drone`, `drone_type`, `drone_confidence` |

## Core Components

### 1. Termux Scanner (`termux/radar_prototype.sh`)

**Purpose**: Passive Wi-Fi network scanning using Android's built-in capabilities.

**Key Features**:
- Uses `termux-wifi-scaninfo` for non-intrusive scanning
- Configurable scan intervals (default: 5 seconds)
- Graceful handling of Android throttling
- SQLite data persistence
- Signal strength analysis
- Distance estimation

**Technical Details**:
- **Language**: Bash + Python
- **Dependencies**: Termux:API, SQLite3, Python 3.8+
- **Permissions**: Location access (required for Wi-Fi scanning)
- **Data Format**: JSON output from Termux:API

**Scan Process**:
1. Call `termux-wifi-scaninfo`
2. Parse JSON output
3. Calculate distance from RSSI
4. Assess risk factors
5. Store in SQLite database
6. Update radar display

### 2. Flask Web Server (`server/app.py`)

**Purpose**: RESTful API and web interface for radar visualization.

**Key Features**:
- Real-time data API endpoints
- WebSocket support for live updates
- Data export functionality
- Network statistics
- Historical data analysis

**API Endpoints**:
- `GET /api/signals` - Latest scan results
- `GET /api/statistics` - Scan statistics
- `GET /api/flock/status` / `GET|POST /api/flock/demo` - Flock camera status / demo data
- `GET /api/police-vehicle/status` / `GET|POST /api/police-vehicle/demo` - Police vehicle status / demo data
- `GET /api/drone/status` / `GET|POST /api/drone/demo` - Drone / UAV status / demo data
- `GET /api/export/<format>` - Data export
- `GET /api/network/<bssid>` - Network details
- `POST /api/scan/start` - Start scanning
- `POST /api/scan/stop` - Stop scanning

**Technical Details**:
- **Language**: Python 3.8+
- **Framework**: Flask with CORS support
- **Database**: SQLite3 with connection pooling
- **Threading**: Multi-threaded for concurrent requests

### 3. Risk Engine (`server/risk_engine.py`)

**Purpose**: Advanced risk assessment and threat analysis.

**Risk Factors**:
- **Open Networks**: +30 points (high risk)
- **Hidden SSIDs**: +20 points (medium risk)
- **Weak Encryption**: +5-25 points (based on type)
- **Suspicious SSIDs**: +10-30 points (pattern matching)
- **Signal Fluctuation**: +8-15 points (rogue AP detection)
- **Proximity Risk**: +5-10 points (signal strength analysis)
- **Vendor Risk**: +5 points (known vulnerable vendors)
- **Beacon Anomalies**: +10-15 points (unusual frequencies)
- **Temporal Risk**: +5 points (unusual access times)

**Algorithm**:
```python
def calculate_risk_score(network, historical_data):
    factors = RiskFactors()
    
    # Basic security assessment
    factors.open_network = assess_open_network(network)
    factors.hidden_ssid = assess_hidden_ssid(network)
    factors.weak_encryption = assess_encryption_strength(network)
    
    # Advanced threat detection
    if historical_data:
        factors.signal_fluctuation = assess_signal_fluctuation(network, historical_data)
        factors.temporal_risk = assess_temporal_patterns(network, historical_data)
    
    return min(100, sum(factors.values()))
```

### 4. Radar Visualization (`server/templates/radar.html`)**Purpose**: Real-time radar display using HTML5 Canvas.

**Visualization Features**:
- Circular radar display with range rings
- Network positioning based on signal strength
- Color-coded risk levels
- Interactive network information
- Real-time updates every 3 seconds

**Technical Implementation**:
- **Frontend**: HTML5 Canvas + JavaScript
- **Styling**: TailwindCSS with dark theme
- **Updates**: AJAX polling every 3 seconds
- **Responsive**: Mobile-friendly design

**Radar Positioning Algorithm**:
```javascript
function calculateRadarPosition(bssid, level, distance) {
    // Use BSSID hash for consistent angle
    const hashVal = hash(bssid) % 360;
    const angle = hashVal * Math.PI / 180;
    
    // Calculate position based on signal strength
    const maxDistance = 200; // meters
    const normalizedDistance = Math.min(distance / maxDistance, 1.0);
    const radius = (1 - normalizedDistance) * 0.8; // 80% of radar radius
    
    return {
        x: radius * Math.cos(angle),
        y: radius * Math.sin(angle),
        angle: hashVal,
        radius: radius
    };
}
```

---

### 5. Flock Detector (`server/flock_detector.py`)

**Purpose**: Identify Flock Safety ALPR cameras and related surveillance hardware from passive Wi-Fi scan data without any active probing or network connection.

**Detection Methods**:

| Method | Indicator | Confidence Score |
|--------|-----------|-----------------|
| Official OUI | IEEE MA-L `b4:1e:52` — assigned to Flock Safety Inc. | 98 → CONFIRMED |
| SSID Pattern (model names) | `falcon-*`, `sparrow-*`, `raven-*` | 90–95 → CONFIRMED |
| SSID Pattern (SoftAP) | `flock-<hex>`, `flock`, `fs-<hex>` | 85–90 → HIGH |
| SSID Pattern (telemetry) | `fs ext battery*`, `fs battery*` | 95 → CONFIRMED |
| Module OUI + Hidden SSID | Known chipset OUI (`00:03:7f`, `70:c9:4e`, `82:6b:f2`) + hidden SSID | 82 → HIGH |
| Module OUI alone | Known chipset OUI, visible non-Flock SSID | 45 → MEDIUM |
| Other ALPR OUI | Motorola Vigilant (`00:1d:a5`), Hikvision (`e0:28:6d`), Vivotek (`00:26:73`) | 70–80 → HIGH |

**Confidence Tiers**:

| Tier | Score Range | Meaning |
|------|------------|---------|
| `CONFIRMED` | ≥ 95 | Near-certain identification |
| `HIGH` | ≥ 80 | Strong evidence, likely ALPR |
| `MEDIUM` | ≥ 50 | Moderate suspicion |
| `LOW` | > 0 | Weak signal, inconclusive |
| `NONE` | 0 | No evidence found |

**Key Class: `FlockDetector.analyze(bssid, ssid, capabilities, level, frequency)`**

Returns a `FlockDetection` dataclass with fields:
- `is_flock` — `True` if identified as a Flock Safety device
- `is_alpr` — `True` if any ALPR device (Flock or other manufacturer)
- `confidence` — Tier string (`CONFIRMED`, `HIGH`, etc.)
- `confidence_score` — Integer 0–100
- `device_type` — Human-readable classification label
- `vendor` — Identified manufacturer name
- `reasons` — List of matched indicator descriptions

**API Endpoints**:
- `GET /api/flock/status` — current detection status and camera list
- `GET|POST /api/flock/demo` — inject demo cameras for UI testing

---

### 6. Police Vehicle Detector (`server/police_vehicle_detector.py`)

**Purpose**: Heuristically identify police / law-enforcement vehicle equipment from passive Wi-Fi scan data.

**Why heuristic**: there is no universal Wi-Fi fingerprint for a police vehicle. Patrol-car mobile
data terminals (MDTs) are usually Wi-Fi *clients* rather than access points, and in-car routers /
ALPR links do not always broadcast a department-identifying SSID. Detection therefore combines two
weak signals instead of relying on a single identifier.

**Detection Methods**:

| Method | Indicator | Confidence Score |
|--------|-----------|-----------------|
| SSID pattern (agency) | `police`, `sheriff`, `highway patrol`, `state police` | 85–88 → HIGH |
| SSID pattern (abbreviation) | `mpd`, `nypd`, `fhp`, `chp`, ... | 80 → HIGH |
| SSID pattern (fleet / MDT) | `mdt`, `fleet`, `municipal`, `cradlepoint` | 55–70 → MEDIUM |
| SSID + vendor OUI | any SSID pattern combined with a verified police-equipment OUI | 95 → CONFIRMED |
| Vendor OUI + hidden SSID | known OUI with a hidden SSID | 70 → MEDIUM |
| Vendor OUI alone | known OUI, ordinary visible SSID | 35–45 → LOW (not flagged) |

**Vendor OUI sources**: every OUI in `POLICE_VEHICLE_OUIS` was verified against the IEEE MA-L
registry (`https://standards-oui.ieee.org/oui/oui.csv`). Categories: mobile ALPR (Avigilon,
Genetec, Leonardo/Selex), mobile surveillance cameras (Bosch, FLIR, Axis, Vivotek), in-car routers
(CradlePoint, Sierra Wireless / Semtech), dispatch radios (Motorola Solutions, Tait, Harris, Codan,
Hytera).

**Confidence Tiers**: same five tiers as the Flock detector (`CONFIRMED` ≥ 95, `HIGH` ≥ 80,
`MEDIUM` ≥ 50, `LOW` > 0, `NONE` = 0).

**Known limitations**:
- High false-negative rate: most police vehicles broadcast nothing identifiable.
- Possible false positives: a civilian SSID containing "police", or a CradlePoint / Axis device in a business.
- The built-in SSID patterns are generic heuristics, not a database of real department SSIDs.
  Tune `POLICE_SSID_PATTERNS` to your local area.

**Key Class**: `PoliceVehicleDetector.analyze(bssid, ssid, capabilities, level, frequency)`
Returns a `PoliceVehicleDetection` dataclass with fields: `is_police_vehicle`, `confidence`,
`confidence_score`, `device_type`, `vendor`, `reasons`, `indicators`.

**API Endpoints**:
- `GET /api/police-vehicle/status` — current detection status and vehicle list
- `GET|POST /api/police-vehicle/demo` — inject demo vehicles for UI testing

---

### 7. Drone Detector (`server/drone_detector.py`)

**Purpose**: Passively identify unmanned aerial vehicles (drones / UAVs / UAS), aerial
surveillance platforms, and FAA Part 89 Remote ID broadcast nodes from Wi-Fi scan data.

**Why heuristic**: most drones never broadcast an identifiable Wi-Fi SSID — DJI OcuSync /
Lightbridge links stay hidden, and proprietary control links do not appear in
`termux-wifi-scaninfo` at all. Detection therefore combines hardware OUIs, SSID naming
conventions, Remote ID signatures, and RF band characteristics.

**Detection Methods**:

| Method | Indicator | Confidence Score |
|--------|-----------|-----------------|
| FAA Remote ID SSID | `RID-<20 digits>`, `UAS-<hex>`, `OpenDroneID-*` | 88–95 → CONFIRMED |
| SSID pattern (DJI fleet) | `DJI-Mavic*`, `DJI-Matrice*`, `DJI-Phantom*`, `DJI-Inspire*`, `DJI-Avata*`, `DJI-Mini*` | 86–92 → HIGH/CONFIRMED |
| SSID pattern (tactical) | `Skydio-X2/X10`, `Anafi-USA`, `Teal-Golden-Eagle` | 88–92 → HIGH/CONFIRMED |
| SSID pattern (enterprise) | `Autel-EVO*`, `DJI-Matrice*`, `Yuneec-Typhoon*` | 84–90 → HIGH |
| SSID pattern (FPV links) | `ExpressLRS-*`, `SpeedyBee-*`, `Betaflight-*`, `iNav-*` | 78–80 → HIGH |
| Vendor OUI + drone SSID | verified drone-hardware OUI combined with any drone SSID | 96 → CONFIRMED |
| Vendor OUI alone | verified drone OUI, hidden/generic SSID | 40–65 → LOW (not flagged) |
| 5.8 GHz RF hint | OUI/SSID match on ≥ 5725 MHz (U-NII-3 video downlink) | +5 |
| Wi-Fi Direct hint | `[P2P]` capability or `DIRECT-` SSID on a drone OUI | +8 |
| WPS penalty | consumer WPS enabled without a drone SSID | −35 |

**Vendor OUI sources**: all 30 prefixes in `DRONE_OUIS` were verified against the IEEE MA-L
registry (`https://standards-oui.ieee.org/oui/oui.csv`) on 2026-11-09. Categories: DJI
(SZ DJI Technology + DJI Baiwang enterprise), DJI Ronin/Osmo handhelds (kept at LOW),
Skydio, Parrot, Teal Drones, AeroVironment, GoPro Karma, XAG, Powervision, and Espressif
ESP32 FPV modules. Autel Robotics and Yuneec have no verified MA-L prefix and are matched
on SSID evidence only.

**Confidence Tiers**:

| Tier | Score Range | Meaning |
|------|------------|---------|
| `CONFIRMED` | ≥ 95 | Near-certain identification (dual verification or Remote ID) |
| `HIGH` | ≥ 80 | Strong evidence — alerts |
| `MEDIUM` | ≥ 60 | Actionable suspicion — alerts |
| `LOW` | > 0 | Weak signal (OUI only), recorded but not flagged |
| `NONE` | 0 | No evidence found |

**Known limitations**:
- High false-negative rate: most drones broadcast nothing identifiable; a clean scan does
  NOT prove the airspace is empty.
- Possible false positives: DJI Ronin/Osmo handheld gimbals share DJI radio hardware, and
  ESP32 modules appear in non-drone devices — both stay at LOW unless corroborated.
- OUI identifies the chipset maker, not the deployment. Treat MEDIUM and above as
  actionable, LOW as informational only.

**Key Class**: `DroneDetector.analyze(bssid, ssid, capabilities, level, frequency)`
Returns a `DroneDetection` dataclass with fields: `is_drone`, `confidence`,
`confidence_score`, `device_type`, `vendor`, `indicators`, `reasons`.

**API Endpoints**:
- `GET /api/drone/status` — current detection status and drone list
- `GET|POST /api/drone/demo` — inject demo drones for UI testing

**Android mirror**: `android/app/src/main/java/io/synthetic/civopsradar/DroneDetector.java`
implements the same model natively (no Python required).

---

## Database Schema

### Scans Table
```sql
CREATE TABLE scans (
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
    is_flock BOOLEAN DEFAULT 0,    -- Flock Safety / ALPR camera flag
    flock_type TEXT DEFAULT '',    -- Human-readable device classification
    alpr_confidence TEXT DEFAULT '', -- Detection confidence tier
    is_police_vehicle BOOLEAN DEFAULT 0, -- Police / law-enforcement vehicle flag
    police_vehicle_type TEXT DEFAULT '', -- Human-readable vehicle classification
    police_confidence TEXT DEFAULT '',   -- Detection confidence tier
    is_drone BOOLEAN DEFAULT 0,          -- Drone / UAV flag
    drone_type TEXT DEFAULT '',          -- Human-readable drone classification
    drone_confidence TEXT DEFAULT ''     -- Detection confidence tier
);
```

### Indexes
```sql
CREATE INDEX idx_bssid ON scans(bssid);
CREATE INDEX idx_timestamp ON scans(timestamp);
CREATE INDEX idx_level ON scans(level);
CREATE INDEX idx_flock ON scans(is_flock);
CREATE INDEX idx_police_vehicle ON scans(is_police_vehicle);
CREATE INDEX idx_drone ON scans(is_drone);
```

> **Automatic Migration**: If `scans.db` was created before the detection features,
> the server adds the missing columns automatically on startup using `ALTER TABLE`, one
> group per detector (Flock, police vehicle, drone). Existing data is preserved and
> retroactively re-analysed by each detector on server start.

## Signal Processing

### Distance Calculation
Uses the log-distance path loss model:

```
Distance (m) = 10 ^ ((TxPower - RSSI) / (10 × n))
```

Where:
- `TxPower`: Transmit power (default: 20 dBm)
- `RSSI`: Received signal strength indicator (dBm)
- `n`: Path loss exponent — `2.8` (calibrated for indoor/urban environments)

### Signal Strength Analysis
- **Excellent**: > -30 dBm (very close)
- **Good**: -30 to -50 dBm (close)
- **Fair**: -50 to -70 dBm (moderate)
- **Poor**: -70 to -80 dBm (far)
- **Very Poor**: < -80 dBm (very far)

## Security Considerations

### Data Privacy
- All data stored locally on device
- No cloud synchronization
- No telemetry or analytics
- User controls all data

### Network Security
- Passive scanning only (no packet injection)
- No password cracking attempts
- No network disruption
- Read-only operations

### Code Security
- Open source and auditable
- No hidden functionality
- Regular security updates
- Community review process

## Performance Optimization

### Database Optimization
- Indexed queries for fast lookups
- Automatic cleanup of old data
- Connection pooling
- Query optimization

### Memory Management
- Streaming data processing
- Garbage collection optimization
- Memory leak prevention
- Resource cleanup

### Network Optimization
- Efficient data structures
- Minimal API calls
- Caching strategies
- Compression where appropriate

## Deployment

### Termux Environment
1. Install Termux from F-Droid
2. Install Termux:API
3. Run installation script
4. Grant required permissions

### Linux Desktop
1. Install Python 3.8+
2. Install required packages
3. Run Flask server
4. Access web interface

### Docker (Future)
```dockerfile
FROM python:3.11-slim
COPY . /app
WORKDIR /app
RUN pip install -r requirements.txt
EXPOSE 5000
CMD ["python", "server/app.py"]
```

## Troubleshooting

### Common Issues

#### Scanner Not Working
- Check Termux:API installation
- Verify location permissions
- Ensure Wi-Fi is enabled
- Check for Android throttling

#### Web Interface Not Loading
- Verify Flask server is running
- Check port 5000 is available
- Ensure firewall allows connections
- Verify database exists

#### Performance Issues
- Check available memory
- Monitor CPU usage
- Optimize database queries
- Reduce scan frequency

### Debug Mode
```bash
# Enable debug logging
export RADAR_DEBUG=1
python server/app.py --debug

# Check logs
tail -f /sdcard/radar/scan.log
```

## Future Enhancements

### Planned Features
- GPS integration for mapping
- Multi-device synchronization
- Advanced threat detection
- Machine learning analysis
- Standalone Kotlin app (the Java WebView APK in `android/` already ships)

### Technical Roadmap
- **v2.0**: GPS mapping and trilateration
- **v3.0**: Machine learning threat detection
- **v4.0**: Native Android app
- **v5.0**: Multi-device mesh network

## Contributing

### Development Setup
1. Fork the repository
2. Create feature branch
3. Make changes
4. Test thoroughly
5. Submit pull request

### Code Standards
- Follow PEP 8 for Python
- Use meaningful variable names
- Add comprehensive comments
- Write unit tests
- Update documentation

### Testing
```bash
# Run tests
python -m pytest tests/

# Test risk engine
python server/test_risk_engine.py

# Test scanner
bash termux/test_scanner.sh
```

## License

This project is licensed under the MIT License. See LICENSE file for details.

---

**For technical support, please open an issue on GitHub or contact the development team.**
