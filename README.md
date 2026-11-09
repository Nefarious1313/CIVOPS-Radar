# CIVOPS-Radar

**Offline-First Recon Radar Tool for Ethical Wi-Fi Scanning**

CIVOPS-Radar is an open-source, privacy-focused alternative to commercial closed-source "civil-ops" scanning tools. Built for Android + Termux, it provides passive Wi-Fi scanning, signal analysis, and radar visualization while maintaining complete offline operation.

## ⚠️ LEGAL DISCLAIMER

**This tool is intended for network diagnostics and authorized wireless environment testing only. Unauthorized use on private or restricted networks is illegal. Users are responsible for ensuring they have proper authorization before scanning any network.**

## Features

- 🔍 **Passive Wi-Fi Scanning** - Uses Termux:API for non-intrusive network detection
- 🚨 **ALPR Camera Detection** - Identifies Flock Safety & surveillance cameras via OUI fingerprinting and SSID patterns
- 🚓 **Police Vehicle Detection** - Heuristically flags police vehicle equipment (in-car routers, mobile ALPR, dispatch radios) using IEEE-verified OUIs and SSID patterns
- 🛸 **Drone / UAV Detection** - Spots consumer, enterprise, and tactical drones plus FAA Remote ID broadcasts via IEEE-verified OUIs, SSID heuristics, and 5.8 GHz RF signatures
- 📡 **Live Radar Visualization** - HTML5 Canvas-based circular radar display
- 📊 **Signal Analysis** - RSSI-based distance estimation and signal strength tracking
- 🛡️ **Risk Assessment** - Automated scoring of detected networks based on security factors
- 💾 **Local Storage** - SQLite database with no cloud dependencies
- 📤 **Export Options** - JSON, CSV, and KML format support
- 🌐 **Offline-First** - Complete operation without internet connection
- 📱 **Cross-Platform** - Works on Android (Termux) and Linux desktop

## Quick Start

### Prerequisites
- Android device with Termux installed
- Termux:API package
- Python 3.8+

### Installation
```bash
# Clone the repository
git clone https://github.com/synthetic-io/CIVOPS-Radar.git
cd CIVOPS-Radar

# Run the one-command installer
bash termux/install.sh
```

### Usage
```bash
# Start the radar system
cd /sdcard/radar
python server/app.py

# Access the web interface
# Open browser to: http://localhost:5000
```

## Project Structure

```
CIVOPS-Radar/
├── termux/                 # Termux scanning modules
│   ├── radar_prototype.sh  # Main scanning script
│   ├── install.sh          # One-command setup
│   └── README.md
├── server/                 # Flask web server
│   ├── app.py             # Main Flask application
│   ├── flock_detector.py  # Flock Safety / ALPR detection engine
│   ├── police_vehicle_detector.py  # Police vehicle equipment detection engine
│   ├── drone_detector.py  # Drone / UAV / Remote ID detection engine
│   ├── risk_engine.py     # Risk scoring algorithm
│   ├── templates/         # HTML templates
│   └── static/            # CSS, JS, assets
├── tests/                  # Automated test suite
│   ├── test_flock_detector.py
│   ├── test_police_vehicle_detector.py
│   ├── test_drone_detector.py
│   ├── test_api_flock.py
│   ├── test_api_police_vehicle.py
│   ├── test_api_drone.py
│   └── test_db_migration.py
├── android/                # Native Android APK (no Termux required)
│   ├── app/src/main/java/io/synthetic/civopsradar/
│   │   ├── WifiRadarScanner.java
│   │   ├── FlockDetector.java
│   │   ├── PoliceVehicleDetector.java
│   │   ├── DroneDetector.java
│   │   └── RiskEngine.java
│   └── README.md
├── native/                # Future Kotlin Android app
├── data/                  # Local data storage
│   ├── scans.db          # SQLite database
│   ├── exports/          # Export files
│   └── samples/          # Sample data
├── docs/                  # Documentation
│   ├── API.md
│   ├── TECH.md
│   └── LEGAL.md
├── LICENSE
└── README.md
```

## Core Modules

### 1. termux-scan
- Bash + Python scanner using `termux-wifi-scaninfo`
- Configurable scan intervals
- Graceful handling of Android throttling
- SQLite data persistence

### 2. radar-hud
- Flask web server with HTML5 Canvas
- Real-time radar visualization
- Signal strength plotting
- Network filtering and search

### 3. risk-engine
- Automated security risk scoring
- Open network detection
- Hidden SSID identification
- Signal fluctuation analysis

### 4. trilateration (v2+)
- Multi-point coordinate estimation
- GPS integration support
- Signal triangulation algorithms

### 5. flock-detector
- OUI fingerprint matching against official Flock Safety IEEE assignments (`b4:1e:52`)
- Module OUI matching for Qualcomm, Lite-On, and SoftAP field signatures
- SSID pattern matching (SoftAP setup, battery telemetry, Falcon/Sparrow/Raven model names)
- Confidence scoring: `CONFIRMED` / `HIGH` / `MEDIUM` / `LOW` / `NONE`
- Retroactive re-analysis of pre-existing scan entries on server start
- API endpoints: `GET /api/flock/status`, `GET|POST /api/flock/demo`
- UI: pulsing purple radar dots and alert banner for detected cameras

### 6. police-vehicle-detector
- Heuristic identification of police / law-enforcement vehicle equipment from passive Wi-Fi scans
- Vendor OUIs verified against the IEEE MA-L registry (mobile ALPR, in-car routers, dispatch radios)
- SSID naming heuristics for agency / municipal fleet equipment
- Confidence scoring: `CONFIRMED` / `HIGH` / `MEDIUM` / `LOW` / `NONE`
- OUI-only matches are recorded as LOW suspicion and do not raise an alert
- API endpoints: `GET /api/police-vehicle/status`, `GET|POST /api/police-vehicle/demo`
- UI: blue radar dots, alert banner, filter button, and statistics counter
- See `docs/TECH.md` for the detection model and known limitations

### 7. drone-detector
- Passive identification of drones / UAVs / UAS, including FAA Part 89 Remote ID broadcast nodes
- 30 IEEE-verified hardware OUIs (DJI, DJI Baiwang, Skydio, Parrot, Teal, AeroVironment, GoPro, XAG, Powervision, Espressif FPV modules)
- SSID heuristics for DJI / Skydio / Autel / Parrot / Teal / Yuneec fleet signatures, OpenDroneID, and FPV links (ExpressLRS, SpeedyBee, Betaflight, iNav)
- RF hints: 5.8 GHz U-NII-3 video-downlink boost, Wi-Fi Direct (P2P) link detection
- Consumer-WPS penalty suppresses handheld gimbals and shared-chipset home routers
- Confidence scoring: `CONFIRMED` / `HIGH` / `MEDIUM` / `LOW` / `NONE` (alert threshold 60)
- API endpoints: `GET /api/drone/status`, `GET|POST /api/drone/demo`
- UI: amber radar dots, alert banner, filter button, and statistics counter
- Android: mirrored natively in `android/.../DroneDetector.java` (no Python required)
- See `docs/TECH.md` for the detection model and known limitations

## Database Migration

If you have an existing `scans.db` created before the detection features were added,
the server **automatically migrates** the schema on startup — no manual steps are needed.
The `scans` table gains one column group per detector:

| Detector | Columns | Description |
|----------|---------|-------------|
| Flock / ALPR | `is_flock`, `flock_type`, `alpr_confidence` | Flock Safety camera flag, classification, confidence tier |
| Police vehicle | `is_police_vehicle`, `police_vehicle_type`, `police_confidence` | Police equipment flag, classification, confidence tier |
| Drone / UAV | `is_drone`, `drone_type`, `drone_confidence` | Drone flag, classification, confidence tier |

Existing rows are preserved and retroactively re-analysed by each detector on server start.

## Development

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### Testing
```bash
# Run all unit tests (Flock, police-vehicle, drone detectors + API + DB migration)
python3 -m unittest discover -s tests
```

## Security & Privacy

- **No Root Required** - Works within Android security model
- **Local Storage Only** - All data stays on device
- **No Telemetry** - Zero network calls or data collection
- **Transparent Code** - Fully auditable source code
- **User Consent** - Clear authorization warnings

## License

MIT License - See [LICENSE](LICENSE) file for details.

## Support

- 📖 Documentation: [docs/](docs/)
- 📱 Android APK: [android/README.md](android/README.md)
- 🐛 Issues: [GitHub Issues](https://github.com/synthetic-io/CIVOPS-Radar/issues)
- 💬 Discussions: [GitHub Discussions](https://github.com/synthetic-io/CIVOPS-Radar/discussions)

---

**Built with ❤️ for the security research community**
