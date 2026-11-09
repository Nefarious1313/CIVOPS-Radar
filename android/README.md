# CIVOPS-Radar Native Android APK

This directory contains the standalone native Android application for **CIVOPS-Radar**.

It packages the complete passive radar system into an independent Android `.apk` file that installs and runs directly on any Android smartphone (Android 7.0 / API 24 through Android 14+ / API 34) **without needing Termux or Python**.

---

## Architecture Overview

```
                      ┌─────────────────────────────────────────┐
                      │            Android OS                   │
                      │  (WifiManager + Location Services)      │
                      └────────────────────┬────────────────────┘
                                           │ BroadcastReceiver (SCAN_RESULTS_AVAILABLE)
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │         WifiRadarScanner.java           │
                      │  - Background Wi-Fi scanner             │
                      │  - Signal RSSI & Distance calculation   │
                      │  - Flock Safety ALPR Detector           │
                      │  - Police Vehicle Fleet Detector        │
                      │  - Drone / UAV Detector                 │
                      │  - Risk Assessment Engine               │
                      └────────────────────┬────────────────────┘
                                           │
         ┌─────────────────────────────────┴─────────────────────────────────┐
         │ shouldInterceptRequest (REST API)        JavaScript Interface     │
         │ (/api/signals, /api/statistics)          (window.AndroidBridge)   │
         └─────────────────────────────────┬─────────────────────────────────┘
                                           ▼
                      ┌─────────────────────────────────────────┐
                      │       Android WebView Container         │
                      │  - Hardware-accelerated Canvas engine   │
                      │  - Assets: assets/radar.html            │
                      │  - Live 360° Circular Radar UI          │
                      └─────────────────────────────────────────┘
```

---

## How to Build the APK

### Method 1: Automatic Cloud Build via GitHub Actions (Easiest)
1. Push your changes to your GitHub repository:
   ```bash
   git add android .github
   git commit -m "Add native Android radar APK project"
   git push origin main
   ```
2. Navigate to your repository on GitHub and click the **Actions** tab.
3. The **Build Radar APK** workflow will run automatically.
4. When finished (usually under 2 minutes), click on the run and download the `CIVOPS-Radar-Debug-APK` artifact containing your ready-to-install `.apk` file!

### Method 2: Android Studio (PC / Mac / Linux)
1. Copy or clone the `android` folder to your computer.
2. Open Android Studio and choose **Open an Existing Project**, selecting the `android` folder.
3. Let Gradle sync dependencies.
4. Go to **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
5. The generated `.apk` will be in `app/build/outputs/apk/debug/app-debug.apk`. Transfer it to your phone and tap to install!

### Method 3: Command Line (Gradle)
```bash
cd android
./gradlew assembleDebug
```
The output file is located at `app/build/outputs/apk/debug/app-debug.apk`.

---

## Android Permissions Required

When launching the app for the first time, Android will prompt for:
- **Location Permission (`ACCESS_FINE_LOCATION`)**: Required by the Android operating system to read Wi-Fi network SSIDs and BSSIDs. (Note: Ensure your device's Location/GPS toggle is turned ON in quick settings).
- **Nearby Wi-Fi Devices (`NEARBY_WIFI_DEVICES`)**: Required on Android 13+ for local network discovery.
