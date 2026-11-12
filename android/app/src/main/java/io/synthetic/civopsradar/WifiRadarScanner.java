package io.synthetic.civopsradar;

import android.content.BroadcastReceiver;
import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.location.Location;
import android.location.LocationListener;
import android.location.LocationManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;

import org.json.JSONArray;
import org.json.JSONObject;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class WifiRadarScanner {

    public static class ScannedNetwork {
        public String bssid;
        public String ssid;
        public int level;
        public int frequency;
        public String capabilities;
        public double distance;
        public int riskScore;
        public boolean isHidden;
        public boolean isOpen;
        public String vendor;
        public String lastSeen;
        public int scanCount;
        public double latitude;
        public double longitude;
        public boolean hasLocation;

        public boolean isFlock;
        public String flockType;
        public String alprConfidence;

        public boolean isPoliceVehicle;
        public String policeVehicleType;
        public String policeConfidence;

        public boolean isDrone;
        public String droneType;
        public String droneConfidence;

        public RadarData.Position position;
    }

    private final Context context;
    private final WifiManager wifiManager;
    private final Map<String, ScannedNetwork> networks = new ConcurrentHashMap<>();
    private final Map<String, Integer> prevLevel = new ConcurrentHashMap<>();
    private final Handler handler = new Handler(Looper.getMainLooper());
    private boolean isScanning = false;
    private BroadcastReceiver wifiScanReceiver;
    private LocationManager locationManager;
    private double lastLat = 0;
    private double lastLon = 0;
    private boolean hasLocation = false;

    private final SimpleDateFormat isoFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", Locale.US);

    public WifiRadarScanner(Context context) {
        this.context = context.getApplicationContext();
        this.wifiManager = (WifiManager) this.context.getSystemService(Context.WIFI_SERVICE);
        setupReceiver();
        // notification channel
        NotificationManager nm = (NotificationManager) this.context.getSystemService(Context.NOTIFICATION_SERVICE);
        if (nm != null && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
            NotificationChannel ch = new NotificationChannel("radar_alerts", "Radar Alerts", NotificationManager.IMPORTANCE_HIGH);
            nm.createNotificationChannel(ch);
        }
        locationManager = (LocationManager) this.context.getSystemService(Context.LOCATION_SERVICE);
        try {
            LocationListener listener = new LocationListener() {
                public void onLocationChanged(Location l) {
                    if (l != null) { lastLat = l.getLatitude(); lastLon = l.getLongitude(); hasLocation = true; }
                }
                public void onStatusChanged(String p, int s, android.os.Bundle e) {}
                public void onProviderEnabled(String p) {}
                public void onProviderDisabled(String p) {}
            };
            if (locationManager != null) {
                if (locationManager.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                    locationManager.requestLocationUpdates(LocationManager.GPS_PROVIDER, 2000, 1, listener);
                }
                if (locationManager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) {
                    locationManager.requestLocationUpdates(LocationManager.NETWORK_PROVIDER, 2000, 1, listener);
                }
                Location last = locationManager.getLastKnownLocation(LocationManager.GPS_PROVIDER);
                if (last == null) last = locationManager.getLastKnownLocation(LocationManager.NETWORK_PROVIDER);
                if (last != null) { lastLat = last.getLatitude(); lastLon = last.getLongitude(); hasLocation = true; }
            }
        } catch (SecurityException ignored) {}
    }

    private void setupReceiver() {
        wifiScanReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context c, Intent intent) {
                if (WifiManager.SCAN_RESULTS_AVAILABLE_ACTION.equals(intent.getAction())) {
                    processScanResults();
                }
            }
        };
        IntentFilter intentFilter = new IntentFilter();
        intentFilter.addAction(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(wifiScanReceiver, intentFilter, Context.RECEIVER_EXPORTED);
        } else {
            context.registerReceiver(wifiScanReceiver, intentFilter);
        }
    }

    public synchronized void startScanning() {
        if (isScanning) return;
        isScanning = true;
        // Show whatever the OS already has cached immediately
        processScanResults();
        scanRunnable.run();
        refreshRunnable.run();
    }

    public synchronized void stopScanning() {
        isScanning = false;
        handler.removeCallbacks(scanRunnable);
        handler.removeCallbacks(refreshRunnable);
    }

    public void clearData() {
        networks.clear();
    }

    private final Runnable scanRunnable = new Runnable() {
        @Override
        public void run() {
            if (!isScanning) return;
            try {
                if (wifiManager != null) {
                    wifiManager.startScan();
                }
            } catch (Exception ignored) {}
            // Request a fresh scan ~every 30s to respect modern Android scan throttling (4 scans / 2 min)
            handler.postDelayed(this, 30000);
        }
    };

    // Periodically re-read cached scan results so the UI stays live even when a fresh scan is throttled
    private final Runnable refreshRunnable = new Runnable() {
        @Override
        public void run() {
            if (!isScanning) return;
            processScanResults();
            handler.postDelayed(this, 3000);
        }
    };

    public void processScanResults() {
        if (wifiManager == null) return;
        try {
            List<ScanResult> results = wifiManager.getScanResults();
            if (results == null) return;

            String nowStr = isoFormat.format(new Date());

            for (ScanResult r : results) {
                if (r == null || r.BSSID == null) continue;
                String bssid = r.BSSID.toLowerCase(Locale.US);
                String ssid = r.SSID != null ? r.SSID : "";
                int level = r.level;
                int freq = r.frequency;
                String caps = r.capabilities != null ? r.capabilities : "";

                boolean isHidden = ssid.isEmpty() || ssid.equalsIgnoreCase("<unknown ssid>");
                boolean isOpen = !caps.contains("WPA") && !caps.contains("WEP") && !caps.contains("RSN") && !caps.contains("SAE");

                double distance = RadarData.calculateDistance(level, freq);

                // Run detectors
                FlockDetector.Detection flock = FlockDetector.analyze(bssid, ssid);
                PoliceVehicleDetector.Detection police = PoliceVehicleDetector.analyze(bssid, ssid);
                DroneDetector.Detection drone = DroneDetector.analyze(bssid, ssid, caps, level, freq);

                String vendor = "Unknown";
                if (!flock.vendor.equals("Unknown")) {
                    vendor = flock.vendor;
                } else if (!police.vendor.equals("Unknown")) {
                    vendor = police.vendor;
                } else if (!drone.vendor.equals("Unknown")) {
                    vendor = drone.vendor;
                }

                int risk = RiskEngine.calculateRisk(ssid, caps, level, distance, isHidden, isOpen, flock.isFlock, police.isPoliceVehicle, drone.isDrone);
                RadarData.Position pos = RadarData.calculateRadarPosition(bssid, level, distance);

                ScannedNetwork net = networks.get(bssid);
                if (net == null) {
                    net = new ScannedNetwork();
                    net.bssid = bssid;
                    net.scanCount = 1;
                } else {
                    net.scanCount += 1;
                }

                net.ssid = isHidden ? "Hidden" : ssid;
                net.level = level;
                net.frequency = freq;
                net.capabilities = caps;
                net.distance = distance;
                net.riskScore = risk;
                net.isHidden = isHidden;
                net.isOpen = isOpen;
                net.vendor = vendor;
                net.lastSeen = nowStr;
                net.latitude = lastLat;
                net.longitude = lastLon;
                net.hasLocation = hasLocation;

                // Movement alert: signal getting significantly stronger
                Integer prev = prevLevel.get(bssid);
                if (prev != null && level - prev >= 6) {
                    sendAlert("Target approaching: " + (ssid.isEmpty() ? bssid : ssid) + " (+" + (level - prev) + " dBm)");
                }
                if (flock.isFlock || police.isPoliceVehicle || drone.isDrone) {
                    // new detection alert on first sight
                    if (net.scanCount == 1) {
                        sendAlert("Detected: " + (flock.isFlock ? "Flock" : police.isPoliceVehicle ? "Police" : "Drone") + " - " + (ssid.isEmpty() ? bssid : ssid));
                    }
                }
                prevLevel.put(bssid, level);
                net.isFlock = flock.isFlock;
                net.flockType = flock.deviceType;
                net.alprConfidence = flock.confidence;
                net.isPoliceVehicle = police.isPoliceVehicle;
                net.policeVehicleType = police.deviceType;
                net.policeConfidence = police.confidence;
                net.isDrone = drone.isDrone;
                net.droneType = drone.deviceType;
                net.droneConfidence = drone.confidence;
                net.position = pos;

                networks.put(bssid, net);
            }
        } catch (SecurityException se) {
            // Permission not yet granted
        } catch (Exception ignored) {}
    }

    public String getSignalsJson() {
        try {
            JSONObject root = new JSONObject();
            JSONArray signalsArray = new JSONArray();

            boolean anyFlock = false;
            boolean anyPolice = false;
            boolean anyDrone = false;

            List<ScannedNetwork> list = new ArrayList<>(networks.values());
            // Sort by signal strength (level descending)
            Collections.sort(list, (a, b) -> Integer.compare(b.level, a.level));

            for (ScannedNetwork net : list) {
                JSONObject obj = new JSONObject();
                obj.put("bssid", net.bssid);
                obj.put("ssid", net.ssid);
                obj.put("level", net.level);
                obj.put("distance", net.distance);
                obj.put("risk_score", net.riskScore);
                obj.put("is_hidden", net.isHidden);
                obj.put("is_open", net.isOpen);
                obj.put("capabilities", net.capabilities);
                obj.put("frequency", net.frequency);
                obj.put("vendor", net.vendor);
                obj.put("last_seen", net.lastSeen);
                obj.put("scan_count", net.scanCount);
                obj.put("latitude", net.latitude);
                obj.put("longitude", net.longitude);
                obj.put("has_location", net.hasLocation);
                obj.put("is_flock", net.isFlock);
                obj.put("flock_type", net.flockType != null ? net.flockType : "");
                obj.put("alpr_confidence", net.alprConfidence != null ? net.alprConfidence : "NONE");
                obj.put("is_police_vehicle", net.isPoliceVehicle);
                obj.put("police_vehicle_type", net.policeVehicleType != null ? net.policeVehicleType : "");
                obj.put("police_confidence", net.policeConfidence != null ? net.policeConfidence : "NONE");
                obj.put("is_drone", net.isDrone);
                obj.put("drone_type", net.droneType != null ? net.droneType : "");
                obj.put("drone_confidence", net.droneConfidence != null ? net.droneConfidence : "NONE");

                if (net.position != null) {
                    JSONObject pos = new JSONObject();
                    pos.put("x", net.position.x);
                    pos.put("y", net.position.y);
                    pos.put("angle", net.position.angle);
                    pos.put("radius", net.position.radius);
                    obj.put("position", pos);
                }

                if (net.isFlock) anyFlock = true;
                if (net.isPoliceVehicle) anyPolice = true;
                if (net.isDrone) anyDrone = true;

                signalsArray.put(obj);
            }

            root.put("signals", signalsArray);
            root.put("count", list.size());
            root.put("timestamp", isoFormat.format(new Date()));
            root.put("flock_detected", anyFlock);
            root.put("police_vehicle_detected", anyPolice);
            root.put("drone_detected", anyDrone);

            return root.toString();
        } catch (Exception e) {
            return "{\"signals\":[],\"count\":0,\"flock_detected\":false,\"police_vehicle_detected\":false,\"drone_detected\":false}";
        }
    }

    public String getStatisticsJson() {
        try {
            JSONObject root = new JSONObject();
            int flockCount = 0;
            int policeCount = 0;
            int droneCount = 0;
            int low = 0;
            int med = 0;
            int high = 0;

            for (ScannedNetwork net : networks.values()) {
                if (net.isFlock) flockCount++;
                if (net.isPoliceVehicle) policeCount++;
                if (net.isDrone) droneCount++;
                if (net.riskScore >= 60) high++;
                else if (net.riskScore >= 30) med++;
                else low++;
            }

            root.put("total_networks", networks.size());
            root.put("active_networks", networks.size());
            JSONObject risk = new JSONObject();
            risk.put("low", low);
            risk.put("medium", med);
            risk.put("high", high);
            root.put("risk_breakdown", risk);
            root.put("flock_count", flockCount);
            root.put("police_count", policeCount);
            root.put("drone_count", droneCount);
            root.put("timestamp", isoFormat.format(new Date()));

            return root.toString();
        } catch (Exception e) {
            return "{}";
        }
    }

    public String getExportJson() {
        return getSignalsJson();
    }

    private void sendAlert(String message) {
        try {
            NotificationManager nm = (NotificationManager) context.getSystemService(Context.NOTIFICATION_SERVICE);
            if (nm == null) return;
            Notification.Builder b;
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                b = new Notification.Builder(context, "radar_alerts");
            } else {
                b = new Notification.Builder(context);
            }
            b.setContentTitle("CIVOPS Radar Alert")
             .setContentText(message)
             .setSmallIcon(android.R.drawable.ic_dialog_alert)
             .setAutoCancel(true);
            nm.notify((int) System.currentTimeMillis(), b.build());
        } catch (Exception ignored) {}
    }

    public void destroy() {
        stopScanning();
        try {
            if (wifiScanReceiver != null) {
                context.unregisterReceiver(wifiScanReceiver);
            }
        } catch (Exception ignored) {}
    }
}
