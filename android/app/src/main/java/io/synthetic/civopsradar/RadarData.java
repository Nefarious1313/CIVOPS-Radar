package io.synthetic.civopsradar;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;

public class RadarData {

    public static class Position {
        public double x;
        public double y;
        public int angle;
        public double radius;

        public Position(double x, double y, int angle, double radius) {
            this.x = x;
            this.y = y;
            this.angle = angle;
            this.radius = radius;
        }
    }

    public static double calculateDistance(int rssi, int frequency) {
        if (rssi == 0) return 999.0;
        try {
            // Standard indoor/outdoor log-distance model: RSSI = -30 - 10*n*log10(d), with n=2.8
            double exponent = (-30.0 - (double) rssi) / (10.0 * 2.8);
            double dist = Math.pow(10.0, exponent);
            return Math.round(dist * 10.0) / 10.0;
        } catch (Exception e) {
            return 50.0;
        }
    }

    public static Position calculateRadarPosition(String bssid, int level, double distance) {
        int hashVal = 0;
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest((bssid != null ? bssid : "").getBytes(StandardCharsets.UTF_8));
            int b0 = hash[0] & 0xFF;
            int b1 = hash[1] & 0xFF;
            hashVal = ((b0 << 8) | b1) % 360;
        } catch (Exception e) {
            hashVal = Math.abs((bssid != null ? bssid.hashCode() : 0)) % 360;
        }

        double angleRad = Math.toRadians(hashVal);
        double maxDistance = 250.0;
        double dist = distance >= 0 ? distance : 50.0;
        double normalizedDist = Math.max(0.0, Math.min(dist / maxDistance, 1.0));
        double radius = 0.12 + (normalizedDist * 0.76);

        double x = radius * Math.cos(angleRad);
        double y = radius * Math.sin(angleRad);

        return new Position(
                Math.round(x * 1000.0) / 1000.0,
                Math.round(y * 1000.0) / 1000.0,
                hashVal,
                Math.round(radius * 1000.0) / 1000.0
        );
    }

    public static String normalizeOui(String bssid) {
        if (bssid == null) return "";
        String clean = bssid.replaceAll("[^0-9a-fA-F]", "").toLowerCase(Locale.US);
        if (clean.length() >= 6) {
            return clean.substring(0, 2) + ":" + clean.substring(2, 4) + ":" + clean.substring(4, 6);
        }
        return "";
    }
}
