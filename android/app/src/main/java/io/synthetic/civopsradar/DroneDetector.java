package io.synthetic.civopsradar;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Passive detection engine for drones / unmanned aerial surveillance (UAV / UAS).
 *
 * Mirrors server/drone_detector.py: OUI lookup, SSID pattern heuristics, FAA Remote ID
 * signatures, 5.8 GHz RF hints, Wi-Fi Direct (P2P) hints and a consumer-WPS penalty.
 *
 * OUIs verified against the IEEE MA-L registry on 2026-11-09.
 */
public class DroneDetector {

    public static class Detection {
        public boolean isDrone;
        public String confidence; // CONFIRMED, HIGH, MEDIUM, LOW, NONE
        public int confidenceScore;
        public String deviceType;
        public String vendor;
        public List<String> indicators = new ArrayList<>();
        public List<String> reasons = new ArrayList<>();
    }

    private static class OuiEntry {
        String vendor;
        String description;
        int baseConfidence;
        String deviceType;

        OuiEntry(String vendor, String description, int baseConfidence, String deviceType) {
            this.vendor = vendor;
            this.description = description;
            this.baseConfidence = baseConfidence;
            this.deviceType = deviceType;
        }
    }

    private static class SsidRule {
        Pattern pattern;
        String description;
        String deviceType;
        int confidence;
        String category;

        SsidRule(String regex, String description, String deviceType, int confidence, String category) {
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.description = description;
            this.deviceType = deviceType;
            this.confidence = confidence;
            this.category = category;
        }
    }

    private static final Map<String, OuiEntry> DRONE_OUIS = new HashMap<>();
    private static final List<SsidRule> DRONE_SSID_RULES = new ArrayList<>();

    static {
        // --- DJI (SZ DJI TECHNOLOGY CO.,LTD) ---
        addOui("60:60:1f", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / OcuSync / Wi-Fi link", 50, "DJI Drone / Aerial Platform");
        addOui("34:d2:62", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / flight hardware", 50, "DJI Drone / Aerial Platform");
        addOui("48:1c:b9", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / wireless flight link", 50, "DJI Drone / Aerial Platform");
        addOui("8c:58:23", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / communication module", 50, "DJI Drone / Aerial Platform");
        addOui("0c:9a:e6", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / aerial robotics module", 50, "DJI Drone / Aerial Platform");
        addOui("e4:7a:2c", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / flight controller", 50, "DJI Drone / Aerial Platform");
        addOui("88:29:85", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / video downlink", 50, "DJI Drone / Aerial Platform");
        addOui("58:b8:58", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / OcuSync module", 50, "DJI Drone / Aerial Platform");
        addOui("04:a8:5a", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / aerial robotics module", 50, "DJI Drone / Aerial Platform");
        addOui("4c:43:f6", "DJI (SZ DJI TECHNOLOGY)", "DJI drone / wireless flight link", 50, "DJI Drone / Aerial Platform");

        // --- DJI Baiwang Technology (enterprise flight systems) ---
        addOui("9c:5a:8a", "DJI (DJI BAIWANG TECHNOLOGY)", "DJI Baiwang enterprise drone flight system", 50, "DJI Enterprise Drone");
        addOui("c8:a1:62", "DJI (DJI BAIWANG TECHNOLOGY)", "DJI Baiwang enterprise drone flight system", 50, "DJI Enterprise Drone");
        addOui("ec:72:f7", "DJI (DJI BAIWANG TECHNOLOGY)", "DJI Baiwang enterprise drone flight system", 50, "DJI Enterprise Drone");
        addOui("34:91:f0", "DJI (DJI BAIWANG TECHNOLOGY)", "DJI Baiwang enterprise drone flight system", 50, "DJI Enterprise Drone");

        // --- DJI Ronin / Osmo (handheld gimbals & cameras; share DJI radio hardware) ---
        addOui("24:91:23", "DJI (SZ DJI Ronin Technology)", "DJI Ronin gimbal / handheld link", 45, "DJI Ronin Gimbal / Handheld");
        addOui("f8:40:68", "DJI (SZ DJI Ronin Technology)", "DJI Ronin gimbal / handheld link", 45, "DJI Ronin Gimbal / Handheld");
        addOui("20:1f:55", "DJI (DJI Osmo Technology)", "DJI Osmo handheld camera link", 45, "DJI Osmo Handheld");

        // --- Skydio Inc. ---
        addOui("38:1d:14", "Skydio Inc.", "Skydio Autonomous Recon Drone (Skydio 2 / X2 / X10)", 60, "Skydio Autonomous Surveillance Drone");

        // --- Parrot SA ---
        addOui("90:03:b7", "Parrot SA", "Parrot Drone / Flight Controller (Anafi / Bebop)", 50, "Parrot Drone / Recon UAS");
        addOui("00:12:1c", "Parrot SA", "Parrot Aircraft Electronics", 50, "Parrot Drone / Recon UAS");
        addOui("a0:14:3d", "Parrot SA", "Parrot UAS Telemetry Link", 50, "Parrot Drone / Recon UAS");
        addOui("00:26:7e", "Parrot SA", "Parrot Drone / Flight Controller", 50, "Parrot Drone / Recon UAS");
        addOui("90:3a:e6", "Parrot SA", "Parrot Drone / Flight Controller", 50, "Parrot Drone / Recon UAS");

        // --- Teal Drones (Red Cat Holdings) ---
        addOui("b0:30:c8", "Teal Drones, Inc.", "Teal Tactical Reconnaissance Drone (Golden Eagle / Teal 2)", 65, "Teal Tactical Defense Drone");

        // --- GoPro (Karma drone program) ---
        addOui("d8:96:85", "GoPro", "GoPro Karma drone / action camera link", 45, "GoPro Karma Drone");

        // --- AeroVironment (military UAS: Raven / Puma / Wasp) ---
        addOui("00:1a:f9", "AeroVironment (AV Inc)", "AeroVironment military UAS (Raven / Puma / Wasp)", 60, "AeroVironment Military UAS");

        // --- XAG (agricultural / industrial drones) ---
        addOui("a4:51:29", "XAG", "XAG agricultural / industrial drone", 50, "XAG Agricultural Drone");

        // --- Powervision (consumer / industrial drones) ---
        addOui("54:7d:40", "Powervision Tech Inc.", "Powervision consumer / industrial drone", 45, "Powervision Drone");

        // --- FPV / ESP32 drone wireless modules ---
        addOui("24:4c:ab", "Espressif Systems (ESP32)", "ESP32 FPV / Betaflight drone wireless module", 40, "FPV Drone Wireless Module");
        addOui("c8:2b:96", "Espressif Systems (ESP32)", "ESP32 FPV / ExpressLRS drone wireless module", 40, "FPV Drone Wireless Module");

        // --- SSID patterns (strongest first; first match wins) ---
        // FAA Part 89 / ASD-STAN OpenDroneID Remote ID broadcasts
        DRONE_SSID_RULES.add(new SsidRule("^(rid|dji[-_]rid|uas[-_]rid|drone[-_]rid)[-_]",
                "SSID matches FAA Part 89 / ASD-STAN standard Remote ID broadcast",
                "FAA Remote ID Drone Broadcast", 95, "remote_id"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(opendroneid|odid)[-_]",
                "SSID matches OpenDroneID standard open-source broadcast",
                "OpenDroneID Remote ID Broadcast", 95, "remote_id"));
        DRONE_SSID_RULES.add(new SsidRule("^uas[-_][a-z0-9]{6,}",
                "SSID matches standard Unmanned Aircraft System identifier prefix",
                "Unmanned Aircraft System (UAS)", 88, "remote_id"));

        // DJI drone fleet & model signatures
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+matrice|matrice[-_\\s]*\\d{2,3}[a-z]*)\\b",
                "SSID matches DJI Matrice enterprise surveillance/inspection UAS",
                "DJI Matrice Enterprise Drone", 92, "enterprise_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+mavic|mavic[-_\\s]*(pro|air|enterprise|\\d))\\b",
                "SSID matches DJI Mavic aerial drone platform",
                "DJI Mavic Drone", 90, "consumer_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+phantom|phantom[-_\\s]*\\d[a-z]*)\\b",
                "SSID matches DJI Phantom series drone",
                "DJI Phantom Drone", 90, "consumer_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+inspire|inspire[-_\\s]*\\d)\\b",
                "SSID matches DJI Inspire aerial cinematography/recon drone",
                "DJI Inspire Drone", 90, "enterprise_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+avata|avata[-_\\s]*\\d*)\\b",
                "SSID matches DJI Avata FPV surveillance/tactical drone",
                "DJI Avata FPV Drone", 88, "fpv_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+mini|mini[-_\\s]*[2-5][a-z]*)\\b",
                "SSID matches DJI Mini ultralight drone",
                "DJI Mini Drone", 86, "consumer_drone"));
        DRONE_SSID_RULES.add(new SsidRule("^dji[-_][a-z0-9]{4,12}$",
                "SSID matches DJI factory drone Wi-Fi broadcast format",
                "DJI Drone / Aerial Platform", 88, "consumer_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(spark[-_][a-z0-9]{6})\\b",
                "SSID matches DJI Spark micro-drone",
                "DJI Spark Drone", 85, "consumer_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(dji[-_]+(fly|pilot|go|assistant))\\b",
                "SSID references DJI flight control / pilot station",
                "DJI Ground Control Station (GCS)", 82, "ground_station"));

        // Skydio autonomous recon drones
        DRONE_SSID_RULES.add(new SsidRule("\\b(skydio[-_\\s]*(x2|x10|2\\+|2))\\b",
                "SSID matches Skydio autonomous tactical reconnaissance drone",
                "Skydio Autonomous Recon Drone", 92, "tactical_drone"));
        DRONE_SSID_RULES.add(new SsidRule("^skydio[-_][a-z0-9]{4,}",
                "SSID matches Skydio drone broadcast",
                "Skydio Autonomous Drone", 90, "tactical_drone"));

        // Autel Robotics
        DRONE_SSID_RULES.add(new SsidRule("\\b(autel[-_\\s]*(evo|dragonfish|max))\\b",
                "SSID matches Autel Robotics enterprise drone",
                "Autel Robotics Drone", 90, "enterprise_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(evo[-_\\s]*(ii|max|lite|nano))\\b",
                "SSID matches Autel EVO series aerial drone",
                "Autel EVO Drone", 86, "enterprise_drone"));

        // Parrot defense & consumer recon
        DRONE_SSID_RULES.add(new SsidRule("\\b(anafi[-_\\s]*(usa|thermal|ai|\\d)?)\\b",
                "SSID matches Parrot Anafi reconnaissance drone",
                "Parrot Anafi Recon Drone", 88, "tactical_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(bebop[-_\\s]*\\d?|parrot[-_]+disco)\\b",
                "SSID matches Parrot aerial platform",
                "Parrot Aerial Drone", 82, "consumer_drone"));

        // Teal Drones (military & SWAT)
        DRONE_SSID_RULES.add(new SsidRule("\\b(teal[-_\\s]*(golden[-_\\s]*eagle|2|\\d)?)\\b",
                "SSID matches Teal tactical defense drone",
                "Teal Tactical Defense Drone", 92, "tactical_drone"));

        // Yuneec industrial
        DRONE_SSID_RULES.add(new SsidRule("\\b(typhoon[-_\\s]*(h520|h|plus)?|yuneec)\\b",
                "SSID matches Yuneec industrial aerial system",
                "Yuneec Aerial Drone", 84, "enterprise_drone"));

        // FPV / open-source drone links
        DRONE_SSID_RULES.add(new SsidRule("\\b(expresslrs|elrs[-_\\s]*(tx|rx)?)\\b",
                "SSID matches ExpressLRS open-source drone telemetry link",
                "ExpressLRS Drone Link", 80, "fpv_drone"));
        DRONE_SSID_RULES.add(new SsidRule("\\b(speedybee|betaflight|inav)[-_\\s]",
                "SSID matches FPV drone flight controller Wi-Fi adapter",
                "FPV Drone Wireless Adapter", 78, "fpv_drone"));
    }

    private static void addOui(String oui, String vendor, String description,
                               int baseConfidence, String deviceType) {
        DRONE_OUIS.put(oui, new OuiEntry(vendor, description, baseConfidence, deviceType));
    }

    public static Detection analyze(String bssid, String ssid, String capabilities,
                                    int level, int frequency) {
        Detection result = new Detection();
        String oui = RadarData.normalizeOui(bssid);
        String cleanSsid = ssid != null ? ssid.trim() : "";
        String caps = capabilities != null ? capabilities.toUpperCase(Locale.US) : "";

        result.isDrone = false;
        result.confidenceScore = 0;
        result.deviceType = "Standard Network";
        result.vendor = "Unknown";

        // --- Step 1: OUI vendor lookup ---
        boolean ouiMatched = DRONE_OUIS.containsKey(oui);
        if (ouiMatched) {
            OuiEntry entry = DRONE_OUIS.get(oui);
            result.vendor = entry.vendor;
            result.indicators.add("drone_vendor_oui");
            result.reasons.add("Hardware OUI " + oui + " matches " + entry.vendor
                    + " (" + entry.description + ")");
            result.confidenceScore = Math.max(result.confidenceScore, entry.baseConfidence);
            result.deviceType = entry.deviceType;
        }

        // --- Step 2: SSID pattern matching ---
        boolean ssidMatched = false;
        if (!cleanSsid.isEmpty()) {
            for (SsidRule rule : DRONE_SSID_RULES) {
                if (rule.pattern.matcher(cleanSsid).find()) {
                    ssidMatched = true;
                    result.indicators.add("drone_ssid_" + rule.category);
                    result.reasons.add("SSID '" + cleanSsid + "': " + rule.description);
                    result.deviceType = rule.deviceType;
                    result.confidenceScore = Math.max(result.confidenceScore, rule.confidence);
                    break;
                }
            }
        }

        // --- Step 3: combined evidence boost ---
        if (ouiMatched && ssidMatched) {
            result.confidenceScore = Math.max(result.confidenceScore, 96);
            result.reasons.add("Dual verification: " + result.vendor
                    + " hardware OUI combined with drone SSID pattern");
            if (!result.indicators.contains("confirmed_drone")) {
                result.indicators.add("confirmed_drone");
            }
        }

        // --- Step 4: 5.8 GHz band hint (U-NII-3, channels 149-165) ---
        if (frequency >= 5725 && (ouiMatched || ssidMatched)) {
            result.confidenceScore = Math.min(98, result.confidenceScore + 5);
            result.reasons.add("Operating on 5.8 GHz band (" + frequency
                    + " MHz) typical of drone video downlinks");
            if (!result.indicators.contains("5ghz_downlink")) {
                result.indicators.add("5ghz_downlink");
            }
        }

        // --- Step 5: Wi-Fi Direct / P2P hints ---
        if ((caps.contains("[P2P]") || cleanSsid.toUpperCase(Locale.US).contains("[DIRECT-")) && ouiMatched) {
            result.confidenceScore = Math.min(98, result.confidenceScore + 8);
            result.reasons.add("Wi-Fi Direct (P2P) mode detected (standard for drone-to-controller links)");
            if (!result.indicators.contains("p2p_link")) {
                result.indicators.add("p2p_link");
            }
        }

        // --- Step 6: consumer WPS penalty ---
        if (caps.contains("WPS") && !ssidMatched && result.confidenceScore > 0) {
            result.confidenceScore = Math.max(0, result.confidenceScore - 35);
            result.reasons.add("Consumer WPS enabled (penalized drone suspicion)");
        }

        // --- Step 7: thresholding ---
        if (result.confidenceScore >= 95) {
            result.confidence = "CONFIRMED";
            result.isDrone = true;
        } else if (result.confidenceScore >= 80) {
            result.confidence = "HIGH";
            result.isDrone = true;
        } else if (result.confidenceScore >= 60) {
            result.confidence = "MEDIUM";
            result.isDrone = true;
        } else if (result.confidenceScore > 0) {
            result.confidence = "LOW";
            result.isDrone = false;
        } else {
            result.confidence = "NONE";
            result.isDrone = false;
        }

        if (!result.isDrone && !ouiMatched && !ssidMatched) {
            result.deviceType = "Standard Network";
        }

        return result;
    }
}
