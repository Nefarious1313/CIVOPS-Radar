package io.synthetic.civopsradar;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public class FlockDetector {

    public static class Detection {
        public boolean isFlock;
        public boolean isAlpr;
        public String confidence; // CONFIRMED, HIGH, MEDIUM, LOW, NONE
        public int confidenceScore;
        public String deviceType;
        public String vendor;
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

        SsidRule(String regex, String description, String deviceType, int confidence) {
            this.pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
            this.description = description;
            this.deviceType = deviceType;
            this.confidence = confidence;
        }
    }

    private static final Map<String, OuiEntry> OFFICIAL_OUIS = new HashMap<>();
    private static final Map<String, OuiEntry> MODULE_OUIS = new HashMap<>();
    private static final Map<String, OuiEntry> OTHER_ALPR_OUIS = new HashMap<>();
    private static final List<SsidRule> SSID_RULES = new ArrayList<>();

    static {
        // Official Flock OUI (IEEE MA-L)
        OFFICIAL_OUIS.put("b4:1e:52", new OuiEntry("Flock Safety Inc.", "Flock Safety Official (Falcon ALPR)", 98, "Flock Safety ALPR Camera"));

        // Hardware Module OUIs
        MODULE_OUIS.put("00:03:7f", new OuiEntry("Qualcomm Atheros", "Qualcomm Radio (Flock Falcon)", 85, "Flock Falcon ALPR (Qualcomm Radio)"));
        MODULE_OUIS.put("70:c9:4e", new OuiEntry("Lite-On Technology Corp.", "Lite-On OEM Module (Flock Assembly)", 85, "Flock Camera Assembly (Lite-On)"));
        MODULE_OUIS.put("82:6b:f2", new OuiEntry("Flock Field Signature", "Flock Camera SoftAP Field Signature", 90, "Flock Camera Node"));

        // Other ALPR / Traffic Camera OUIs
        OTHER_ALPR_OUIS.put("00:1d:a5", new OuiEntry("Motorola Solutions", "Motorola / Vigilant ALPR", 80, "Vigilant ALPR Surveillance Camera"));
        OTHER_ALPR_OUIS.put("00:26:73", new OuiEntry("Vivotek Inc.", "Vivotek Traffic / ALPR Camera", 75, "Traffic Surveillance Camera"));
        OTHER_ALPR_OUIS.put("e0:28:6d", new OuiEntry("Hikvision", "Hikvision Traffic / ALPR Camera", 70, "Traffic Monitoring Camera"));
        OTHER_ALPR_OUIS.put("00:11:7f", new OuiEntry("Qualcomm Atheros", "Embedded Surveillance Wireless Unit", 65, "Surveillance Wireless Unit"));

        // SSID Patterns
        SSID_RULES.add(new SsidRule("^flock[-_ ]?[0-9a-f]{2,}", "Flock Camera SoftAP broadcast", "Flock Safety ALPR Camera", 85));
        SSID_RULES.add(new SsidRule("^flock$", "Flock default SSID", "Flock Safety Device", 90));
        SSID_RULES.add(new SsidRule("^fs[-_ ]?ext[-_ ]?battery.*", "Flock External Battery Telemetry", "Flock Solar Power Telemetry", 95));
        SSID_RULES.add(new SsidRule("^fs[-_ ]?battery.*", "Flock Battery Telemetry", "Flock Solar Power Telemetry", 95));
        SSID_RULES.add(new SsidRule("^fs[-_ ][0-9a-f]{4,}", "Flock Safety node SSID", "Flock Safety Node", 90));
        SSID_RULES.add(new SsidRule("^falcon[-_ ]?[0-9a-f]*", "Flock Falcon camera broadcast", "Flock Falcon ALPR Camera", 95));
        SSID_RULES.add(new SsidRule("^sparrow[-_ ]?[0-9a-f]*", "Flock Sparrow camera broadcast", "Flock Sparrow ALPR Camera", 90));
        SSID_RULES.add(new SsidRule("^raven[-_ ]?[0-9a-f]*", "Flock Raven acoustic sensor broadcast", "Flock Raven Audio Sensor", 90));
        SSID_RULES.add(new SsidRule(".*deflock.*", "DeFlock test node", "DeFlock Audit Device", 80));
        SSID_RULES.add(new SsidRule("^alpr[-_ ]?.*", "General ALPR system SSID", "ALPR System", 85));
        SSID_RULES.add(new SsidRule(".*license[-_ ]?plate.*", "License plate recognition SSID", "ALPR System", 85));
    }

    public static Detection analyze(String bssid, String ssid) {
        Detection result = new Detection();
        String oui = RadarData.normalizeOui(bssid);
        String cleanSsid = ssid != null ? ssid.trim() : "";
        boolean isHidden = cleanSsid.isEmpty() || cleanSsid.equalsIgnoreCase("<unknown ssid>");

        result.isFlock = false;
        result.isAlpr = false;
        result.confidenceScore = 0;
        result.deviceType = "Standard Wi-Fi";
        result.vendor = "Unknown";

        // Check Official OUI
        if (OFFICIAL_OUIS.containsKey(oui)) {
            OuiEntry entry = OFFICIAL_OUIS.get(oui);
            result.isFlock = true;
            result.isAlpr = true;
            result.vendor = entry.vendor;
            result.deviceType = entry.deviceType;
            result.confidenceScore = entry.baseConfidence;
            result.reasons.add("Matches Official " + entry.description + " (" + oui + ")");
        }

        // Check SSID Rules
        boolean matchedSsid = false;
        for (SsidRule rule : SSID_RULES) {
            if (rule.pattern.matcher(cleanSsid).find()) {
                matchedSsid = true;
                result.isFlock = true;
                result.isAlpr = true;
                result.deviceType = rule.deviceType;
                result.confidenceScore = Math.max(result.confidenceScore, rule.confidence);
                result.reasons.add("SSID matches " + rule.description);
                if (rule.deviceType.contains("Flock")) {
                    result.vendor = "Flock Safety";
                }
                break;
            }
        }

        // Check Module OUI
        if (MODULE_OUIS.containsKey(oui)) {
            OuiEntry entry = MODULE_OUIS.get(oui);
            if (result.vendor.equals("Unknown")) {
                result.vendor = entry.vendor;
            }
            if (matchedSsid || OFFICIAL_OUIS.containsKey(oui)) {
                result.confidenceScore = 100;
                result.reasons.add("Hardware confirms: " + entry.description);
            } else if (isHidden) {
                result.isFlock = true;
                result.isAlpr = true;
                result.deviceType = "Suspected " + entry.deviceType + " (Stealth Probe)";
                result.confidenceScore = Math.max(result.confidenceScore, 82);
                result.reasons.add("Stealth/Hidden Wi-Fi on known " + entry.description);
            } else {
                result.confidenceScore = Math.max(result.confidenceScore, 45);
                result.reasons.add("Shares hardware chipset with " + entry.description);
            }
        }

        // Check other ALPR OUIs
        if (!result.isFlock && OTHER_ALPR_OUIS.containsKey(oui)) {
            OuiEntry entry = OTHER_ALPR_OUIS.get(oui);
            result.isAlpr = true;
            result.vendor = entry.vendor;
            result.deviceType = entry.deviceType;
            result.confidenceScore = Math.max(result.confidenceScore, entry.baseConfidence);
            result.reasons.add("Known ALPR manufacturer: " + entry.description);
        }

        // Assign Confidence text
        if (result.confidenceScore >= 90) {
            result.confidence = "CONFIRMED";
        } else if (result.confidenceScore >= 75) {
            result.confidence = "HIGH";
        } else if (result.confidenceScore >= 50) {
            result.confidence = "MEDIUM";
        } else if (result.confidenceScore >= 25) {
            result.confidence = "LOW";
        } else {
            result.confidence = "NONE";
        }

        return result;
    }
}
