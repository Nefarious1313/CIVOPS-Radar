package io.synthetic.civopsradar;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

public class PoliceVehicleDetector {

    public static class Detection {
        public boolean isPoliceVehicle;
        public String confidence; // CONFIRMED, HIGH, MEDIUM, LOW, NONE
        public int confidenceScore;
        public String deviceType;
        public String vendor;
        public List<String> reasons = new ArrayList<>();
    }

    private static class OuiEntry {
        String vendor;
        String category;
        String description;
        int baseConfidence;
        String deviceType;

        OuiEntry(String vendor, String category, String description, int baseConfidence, String deviceType) {
            this.vendor = vendor;
            this.category = category;
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

    private static final Map<String, OuiEntry> POLICE_OUIS = new HashMap<>();
    private static final List<SsidRule> POLICE_SSID_RULES = new ArrayList<>();

    static {
        // --- Mobile ALPR & Camera Hardware ---
        POLICE_OUIS.put("70:1a:d5", new OuiEntry("Avigilon (Motorola)", "alpr", "Avigilon Mobile ALPR camera", 45, "Police ALPR Unit (Mobile)"));
        POLICE_OUIS.put("0c:bf:15", new OuiEntry("Genetec Inc.", "alpr", "Genetec AutoVu ALPR camera", 45, "Police ALPR Unit (Mobile)"));
        POLICE_OUIS.put("00:bf:15", new OuiEntry("Genetec Inc.", "alpr", "Genetec AutoVu ALPR camera", 45, "Police ALPR Unit (Mobile)"));
        POLICE_OUIS.put("00:0a:b1", new OuiEntry("Genetec Inc.", "alpr", "Genetec AutoVu ALPR camera", 45, "Police ALPR Unit (Mobile)"));
        POLICE_OUIS.put("00:80:e7", new OuiEntry("Leonardo UK Ltd", "alpr", "Leonardo / Selex traffic & ALPR", 45, "Police ALPR Unit (Mobile)"));
        POLICE_OUIS.put("00:17:28", new OuiEntry("Selex (Leonardo)", "alpr", "Selex traffic & ALPR", 45, "Police ALPR Unit (Mobile)"));

        // --- In-Car Routers & Gateways (Cradlepoint, Sierra Wireless, Peplink, Digi) ---
        POLICE_OUIS.put("00:30:44", new OuiEntry("Cradlepoint, Inc.", "router", "Cradlepoint IBR in-car router", 40, "Police In-Car Gateway (Cradlepoint)"));
        POLICE_OUIS.put("00:1c:7b", new OuiEntry("Cradlepoint, Inc.", "router", "Cradlepoint IBR in-car router", 40, "Police In-Car Gateway (Cradlepoint)"));
        POLICE_OUIS.put("ec:f4:51", new OuiEntry("Cradlepoint, Inc.", "router", "Cradlepoint in-car router", 40, "Police In-Car Gateway (Cradlepoint)"));
        POLICE_OUIS.put("00:12:a2", new OuiEntry("Digi International", "router", "Digi WR-series in-car router", 35, "Mobile Broadband Router (Digi)"));
        POLICE_OUIS.put("00:0f:78", new OuiEntry("Sierra Wireless", "router", "Sierra Wireless AirLink gateway", 40, "Police In-Car Gateway (AirLink)"));
        POLICE_OUIS.put("00:a0:8e", new OuiEntry("Sierra Wireless", "router", "Sierra Wireless AirLink gateway", 40, "Police In-Car Gateway (AirLink)"));
        POLICE_OUIS.put("00:1a:dd", new OuiEntry("Peplink / Pismo Labs", "router", "Peplink MAX in-car router", 35, "Mobile Router (Peplink)"));

        // --- Bodycam / Dashcam / Dispatch (Axon, WatchGuard, L3Harris) ---
        POLICE_OUIS.put("94:3a:f0", new OuiEntry("Axon Enterprise, Inc.", "camera", "Axon Fleet / Bodycam link", 50, "Axon Police Video System"));
        POLICE_OUIS.put("74:ea:e8", new OuiEntry("Axon Enterprise, Inc.", "camera", "Axon Fleet / Bodycam link", 50, "Axon Police Video System"));
        POLICE_OUIS.put("00:25:df", new OuiEntry("WatchGuard Video", "camera", "WatchGuard 4RE In-Car Video", 50, "WatchGuard Police Video System"));
        POLICE_OUIS.put("00:0b:86", new OuiEntry("L3Harris Technologies", "radio", "L3Harris tactical dispatch link", 50, "Tactical Communications Link"));

        // --- Police SSID Patterns ---
        POLICE_SSID_RULES.add(new SsidRule("\\bhighway[\\s_-]+patrol\\b", "References 'highway patrol'", "State Highway Patrol Vehicle", 88));
        POLICE_SSID_RULES.add(new SsidRule("\\bstate[\\s_-]+police\\b", "References 'state police'", "State Police Vehicle", 88));
        POLICE_SSID_RULES.add(new SsidRule("\\bpolice[\\s_-]+department\\b", "References 'police department'", "Police Department Vehicle", 88));
        POLICE_SSID_RULES.add(new SsidRule("\\bmetropolitan[\\s_-]+police\\b", "References 'metropolitan police'", "Police Patrol Vehicle", 88));
        POLICE_SSID_RULES.add(new SsidRule("\\bsheriff('s|[\\s_-]+office|[\\s_-]+dept)?\\b", "References 'sheriff'", "Sheriff Vehicle", 85));
        POLICE_SSID_RULES.add(new SsidRule("\\bpolice\\b", "References 'police'", "Police Patrol Vehicle", 85));
        POLICE_SSID_RULES.add(new SsidRule("\\b(nypd|lapd|kcpd|dmpd|bcpd|hpd|spd|cpd|apd|mpd)\\b", "Major police department abbreviation", "Police Department Vehicle", 80));
        POLICE_SSID_RULES.add(new SsidRule("\\b(fhp|chp|txdps|msp|vsp|ohp|isp|nhp|scp)\\b", "State police abbreviation", "State Police Vehicle", 80));
        POLICE_SSID_RULES.add(new SsidRule("\\btrooper\\b", "References 'trooper'", "State Trooper Vehicle", 78));
        POLICE_SSID_RULES.add(new SsidRule("\\bconstable\\b", "References 'constable'", "Constable Vehicle", 75));
        POLICE_SSID_RULES.add(new SsidRule("\\bpatrol\\b", "References 'patrol'", "Suspected Patrol Vehicle", 60));
        POLICE_SSID_RULES.add(new SsidRule("\\bdispatch\\b", "References 'dispatch'", "Dispatch / Emergency Unit", 60));
        POLICE_SSID_RULES.add(new SsidRule("\\bmobile[\\s_-]+command\\b", "References 'mobile command'", "Mobile Command Unit", 85));
        POLICE_SSID_RULES.add(new SsidRule("\\bk9\\b|\\bk-9\\b", "References 'k9 unit'", "Police K9 Unit", 75));
        POLICE_SSID_RULES.add(new SsidRule("\\bmdt[\\s_-]?[0-9]*\\b", "Mobile Data Terminal ID pattern", "In-Vehicle MDT Unit", 70));
        POLICE_SSID_RULES.add(new SsidRule("\\bunit[\\s_-]?[0-9]{2,4}\\b", "Unit number pattern", "Emergency Fleet Unit", 60));
        POLICE_SSID_RULES.add(new SsidRule("(?i)(axon|watchguard|cradlepoint)[-_ ][0-9a-f]+", "Police equipment hardware SSID", "Police In-Car Hardware", 85));
    }

    public static Detection analyze(String bssid, String ssid) {
        Detection result = new Detection();
        String oui = RadarData.normalizeOui(bssid);
        String cleanSsid = ssid != null ? ssid.trim() : "";
        boolean isHidden = cleanSsid.isEmpty() || cleanSsid.equalsIgnoreCase("<unknown ssid>");

        result.isPoliceVehicle = false;
        result.confidenceScore = 0;
        result.deviceType = "Standard Wi-Fi";
        result.vendor = "Unknown";

        boolean ssidMatched = false;
        for (SsidRule rule : POLICE_SSID_RULES) {
            if (rule.pattern.matcher(cleanSsid).find()) {
                ssidMatched = true;
                result.isPoliceVehicle = true;
                result.deviceType = rule.deviceType;
                result.confidenceScore = Math.max(result.confidenceScore, rule.confidence);
                result.reasons.add("SSID matches " + rule.description);
                break;
            }
        }

        boolean ouiMatched = POLICE_OUIS.containsKey(oui);
        if (ouiMatched) {
            OuiEntry entry = POLICE_OUIS.get(oui);
            result.vendor = entry.vendor;
            if (ssidMatched) {
                result.confidenceScore = Math.max(result.confidenceScore, 95);
                result.reasons.add("Hardware confirms: " + entry.description + " (" + oui + ")");
            } else if (isHidden) {
                result.isPoliceVehicle = true;
                result.deviceType = "Suspected " + entry.deviceType + " (Hidden SSID)";
                result.confidenceScore = Math.max(result.confidenceScore, 70);
                result.reasons.add("Hidden SSID on known " + entry.description);
            } else {
                result.confidenceScore = Math.max(result.confidenceScore, entry.baseConfidence);
                result.reasons.add("Shares hardware vendor with " + entry.description);
            }
        }

        if (result.confidenceScore >= 85) {
            result.confidence = "CONFIRMED";
        } else if (result.confidenceScore >= 70) {
            result.confidence = "HIGH";
        } else if (result.confidenceScore >= 45) {
            result.confidence = "MEDIUM";
        } else if (result.confidenceScore >= 20) {
            result.confidence = "LOW";
        } else {
            result.confidence = "NONE";
        }

        return result;
    }
}
