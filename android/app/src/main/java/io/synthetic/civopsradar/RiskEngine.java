package io.synthetic.civopsradar;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class RiskEngine {

    private static final List<Pattern> SUSPICIOUS_PATTERNS = new ArrayList<>();

    static {
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(free|public|guest|open)"));
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(wifi|internet|hotspot)"));
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(admin|root|test|demo)"));
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(hack|crack|pwn)"));
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(evil|rogue|fake)"));
        SUSPICIOUS_PATTERNS.add(Pattern.compile("(?i)(backdoor|trojan|virus)"));
    }

    public static int calculateRisk(String ssid, String capabilities, int level, double distance,
                                    boolean isHidden, boolean isOpen, boolean isFlock, boolean isPolice,
                                    boolean isDrone) {
        int score = 0;

        // Open network penalty
        if (isOpen) {
            score += 35;
        }

        // Hidden SSID
        if (isHidden) {
            score += 20;
        }

        // Weak encryption (WEP or plain WPA1)
        if (capabilities != null) {
            String caps = capabilities.toUpperCase();
            if (caps.contains("WEP")) {
                score += 30;
            } else if (caps.contains("WPA-PSK") && !caps.contains("WPA2") && !caps.contains("RSN") && !caps.contains("SAE")) {
                score += 20;
            }
        }

        // Suspicious patterns
        if (ssid != null && !ssid.isEmpty()) {
            for (Pattern p : SUSPICIOUS_PATTERNS) {
                if (p.matcher(ssid).find()) {
                    score += 10;
                    break;
                }
            }
        }

        // Close proximity high signal
        if (level > -50 || distance < 10.0) {
            score += 10;
        }

        // Surveillance equipment penalty
        if (isFlock) {
            score += 40;
        }
        if (isPolice) {
            score += 30;
        }
        if (isDrone) {
            score += 25;
        }

        return Math.min(100, Math.max(0, score));
    }
}
