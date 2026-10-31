#!/usr/bin/env python3
"""
CIVOPS-Radar: Flock Safety & ALPR Camera Detector
Author: CIVOPS-Radar Contributors
License: MIT

Specialized detection engine for identifying Flock Safety automated license plate
recognition (ALPR) cameras, solar telemetry nodes, and surveillance infrastructure
using hardware OUI fingerprinting, SSID patterns, and RF characteristics.
"""

import re
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass


@dataclass
class FlockDetection:
    is_flock: bool
    is_alpr: bool
    confidence: str          # "CONFIRMED", "HIGH", "MEDIUM", "LOW", "NONE"
    confidence_score: int    # 0 to 100
    device_type: str         # Human-readable classification
    vendor: str              # Identified manufacturer
    reasons: List[str]       # Matched indicators


# Official and community-verified Flock Safety hardware OUIs.
# Source: IEEE MA-L registry (https://regauth.standards.ieee.org/standards-ra-web/pub/view.html#registries)
# b4:1e:52 is the sole IEEE-assigned OUI for Flock Safety, Inc. as of 2024.
FLOCK_OFFICIAL_OUIS = {
    "b4:1e:52": {
        "vendor": "Flock Safety Inc.",
        "description": "Flock Safety Official IEEE MA-L Assignment (Falcon V2/V3 ALPR)",
        "base_confidence": 98,
        "device_type": "Flock Safety ALPR Camera"
    }
}

# Chipset / OEM modules verified in Flock camera teardowns and firmware dumps.
# These OUIs belong to component vendors (Qualcomm, Lite-On) used across many devices,
# so they only raise suspicion when combined with Flock SSIDs or hidden-probe mode.
# Sources: community teardown reports and FCC ID filings for Flock Falcon hardware.
FLOCK_MODULE_OUIS = {
    "00:03:7f": {
        "vendor": "Qualcomm Atheros",
        "description": "Qualcomm QCA9377 Radio Module (Flock Falcon V1/V2 Assembly)",
        "base_confidence": 85,
        "device_type": "Flock Falcon ALPR (Qualcomm Radio)"
    },
    "70:c9:4e": {
        "vendor": "Lite-On Technology Corp.",
        "description": "Lite-On OEM Wi-Fi Module (Flock Camera Production Line)",
        "base_confidence": 85,
        "device_type": "Flock Camera Assembly (Lite-On)"
    },
    "82:6b:f2": {
        "vendor": "Flock Field Signature",
        "description": "Flock Camera SoftAP Field Signature",
        "base_confidence": 90,
        "device_type": "Flock Camera Node"
    }
}

# Other law enforcement and traffic surveillance ALPR manufacturers
OTHER_ALPR_OUIS = {
    "00:1d:a5": {
        "vendor": "Motorola Solutions",
        "description": "Motorola Solutions / Vigilant ALPR Camera",
        "base_confidence": 80,
        "device_type": "Vigilant ALPR Surveillance Camera"
    },
    "00:26:73": {
        "vendor": "Vivotek Inc.",
        "description": "Vivotek Traffic / License Plate Recognition Camera",
        "base_confidence": 75,
        "device_type": "Traffic Surveillance Camera"
    },
    "e0:28:6d": {
        "vendor": "Hikvision",
        "description": "Hikvision Traffic / Vehicle Recognition Camera",
        "base_confidence": 70,
        "device_type": "Traffic Monitoring Camera"
    },
    "00:11:7f": {
        "vendor": "Qualcomm Atheros",
        "description": "Embedded Surveillance Wireless Unit",
        "base_confidence": 65,
        "device_type": "Surveillance Wireless Unit"
    }
}

# Regex patterns for SSIDs emitted during setup, maintenance, or solar telemetry.
# Flock cameras broadcast in four categories:
#   1. SoftAP setup mode  — "flock-<hex>", "flock", "fs-<hex>" (camera config interface)
#   2. Battery telemetry  — "fs ext battery*", "fs battery*" (solar power node)
#   3. Model name SSIDs   — "falcon-*", "sparrow-*", "raven-*" (device family names)
#   4. Maintenance / audit — "deflock*", "alpr-*", "license plate*"
# Each tuple: (regex_pattern, description, device_type, confidence_score)
FLOCK_SSID_PATTERNS = [
    (r'(?i)^flock[-_ ]?[0-9a-f]{2,}', "Flock Camera SoftAP broadcast", "Flock Safety ALPR Camera", 85),
    (r'(?i)^flock$', "Flock default SSID", "Flock Safety Device", 90),
    (r'(?i)^fs[-_ ]?ext[-_ ]?battery.*', "Flock External Battery Telemetry broadcast", "Flock Solar Power Telemetry", 95),
    (r'(?i)^fs[-_ ]?battery.*', "Flock Battery Telemetry broadcast", "Flock Solar Power Telemetry", 95),
    (r'(?i)^fs[-_ ][0-9a-f]{4,}', "Flock Safety node SSID", "Flock Safety Node", 90),
    (r'(?i)^falcon[-_ ]?[0-9a-f]*', "Flock Falcon camera broadcast", "Flock Falcon ALPR Camera", 95),
    (r'(?i)^sparrow[-_ ]?[0-9a-f]*', "Flock Sparrow camera broadcast", "Flock Sparrow ALPR Camera", 90),
    (r'(?i)^raven[-_ ]?[0-9a-f]*', "Flock Raven acoustic/audio sensor broadcast", "Flock Raven Audio Sensor", 90),
    (r'(?i).*deflock.*', "DeFlock test node", "DeFlock Audit Device", 80),
    (r'(?i)^alpr[-_ ]?.*', "General ALPR system SSID", "ALPR System", 85),
    (r'(?i).*license[-_ ]?plate.*', "License plate recognition SSID", "ALPR System", 85)
]


class FlockDetector:
    """Detection engine for Flock Safety and ALPR cameras"""

    @staticmethod
    def normalize_oui(bssid: str) -> str:
        """Extract first 3 bytes (XX:XX:XX) in lowercase"""
        if not bssid:
            return ""
        clean = re.sub(r'[^0-9a-fA-F]', '', bssid.strip().lower())
        if len(clean) >= 6:
            return f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
        return ""

    def analyze(self, bssid: str, ssid: Optional[str] = None, 
                capabilities: Optional[str] = None, 
                level: Optional[int] = None,
                frequency: Optional[int] = None) -> FlockDetection:
        """
        Analyze a wireless network profile and determine if it is a Flock or ALPR camera.
        """
        oui = self.normalize_oui(bssid)
        ssid_clean = (ssid or "").strip()
        is_hidden = (ssid_clean == "" or ssid_clean.lower() == "<unknown ssid>")
        reasons: List[str] = []
        
        is_flock = False
        is_alpr = False
        confidence_score = 0
        device_type = "Standard Wi-Fi"
        vendor = "Unknown"

        # Step 1 — Official OUI: highest confidence; b4:1e:52 is IEEE-registered to Flock Safety Inc.
        if oui in FLOCK_OFFICIAL_OUIS:
            entry = FLOCK_OFFICIAL_OUIS[oui]
            is_flock = True
            is_alpr = True
            vendor = entry["vendor"]
            device_type = entry["device_type"]
            confidence_score = entry["base_confidence"]
            reasons.append(f"Matches Official {entry['description']} ({oui})")

        # Step 2 — SSID patterns: match against known Flock broadcast names.
        # Patterns with confidence ≥ 95 yield CONFIRMED; ≥ 80 yield HIGH.
        # 2. Check SSID Patterns
        matched_ssid_rule = False
        for pattern, desc, d_type, conf in FLOCK_SSID_PATTERNS:
            if re.search(pattern, ssid_clean):
                matched_ssid_rule = True
                is_flock = True
                is_alpr = True
                device_type = d_type
                confidence_score = max(confidence_score, conf)
                reasons.append(f"SSID '{ssid_clean}' matches {desc}")
                if "Flock" in d_type:
                    vendor = "Flock Safety"
                break

        # Step 3 — Module OUI: shared chipsets raise suspicion but alone are not conclusive.
        # Combined with an SSID match or a hidden probe → confidence elevated to HIGH/CONFIRMED.
        # 3. Check Flock Hardware Module OUIs
        if oui in FLOCK_MODULE_OUIS:
            entry = FLOCK_MODULE_OUIS[oui]
            if vendor == "Unknown":
                vendor = entry["vendor"]
                
            if matched_ssid_rule or (oui in FLOCK_OFFICIAL_OUIS):
                confidence_score = 100
                reasons.append(f"Hardware confirms: {entry['description']}")
            elif is_hidden:
                # Stealth / Wildcard probe mode on a known Flock camera radio chipset
                is_flock = True
                is_alpr = True
                device_type = f"Suspected {entry['device_type']} (Stealth Probe)"
                confidence_score = max(confidence_score, 82)
                reasons.append(f"Stealth/Hidden Wi-Fi on known {entry['description']} ({oui})")
            else:
                # Known chipset but standard SSID: moderate suspicion
                confidence_score = max(confidence_score, 45)
                reasons.append(f"Shares hardware chipset with {entry['description']} ({oui})")

        # Step 4 — Other ALPR OUIs: non-Flock surveillance manufacturers.
        # Flagged as is_alpr=True but is_flock remains False.
        # 4. Check Other ALPR Manufacturer OUIs
        if not is_flock and oui in OTHER_ALPR_OUIS:
            entry = OTHER_ALPR_OUIS[oui]
            is_alpr = True
            vendor = entry["vendor"]
            device_type = entry["device_type"]
            confidence_score = max(confidence_score, entry["base_confidence"])
            reasons.append(f"Matches {entry['description']} ({oui})")

        # Assign confidence tier
        if confidence_score >= 95:
            confidence = "CONFIRMED"
        elif confidence_score >= 80:
            confidence = "HIGH"
        elif confidence_score >= 50:
            confidence = "MEDIUM"
        elif confidence_score > 0:
            confidence = "LOW"
        else:
            confidence = "NONE"

        return FlockDetection(
            is_flock=is_flock,
            is_alpr=is_alpr or is_flock,
            confidence=confidence,
            confidence_score=confidence_score,
            device_type=device_type,
            vendor=vendor,
            reasons=reasons
        )


# Singleton detector instance for fast access
detector = FlockDetector()
