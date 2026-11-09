#!/usr/bin/env python3
"""
CIVOPS-Radar: Police Vehicle Detector
Author: CIVOPS-Radar Contributors
License: MIT

Heuristic detector for police / law-enforcement vehicle equipment observed on Wi-Fi.

There is no universal Wi-Fi fingerprint that identifies a police vehicle: patrol-car
mobile data terminals (MDTs) are usually Wi-Fi *clients* rather than access points, and
in-car routers / ALPR links do not always broadcast a department-identifying SSID.
Detection is therefore probabilistic and combines two weak signals:

  1. SSID naming patterns that reference police / municipal fleet equipment.
  2. Hardware vendor OUIs (first 3 bytes of the BSSID) for manufacturers whose gear is
     commonly installed in police vehicles (mobile ALPR, in-car routers, dispatch radios).

Every OUI below was verified against the IEEE MA-L registry
(https://standards-oui.ieee.org/oui/oui.csv). An OUI identifies the *manufacturer*, not
the installation, so an OUI on its own is only LOW confidence and does not flag a device.
Confidence rises when an OUI is combined with a matching SSID, or when the SSID itself is
strongly indicative.

Expected error rates: false negatives are high (most police vehicles broadcast nothing
identifiable); false positives are possible (a civilian SSID containing "police", or a
CradlePoint / Axis device in a business). Tune POLICE_SSID_PATTERNS to your local area and
treat LOW/MEDIUM results as leads, not conclusions.

This detector is passive: it only reads information the device itself broadcasts.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class PoliceVehicleDetection:
    is_police_vehicle: bool
    confidence: str          # "CONFIRMED", "HIGH", "MEDIUM", "LOW", "NONE"
    confidence_score: int    # 0 to 100
    device_type: str         # Human-readable classification
    vendor: str              # Identified manufacturer
    reasons: List[str] = field(default_factory=list)      # Matched indicators
    indicators: List[str] = field(default_factory=list)   # Category tags


# ---------------------------------------------------------------------------
# Vendor OUIs — verified against the IEEE MA-L registry.
#
# Categories:
#   alpr    mobile automated licence plate readers (patrol-car ALPR)
#   camera  mobile surveillance / thermal cameras (also common in civilian use)
#   router  in-car routers / mobile broadband gateways
#   radio   dispatch / two-way radio equipment
#
# base_confidence is deliberately low: an OUI alone only says "this chipset is made by a
# company that sells to police fleets", not "this is a police vehicle".
# ---------------------------------------------------------------------------
POLICE_VEHICLE_OUIS: Dict[str, Dict[str, Any]] = {
    # --- Mobile ALPR / traffic enforcement ---
    "70:1a:d5": {
        "vendor": "Avigilon (Motorola Solutions)",
        "category": "alpr",
        "description": "Avigilon ALPR / surveillance camera",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },
    "0c:bf:15": {
        "vendor": "Genetec Inc.",
        "category": "alpr",
        "description": "Genetec AutoVu ALPR camera",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },
    "00:bf:15": {
        "vendor": "Genetec Inc.",
        "category": "alpr",
        "description": "Genetec AutoVu ALPR camera",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },
    "00:0a:b1": {
        "vendor": "GENETEC Corporation",
        "category": "alpr",
        "description": "Genetec AutoVu ALPR camera",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },
    "00:80:e7": {
        "vendor": "Leonardo UK Ltd",
        "category": "alpr",
        "description": "Leonardo / Selex traffic & ALPR systems",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },
    "00:17:28": {
        "vendor": "Selex Communications (Leonardo)",
        "category": "alpr",
        "description": "Selex traffic & ALPR systems",
        "base_confidence": 45,
        "device_type": "Police ALPR Unit (Mobile)",
    },

    # --- Mobile surveillance cameras (weak: common in civilian use) ---
    "00:01:31": {
        "vendor": "Bosch Security Systems, Inc.",
        "category": "camera",
        "description": "Bosch surveillance camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "00:04:63": {
        "vendor": "Bosch Security Systems",
        "category": "camera",
        "description": "Bosch surveillance camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "00:40:7f": {
        "vendor": "FLIR Systems",
        "category": "camera",
        "description": "FLIR thermal / surveillance camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "00:1b:d8": {
        "vendor": "FLIR Systems Inc",
        "category": "camera",
        "description": "FLIR thermal / surveillance camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "b8:a4:4f": {
        "vendor": "Axis Communications AB",
        "category": "camera",
        "description": "Axis network camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "00:40:8c": {
        "vendor": "Axis Communications AB",
        "category": "camera",
        "description": "Axis network camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "e8:27:25": {
        "vendor": "Axis Communications AB",
        "category": "camera",
        "description": "Axis network camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "ac:cc:8e": {
        "vendor": "Axis Communications AB",
        "category": "camera",
        "description": "Axis network camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },
    "00:02:d1": {
        "vendor": "Vivotek, Inc.",
        "category": "camera",
        "description": "Vivotek network camera",
        "base_confidence": 35,
        "device_type": "Suspected Mobile Surveillance Camera",
    },

    # --- In-car routers / mobile gateways ---
    "00:30:44": {
        "vendor": "CradlePoint, Inc",
        "category": "router",
        "description": "CradlePoint in-car router / mobile gateway",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "00:e0:1c": {
        "vendor": "CradlePoint, Inc",
        "category": "router",
        "description": "CradlePoint in-car router / mobile gateway",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "50:13:9d": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "84:db:2f": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "64:ce:6e": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "cc:93:4a": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "00:a0:d5": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "28:a3:31": {
        "vendor": "Sierra Wireless, ULC",
        "category": "router",
        "description": "Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },
    "00:16:c0": {
        "vendor": "Semtech Corporation (Sierra Wireless parent)",
        "category": "router",
        "description": "Semtech / Sierra Wireless mobile broadband router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },

    # --- MDT tablets (Panasonic Toughbook, Getac) ---
    "00:40:f4": {
        "vendor": "Panasonic Communications",
        "category": "mdt",
        "description": "Panasonic Toughbook MDT (police in-car laptop)",
        "base_confidence": 42,
        "device_type": "Police Mobile Data Terminal (Toughbook)",
    },
    "00:00:04": {
        "vendor": "Panasonic Communications Corporation",
        "category": "mdt",
        "description": "Panasonic MDT networking hardware",
        "base_confidence": 35,
        "device_type": "Police Mobile Data Terminal",
    },
    "e8:9f:80": {
        "vendor": "Getac Technology Corporation",
        "category": "mdt",
        "description": "Getac rugged tablet / MDT",
        "base_confidence": 42,
        "device_type": "Police Mobile Data Terminal (Getac)",
    },

    # --- Additional CradlePoint OUIs ---
    "28:3b:82": {
        "vendor": "CradlePoint, Inc",
        "category": "router",
        "description": "CradlePoint IBR/AER in-car router",
        "base_confidence": 40,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },

    # --- Digi International (fleet cellular routers) ---
    "00:40:9d": {
        "vendor": "Digi International Inc.",
        "category": "router",
        "description": "Digi WR/IX fleet cellular router",
        "base_confidence": 38,
        "device_type": "Police In-Car Router / Mobile Gateway",
    },

    # --- Utility / Public Safety FirstNet routers ---
    "4c:14:a3": {
        "vendor": "Franklin Wireless",
        "category": "router",
        "description": "Franklin T10 / FirstNet mobile hotspot",
        "base_confidence": 35,
        "device_type": "Suspected FirstNet / Public-Safety Hotspot",
    },

    # --- Dispatch / two-way radio equipment ---
    "00:04:7d": {
        "vendor": "Motorola Solutions Inc.",
        "category": "radio",
        "description": "Motorola Solutions public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:1f:92": {
        "vendor": "Motorola Solutions Inc.",
        "category": "radio",
        "description": "Motorola Solutions public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "4c:cc:34": {
        "vendor": "Motorola Solutions Inc.",
        "category": "radio",
        "description": "Motorola Solutions public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:18:85": {
        "vendor": "Motorola Solutions Inc.",
        "category": "radio",
        "description": "Motorola Solutions public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:0d:ca": {
        "vendor": "Tait Electronics",
        "category": "radio",
        "description": "Tait public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:17:f3": {
        "vendor": "Harris Corporation",
        "category": "radio",
        "description": "Harris / L3Harris public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:06:ec": {
        "vendor": "Harris Corporation",
        "category": "radio",
        "description": "Harris / L3Harris public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:14:91": {
        "vendor": "Daniels Electronics Ltd. (Codan Radio Communications)",
        "category": "radio",
        "description": "Codan public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "00:12:e0": {
        "vendor": "Codan Limited",
        "category": "radio",
        "description": "Codan public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "64:69:bc": {
        "vendor": "Hytera Communications",
        "category": "radio",
        "description": "Hytera public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
    "9c:06:6e": {
        "vendor": "Hytera Communications Corporation Limited",
        "category": "radio",
        "description": "Hytera public-safety radio",
        "base_confidence": 35,
        "device_type": "Police Dispatch Radio",
    },
}


# ---------------------------------------------------------------------------
# SSID naming heuristics.
#
# The built-in patterns are *generic* heuristics, not a database of real department SSIDs.
# Police departments do not publish a naming standard, so expect to add local patterns.
# Each tuple: (regex, description, device_type, confidence_score, category)
# Patterns are evaluated in order; the first (strongest) match wins.
# ---------------------------------------------------------------------------
POLICE_SSID_PATTERNS: List[Tuple[str, str, str, int, str]] = [
    # --- Strong agency identifiers (HIGH) ---
    (r'(?i)\bhighway[\s_-]+patrol\b', "SSID references 'highway patrol'",
     "State Highway Patrol Vehicle", 88, "agency"),
    (r'(?i)\bstate[\s_-]+police\b', "SSID references 'state police'",
     "State Police Vehicle", 88, "agency"),
    (r'(?i)\bpolice[\s_-]+department\b', "SSID references 'police department'",
     "Police Department Vehicle", 88, "agency"),
    (r'(?i)\bmetropolitan[\s_-]+police\b', "SSID references 'metropolitan police'",
     "Police Patrol Vehicle", 88, "agency"),
    (r'(?i)\bsheriff(\'s|[\s_-]+office|[\s_-]+dept)?\b', "SSID references 'sheriff'",
     "Sheriff Vehicle", 85, "agency"),
    (r'(?i)\bpolice\b', "SSID references 'police'",
     "Police Patrol Vehicle", 85, "agency"),

    # --- Department / agency abbreviations (HIGH) ---
    (r'(?i)\b(nypd|lapd|kcpd|dmpd|bcpd|hpd|spd|cpd|apd|mpd)\b',
     "SSID matches a major police department abbreviation",
     "Police Department Vehicle", 80, "agency"),
    (r'(?i)\b(fhp|chp|txdps|msp|vsp|ohp|isp|nhp|scp)\b',
     "SSID matches a state police / highway patrol abbreviation",
     "State Police Vehicle", 80, "agency"),

    # --- Other agency roles (MEDIUM-HIGH) ---
    (r'(?i)\btrooper\b', "SSID references 'trooper'",
     "State Trooper Vehicle", 78, "agency"),
    (r'(?i)\bconstable\b', "SSID references 'constable'",
     "Constable Vehicle", 75, "agency"),
    (r'(?i)\bpatrol\b', "SSID references 'patrol'",
     "Suspected Patrol Vehicle", 60, "agency"),
    (r'(?i)\bdispatch\b', "SSID references 'dispatch'",
     "Police Dispatch Vehicle", 60, "agency"),

    # --- Mobile data terminal / equipment branding (MEDIUM) ---
    (r'(?i)\bmdt\b', "SSID references 'MDT' (mobile data terminal)",
     "Police Mobile Data Terminal", 70, "equipment"),
    (r'(?i)\bmobile[\s_-]+data\b', "SSID references 'mobile data'",
     "Police Mobile Data Terminal", 70, "equipment"),
    (r'(?i)\btoughbook\b', "SSID references Panasonic Toughbook MDT",
     "Police Mobile Data Terminal", 70, "equipment"),
    (r'(?i)\bcradlepoint\b', "SSID references CradlePoint in-car router",
     "Police In-Car Router / Mobile Gateway", 65, "equipment"),
    (r'(?i)\bsierra[\s_-]+wireless\b', "SSID references Sierra Wireless router",
     "Police In-Car Router / Mobile Gateway", 65, "equipment"),
    (r'(?i)\bfirstnet\b', "SSID references FirstNet (AT&T public-safety network)",
     "FirstNet / Public-Safety Device", 72, "equipment"),

    # --- Municipal / fleet (MEDIUM-LOW, generic) ---
    (r'(?i)\bmunicipal\b', "SSID references 'municipal'",
     "Municipal Vehicle", 60, "municipal"),
    (r'(?i)\bfleet\b', "SSID references 'fleet'",
     "Municipal / Fleet Vehicle", 55, "municipal"),
    (r'(?i)\bmuni\b', "SSID references 'muni'",
     "Municipal Vehicle", 55, "municipal"),
    (r'(?i)\bcity[\s_-]+of\b', "SSID references a city",
     "Municipal Vehicle", 55, "municipal"),
    (r'(?i)\bcounty[\s_-]+of\b', "SSID references a county",
     "Municipal / County Vehicle", 55, "municipal"),
]


class PoliceVehicleDetector:
    """Detection engine for police / law-enforcement vehicle equipment."""

    @staticmethod
    def normalize_oui(bssid: str) -> str:
        """Extract first 3 bytes (XX:XX:XX) in lowercase."""
        if not bssid:
            return ""
        clean = re.sub(r'[^0-9a-fA-F]', '', bssid.strip().lower())
        if len(clean) >= 6:
            return f"{clean[0:2]}:{clean[2:4]}:{clean[4:6]}"
        return ""

    def analyze(self, bssid: str, ssid: Optional[str] = None,
                capabilities: Optional[str] = None,
                level: Optional[int] = None,
                frequency: Optional[int] = None) -> PoliceVehicleDetection:
        """
        Analyze a wireless network profile and determine if it belongs to (or is
        consistent with) a police / law-enforcement vehicle.
        """
        oui = self.normalize_oui(bssid)
        ssid_clean = (ssid or "").strip()
        is_hidden = (ssid_clean == "" or ssid_clean.lower() == "<unknown ssid>")
        reasons: List[str] = []
        indicators: List[str] = []

        is_police = False
        confidence_score = 0
        device_type = "Standard Wi-Fi"
        vendor = "Unknown"

        # --- Step 1: SSID naming heuristics -------------------------------------
        ssid_matched = False
        for pattern, desc, d_type, conf, category in POLICE_SSID_PATTERNS:
            if re.search(pattern, ssid_clean):
                ssid_matched = True
                is_police = True
                device_type = d_type
                confidence_score = max(confidence_score, conf)
                reasons.append(f"SSID '{ssid_clean}' matches {desc}")
                indicators.append(category)
                break  # first (strongest) pattern wins

        # --- Step 2: Vendor OUI -------------------------------------------------
        oui_matched = oui in POLICE_VEHICLE_OUIS
        if oui_matched:
            entry = POLICE_VEHICLE_OUIS[oui]
            if vendor == "Unknown":
                vendor = entry["vendor"]
            indicators.append(entry["category"])

            if ssid_matched:
                # SSID + known police-equipment vendor = strongest combination.
                confidence_score = max(confidence_score, 95)
                reasons.append(
                    f"Hardware confirms: {entry['description']} ({oui})"
                )
            elif is_hidden:
                # Hidden SSID on police-equipment hardware: suggestive, not proof.
                is_police = True
                device_type = f"Suspected {entry['device_type']} (Hidden SSID)"
                confidence_score = max(confidence_score, 70)
                reasons.append(
                    f"Hidden SSID on known {entry['description']} ({oui})"
                )
            else:
                # OUI alone: weak. Recorded as LOW suspicion, does not flag.
                confidence_score = max(confidence_score, entry["base_confidence"])
                reasons.append(
                    f"Shares hardware vendor with {entry['description']} ({oui})"
                )

        # --- Step 2b: Capability string analysis (EAP boost) -------------------
        if oui_matched:
            caps = (capabilities or "").upper()
            if "EAP" in caps:
                new_score = min(95, confidence_score + 15)
                if new_score > confidence_score:
                    confidence_score = new_score
                    reasons.append("Enterprise auth (EAP) on fleet-grade hardware")
                    if "enterprise_auth" not in indicators:
                        indicators.append("enterprise_auth")

        # --- Step 2c: Frequency band hint (5 GHz on hidden fleet router) -------
        if oui_matched:
            entry = POLICE_VEHICLE_OUIS[oui]
            if (entry["category"] in ("router", "alpr")
                    and frequency is not None and frequency >= 5000
                    and is_hidden):
                if confidence_score < 75:
                    confidence_score = 75
                reasons.append(
                    "5 GHz band on hidden fleet router (less common for residential)"
                )

        # --- Step 3: Confidence tier --------------------------------------------
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

        return PoliceVehicleDetection(
            is_police_vehicle=is_police,
            confidence=confidence,
            confidence_score=confidence_score,
            device_type=device_type,
            vendor=vendor,
            reasons=reasons,
            indicators=sorted(set(indicators)),
        )


# Singleton detector instance for fast access
detector = PoliceVehicleDetector()
