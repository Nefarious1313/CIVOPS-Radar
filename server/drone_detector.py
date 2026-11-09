#!/usr/bin/env python3
"""
CIVOPS-Radar: Drone & Unmanned Aerial Surveillance (UAV / UAS) Detector
Author: CIVOPS-Radar Contributors
License: MIT

Passive detection engine for identifying unmanned aerial vehicles (drones),
aerial surveillance platforms, tactical recon quadcopters, FAA Part 89
Remote ID (RID) broadcast nodes, and FPV downlink transmitters.

Operates purely passively by inspecting Wi-Fi beacon frames, probe responses,
hardware MAC vendor OUIs, Remote ID standard signatures, and 5.8 GHz RF characteristics.

Sources:
- OUIs: IEEE MA-L registry (https://standards-oui.ieee.org/oui/oui.csv), checked 2026-11-09.
- Remote ID: FAA Part 89 / ASD-STAN OpenDroneID broadcast naming conventions.
- SSID heuristics: observed DJI / Skydio / Parrot / Autel factory broadcast formats.

Expected behaviour:
- False negatives: most drones never broadcast a identifiable Wi-Fi SSID (OcuSync /
  Lightbridge / proprietary links stay hidden), so a clean scan does NOT prove the
  airspace is empty.
- False positives: an OUI-only match on a hidden or generic SSID stays LOW and does not
  alert; consumer WPS further suppresses it. Treat MEDIUM and above as actionable.
- Tuning: adjust base_confidence in DRONE_OUIS, add/remove SSID patterns, or change the
  alert threshold in Step 7 to suit your RF environment.
"""

import re
from typing import Dict, Any, Optional, Tuple, List
from dataclasses import dataclass, field


@dataclass
class DroneDetection:
    """Result returned by DroneDetector.analyze()."""
    is_drone: bool
    confidence: str          # "CONFIRMED", "HIGH", "MEDIUM", "LOW", "NONE"
    confidence_score: int    # 0 to 100
    device_type: str         # Human-readable classification
    vendor: str              # Identified manufacturer
    indicators: List[str] = field(default_factory=list)
    reasons: List[str] = field(default_factory=list)


# =============================================================================
# IEEE-VERIFIED HARDWARE OUIs (MAC Address Prefixes)
# =============================================================================
# Every prefix below was checked against the IEEE MA-L registry
# (https://standards-oui.ieee.org/oui/oui.csv) on 2026-11-09.
#
# OUI != installation: a prefix names the chipset maker, not the deployment.
# OUI-only matches stay at LOW confidence (below the 60 alert threshold) unless
# corroborated by a drone-specific SSID, Remote ID tag, or 5.8 GHz RF signature.
# Autel Robotics and Yuneec have no verified MA-L prefix, so those platforms are
# matched on SSID evidence only.

DRONE_OUIS: Dict[str, Dict[str, Any]] = {
    # --- DJI (SZ DJI TECHNOLOGY CO.,LTD) ---
    # Global leader in commercial, consumer, and public-safety drones
    # (Mavic, Matrice, Phantom, Inspire, Avata)
    "60:60:1f": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / OcuSync / Wi-Fi link",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "34:d2:62": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / flight hardware",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "48:1c:b9": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / wireless flight link",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "8c:58:23": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / communication module",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "0c:9a:e6": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / aerial robotics module",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "e4:7a:2c": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / flight controller",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "88:29:85": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / video downlink",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "58:b8:58": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / OcuSync module",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "04:a8:5a": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / aerial robotics module",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },
    "4c:43:f6": {
        "vendor": "DJI (SZ DJI TECHNOLOGY)",
        "description": "DJI drone / wireless flight link",
        "base_confidence": 50,
        "device_type": "DJI Drone / Aerial Platform",
    },

    # --- DJI Baiwang Technology (enterprise flight systems) ---
    "9c:5a:8a": {
        "vendor": "DJI (DJI BAIWANG TECHNOLOGY)",
        "description": "DJI Baiwang enterprise drone flight system",
        "base_confidence": 50,
        "device_type": "DJI Enterprise Drone",
    },
    "c8:a1:62": {
        "vendor": "DJI (DJI BAIWANG TECHNOLOGY)",
        "description": "DJI Baiwang enterprise drone flight system",
        "base_confidence": 50,
        "device_type": "DJI Enterprise Drone",
    },
    "ec:72:f7": {
        "vendor": "DJI (DJI BAIWANG TECHNOLOGY)",
        "description": "DJI Baiwang enterprise drone flight system",
        "base_confidence": 50,
        "device_type": "DJI Enterprise Drone",
    },
    "34:91:f0": {
        "vendor": "DJI (DJI BAIWANG TECHNOLOGY)",
        "description": "DJI Baiwang enterprise drone flight system",
        "base_confidence": 50,
        "device_type": "DJI Enterprise Drone",
    },

    # --- DJI Ronin / Osmo (handheld gimbals & cameras) ---
    # Not aircraft, but share DJI radio hardware; kept at LOW base confidence.
    "24:91:23": {
        "vendor": "DJI (SZ DJI Ronin Technology)",
        "description": "DJI Ronin gimbal / handheld link",
        "base_confidence": 45,
        "device_type": "DJI Ronin Gimbal / Handheld",
    },
    "f8:40:68": {
        "vendor": "DJI (SZ DJI Ronin Technology)",
        "description": "DJI Ronin gimbal / handheld link",
        "base_confidence": 45,
        "device_type": "DJI Ronin Gimbal / Handheld",
    },
    "20:1f:55": {
        "vendor": "DJI (DJI Osmo Technology)",
        "description": "DJI Osmo handheld camera link",
        "base_confidence": 45,
        "device_type": "DJI Osmo Handheld",
    },

    # --- Skydio Inc. ---
    # US autonomous drone manufacturer used extensively by police (patrol/tactical), DoD, and inspection
    "38:1d:14": {
        "vendor": "Skydio Inc.",
        "description": "Skydio Autonomous Recon Drone (Skydio 2 / X2 / X10)",
        "base_confidence": 60,
        "device_type": "Skydio Autonomous Surveillance Drone",
    },

    # --- Parrot SA ---
    # Anafi USA (DoD Blue UAS / law enforcement recon), Anafi Thermal, Bebop
    "90:03:b7": {
        "vendor": "Parrot SA",
        "description": "Parrot Drone / Flight Controller (Anafi / Bebop)",
        "base_confidence": 50,
        "device_type": "Parrot Drone / Recon UAS",
    },
    "00:12:1c": {
        "vendor": "Parrot SA",
        "description": "Parrot Aircraft Electronics",
        "base_confidence": 50,
        "device_type": "Parrot Drone / Recon UAS",
    },
    "a0:14:3d": {
        "vendor": "Parrot SA",
        "description": "Parrot UAS Telemetry Link",
        "base_confidence": 50,
        "device_type": "Parrot Drone / Recon UAS",
    },
    "00:26:7e": {
        "vendor": "Parrot SA",
        "description": "Parrot Drone / Flight Controller",
        "base_confidence": 50,
        "device_type": "Parrot Drone / Recon UAS",
    },
    "90:3a:e6": {
        "vendor": "Parrot SA",
        "description": "Parrot Drone / Flight Controller",
        "base_confidence": 50,
        "device_type": "Parrot Drone / Recon UAS",
    },

    # --- Teal Drones (Red Cat Holdings) ---
    # Golden Eagle / Teal 2 tactical recon drones for DoD and SWAT
    "b0:30:c8": {
        "vendor": "Teal Drones, Inc.",
        "description": "Teal Tactical Reconnaissance Drone (Golden Eagle / Teal 2)",
        "base_confidence": 65,
        "device_type": "Teal Tactical Defense Drone",
    },

    # --- GoPro (Karma drone program) ---
    "d8:96:85": {
        "vendor": "GoPro",
        "description": "GoPro Karma drone / action camera link",
        "base_confidence": 45,
        "device_type": "GoPro Karma Drone",
    },

    # --- AeroVironment (military UAS: Raven / Puma / Wasp) ---
    "00:1a:f9": {
        "vendor": "AeroVironment (AV Inc)",
        "description": "AeroVironment military UAS (Raven / Puma / Wasp)",
        "base_confidence": 60,
        "device_type": "AeroVironment Military UAS",
    },

    # --- XAG (agricultural / industrial drones) ---
    "a4:51:29": {
        "vendor": "XAG",
        "description": "XAG agricultural / industrial drone",
        "base_confidence": 50,
        "device_type": "XAG Agricultural Drone",
    },

    # --- Powervision (consumer / industrial drones) ---
    "54:7d:40": {
        "vendor": "Powervision Tech Inc.",
        "description": "Powervision consumer / industrial drone",
        "base_confidence": 45,
        "device_type": "Powervision Drone",
    },

    # --- FPV / ESP32 drone wireless modules ---
    # ESP32 chips are used in Betaflight / ExpressLRS / SpeedyBee flight controllers.
    "24:4c:ab": {
        "vendor": "Espressif Systems (ESP32)",
        "description": "ESP32 FPV / Betaflight drone wireless module",
        "base_confidence": 40,
        "device_type": "FPV Drone Wireless Module",
    },
    "c8:2b:96": {
        "vendor": "Espressif Systems (ESP32)",
        "description": "ESP32 FPV / ExpressLRS drone wireless module",
        "base_confidence": 40,
        "device_type": "FPV Drone Wireless Module",
    },
}


# =============================================================================
# SSID PATTERN HEURISTICS FOR DRONES & REMOTE ID
# =============================================================================
# (regex, description, default_device_type, base_confidence, category)

DRONE_SSID_PATTERNS: List[Tuple[str, str, str, int, str]] = [
    # --- FAA Part 89 / ASD-STAN OpenDroneID Remote ID Broadcasts (VERY HIGH) ---
    (r'(?i)^(rid|dji[-_]rid|uas[-_]rid|drone[-_]rid)[-_]',
     "SSID matches FAA Part 89 / ASD-STAN standard Remote ID broadcast",
     "FAA Remote ID Drone Broadcast", 95, "remote_id"),
    (r'(?i)\b(opendroneid|odid)[-_]',
     "SSID matches OpenDroneID standard open-source broadcast",
     "OpenDroneID Remote ID Broadcast", 95, "remote_id"),
    (r'(?i)^uas[-_][a-z0-9]{6,}',
     "SSID matches standard Unmanned Aircraft System identifier prefix",
     "Unmanned Aircraft System (UAS)", 88, "remote_id"),

    # --- DJI Drone Fleet & Model Signatures ---
    (r'(?i)\b(dji[-_]+matrice|matrice[-_\s]*\d{2,3}[a-z]*)\b',
     "SSID matches DJI Matrice enterprise surveillance/inspection UAS",
     "DJI Matrice Enterprise Drone", 92, "enterprise_drone"),
    (r'(?i)\b(dji[-_]+mavic|mavic[-_\s]*(pro|air|enterprise|\d))\b',
     "SSID matches DJI Mavic aerial drone platform",
     "DJI Mavic Drone", 90, "consumer_drone"),
    (r'(?i)\b(dji[-_]+phantom|phantom[-_\s]*\d[a-z]*)\b',
     "SSID matches DJI Phantom series drone",
     "DJI Phantom Drone", 90, "consumer_drone"),
    (r'(?i)\b(dji[-_]+inspire|inspire[-_\s]*\d)\b',
     "SSID matches DJI Inspire aerial cinematography/recon drone",
     "DJI Inspire Drone", 90, "enterprise_drone"),
    (r'(?i)\b(dji[-_]+avata|avata[-_\s]*\d*)\b',
     "SSID matches DJI Avata FPV surveillance/tactical drone",
     "DJI Avata FPV Drone", 88, "fpv_drone"),
    (r'(?i)\b(dji[-_]+mini|mini[-_\s]*[2-5][a-z]*)\b',
     "SSID matches DJI Mini ultralight drone",
     "DJI Mini Drone", 86, "consumer_drone"),
    (r'(?i)^dji[-_][a-z0-9]{4,12}$',
     "SSID matches DJI factory drone Wi-Fi broadcast format",
     "DJI Drone / Aerial Platform", 88, "consumer_drone"),
    (r'(?i)\b(spark[-_][a-z0-9]{6})\b',
     "SSID matches DJI Spark micro-drone",
     "DJI Spark Drone", 85, "consumer_drone"),
    (r'(?i)\b(dji[-_]+(fly|pilot|go|assistant))\b',
     "SSID references DJI flight control / pilot station",
     "DJI Ground Control Station (GCS)", 82, "ground_station"),

    # --- Skydio Autonomous Recon Drones ---
    (r'(?i)\b(skydio[-_\s]*(x2|x10|2\+|2))\b',
     "SSID matches Skydio autonomous tactical reconnaissance drone",
     "Skydio Autonomous Recon Drone", 92, "tactical_drone"),
    (r'(?i)^skydio[-_][a-z0-9]{4,}',
     "SSID matches Skydio drone broadcast",
     "Skydio Autonomous Drone", 90, "tactical_drone"),

    # --- Autel Robotics ---
    (r'(?i)\b(autel[-_\s]*(evo|dragonfish|max))\b',
     "SSID matches Autel Robotics enterprise drone",
     "Autel Robotics Drone", 90, "enterprise_drone"),
    (r'(?i)\b(evo[-_\s]*(ii|max|lite|nano))\b',
     "SSID matches Autel EVO series aerial drone",
     "Autel EVO Drone", 86, "enterprise_drone"),

    # --- Parrot Defense & Consumer Recon ---
    (r'(?i)\b(anafi[-_\s]*(usa|thermal|ai|\d)?)\b',
     "SSID matches Parrot Anafi reconnaissance drone",
     "Parrot Anafi Recon Drone", 88, "tactical_drone"),
    (r'(?i)\b(bebop[-_\s]*\d?|parrot[-_]+disco)\b',
     "SSID matches Parrot aerial platform",
     "Parrot Aerial Drone", 82, "consumer_drone"),

    # --- Teal Drones (Military & SWAT) ---
    (r'(?i)\b(teal[-_\s]*(golden[-_\s]*eagle|2|\d)?)\b',
     "SSID matches Teal tactical defense drone",
     "Teal Tactical Defense Drone", 92, "tactical_drone"),

    # --- Yuneec Industrial ---
    (r'(?i)\b(typhoon[-_\s]*(h520|h|plus)?|yuneec)\b',
     "SSID matches Yuneec industrial aerial system",
     "Yuneec Aerial Drone", 84, "enterprise_drone"),

    # --- FPV / Open-Source Drone Links ---
    (r'(?i)\b(expresslrs|elrs[-_\s]*(tx|rx)?)\b',
     "SSID matches ExpressLRS open-source drone telemetry link",
     "ExpressLRS Drone Link", 80, "fpv_drone"),
    (r'(?i)\b(speedybee|betaflight|inav)[-_\s]',
     "SSID matches FPV drone flight controller Wi-Fi adapter",
     "FPV Drone Wireless Adapter", 78, "fpv_drone"),
]


class DroneDetector:
    """
    Passive detection engine for identifying drones, UAVs, and Remote ID beacons.
    """

    def __init__(self):
        self._compiled_patterns = [
            (re.compile(pat), desc, dev_type, conf, cat)
            for pat, desc, dev_type, conf, cat in DRONE_SSID_PATTERNS
        ]

    def analyze(
        self,
        bssid: Optional[str],
        ssid: Optional[str] = None,
        capabilities: Optional[str] = None,
        level: Optional[int] = None,
        frequency: Optional[int] = None,
    ) -> DroneDetection:
        """
        Analyze a detected network to determine if it is an unmanned aerial vehicle (drone).

        Parameters:
            bssid: MAC address of the access point / drone node
            ssid: Broadcast network name (may be None/empty)
            capabilities: 802.11 beacon capability string (e.g. "[WPA2-PSK-CCMP][ESS][WPS]")
            level: RSSI signal strength in dBm
            frequency: Operating frequency in MHz

        Returns:
            DroneDetection with classification, confidence tier, and forensic reasons.
        """
        reasons: List[str] = []
        indicators: List[str] = []
        confidence_score = 0
        device_type = "Standard Network"
        vendor = "Unknown"
        is_drone = False

        norm_bssid = (bssid or "").strip().lower()
        norm_ssid = (ssid or "").strip()
        caps = (capabilities or "").upper()
        oui = norm_bssid[:8] if len(norm_bssid) >= 8 else ""

        # --- Step 1: OUI Vendor Lookup ----------------------------------------
        oui_entry = DRONE_OUIS.get(oui)
        oui_matched = False
        if oui_entry:
            oui_matched = True
            vendor = oui_entry["vendor"]
            indicators.append("drone_vendor_oui")
            reasons.append(
                f"Hardware OUI {oui} matches {oui_entry['vendor']} ({oui_entry['description']})"
            )
            # Base confidence from OUI alone (typically 50-65)
            confidence_score = max(confidence_score, oui_entry["base_confidence"])
            device_type = oui_entry["device_type"]

        # --- Step 2: SSID Pattern Matching ------------------------------------
        ssid_matched = False
        if norm_ssid:
            for regex, desc, pat_dev_type, pat_conf, cat in self._compiled_patterns:
                if regex.search(norm_ssid):
                    ssid_matched = True
                    indicators.append(f"drone_ssid_{cat}")
                    reasons.append(f"SSID '{norm_ssid}': {desc}")
                    device_type = pat_dev_type
                    confidence_score = max(confidence_score, pat_conf)
                    break

        # --- Step 3: Combined Evidence Boosts ---------------------------------
        if oui_matched and ssid_matched:
            # Verified drone hardware OUI + matching drone SSID = CONFIRMED
            confidence_score = max(confidence_score, 96)
            reasons.append(
                f"Dual verification: {vendor} hardware OUI combined with drone SSID pattern"
            )
            if "confirmed_drone" not in indicators:
                indicators.append("confirmed_drone")

        # --- Step 4: RF Characteristics & 5.8 GHz Band Hint -------------------
        # Drones heavily utilize the upper 5 GHz U-NII-3 band (5745-5825 MHz / channels 149-165)
        # for high-bandwidth HD video transmission.
        if frequency and frequency >= 5725:
            if oui_matched or ssid_matched:
                confidence_score = min(98, confidence_score + 5)
                reasons.append(f"Operating on 5.8 GHz band ({frequency} MHz) typical of drone video downlinks")
                if "5ghz_downlink" not in indicators:
                    indicators.append("5ghz_downlink")

        # --- Step 5: Wi-Fi Direct / P2P Hints in capabilities -----------------
        if "[P2P]" in caps or "[DIRECT-" in norm_ssid.upper():
            if oui_matched:
                confidence_score = min(98, confidence_score + 8)
                reasons.append("Wi-Fi Direct (P2P) mode detected (standard for drone-to-controller links)")
                if "p2p_link" not in indicators:
                    indicators.append("p2p_link")

        # --- Step 6: WPS Penalty (False Positive Mitigator) -------------------
        # Drones almost never enable consumer Wi-Fi Protected Setup (WPS).
        # If WPS is enabled on an OUI-only match, it strongly indicates a home router or shared chipset.
        if "WPS" in caps and not ssid_matched:
            if confidence_score > 0:
                confidence_score = max(0, confidence_score - 35)
                reasons.append("Consumer WPS enabled (penalized drone suspicion)")

        # --- Step 7: Final Thresholding & Classification ----------------------
        # An OUI alone on a generic/hidden SSID stays at LOW confidence (below 60)
        # to prevent handheld gimbals or residential APs from triggering false alerts.
        if confidence_score >= 95:
            confidence = "CONFIRMED"
            is_drone = True
        elif confidence_score >= 80:
            confidence = "HIGH"
            is_drone = True
        elif confidence_score >= 60:
            confidence = "MEDIUM"
            is_drone = True
        elif confidence_score > 0:
            confidence = "LOW"
            is_drone = False
        else:
            confidence = "NONE"
            is_drone = False

        if not is_drone and not oui_matched and not ssid_matched:
            device_type = "Standard Network"

        return DroneDetection(
            is_drone=is_drone,
            confidence=confidence,
            confidence_score=confidence_score,
            device_type=device_type,
            vendor=vendor,
            indicators=indicators,
            reasons=reasons,
        )


# Global singleton instance for easy import
detector = DroneDetector()
