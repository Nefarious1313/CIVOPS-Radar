#!/usr/bin/env python3
"""
Unit tests for the police / law-enforcement vehicle detection engine.

Confidence tiers (from police_vehicle_detector.py):
  CONFIRMED  >= 95
  HIGH       >= 80
  MEDIUM     >= 50
  LOW        > 0
  NONE       = 0

Detection model:
  - SSID pattern match                -> flagged, at the pattern's confidence
  - SSID pattern + verified vendor OUI -> CONFIRMED (95)
  - vendor OUI + hidden SSID          -> flagged, MEDIUM (70)
  - vendor OUI alone (standard SSID)  -> NOT flagged, LOW recorded for review
"""

import os
import re
import sys
import unittest

# Ensure the server package is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.police_vehicle_detector import (  # noqa: E402
    PoliceVehicleDetector,
    POLICE_SSID_PATTERNS,
    POLICE_VEHICLE_OUIS,
)


class TestPoliceVehicleDetector(unittest.TestCase):
    def setUp(self):
        self.detector = PoliceVehicleDetector()

    # --- SSID-only detection -------------------------------------------------
    def test_police_ssid_is_high(self):
        """SSID containing 'police' should flag at HIGH confidence."""
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="police-scanner")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "HIGH")
        self.assertIn("police", res.reasons[0].lower())

    def test_highway_patrol_ssid_is_high(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="Highway-Patrol-07")
        self.assertTrue(res.is_police_vehicle)
        self.assertGreaterEqual(res.confidence_score, 80)

    def test_sheriff_ssid_is_high(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="Sheriff-Office")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "HIGH")

    def test_municipal_ssid_is_medium(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="City-of-Springfield")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "MEDIUM")

    def test_department_abbreviation_is_high(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="MPD-Data")
        self.assertTrue(res.is_police_vehicle)
        self.assertGreaterEqual(res.confidence_score, 80)

    # --- SSID + OUI combination ---------------------------------------------
    def test_ssid_plus_verified_oui_is_confirmed(self):
        """Avigilon (ALPR vendor) OUI + MPD SSID should be CONFIRMED."""
        res = self.detector.analyze(bssid="70:1a:d5:12:34:56", ssid="MPD-Fleet")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertEqual(res.confidence_score, 95)
        self.assertTrue(any("Hardware confirms" in r for r in res.reasons))

    def test_dispatch_ssid_plus_motorola_oui_is_confirmed(self):
        res = self.detector.analyze(bssid="00:04:7d:11:22:33", ssid="Dispatch-1")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "CONFIRMED")

    # --- OUI-only behaviour --------------------------------------------------
    def test_oui_alone_is_not_flagged(self):
        """A known police-equipment vendor OUI with an ordinary SSID is not flagged."""
        res = self.detector.analyze(bssid="00:30:44:aa:bb:cc", ssid="HomeWiFi")
        self.assertFalse(res.is_police_vehicle)
        self.assertEqual(res.confidence, "LOW")
        self.assertTrue(any("Shares hardware vendor" in r for r in res.reasons))

    def test_oui_plus_hidden_ssid_is_flagged(self):
        """Hidden SSID on police-equipment hardware is suggestive and flags at MEDIUM."""
        res = self.detector.analyze(bssid="00:30:44:aa:bb:cc", ssid="")
        self.assertTrue(res.is_police_vehicle)
        self.assertEqual(res.confidence, "MEDIUM")
        self.assertIn("Hidden SSID", res.device_type)

    # --- Negative cases ------------------------------------------------------
    def test_unknown_device_is_clean(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNetwork")
        self.assertFalse(res.is_police_vehicle)
        self.assertEqual(res.confidence, "NONE")
        self.assertEqual(res.confidence_score, 0)

    def test_unrelated_ssid_is_not_flagged(self):
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="Starbucks-Guest")
        self.assertFalse(res.is_police_vehicle)
        self.assertEqual(res.confidence, "NONE")

    # --- Data integrity ------------------------------------------------------
    def test_oui_keys_are_well_formed(self):
        for oui in POLICE_VEHICLE_OUIS:
            self.assertIsInstance(oui, str)
            self.assertTrue(
                re.fullmatch(r'[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}', oui),
                f"Malformed OUI key: {oui}"
            )

    def test_oui_entries_have_required_fields(self):
        for oui, entry in POLICE_VEHICLE_OUIS.items():
            for field in ('vendor', 'category', 'description', 'base_confidence', 'device_type'):
                self.assertIn(field, entry, f"{oui} missing field {field}")
            self.assertGreater(entry['base_confidence'], 0)
            # OUI-only signals must stay weak by design
            self.assertLessEqual(entry['base_confidence'], 60)

    def test_ssid_patterns_are_well_formed(self):
        for pattern, desc, d_type, conf, category in POLICE_SSID_PATTERNS:
            self.assertGreater(conf, 0)
            self.assertLessEqual(conf, 95)
            re.compile(pattern)  # must be a valid regex

    def test_oui_table_is_not_empty(self):
        self.assertGreater(len(POLICE_VEHICLE_OUIS), 0)
        self.assertGreater(len(POLICE_SSID_PATTERNS), 0)


if __name__ == '__main__':
    unittest.main()
