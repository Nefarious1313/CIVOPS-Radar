#!/usr/bin/env python3
"""
Unit tests for the drone and unmanned aerial surveillance (UAV / UAS) detector.

Confidence tiers:
  CONFIRMED  >= 95
  HIGH       >= 80
  MEDIUM     >= 60
  LOW        > 0 (non-alerting)
  NONE       = 0
"""

import os
import sys
import unittest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.drone_detector import (  # noqa: E402
    DroneDetector,
    DRONE_OUIS,
    DRONE_SSID_PATTERNS,
)


class TestDroneDetector(unittest.TestCase):
    def setUp(self):
        self.detector = DroneDetector()

    def test_dji_mavic_ssid_plus_oui_is_confirmed(self):
        """DJI OUI + Mavic SSID must score CONFIRMED (>= 95)."""
        res = self.detector.analyze(
            bssid="60:60:1f:aa:bb:cc",
            ssid="DJI-Mavic3-8120"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertGreaterEqual(res.confidence_score, 95)
        self.assertIn("DJI", res.vendor)
        self.assertIn("DJI Mavic", res.device_type)

    def test_faa_remote_id_ssid_is_confirmed(self):
        """Standard FAA Remote ID broadcast SSID should trigger CONFIRMED detection."""
        res = self.detector.analyze(
            bssid="12:34:56:78:90:ab",
            ssid="RID-15962804291849182910"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertGreaterEqual(res.confidence_score, 95)
        self.assertIn("Remote ID", res.device_type)

    def test_opendroneid_ssid_is_confirmed(self):
        """OpenDroneID SSID prefix should flag as CONFIRMED."""
        res = self.detector.analyze(
            bssid="aa:bb:cc:dd:ee:ff",
            ssid="OpenDroneID-Broadcast"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "CONFIRMED")

    def test_skydio_x2_tactical_drone(self):
        """Skydio X2 tactical drone should flag as HIGH or CONFIRMED."""
        res = self.detector.analyze(
            bssid="38:1d:14:11:22:33",
            ssid="Skydio-X2-9014"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertEqual(res.vendor, "Skydio Inc.")
        self.assertIn("Skydio", res.device_type)

    def test_autel_evo_enterprise_ssid_only(self):
        """Autel EVO SSID alone (no verified Autel OUI) should score HIGH."""
        res = self.detector.analyze(
            bssid="02:00:00:00:00:01",
            ssid="Autel-EVO-II-Enterprise"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "HIGH")
        self.assertIn("Autel", res.device_type)

    def test_parrot_anafi_usa_recon_drone(self):
        """Parrot Anafi USA recon drone should flag with vendor and device type."""
        res = self.detector.analyze(
            bssid="90:03:b7:88:99:00",
            ssid="Anafi-USA-55"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertEqual(res.vendor, "Parrot SA")

    def test_dji_matrice_enterprise_ssid_only(self):
        """DJI Matrice SSID alone on arbitrary BSSID should score HIGH."""
        res = self.detector.analyze(
            bssid="02:00:00:00:00:01",
            ssid="DJI-Matrice300-RTK"
        )
        self.assertTrue(res.is_drone)
        self.assertEqual(res.confidence, "HIGH")
        self.assertGreaterEqual(res.confidence_score, 90)

    def test_dji_oui_only_with_hidden_ssid_is_low(self):
        """DJI OUI alone without drone-specific SSID must stay LOW to avoid gimbal false alarms."""
        res = self.detector.analyze(
            bssid="60:60:1f:12:34:56",
            ssid=""
        )
        self.assertFalse(res.is_drone)
        self.assertEqual(res.confidence, "LOW")
        self.assertLess(res.confidence_score, 60)

    def test_wps_penalty_suppresses_residential_router(self):
        """Residential AP with consumer WPS enabled should be penalized."""
        res = self.detector.analyze(
            bssid="60:60:1f:00:11:22",
            ssid="",
            capabilities="[WPA2-PSK-CCMP][ESS][WPS]"
        )
        self.assertFalse(res.is_drone)
        self.assertEqual(res.confidence, "LOW")
        self.assertLessEqual(res.confidence_score, 20)

    def test_5ghz_downlink_frequency_boost(self):
        """5.8 GHz frequency should apply RF downlink boost."""
        res_24 = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="ExpressLRS-TX", frequency=2412)
        res_58 = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="ExpressLRS-TX", frequency=5785)
        self.assertGreaterEqual(res_58.confidence_score, res_24.confidence_score)
        self.assertIn("5ghz_downlink", res_58.indicators)

    def test_negative_residential_wifi(self):
        """Standard residential Wi-Fi should score 0 / NONE."""
        res = self.detector.analyze(
            bssid="14:59:c0:99:88:77",
            ssid="MyHome-5G",
            capabilities="[WPA2-PSK-CCMP][ESS]"
        )
        self.assertFalse(res.is_drone)
        self.assertEqual(res.confidence, "NONE")
        self.assertEqual(res.confidence_score, 0)
        self.assertEqual(res.device_type, "Standard Network")

    def test_database_constants_populated(self):
        """Verify constant tables are populated."""
        self.assertGreater(len(DRONE_OUIS), 10)
        self.assertGreater(len(DRONE_SSID_PATTERNS), 10)

    def test_oui_keys_are_well_formed(self):
        """Every OUI key must be a lowercase xx:xx:xx prefix with required fields."""
        for oui, entry in DRONE_OUIS.items():
            self.assertRegex(oui, r'^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$')
            for field_name in ('vendor', 'description', 'base_confidence', 'device_type'):
                self.assertIn(field_name, entry, f"{oui} missing field {field_name}")
            self.assertGreaterEqual(entry['base_confidence'], 0)
            self.assertLessEqual(entry['base_confidence'], 100)

    def test_verified_oui_table_matches_ieee_prefixes(self):
        """Spot-check that known IEEE-registered prefixes are present and labelled."""
        # All three verified against the IEEE MA-L registry on 2026-11-09.
        self.assertIn("60:60:1f", DRONE_OUIS)   # SZ DJI TECHNOLOGY
        self.assertIn("38:1d:14", DRONE_OUIS)   # Skydio Inc.
        self.assertIn("90:03:b7", DRONE_OUIS)   # Parrot SA
        self.assertIn("b0:30:c8", DRONE_OUIS)   # Teal Drones, Inc.
        self.assertIn("00:1a:f9", DRONE_OUIS)   # AeroVironment (AV Inc)


if __name__ == '__main__':
    unittest.main()
