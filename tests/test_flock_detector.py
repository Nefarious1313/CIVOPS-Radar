#!/usr/bin/env python3
"""
Unit tests for the Flock Safety & ALPR camera detection engine.

Confidence tiers (from flock_detector.py):
  CONFIRMED  >= 95
  HIGH       >= 80
  MEDIUM     >= 50
  LOW        > 0
  NONE       = 0
"""

import os
import sys
import unittest

# Ensure the server package is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.flock_detector import FlockDetector  # noqa: E402


class TestFlockDetector(unittest.TestCase):
    def setUp(self):
        self.detector = FlockDetector()

    def test_official_flock_oui_is_confirmed(self):
        """Official Flock OUI (b4:1e:52) must yield CONFIRMED confidence."""
        res = self.detector.analyze(bssid="b4:1e:52:aa:bb:cc", ssid="SomeNetwork")
        self.assertTrue(res.is_flock)
        self.assertTrue(res.is_alpr)
        self.assertEqual(res.confidence, "CONFIRMED")
        self.assertIn("Official", res.reasons[0])

    def test_flock_ssid_pattern_is_high(self):
        """SSID matching a Flock pattern (confidence 85) should yield HIGH."""
        res = self.detector.analyze(bssid="00:11:22:33:44:55", ssid="flock-01ab")
        self.assertTrue(res.is_flock)
        self.assertTrue(res.is_alpr)
        # Pattern confidence is 85 → HIGH tier
        self.assertEqual(res.confidence, "HIGH")
        self.assertIn("SSID", res.reasons[0])

    def test_flock_ssid_falcon_is_confirmed(self):
        """Falcon SSID pattern (confidence 95) should yield CONFIRMED."""
        res = self.detector.analyze(bssid="00:11:22:33:44:55", ssid="falcon-abc1")
        self.assertTrue(res.is_flock)
        self.assertTrue(res.is_alpr)
        self.assertEqual(res.confidence, "CONFIRMED")

    def test_other_alpr_oui_is_high(self):
        """Motorola Vigilant OUI (base_confidence 80) should yield HIGH, not Flock."""
        res = self.detector.analyze(bssid="00:1d:a5:aa:bb:cc", ssid="GenericNetwork")
        self.assertFalse(res.is_flock)
        self.assertTrue(res.is_alpr)
        # base_confidence 80 → HIGH
        self.assertEqual(res.confidence, "HIGH")

    def test_hidden_flock_module_is_detected(self):
        """Hidden SSID on a known Flock chipset OUI should be flagged as Stealth."""
        res = self.detector.analyze(bssid="00:03:7f:aa:bb:cc", ssid="<unknown ssid>")
        self.assertTrue(res.is_flock)
        self.assertTrue(res.is_alpr)
        self.assertIn("Stealth", res.reasons[-1])

    def test_unknown_device_is_clean(self):
        """Completely unknown device should not be flagged."""
        res = self.detector.analyze(bssid="aa:bb:cc:dd:ee:ff", ssid="HomeNetwork")
        self.assertFalse(res.is_flock)
        self.assertFalse(res.is_alpr)
        self.assertEqual(res.confidence, "NONE")


if __name__ == "__main__":
    unittest.main()
