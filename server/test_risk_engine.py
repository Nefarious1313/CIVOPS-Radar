#!/usr/bin/env python3
"""
Unit tests for CIVOPS-Radar Risk Assessment Engine
"""

import unittest
from datetime import datetime
from risk_engine import RiskEngine, NetworkProfile, RiskFactors


class TestRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = RiskEngine()

    def test_open_network_risk(self):
        profile = NetworkProfile(
            bssid="00:11:22:33:44:55",
            ssid="CoffeeShop_Free",
            capabilities="[ESS]",
            frequency=2412,
            level=-65,
            is_hidden=False,
            is_open=True
        )
        score, factors = self.engine.calculate_risk_score(profile)
        self.assertGreaterEqual(factors.open_network, 30)
        self.assertGreaterEqual(score, 30)

    def test_hidden_network_risk(self):
        profile = NetworkProfile(
            bssid="00:11:22:33:44:56",
            ssid="",
            capabilities="[WPA2-PSK-CCMP][ESS]",
            frequency=2437,
            level=-65,
            is_hidden=True,
            is_open=False
        )
        score, factors = self.engine.calculate_risk_score(profile)
        self.assertEqual(factors.hidden_ssid, 20)

    def test_5ghz_and_wpa3_legitimate_network(self):
        profile = NetworkProfile(
            bssid="00:11:22:33:44:57",
            ssid="SecureOffice",
            capabilities="[WPA3-SAE-CCMP][ESS]",
            frequency=5180,  # 5 GHz band
            level=-60,
            is_hidden=False,
            is_open=False
        )
        score, factors = self.engine.calculate_risk_score(profile)
        # Should not flag 5GHz as beacon anomaly
        self.assertEqual(factors.beacon_anomaly, 0)
        # WPA3 should have 0 weak_encryption score
        self.assertEqual(factors.weak_encryption, 0)
        self.assertLessEqual(score, 10)

    def test_suspicious_ssid_detection(self):
        profile = NetworkProfile(
            bssid="00:11:22:33:44:58",
            ssid="Evil_Free_Hotspot",
            capabilities="[WPA2-PSK-CCMP][ESS]",
            frequency=2412,
            level=-60,
            is_hidden=False,
            is_open=False
        )
        score, factors = self.engine.calculate_risk_score(profile)
        self.assertGreater(factors.suspicious_ssid, 0)

    def test_risk_level_and_report_generation(self):
        profile = NetworkProfile(
            bssid="00:11:22:33:44:59",
            ssid="Airport_Guest",
            capabilities="[ESS]",
            frequency=2412,
            level=-25,  # Very close proximity
            is_hidden=False,
            is_open=True
        )
        score, factors = self.engine.calculate_risk_score(profile)
        report = self.engine.generate_risk_report(profile, score, factors)
        self.assertIn('risk_score', report)
        self.assertIn('risk_level', report)
        self.assertIn('recommendations', report)
        self.assertGreaterEqual(len(report['recommendations']), 1)


if __name__ == '__main__':
    unittest.main()
