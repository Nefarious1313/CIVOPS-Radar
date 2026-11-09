#!/usr/bin/env python3
"""
Integration tests for the drone & UAV API endpoints.

Tests:
  - GET /api/drone/status
  - POST/GET /api/drone/demo
  - /api/signals includes drone_detected flag and drone signal attributes
"""

import json
import unittest
import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.app import app  # noqa: E402


class TestDroneStatusEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_drone_status_returns_200(self):
        """GET /api/drone/status must return HTTP 200."""
        resp = self.client.get('/api/drone/status')
        self.assertEqual(resp.status_code, 200)

    def test_drone_status_has_required_keys(self):
        """Response must contain all required top-level keys."""
        resp = self.client.get('/api/drone/status')
        data = json.loads(resp.data)
        for key in ('status', 'drone_detected', 'drone_count', 'drones', 'timestamp'):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_drone_status_values_are_correct_types(self):
        """drone_count must be int, drones must be list, detected must be bool."""
        resp = self.client.get('/api/drone/status')
        data = json.loads(resp.data)
        self.assertIsInstance(data['drone_count'], int)
        self.assertIsInstance(data['drones'], list)
        self.assertIsInstance(data['drone_detected'], bool)

    def test_drone_status_consistent_with_detected(self):
        """drone_detected must be True iff drone_count > 0."""
        resp = self.client.get('/api/drone/status')
        data = json.loads(resp.data)
        if data['drone_count'] > 0:
            self.assertTrue(data['drone_detected'])
            self.assertEqual(data['status'], 'alert')
        else:
            self.assertFalse(data['drone_detected'])
            self.assertEqual(data['status'], 'clear')


class TestDroneDemoEndpoint(unittest.TestCase):
    # Fixed demo BSSIDs used by /api/drone/demo, so we can clean up afterwards.
    DEMO_BSSIDS = ('60:60:1f:33:44:55', '00:26:7e:99:88:77', 'fa:0b:bc:12:34:56')

    def setUp(self):
        self.client = app.test_client()

    def tearDown(self):
        """Remove the demo rows this test class injected into the live DB."""
        try:
            import sqlite3
            from server.app import DB_PATH
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "DELETE FROM scans WHERE bssid IN (?,?,?)", self.DEMO_BSSIDS
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def test_demo_post_injects_drones(self):
        """POST /api/drone/demo should inject demo drones and return count."""
        resp = self.client.post('/api/drone/demo')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data.get('status'), 'demo_drones_injected')
        self.assertGreater(data.get('count', 0), 0)

    def test_demo_get_injects_drones(self):
        """GET /api/drone/demo should also work for browser test convenience."""
        resp = self.client.get('/api/drone/demo')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertEqual(data.get('status'), 'demo_drones_injected')

    def test_status_after_demo_shows_alert(self):
        """After injecting demo drones, /api/drone/status must report 'alert'."""
        self.client.post('/api/drone/demo')
        resp = self.client.get('/api/drone/status')
        data = json.loads(resp.data)
        self.assertEqual(data['status'], 'alert')
        self.assertTrue(data['drone_detected'])
        self.assertGreaterEqual(data['drone_count'], 1)
        self.assertIsNotNone(data['nearest_drone'])

    def test_signals_endpoint_reflects_drone_detection(self):
        """After injecting demo drones, /api/signals must report drone_detected=True."""
        self.client.post('/api/drone/demo')
        resp = self.client.get('/api/signals')
        self.assertEqual(resp.status_code, 200)
        data = json.loads(resp.data)
        self.assertIn('drone_detected', data)
        self.assertTrue(data['drone_detected'])
        
        # Verify drone signal fields exist in at least one signal
        drone_signals = [s for s in data['signals'] if s.get('is_drone')]
        self.assertGreater(len(drone_signals), 0)
        first_drone = drone_signals[0]
        self.assertIn('drone_type', first_drone)
        self.assertIn('drone_confidence', first_drone)


if __name__ == '__main__':
    unittest.main()
