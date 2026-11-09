#!/usr/bin/env python3
"""
Integration tests for the police-vehicle API endpoints.

Tests use the actual live DB_PATH via the Flask test client, so the
demo endpoint (which hardcodes DB_PATH) works without monkey-patching.
The /api/police-vehicle/status response shape is:
  {
    "status": "clear" | "alert",
    "police_vehicle_detected": bool,
    "vehicle_count": int,
    "nearest_vehicle": {...} | null,
    "vehicles": [...],
    "timestamp": "..."
  }
"""

import json
import unittest
import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.app import app  # noqa: E402


class TestPoliceVehicleStatusEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_police_status_returns_200(self):
        """GET /api/police-vehicle/status must return HTTP 200."""
        resp = self.client.get('/api/police-vehicle/status')
        self.assertEqual(resp.status_code, 200)

    def test_police_status_has_required_keys(self):
        """Response must contain all required top-level keys."""
        resp = self.client.get('/api/police-vehicle/status')
        data = json.loads(resp.data)
        for key in ('status', 'police_vehicle_detected', 'vehicle_count', 'vehicles', 'timestamp'):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_police_status_values_are_correct_types(self):
        """vehicle_count must be int, vehicles must be list, detected must be bool."""
        resp = self.client.get('/api/police-vehicle/status')
        data = json.loads(resp.data)
        self.assertIsInstance(data['vehicle_count'], int)
        self.assertIsInstance(data['vehicles'], list)
        self.assertIsInstance(data['police_vehicle_detected'], bool)

    def test_police_status_consistent_with_detected(self):
        """police_vehicle_detected must be True iff vehicle_count > 0."""
        resp = self.client.get('/api/police-vehicle/status')
        data = json.loads(resp.data)
        if data['vehicle_count'] > 0:
            self.assertTrue(data['police_vehicle_detected'])
            self.assertEqual(data['status'], 'alert')
        else:
            self.assertFalse(data['police_vehicle_detected'])
            self.assertEqual(data['status'], 'clear')


class TestPoliceVehicleDemoEndpoint(unittest.TestCase):
    # Fixed demo BSSIDs used by /api/police-vehicle/demo, so we can clean up afterwards.
    DEMO_BSSIDS = ('70:1a:d5:12:34:56', '00:30:44:ab:cd:ef', '00:04:7d:11:22:33')

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

    def test_police_demo_get_returns_200(self):
        """GET /api/police-vehicle/demo must return HTTP 200."""
        resp = self.client.get('/api/police-vehicle/demo')
        self.assertEqual(resp.status_code, 200)

    def test_police_demo_post_injects_vehicles(self):
        """POST /api/police-vehicle/demo must inject vehicles and status must then show them."""
        resp = self.client.post('/api/police-vehicle/demo')
        self.assertEqual(resp.status_code, 200)
        demo_data = json.loads(resp.data)
        self.assertIn('count', demo_data)
        injected = demo_data['count']
        self.assertGreater(injected, 0)

        status_resp = self.client.get('/api/police-vehicle/status')
        status_data = json.loads(status_resp.data)
        self.assertGreaterEqual(status_data['vehicle_count'], injected)
        self.assertTrue(status_data['police_vehicle_detected'])

    def test_demo_vehicles_have_expected_fields(self):
        """Each vehicle in /api/police-vehicle/status response must have key fields."""
        self.client.post('/api/police-vehicle/demo')
        resp = self.client.get('/api/police-vehicle/status')
        data = json.loads(resp.data)
        for vehicle in data['vehicles']:
            for field in ('bssid', 'ssid', 'is_police_vehicle',
                          'police_vehicle_type', 'police_confidence'):
                self.assertIn(field, vehicle, f"Vehicle missing field: {field}")
            self.assertTrue(vehicle['is_police_vehicle'])


if __name__ == '__main__':
    unittest.main()
