#!/usr/bin/env python3
"""
Integration tests for the Flock Safety API endpoints.

Tests use the actual live DB_PATH via the Flask test client, so the
demo endpoint (which hardcodes DB_PATH) will work without monkey-patching.
The /api/flock/status response shape is:
  {
    "status": "clear" | "alert",
    "flock_detected": bool,
    "camera_count": int,          # NOT "flock_cameras"
    "nearest_camera": {...} | null,
    "cameras": [...],
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


class TestFlockStatusEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_flock_status_returns_200(self):
        """GET /api/flock/status must return HTTP 200."""
        resp = self.client.get('/api/flock/status')
        self.assertEqual(resp.status_code, 200)

    def test_flock_status_has_required_keys(self):
        """Response must contain all required top-level keys."""
        resp = self.client.get('/api/flock/status')
        data = json.loads(resp.data)
        for key in ('status', 'flock_detected', 'camera_count', 'cameras', 'timestamp'):
            self.assertIn(key, data, f"Missing key: {key}")

    def test_flock_status_values_are_correct_types(self):
        """camera_count must be int, cameras must be list, flock_detected must be bool."""
        resp = self.client.get('/api/flock/status')
        data = json.loads(resp.data)
        self.assertIsInstance(data['camera_count'], int)
        self.assertIsInstance(data['cameras'], list)
        self.assertIsInstance(data['flock_detected'], bool)

    def test_flock_status_consistent_with_flock_detected(self):
        """flock_detected must be True iff camera_count > 0."""
        resp = self.client.get('/api/flock/status')
        data = json.loads(resp.data)
        if data['camera_count'] > 0:
            self.assertTrue(data['flock_detected'])
            self.assertEqual(data['status'], 'alert')
        else:
            self.assertFalse(data['flock_detected'])
            self.assertEqual(data['status'], 'clear')


class TestFlockDemoEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_flock_demo_get_returns_200(self):
        """GET /api/flock/demo must return HTTP 200."""
        resp = self.client.get('/api/flock/demo')
        self.assertEqual(resp.status_code, 200)

    def test_flock_demo_post_injects_cameras(self):
        """POST /api/flock/demo must inject cameras and status must then show them."""
        resp = self.client.post('/api/flock/demo')
        self.assertEqual(resp.status_code, 200)
        demo_data = json.loads(resp.data)
        self.assertIn('count', demo_data)
        injected = demo_data['count']
        self.assertGreater(injected, 0)

        # After injection, status should report at least the injected cameras
        status_resp = self.client.get('/api/flock/status')
        status_data = json.loads(status_resp.data)
        self.assertGreaterEqual(status_data['camera_count'], injected)
        self.assertTrue(status_data['flock_detected'])

    def test_demo_cameras_have_expected_fields(self):
        """Each camera in /api/flock/status response must have key fields."""
        self.client.post('/api/flock/demo')
        resp = self.client.get('/api/flock/status')
        data = json.loads(resp.data)
        for cam in data['cameras']:
            for field in ('bssid', 'ssid', 'is_flock', 'flock_type', 'alpr_confidence'):
                self.assertIn(field, cam, f"Camera missing field: {field}")
            self.assertTrue(cam['is_flock'])


if __name__ == '__main__':
    unittest.main()
