#!/usr/bin/env python3
"""
Tests for DB schema migration to include Flock fields.
"""

import os
import sys
import sqlite3
import tempfile
import unittest

# Ensure the server package can be imported
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.append(repo_root)

from server.app import RadarData  # noqa: E402

class TestDBMigration(unittest.TestCase):
    def setUp(self):
        # Create a temporary directory to act as RADAR_DIR
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, 'scans.db')
        # Initialise RadarData which creates/updates schema
        self.radar = RadarData(self.db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_flock_columns_exist(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(scans)')
        cols = {row[1] for row in cursor.fetchall()}
        self.assertIn('is_flock', cols)
        self.assertIn('flock_type', cols)
        self.assertIn('alpr_confidence', cols)
        conn.close()

    def test_police_vehicle_columns_exist(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(scans)')
        cols = {row[1] for row in cursor.fetchall()}
        self.assertIn('is_police_vehicle', cols)
        self.assertIn('police_vehicle_type', cols)
        self.assertIn('police_confidence', cols)
        conn.close()

    def test_drone_columns_exist(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(scans)')
        cols = {row[1] for row in cursor.fetchall()}
        self.assertIn('is_drone', cols)
        self.assertIn('drone_type', cols)
        self.assertIn('drone_confidence', cols)
        conn.close()

if __name__ == '__main__':
    unittest.main()
