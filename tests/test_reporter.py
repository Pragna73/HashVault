"""Unit tests for Report Generation & Export Engine."""

import csv
import io
import json
import os
import tempfile
import unittest

from core.database import init_db, save_baseline_files, save_events, save_scan
from core.reporter import generate_csv_report, generate_json_report, get_full_report_data


class TestReporter(unittest.TestCase):
    """Test suite for core.reporter module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.test_dir.name, "test_hashvault.db")
        init_db(self.db_path)

        # Seed sample baseline, scan, and events
        save_baseline_files(
            [
                {"filename": "app.py", "filepath": "app.py", "baseline_hash": "a" * 64, "status": "SAFE"},
                {"filename": "key.pem", "filepath": "key.pem", "baseline_hash": "b" * 64, "status": "MODIFIED"},
            ],
            self.db_path,
        )

        self.scan_id = save_scan(
            {
                "scan_time": "2026-09-22 12:00:00",
                "total_files": 2,
                "safe_files": 1,
                "modified_files": 1,
                "new_files": 0,
                "deleted_files": 0,
                "integrity_score": 50,
            },
            self.db_path,
        )

        save_events(
            [
                {
                    "filepath": "key.pem",
                    "filename": "key.pem",
                    "event_type": "MODIFIED",
                    "old_hash": "b" * 64,
                    "new_hash": "c" * 64,
                    "timestamp": "2026-09-22 12:00:00",
                }
            ],
            self.db_path,
        )

    def tearDown(self):
        self.test_dir.cleanup()

    def test_generate_json_report(self):
        """Test valid JSON generation matching project schema."""
        raw_json = generate_json_report(scan_id=self.scan_id, db_path=self.db_path)
        data = json.loads(raw_json)

        self.assertEqual(data["project"], "HashVault")
        self.assertEqual(data["scan_time"], "2026-09-22 12:00:00")
        self.assertIn("summary", data)
        self.assertEqual(data["summary"]["total_files"], 2)
        self.assertEqual(data["summary"]["integrity_score"], 50)
        self.assertIn("events", data)
        self.assertEqual(len(data["events"]), 1)
        self.assertEqual(data["events"][0]["event_type"], "MODIFIED")

    def test_generate_csv_report(self):
        """Test valid CSV generation containing security events."""
        csv_text = generate_csv_report(scan_id=self.scan_id, db_path=self.db_path)
        reader = csv.DictReader(io.StringIO(csv_text))
        rows = list(reader)

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filepath"], "key.pem")
        self.assertEqual(rows[0]["event_type"], "MODIFIED")
        self.assertEqual(rows[0]["old_hash"], "b" * 64)

    def test_get_full_report_data(self):
        """Test composite report view model assembly."""
        report = get_full_report_data(scan_id=self.scan_id, db_path=self.db_path)
        self.assertIn("summary", report)
        self.assertIn("files", report)
        self.assertIn("events", report)
        self.assertEqual(report["summary"]["integrity_score"], 50)


if __name__ == "__main__":
    unittest.main()
