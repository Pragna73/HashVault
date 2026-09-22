"""Unit tests for Database Operations and Parameterized Queries."""

import os
import tempfile
import unittest
from pathlib import Path

from core.database import (
    clear_baseline,
    get_all_files,
    get_all_scans,
    get_dashboard_metrics,
    get_events,
    get_file_by_id,
    get_file_events,
    get_latest_scan,
    get_scan_by_id,
    has_baseline,
    init_db,
    save_baseline_files,
    save_events,
    save_scan,
    update_file_record,
)


class TestDatabase(unittest.TestCase):
    """Test suite for core.database module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.test_dir.name, "test_hashvault.db")
        init_db(self.db_path)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_init_db_and_baseline_crud(self):
        """Test database table creation and baseline records."""
        self.assertFalse(has_baseline(self.db_path))

        sample_files = [
            {
                "filename": "conf.txt",
                "filepath": "conf.txt",
                "baseline_hash": "a" * 64,
                "current_hash": "a" * 64,
                "status": "SAFE",
            },
            {
                "filename": "auth.txt",
                "filepath": "auth.txt",
                "baseline_hash": "b" * 64,
                "current_hash": "b" * 64,
                "status": "SAFE",
            },
        ]

        count = save_baseline_files(sample_files, self.db_path)
        self.assertEqual(count, 2)
        self.assertTrue(has_baseline(self.db_path))

        files = get_all_files(self.db_path)
        self.assertEqual(len(files), 2)

        file_id = files[0]["id"]
        fetched = get_file_by_id(file_id, self.db_path)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["filename"], files[0]["filename"])

    def test_save_and_retrieve_scans(self):
        """Test scan summary insertion and queries."""
        scan_data = {
            "scan_time": "2026-09-22 10:00:00",
            "total_files": 10,
            "safe_files": 8,
            "modified_files": 1,
            "new_files": 1,
            "deleted_files": 0,
            "integrity_score": 80,
        }

        scan_id = save_scan(scan_data, self.db_path)
        self.assertIsInstance(scan_id, int)

        latest = get_latest_scan(self.db_path)
        self.assertEqual(latest["id"], scan_id)
        self.assertEqual(latest["integrity_score"], 80)

        by_id = get_scan_by_id(scan_id, self.db_path)
        self.assertEqual(by_id["total_files"], 10)

        all_scans = get_all_scans(db_path=self.db_path)
        self.assertEqual(len(all_scans), 1)

    def test_save_and_filter_events(self):
        """Test event batch persistence and parameterized filter queries."""
        events = [
            {
                "filepath": "config.txt",
                "filename": "config.txt",
                "event_type": "MODIFIED",
                "old_hash": "111",
                "new_hash": "222",
                "timestamp": "2026-09-22 10:05:00",
            },
            {
                "filepath": "secret.txt",
                "filename": "secret.txt",
                "event_type": "DELETED",
                "old_hash": "333",
                "new_hash": None,
                "timestamp": "2026-09-22 10:05:00",
            },
        ]

        save_events(events, self.db_path)

        all_ev = get_events(db_path=self.db_path)
        self.assertEqual(len(all_ev), 2)

        # Filter by type
        mod_ev = get_events(event_type="MODIFIED", db_path=self.db_path)
        self.assertEqual(len(mod_ev), 1)
        self.assertEqual(mod_ev[0]["event_type"], "MODIFIED")

        # Filter by search term
        search_ev = get_events(search_term="secret", db_path=self.db_path)
        self.assertEqual(len(search_ev), 1)
        self.assertEqual(search_ev[0]["filename"], "secret.txt")

    def test_dashboard_metrics(self):
        """Test aggregation calculations for the security dashboard."""
        sample_files = [
            {"filename": "a.txt", "filepath": "a.txt", "baseline_hash": "1", "status": "SAFE"},
            {"filename": "b.txt", "filepath": "b.txt", "baseline_hash": "2", "status": "SAFE"},
            {"filename": "c.txt", "filepath": "c.txt", "baseline_hash": "3", "status": "MODIFIED"},
        ]
        save_baseline_files(sample_files, self.db_path)

        metrics = get_dashboard_metrics(self.db_path)
        self.assertEqual(metrics["total_files"], 3)
        self.assertEqual(metrics["safe_files"], 2)
        self.assertEqual(metrics["modified_files"], 1)
        self.assertEqual(metrics["integrity_score"], 67)  # (2 / 3) * 100 = 66.66% -> 67%
        self.assertTrue(metrics["has_baseline"])


if __name__ == "__main__":
    unittest.main()
