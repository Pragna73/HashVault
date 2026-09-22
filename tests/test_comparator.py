"""Unit tests for Comparator & Integrity Scanner."""

import os
import tempfile
import unittest
from pathlib import Path

from core.baseline import create_baseline
from core.comparator import calculate_integrity_score, run_integrity_scan
from core.database import get_all_files, get_events, get_latest_scan, init_db


class TestComparator(unittest.TestCase):
    """Test suite for core.comparator module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.db_path = str(self.base_path / "test_hashvault.db")
        init_db(self.db_path)

        self.prot_dir = self.base_path / "protected"
        self.prot_dir.mkdir()

        # Create 3 baseline files
        (self.prot_dir / "file_safe.txt").write_text("safe content")
        (self.prot_dir / "file_to_modify.txt").write_text("initial content")
        (self.prot_dir / "file_to_delete.txt").write_text("will be deleted")

        # Establish initial baseline
        create_baseline(str(self.prot_dir), force=True, db_path=self.db_path)

    def tearDown(self):
        self.test_dir.cleanup()

    def test_calculate_integrity_score(self):
        """Test score math and rounding."""
        self.assertEqual(calculate_integrity_score(10, 10), 100)
        self.assertEqual(calculate_integrity_score(21, 24), 88)  # 87.5% -> 88%
        self.assertEqual(calculate_integrity_score(0, 5), 0)
        self.assertEqual(calculate_integrity_score(0, 0), 100)

    def test_scan_all_safe(self):
        """Test scanning when no files have been altered."""
        success, msg, summary = run_integrity_scan(str(self.prot_dir), db_path=self.db_path)

        self.assertTrue(success)
        self.assertEqual(summary["safe_files"], 3)
        self.assertEqual(summary["modified_files"], 0)
        self.assertEqual(summary["new_files"], 0)
        self.assertEqual(summary["deleted_files"], 0)
        self.assertEqual(summary["integrity_score"], 100)

    def test_detect_modified_new_and_deleted(self):
        """Test simultaneous detection of MODIFIED, NEW, and DELETED files."""
        # 1. Modify file
        (self.prot_dir / "file_to_modify.txt").write_text("ALTERED CONTENT")

        # 2. Add new file
        (self.prot_dir / "suspicious_new.txt").write_text("unauthorized file")

        # 3. Delete file
        (self.prot_dir / "file_to_delete.txt").unlink()

        # Run integrity scan
        success, msg, summary = run_integrity_scan(str(self.prot_dir), db_path=self.db_path)

        self.assertTrue(success)
        self.assertEqual(summary["safe_files"], 1)      # file_safe.txt
        self.assertEqual(summary["modified_files"], 1)  # file_to_modify.txt
        self.assertEqual(summary["new_files"], 1)       # suspicious_new.txt
        self.assertEqual(summary["deleted_files"], 1)   # file_to_delete.txt
        self.assertEqual(summary["total_files"], 4)
        # Score = (1 / 4) * 100 = 25%
        self.assertEqual(summary["integrity_score"], 25)

        # Check recorded events
        events = get_events(limit=50, db_path=self.db_path)
        event_types = [e["event_type"] for e in events]
        self.assertIn("MODIFIED", event_types)
        self.assertIn("NEW", event_types)
        self.assertIn("DELETED", event_types)

        # Check scan record saved to database
        scan = get_latest_scan(self.db_path)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["integrity_score"], 25)


if __name__ == "__main__":
    unittest.main()
