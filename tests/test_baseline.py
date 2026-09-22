"""Unit tests for Baseline Manager."""

import os
import tempfile
import unittest
from pathlib import Path

from core.baseline import create_baseline
from core.database import get_all_files, has_baseline, init_db


class TestBaseline(unittest.TestCase):
    """Test suite for core.baseline module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.db_path = str(self.base_path / "test_hashvault.db")
        init_db(self.db_path)

        # Create demo files
        self.prot_dir = self.base_path / "protected"
        self.prot_dir.mkdir()
        (self.prot_dir / "conf.txt").write_text("setting=1")
        (self.prot_dir / "auth.txt").write_text("auth=enabled")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_create_baseline_success(self):
        """Test initial baseline creation."""
        self.assertFalse(has_baseline(self.db_path))

        success, msg, data = create_baseline(
            target_dir=str(self.prot_dir),
            force=False,
            db_path=self.db_path,
        )

        self.assertTrue(success)
        self.assertIn("Baseline created successfully", msg)
        self.assertEqual(data["total_protected"], 2)
        self.assertTrue(has_baseline(self.db_path))

        files = get_all_files(self.db_path)
        self.assertEqual(len(files), 2)
        for f in files:
            self.assertEqual(f["status"], "SAFE")
            self.assertIsNotNone(f["baseline_hash"])
            self.assertEqual(f["baseline_hash"], f["current_hash"])

    def test_create_baseline_requires_confirmation_when_exists(self):
        """Test that attempting to create baseline when one exists requires force=True."""
        # 1st creation
        create_baseline(str(self.prot_dir), force=False, db_path=self.db_path)

        # 2nd creation without force
        success, msg, data = create_baseline(str(self.prot_dir), force=False, db_path=self.db_path)
        self.assertFalse(success)
        self.assertTrue(data.get("requires_confirmation"))

        # 3rd creation with force=True
        success, msg, data = create_baseline(str(self.prot_dir), force=True, db_path=self.db_path)
        self.assertTrue(success)
        self.assertEqual(data["total_protected"], 2)


if __name__ == "__main__":
    unittest.main()
