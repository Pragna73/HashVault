"""Unit tests for File Scanner & Ignored Filters Engine."""

import os
import tempfile
import unittest
from pathlib import Path

from core.scanner import discover_and_hash_files, is_ignored, normalize_filepath


class TestScanner(unittest.TestCase):
    """Test suite for core.scanner module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)

        # Create valid monitored files
        (self.base_path / "valid1.txt").write_text("content 1")
        
        subfolder = self.base_path / "subfolder"
        subfolder.mkdir()
        (subfolder / "valid2.txt").write_text("content 2")

        # Create ignored folders & files
        git_dir = self.base_path / ".git"
        git_dir.mkdir()
        (git_dir / "HEAD").write_text("ref: refs/heads/main")

        pycache_dir = self.base_path / "__pycache__"
        pycache_dir.mkdir()
        (pycache_dir / "test.cpython-311.pyc").write_text("bytecode")

        (self.base_path / "app.db").write_text("sqlite db")
        (self.base_path / "scan.log").write_text("log file")
        (self.base_path / "temp.tmp").write_text("temporary")
        (self.base_path / ".gitkeep").write_text("")

    def tearDown(self):
        self.test_dir.cleanup()

    def test_is_ignored_rules(self):
        """Test file path exclusion logic."""
        self.assertTrue(is_ignored(self.base_path / ".git" / "config"))
        self.assertTrue(is_ignored(self.base_path / "__pycache__" / "file.pyc"))
        self.assertTrue(is_ignored(self.base_path / "test.db"))
        self.assertTrue(is_ignored(self.base_path / "test.sqlite3"))
        self.assertTrue(is_ignored(self.base_path / "test.tmp"))
        self.assertTrue(is_ignored(self.base_path / ".gitkeep"))

        self.assertFalse(is_ignored(self.base_path / "config.txt"))
        self.assertFalse(is_ignored(self.base_path / "users.json"))

    def test_normalize_filepath(self):
        """Test relative path normalization with forward slashes."""
        file_path = os.path.join(self.test_dir.name, "subfolder", "data.txt")
        normalized = normalize_filepath(file_path, self.test_dir.name)
        self.assertEqual(normalized, "subfolder/data.txt")

    def test_discover_and_hash_files(self):
        """Test recursive discovery returns only unignored files with valid SHA-256."""
        discovered = discover_and_hash_files(str(self.base_path))

        # Should only contain valid1.txt and subfolder/valid2.txt
        self.assertIn("valid1.txt", discovered)
        self.assertIn("subfolder/valid2.txt", discovered)

        # Should NOT contain ignored items
        self.assertNotIn("app.db", discovered)
        self.assertNotIn("scan.log", discovered)
        self.assertNotIn("temp.tmp", discovered)
        self.assertNotIn(".gitkeep", discovered)
        self.assertNotIn(".git/HEAD", discovered)

        # Verify hash values exist
        self.assertIsNotNone(discovered["valid1.txt"]["sha256"])
        self.assertEqual(len(discovered["valid1.txt"]["sha256"]), 64)


if __name__ == "__main__":
    unittest.main()
