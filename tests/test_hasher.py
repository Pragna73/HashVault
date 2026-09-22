"""Unit tests for SHA-256 Hasher Engine."""

import hashlib
import os
import tempfile
import unittest

from core.hasher import calculate_sha256, hash_string


class TestHasher(unittest.TestCase):
    """Test suite for core.hasher module."""

    def setUp(self):
        self.test_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.test_dir.cleanup()

    def test_hash_string(self):
        """Test hashing in-memory strings."""
        sample = "HashVault Security 2026"
        expected = hashlib.sha256(sample.encode("utf-8")).hexdigest()
        self.assertEqual(hash_string(sample), expected)

    def test_calculate_sha256_identical(self):
        """Test that identical file contents produce identical hashes."""
        file1 = os.path.join(self.test_dir.name, "file1.txt")
        file2 = os.path.join(self.test_dir.name, "file2.txt")
        content = b"DEFENSIVE_CYBERSECURITY_INTEGRITY_CHECK_12345"

        with open(file1, "wb") as f:
            f.write(content)
        with open(file2, "wb") as f:
            f.write(content)

        hash1, err1, size1 = calculate_sha256(file1)
        hash2, err2, size2 = calculate_sha256(file2)

        self.assertIsNone(err1)
        self.assertIsNone(err2)
        self.assertEqual(hash1, hash2)
        self.assertEqual(size1, len(content))
        self.assertEqual(hash1, hashlib.sha256(content).hexdigest())

    def test_calculate_sha256_modified(self):
        """Test that modified file contents produce different hashes."""
        filepath = os.path.join(self.test_dir.name, "config.txt")
        
        with open(filepath, "w") as f:
            f.write("PORT=5000\nDEBUG=false")
        hash_orig, err_orig, _ = calculate_sha256(filepath)

        with open(filepath, "w") as f:
            f.write("PORT=5000\nDEBUG=true")  # Modified
        hash_mod, err_mod, _ = calculate_sha256(filepath)

        self.assertIsNone(err_orig)
        self.assertIsNone(err_mod)
        self.assertNotEqual(hash_orig, hash_mod)

    def test_calculate_sha256_missing_file(self):
        """Test handling of non-existent files."""
        fake_path = os.path.join(self.test_dir.name, "ghost.txt")
        digest, err, size = calculate_sha256(fake_path)

        self.assertIsNone(digest)
        self.assertIn("File not found", err)
        self.assertEqual(size, 0)

    def test_calculate_sha256_max_size_limit(self):
        """Test that oversized files are skipped safely."""
        large_file = os.path.join(self.test_dir.name, "large.dat")
        with open(large_file, "wb") as f:
            f.write(b"0" * 1024)  # 1 KB file

        # Set limit to 500 bytes
        digest, err, size = calculate_sha256(large_file, max_size_bytes=500)

        self.assertIsNone(digest)
        self.assertIn("exceeds the configured scan size limit", err)
        self.assertEqual(size, 1024)


if __name__ == "__main__":
    unittest.main()
