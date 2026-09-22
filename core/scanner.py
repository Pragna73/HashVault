"""Recursive File Discovery & Scanning Engine for HashVault.

Traverses protected directories, applies security filter rules to ignore runtime
artifacts/databases/caches, and computes current cryptographic digests for every file.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Set

from core.hasher import calculate_sha256

# Directories to ignore during scanning
IGNORED_DIRS: Set[str] = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "env",
    "database",
    "instance",
    ".vscode",
    ".idea",
    "node_modules",
}

# File extensions to ignore during scanning
IGNORED_EXTENSIONS: Set[str] = {
    ".db",
    ".sqlite",
    ".sqlite3",
    ".pyc",
    ".pyo",
    ".pyd",
    ".log",
    ".tmp",
    ".swp",
    ".swo",
    ".DS_Store",
}

# File names to ignore
IGNORED_FILENAMES: Set[str] = {
    ".gitkeep",
    ".gitignore",
    "Thumbs.db",
}


def is_ignored(path_obj: Path) -> bool:
    """Evaluates whether a given file path matches any exclusion rule."""
    # Check directory components
    for part in path_obj.parts:
        if part in IGNORED_DIRS:
            return True

    # Check filename
    if path_obj.name in IGNORED_FILENAMES:
        return True

    # Check temporary/hidden patterns
    if path_obj.name.startswith("~") or (path_obj.name.startswith(".") and not path_obj.name == "."):
        # Hidden files except regular ones
        if path_obj.name in {".gitignore", ".gitkeep"}:
            return True

    # Check extension
    if path_obj.suffix.lower() in IGNORED_EXTENSIONS:
        return True

    return False


def normalize_filepath(filepath: str, base_dir: str) -> str:
    """Normalizes a file path relative to base_dir with forward slashes for cross-platform consistency."""
    abs_filepath = os.path.abspath(filepath)
    abs_base = os.path.abspath(base_dir)

    try:
        rel_path = os.path.relpath(abs_filepath, abs_base)
        # Convert to unified forward slashes
        return rel_path.replace("\\", "/")
    except ValueError:
        # On Windows if across drives
        return abs_filepath.replace("\\", "/")


def discover_and_hash_files(target_dir: str) -> Dict[str, Dict[str, Any]]:
    """Recursively discovers all valid files in target_dir and computes their SHA-256 hashes.

    Args:
        target_dir: Root directory to scan (e.g., 'protected/').

    Returns:
        Dict mapping normalized relative filepath -> {
            'filename': str,
            'filepath': str (normalized relative or absolute),
            'full_path': str,
            'sha256': str or None,
            'error': str or None,
            'size': int
        }
    """
    target_path = Path(target_dir).resolve()
    results: Dict[str, Dict[str, Any]] = {}

    if not target_path.exists() or not target_path.is_dir():
        return results

    for root, dirs, files in os.walk(target_path):
        # Filter out ignored directories in-place to prune walk
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for file_name in files:
            full_file_path = Path(root) / file_name

            if is_ignored(full_file_path):
                continue

            normalized_rel = normalize_filepath(str(full_file_path), str(target_path))
            digest, error, size = calculate_sha256(str(full_file_path))

            results[normalized_rel] = {
                "filename": file_name,
                "filepath": normalized_rel,
                "full_path": str(full_file_path),
                "sha256": digest,
                "error": error,
                "size": size,
            }

    return results
