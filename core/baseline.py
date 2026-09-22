"""Baseline Creation & Management Engine for HashVault.

Establishes a cryptographically verified snapshot of all protected files,
stores immutable baseline SHA-256 hashes, and handles safe baseline re-initialization.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from core.database import DEFAULT_DB_PATH, has_baseline, save_baseline_files
from core.scanner import discover_and_hash_files


def create_baseline(
    target_dir: str,
    force: bool = False,
    db_path: str = DEFAULT_DB_PATH,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Creates a new trusted baseline of all files in target_dir.

    Args:
        target_dir: Target directory path to protect (e.g. 'protected/').
        force: If True, overwrites an existing baseline without prompting.
        db_path: Path to the SQLite database.

    Returns:
        Tuple of:
            - success (bool): True if baseline was created or False if blocked/failed.
            - message (str): User-facing status message.
            - data (dict): Detailed summary including count and file details.
    """
    if not os.path.exists(target_dir):
        return (
            False,
            f"Target directory does not exist: {target_dir}",
            {"total_protected": 0, "files": []},
        )

    # If baseline already exists and force is not set, require confirmation
    if has_baseline(db_path) and not force:
        return (
            False,
            "A trusted baseline already exists. Please confirm replacement before continuing.",
            {"requires_confirmation": True},
        )

    discovered = discover_and_hash_files(target_dir)

    if not discovered:
        return (
            False,
            "No valid files found in the target directory to create a baseline.",
            {"total_protected": 0, "files": []},
        )

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    files_to_save: List[Dict[str, Any]] = []

    for rel_path, file_info in discovered.items():
        if file_info["sha256"]:
            files_to_save.append(
                {
                    "filename": file_info["filename"],
                    "filepath": file_info["filepath"],
                    "baseline_hash": file_info["sha256"],
                    "current_hash": file_info["sha256"],
                    "status": "SAFE",
                    "first_seen": now_str,
                    "last_checked": now_str,
                    "change_count": 0,
                }
            )

    count = save_baseline_files(files_to_save, db_path)

    message = f"Baseline created successfully. {count} files are now protected."
    return True, message, {
        "total_protected": count,
        "files": files_to_save,
        "created_at": now_str,
    }
