"""Comparison & Integrity Analysis Engine for HashVault.

Compares live filesystem cryptographic state against the trusted baseline,
classifies file statuses (SAFE, MODIFIED, NEW, DELETED), records audit events,
and computes overall application integrity health scores.
"""

import os
from datetime import datetime
from typing import Any, Dict, List, Tuple

from core.database import (
    DEFAULT_DB_PATH,
    get_all_files,
    has_baseline,
    insert_new_file,
    save_events,
    save_scan,
    update_file_record,
)
from core.scanner import discover_and_hash_files


def calculate_integrity_score(safe_files: int, total_files: int) -> int:
    """Calculates the Application Integrity Score percentage.

    Formula: (safe_files / total_files) * 100 rounded to the nearest integer.
    Safe handling of zero files.
    """
    if total_files <= 0:
        return 100
    score = (safe_files / total_files) * 100.0
    return round(score)


def run_integrity_scan(
    target_dir: str,
    db_path: str = DEFAULT_DB_PATH,
) -> Tuple[bool, str, Dict[str, Any]]:
    """Executes a full file integrity scan against the trusted baseline.

    Args:
        target_dir: Target directory to scan (e.g. 'protected/').
        db_path: Path to the SQLite database.

    Returns:
        Tuple of (success, message, scan_results_dict)
    """
    if not has_baseline(db_path):
        return (
            False,
            "No trusted baseline found. Please create a baseline first before running an integrity scan.",
            {
                "total_files": 0,
                "safe_files": 0,
                "modified_files": 0,
                "new_files": 0,
                "deleted_files": 0,
                "integrity_score": 100,
                "events": [],
            },
        )

    # 1. Fetch current baseline records from database
    baseline_records = {row["filepath"]: dict(row) for row in get_all_files(db_path)}

    # 2. Discover live files on disk
    live_files = discover_and_hash_files(target_dir)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    events_to_record: List[Dict[str, Any]] = []

    safe_count = 0
    modified_count = 0
    new_count = 0
    deleted_count = 0

    processed_live_paths = set()

    # 3. Check baseline files against live filesystem
    for filepath, file_record in baseline_records.items():
        file_id = file_record["id"]
        baseline_hash = file_record["baseline_hash"]
        current_change_count = file_record.get("change_count", 0)

        # File was deleted from disk
        if filepath not in live_files:
            deleted_count += 1
            new_change_count = current_change_count + 1 if file_record["status"] != "DELETED" else current_change_count
            update_file_record(
                file_id=file_id,
                current_hash="NONE (Deleted)",
                status="DELETED",
                change_count=new_change_count,
                last_checked=now_str,
                db_path=db_path,
            )

            # Record event only if changed or newly detected
            events_to_record.append(
                {
                    "filepath": filepath,
                    "filename": file_record["filename"],
                    "event_type": "DELETED",
                    "old_hash": baseline_hash,
                    "new_hash": "NONE (File removed)",
                    "timestamp": now_str,
                }
            )
            continue

        # File exists on disk
        processed_live_paths.add(filepath)
        live_info = live_files[filepath]
        live_hash = live_info["sha256"]

        if live_hash is None:
            # File unreadable (e.g. permission or error)
            modified_count += 1
            update_file_record(
                file_id=file_id,
                current_hash=f"ERROR: {live_info.get('error', 'Unreadable')}",
                status="MODIFIED",
                change_count=current_change_count + 1,
                last_checked=now_str,
                db_path=db_path,
            )
            events_to_record.append(
                {
                    "filepath": filepath,
                    "filename": file_record["filename"],
                    "event_type": "MODIFIED",
                    "old_hash": baseline_hash,
                    "new_hash": f"ERROR: {live_info.get('error', 'Unreadable')}",
                    "timestamp": now_str,
                }
            )
        elif live_hash == baseline_hash:
            # Identical hash: SAFE
            safe_count += 1
            update_file_record(
                file_id=file_id,
                current_hash=live_hash,
                status="SAFE",
                change_count=current_change_count,
                last_checked=now_str,
                db_path=db_path,
            )
        else:
            # Hash mismatch: MODIFIED
            modified_count += 1
            update_file_record(
                file_id=file_id,
                current_hash=live_hash,
                status="MODIFIED",
                change_count=current_change_count + 1,
                last_checked=now_str,
                db_path=db_path,
            )
            events_to_record.append(
                {
                    "filepath": filepath,
                    "filename": file_record["filename"],
                    "event_type": "MODIFIED",
                    "old_hash": baseline_hash,
                    "new_hash": live_hash,
                    "timestamp": now_str,
                }
            )

    # 4. Check for newly introduced files not present in the baseline
    for filepath, live_info in live_files.items():
        if filepath not in processed_live_paths:
            new_count += 1
            insert_new_file(
                filename=live_info["filename"],
                filepath=filepath,
                current_hash=live_info["sha256"] or "UNREADABLE",
                status="NEW",
                first_seen=now_str,
                last_checked=now_str,
                db_path=db_path,
            )
            events_to_record.append(
                {
                    "filepath": filepath,
                    "filename": live_info["filename"],
                    "event_type": "NEW",
                    "old_hash": "NONE (New unmonitored file)",
                    "new_hash": live_info["sha256"] or "UNREADABLE",
                    "timestamp": now_str,
                }
            )

    total_monitored = safe_count + modified_count + new_count + deleted_count
    score = calculate_integrity_score(safe_count, total_monitored)

    # 5. Persist audit events into SQLite
    if events_to_record:
        save_events(events_to_record, db_path)

    # 6. Record scan summary in SQLite
    scan_summary = {
        "scan_time": now_str,
        "total_files": total_monitored,
        "safe_files": safe_count,
        "modified_files": modified_count,
        "new_files": new_count,
        "deleted_files": deleted_count,
        "integrity_score": score,
    }
    scan_id = save_scan(scan_summary, db_path)
    scan_summary["scan_id"] = scan_id
    scan_summary["events"] = events_to_record

    # Status message
    if modified_count == 0 and new_count == 0 and deleted_count == 0:
        message = "Integrity check passed. No unexpected changes detected."
    else:
        message = f"Security alert: Integrity changes detected ({modified_count} modified, {new_count} new, {deleted_count} deleted)."

    return True, message, scan_summary
