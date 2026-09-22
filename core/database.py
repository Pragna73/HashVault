"""SQLite Database Management Module for HashVault.

Provides parameterized queries, connection management, schema migrations,
and data access methods for files, scans, and security events.
"""

import os
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "database",
    "hashvault.db",
)


def get_db_connection(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """Creates and returns a SQLite connection with dict-like row factories."""
    db_dir = os.path.dirname(db_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(db_path: str = DEFAULT_DB_PATH) -> None:
    """Initializes the SQLite schema if tables do not already exist."""
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.cursor()

        # Files table: monitors individual files and their baseline vs current state
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                filepath TEXT UNIQUE NOT NULL,
                baseline_hash TEXT NOT NULL,
                current_hash TEXT,
                status TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_checked TEXT NOT NULL,
                change_count INTEGER DEFAULT 0
            )
            """
        )

        # Scans table: records summary metrics for every integrity scan
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TEXT NOT NULL,
                total_files INTEGER NOT NULL,
                safe_files INTEGER NOT NULL,
                modified_files INTEGER NOT NULL,
                new_files INTEGER NOT NULL,
                deleted_files INTEGER NOT NULL,
                integrity_score INTEGER NOT NULL
            )
            """
        )

        # Events table: stores granular audit events for every detected change
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filepath TEXT NOT NULL,
                filename TEXT,
                event_type TEXT NOT NULL,
                old_hash TEXT,
                new_hash TEXT,
                timestamp TEXT NOT NULL
            )
            """
        )

        # Indexes for fast search and filtering
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_files_status ON files (status)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events (event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_filepath ON events (filepath)")
    conn.close()


def has_baseline(db_path: str = DEFAULT_DB_PATH) -> bool:
    """Checks whether a trusted baseline has been initialized."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM files")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0


def clear_baseline(db_path: str = DEFAULT_DB_PATH) -> None:
    """Clears existing monitored files baseline for re-initialization."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute("DELETE FROM files")
    conn.close()


def save_baseline_files(files_data: List[Dict[str, Any]], db_path: str = DEFAULT_DB_PATH) -> int:
    """Saves baseline files into the database, replacing previous baseline records."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM files")

        for item in files_data:
            cursor.execute(
                """
                INSERT INTO files (filename, filepath, baseline_hash, current_hash, status, first_seen, last_checked, change_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["filename"],
                    item["filepath"],
                    item["baseline_hash"],
                    item.get("current_hash", item["baseline_hash"]),
                    item.get("status", "SAFE"),
                    item.get("first_seen", now_str),
                    item.get("last_checked", now_str),
                    item.get("change_count", 0),
                ),
            )
    conn.close()
    return len(files_data)


def get_all_files(db_path: str = DEFAULT_DB_PATH, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
    """Fetches all monitored files, optionally filtered by status."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    if status_filter and status_filter.upper() != "ALL":
        cursor.execute("SELECT * FROM files WHERE status = ? ORDER BY filename ASC", (status_filter.upper(),))
    else:
        cursor.execute("SELECT * FROM files ORDER BY filename ASC")

    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_file_by_id(file_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a single file record by its primary ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE id = ?", (file_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_file_by_path(filepath: str, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a single file record by its normalized path."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM files WHERE filepath = ?", (filepath,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def update_file_record(file_id: int, current_hash: Optional[str], status: str, change_count: int, last_checked: str, db_path: str = DEFAULT_DB_PATH) -> None:
    """Updates the live status and hashes for a monitored file."""
    conn = get_db_connection(db_path)
    with conn:
        conn.execute(
            """
            UPDATE files
            SET current_hash = ?, status = ?, change_count = ?, last_checked = ?
            WHERE id = ?
            """,
            (current_hash, status, change_count, last_checked, file_id),
        )
    conn.close()


def insert_new_file(filename: str, filepath: str, current_hash: str, status: str, first_seen: str, last_checked: str, db_path: str = DEFAULT_DB_PATH) -> int:
    """Inserts an unmonitored newly discovered file into the files table."""
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO files (filename, filepath, baseline_hash, current_hash, status, first_seen, last_checked, change_count)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)
            """,
            (filename, filepath, "NONE (Unmonitored)", current_hash, status, first_seen, last_checked),
        )
        new_id = cursor.lastrowid
    conn.close()
    return new_id


def save_scan(scan_summary: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    """Inserts a completed scan summary record."""
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO scans (scan_time, total_files, safe_files, modified_files, new_files, deleted_files, integrity_score)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_summary["scan_time"],
                scan_summary["total_files"],
                scan_summary["safe_files"],
                scan_summary["modified_files"],
                scan_summary["new_files"],
                scan_summary["deleted_files"],
                scan_summary["integrity_score"],
            ),
        )
        scan_id = cursor.lastrowid
    conn.close()
    return scan_id


def get_latest_scan(db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves the most recent scan record."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def get_all_scans(limit: int = 50, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves list of scans ordered from newest to oldest."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    """Retrieves a specific scan record by ID."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None


def save_events(events: List[Dict[str, Any]], db_path: str = DEFAULT_DB_PATH) -> None:
    """Batch inserts security change events into the events log."""
    if not events:
        return
    conn = get_db_connection(db_path)
    with conn:
        cursor = conn.cursor()
        for ev in events:
            cursor.execute(
                """
                INSERT INTO events (filepath, filename, event_type, old_hash, new_hash, timestamp)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    ev["filepath"],
                    ev.get("filename", os.path.basename(ev["filepath"])),
                    ev["event_type"],
                    ev.get("old_hash"),
                    ev.get("new_hash"),
                    ev["timestamp"],
                ),
            )
    conn.close()


def get_events(
    limit: int = 100,
    event_type: Optional[str] = None,
    search_term: Optional[str] = None,
    db_path: str = DEFAULT_DB_PATH,
) -> List[Dict[str, Any]]:
    """Fetches audit events with optional event_type and search filters."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    query = "SELECT * FROM events WHERE 1=1"
    params: List[Any] = []

    if event_type and event_type.upper() != "ALL":
        query += " AND event_type = ?"
        params.append(event_type.upper())

    if search_term and search_term.strip():
        query += " AND (filename LIKE ? OR filepath LIKE ?)"
        term = f"%{search_term.strip()}%"
        params.extend([term, term])

    query += " ORDER BY id DESC LIMIT ?"
    params.append(limit)

    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_file_events(filepath: str, limit: int = 20, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    """Retrieves all historical events for a specific file path."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM events WHERE filepath = ? ORDER BY id DESC LIMIT ?",
        (filepath, limit),
    )
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_dashboard_metrics(db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Computes aggregated dashboard metrics for real-time rendering."""
    init_db(db_path)
    conn = get_db_connection(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM files")
    total_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'SAFE'")
    safe_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'MODIFIED'")
    modified_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'NEW'")
    new_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM files WHERE status = 'DELETED'")
    deleted_files = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    latest_scan = get_latest_scan(db_path)

    # Score calculation
    if total_files > 0:
        integrity_score = round((safe_files / total_files) * 100)
    else:
        integrity_score = 100

    conn.close()

    return {
        "total_files": total_files,
        "safe_files": safe_files,
        "modified_files": modified_files,
        "new_files": new_files,
        "deleted_files": deleted_files,
        "integrity_score": integrity_score,
        "total_events": total_events,
        "has_baseline": total_files > 0,
        "latest_scan": latest_scan,
    }
