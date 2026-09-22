"""Report Generation & Export Engine for HashVault.

Generates structured JSON security reports, CSV change logs,
and comprehensive audit summaries for security compliance and incident reviews.
"""

import csv
import io
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from core.database import (
    DEFAULT_DB_PATH,
    get_all_files,
    get_dashboard_metrics,
    get_events,
    get_latest_scan,
    get_scan_by_id,
)


def generate_json_report(scan_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH) -> str:
    """Generates a standardized JSON security report.

    If scan_id is provided, returns the report for that specific scan;
    otherwise returns the report based on the latest scan & current database state.
    """
    if scan_id:
        scan_record = get_scan_by_id(scan_id, db_path)
    else:
        scan_record = get_latest_scan(db_path)

    if scan_record:
        scan_time = scan_record["scan_time"]
        summary = {
            "total_files": scan_record["total_files"],
            "safe_files": scan_record["safe_files"],
            "modified_files": scan_record["modified_files"],
            "new_files": scan_record["new_files"],
            "deleted_files": scan_record["deleted_files"],
            "integrity_score": scan_record["integrity_score"],
        }
    else:
        metrics = get_dashboard_metrics(db_path)
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        summary = {
            "total_files": metrics["total_files"],
            "safe_files": metrics["safe_files"],
            "modified_files": metrics["modified_files"],
            "new_files": metrics["new_files"],
            "deleted_files": metrics["deleted_files"],
            "integrity_score": metrics["integrity_score"],
        }

    events = get_events(limit=500, db_path=db_path)
    cleaned_events = []
    for ev in events:
        cleaned_events.append(
            {
                "id": ev["id"],
                "timestamp": ev["timestamp"],
                "filepath": ev["filepath"],
                "filename": ev.get("filename", ""),
                "event_type": ev["event_type"],
                "old_hash": ev.get("old_hash") or "N/A",
                "new_hash": ev.get("new_hash") or "N/A",
            }
        )

    report_payload = {
        "project": "HashVault",
        "system": "File Integrity Monitoring & Security Investigation System",
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "scan_time": scan_time,
        "summary": summary,
        "events": cleaned_events,
    }

    return json.dumps(report_payload, indent=2)


def generate_csv_report(scan_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH) -> str:
    """Generates a standard CSV export of all recorded security integrity events."""
    events = get_events(limit=1000, db_path=db_path)

    output = io.StringIO()
    fieldnames = ["timestamp", "filepath", "filename", "event_type", "old_hash", "new_hash"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\n")

    writer.writeheader()
    for ev in events:
        writer.writerow(
            {
                "timestamp": ev["timestamp"],
                "filepath": ev["filepath"],
                "filename": ev.get("filename") or "",
                "event_type": ev["event_type"],
                "old_hash": ev.get("old_hash") or "N/A",
                "new_hash": ev.get("new_hash") or "N/A",
            }
        )

    return output.getvalue()


def get_full_report_data(scan_id: Optional[int] = None, db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    """Assembles all data needed for the security audit report HTML view."""
    if scan_id:
        scan_record = get_scan_by_id(scan_id, db_path)
    else:
        scan_record = get_latest_scan(db_path)

    files = get_all_files(db_path)
    events = get_events(limit=100, db_path=db_path)

    if scan_record:
        summary = {
            "scan_id": scan_record["id"],
            "scan_time": scan_record["scan_time"],
            "total_files": scan_record["total_files"],
            "safe_files": scan_record["safe_files"],
            "modified_files": scan_record["modified_files"],
            "new_files": scan_record["new_files"],
            "deleted_files": scan_record["deleted_files"],
            "integrity_score": scan_record["integrity_score"],
        }
    else:
        metrics = get_dashboard_metrics(db_path)
        summary = {
            "scan_id": None,
            "scan_time": "No scans recorded yet",
            "total_files": metrics["total_files"],
            "safe_files": metrics["safe_files"],
            "modified_files": metrics["modified_files"],
            "new_files": metrics["new_files"],
            "deleted_files": metrics["deleted_files"],
            "integrity_score": metrics["integrity_score"],
        }

    return {
        "summary": summary,
        "files": files,
        "events": events,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
