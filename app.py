"""HashVault - File Integrity Monitoring & Security Investigation System.

Flask Web Application Entrypoint & REST API Endpoints.
"""

import os
from pathlib import Path
from flask import (
    Flask,
    Response,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from core.baseline import create_baseline
from core.comparator import run_integrity_scan
from core.database import (
    DEFAULT_DB_PATH,
    get_all_files,
    get_all_scans,
    get_dashboard_metrics,
    get_events,
    get_file_by_id,
    get_file_events,
    get_latest_scan,
    get_scan_by_id,
    init_db,
)
from core.reporter import (
    generate_csv_report,
    generate_json_report,
    get_full_report_data,
)

# Base application paths
BASE_DIR = Path(__file__).resolve().parent
PROTECTED_DIR = os.path.join(BASE_DIR, "protected")
DB_PATH = DEFAULT_DB_PATH

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Ensure database and tables are ready
init_db(DB_PATH)


@app.context_processor
def inject_global_metrics():
    """Injects real-time metrics across all rendered templates."""
    try:
        metrics = get_dashboard_metrics(DB_PATH)
    except Exception:
        metrics = {
            "total_files": 0,
            "safe_files": 0,
            "modified_files": 0,
            "new_files": 0,
            "deleted_files": 0,
            "integrity_score": 100,
            "total_events": 0,
            "has_baseline": False,
            "latest_scan": None,
        }
    return {"metrics": metrics}


# ============================================================================
# Core HTML Views
# ============================================================================

@app.route("/")
@app.route("/dashboard")
def dashboard_view():
    """Main dashboard displaying health metrics, status cards, and charts."""
    metrics = get_dashboard_metrics(DB_PATH)
    return render_template("dashboard.html", active_page="dashboard", metrics=metrics)


@app.route("/files")
def files_view():
    """Protected files inventory catalog."""
    status_filter = request.args.get("status", "ALL")
    files = get_all_files(DB_PATH, status_filter=status_filter)
    return render_template("files.html", active_page="files", files=files, current_filter=status_filter)


@app.route("/files/<int:file_id>")
def file_details_view(file_id: int):
    """Granular file inspection page with hash history and audit events."""
    file_record = get_file_by_id(file_id, DB_PATH)
    if not file_record:
        flash(f"File record #{file_id} not found.", "danger")
        return redirect(url_for("files_view"))

    events = get_file_events(file_record["filepath"], DB_PATH)
    return render_template("file_details.html", active_page="files", file=file_record, events=events)


@app.route("/scan")
def scan_view():
    """Scan and baseline management panel."""
    latest_scan = get_latest_scan(DB_PATH)
    return render_template(
        "scan.html",
        active_page="scan",
        target_dir="protected/",
        latest_scan=latest_scan,
    )


@app.route("/events")
def events_view():
    """Security events audit log."""
    event_type = request.args.get("type", "ALL")
    search_query = request.args.get("q", "")
    events = get_events(limit=200, event_type=event_type, search_term=search_query, db_path=DB_PATH)
    return render_template("events.html", active_page="events", events=events, current_type=event_type, search_query=search_query)


@app.route("/investigate")
def investigate_view():
    """Security investigation view focused on detected changes and triage."""
    files = get_all_files(DB_PATH)
    anomalies = [f for f in files if f["status"] in ("MODIFIED", "NEW", "DELETED")]
    
    # Enrich with latest event info if available
    investigation_items = []
    for f in anomalies:
        item = {
            "id": f["id"],
            "filename": f["filename"],
            "filepath": f["filepath"],
            "event_type": f["status"],
            "old_hash": f["baseline_hash"],
            "new_hash": f["current_hash"] or "NONE",
            "timestamp": f["last_checked"],
            "change_count": f["change_count"],
        }
        investigation_items.append(item)

    return render_template("investigate.html", active_page="investigate", anomalies=investigation_items)


@app.route("/history")
def history_view():
    """Chronological scan history archive."""
    scans = get_all_scans(limit=100, db_path=DB_PATH)
    return render_template("history.html", active_page="history", scans=scans)


@app.route("/report")
@app.route("/report/<int:scan_id>")
def report_view(scan_id: int = None):
    """Full security audit report."""
    report_data = get_full_report_data(scan_id=scan_id, db_path=DB_PATH)
    return render_template("report.html", active_page="report", report=report_data)


# ============================================================================
# RESTful API Endpoints
# ============================================================================

@app.route("/api/baseline", methods=["POST"])
def api_create_baseline():
    """API endpoint to create or replace the trusted cryptographic baseline."""
    data = request.get_json(silent=True) or {}
    force = bool(data.get("force", False))

    success, message, result_data = create_baseline(
        target_dir=PROTECTED_DIR,
        force=force,
        db_path=DB_PATH,
    )

    status_code = 200 if success else (409 if result_data.get("requires_confirmation") else 400)
    return jsonify({
        "success": success,
        "message": message,
        "data": result_data,
    }), status_code


@app.route("/api/scan", methods=["POST"])
def api_run_scan():
    """API endpoint to execute an integrity scan against the live filesystem."""
    success, message, result_data = run_integrity_scan(
        target_dir=PROTECTED_DIR,
        db_path=DB_PATH,
    )

    status_code = 200 if success else 400
    return jsonify({
        "success": success,
        "message": message,
        "data": result_data,
    }), status_code


@app.route("/api/stats")
def api_stats():
    """API endpoint providing dataset metrics for dynamic Chart.js visualizations."""
    metrics = get_dashboard_metrics(DB_PATH)
    scans = get_all_scans(limit=15, db_path=DB_PATH)

    distribution = {
        "safe": metrics["safe_files"],
        "modified": metrics["modified_files"],
        "new": metrics["new_files"],
        "deleted": metrics["deleted_files"],
    }

    return jsonify({
        "metrics": metrics,
        "distribution": distribution,
        "scans": scans,
    })


# ============================================================================
# Export Endpoints (JSON / CSV)
# ============================================================================

@app.route("/export/json")
@app.route("/export/json/<int:scan_id>")
def export_json_view(scan_id: int = None):
    """Downloads the security report formatted as JSON."""
    json_content = generate_json_report(scan_id=scan_id, db_path=DB_PATH)
    filename = f"hashvault_report_{scan_id or 'latest'}.json"
    
    return Response(
        json_content,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


@app.route("/export/csv")
@app.route("/export/csv/<int:scan_id>")
def export_csv_view(scan_id: int = None):
    """Downloads recorded security events formatted as CSV."""
    csv_content = generate_csv_report(scan_id=scan_id, db_path=DB_PATH)
    filename = f"hashvault_events_{scan_id or 'latest'}.csv"
    
    return Response(
        csv_content,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )


# ============================================================================
# Error Handlers
# ============================================================================

@app.errorhandler(404)
def not_found_error(error):
    return render_template(
        "error.html",
        error_code=404,
        error_title="Page Not Found",
        error_message="The requested security resource or URL endpoint was not found.",
        active_page="",
    ), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template(
        "error.html",
        error_code=500,
        error_title="Internal System Error",
        error_message="An unexpected server error occurred while processing the cryptographic audit request.",
        active_page="",
    ), 500


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
