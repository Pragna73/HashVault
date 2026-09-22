"""Integration tests for Flask application routes and API endpoints."""

import json
import unittest

from app import app


class TestApp(unittest.TestCase):
    """Test suite for Flask web application."""

    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_dashboard_route(self):
        """Test dashboard index loads successfully."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"HASHVAULT", response.data)
        self.assertIn(b"Security Dashboard", response.data)

    def test_files_route(self):
        """Test protected files catalog page."""
        response = self.client.get("/files")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Protected Files Inventory", response.data)

    def test_scan_route(self):
        """Test scan management page."""
        response = self.client.get("/scan")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan & Baseline", response.data)

    def test_events_route(self):
        """Test security events audit log page."""
        response = self.client.get("/events")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Event Audit Log", response.data)

    def test_investigate_route(self):
        """Test investigation mode page."""
        response = self.client.get("/investigate")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Investigation Mode", response.data)

    def test_history_route(self):
        """Test scan history page."""
        response = self.client.get("/history")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan History Archive", response.data)

    def test_report_route(self):
        """Test security report page."""
        response = self.client.get("/report")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Security Audit Report", response.data)

    def test_api_stats_route(self):
        """Test API stats endpoint returns JSON with expected schema."""
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.data)
        self.assertIn("distribution", data)
        self.assertIn("metrics", data)
        self.assertIn("scans", data)

    def test_baseline_and_scan_apis(self):
        """Test creating baseline and executing scan via API."""
        # Baseline creation
        base_resp = self.client.post("/api/baseline", json={"force": True})
        self.assertEqual(base_resp.status_code, 200)
        base_data = json.loads(base_resp.data)
        self.assertTrue(base_data["success"])

        # Integrity scan
        scan_resp = self.client.post("/api/scan", json={})
        self.assertEqual(scan_resp.status_code, 200)
        scan_data = json.loads(scan_resp.data)
        self.assertTrue(scan_data["success"])

    def test_export_endpoints(self):
        """Test export endpoints return proper attachments."""
        # JSON export
        json_resp = self.client.get("/export/json")
        self.assertEqual(json_resp.status_code, 200)
        self.assertEqual(json_resp.mimetype, "application/json")

        # CSV export
        csv_resp = self.client.get("/export/csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertEqual(csv_resp.mimetype, "text/csv")

    def test_404_error_page(self):
        """Test custom 404 handler."""
        response = self.client.get("/nonexistent-page-404")
        self.assertEqual(response.status_code, 404)
        self.assertIn(b"404", response.data)


if __name__ == "__main__":
    unittest.main()
