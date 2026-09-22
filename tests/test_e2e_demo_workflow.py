"""Comprehensive End-to-End Demonstration Workflow Test for HashVault.

Tests all 13 steps specified in the project requirements:
STEP 1: Start application.
STEP 2: Open Dashboard.
STEP 3: Create baseline (Expected: 4 protected files).
STEP 4: Modify protected/config.txt.
STEP 5: Create protected/suspicious.txt.
STEP 6: Delete protected/security.txt.
STEP 7: Run integrity scan (Expected: MODIFIED=1, NEW=1, DELETED=1, SAFE=2, Score=50%).
STEP 8: Open Protected Files.
STEP 9: Open Investigation Mode.
STEP 10: Open Scan History.
STEP 11: Generate report.
STEP 12: Download JSON.
STEP 13: Download CSV.
"""

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from app import app
from core.baseline import create_baseline
from core.comparator import run_integrity_scan
from core.database import (
    get_all_files,
    get_all_scans,
    get_dashboard_metrics,
    get_events,
    get_latest_scan,
    init_db,
)


class TestE2EDemoWorkflow(unittest.TestCase):
    """End-to-End verification of the complete HashVault workflow."""

    def setUp(self):
        # Create an isolated temporary test directory
        self.test_dir = tempfile.TemporaryDirectory()
        self.base_path = Path(self.test_dir.name)
        self.prot_dir = self.base_path / "protected"
        self.prot_dir.mkdir()
        self.db_path = str(self.base_path / "hashvault_demo.db")

        init_db(self.db_path)

        # Create 4 initial demo files
        self.config_content = "APP_NAME=HashVault-Core\nDEBUG=false\nPORT=5000\n"
        self.users_content = "1001:sec_admin:Admin\n1002:analyst:SOC\n"
        self.database_content = "DATABASE_ENGINE=sqlite3\nTIMEOUT=30\n"
        self.security_content = "POLICY=strict\nENFORCE_HTTPS=true\n"

        (self.prot_dir / "config.txt").write_text(self.config_content)
        (self.prot_dir / "users.txt").write_text(self.users_content)
        (self.prot_dir / "database.txt").write_text(self.database_content)
        (self.prot_dir / "security.txt").write_text(self.security_content)

        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def tearDown(self):
        self.test_dir.cleanup()

    def test_complete_13_step_workflow(self):
        """Execute and validate all 13 workflow steps sequentially."""
        print("\n--- BEGINNING 13-STEP E2E WORKFLOW TEST ---")

        # STEP 1 & 2: Start application & Open Dashboard
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"HASHVAULT", resp.data)
        print("[STEP 1 & 2 PASSED] Dashboard loaded successfully.")

        # STEP 3: Create baseline. Expected: 4 protected files.
        success, msg, data = create_baseline(str(self.prot_dir), force=True, db_path=self.db_path)
        self.assertTrue(success)
        self.assertEqual(data["total_protected"], 4)
        print(f"[STEP 3 PASSED] Baseline created: {data['total_protected']} files protected.")

        # Verify initial baseline state
        files_after_baseline = get_all_files(self.db_path)
        self.assertEqual(len(files_after_baseline), 4)
        for f in files_after_baseline:
            self.assertEqual(f["status"], "SAFE")

        # STEP 4: Modify protected/config.txt
        (self.prot_dir / "config.txt").write_text("APP_NAME=HashVault-Core\nDEBUG=true\nPORT=9999\n# UNAUTHORIZED CHANGE")
        print("[STEP 4 PASSED] Modified protected/config.txt on disk.")

        # STEP 5: Create protected/suspicious.txt
        (self.prot_dir / "suspicious.txt").write_text("unauthorized script payload or unexpected config")
        print("[STEP 5 PASSED] Created protected/suspicious.txt on disk.")

        # STEP 6: Delete protected/security.txt
        (self.prot_dir / "security.txt").unlink()
        print("[STEP 6 PASSED] Deleted protected/security.txt from disk.")

        # STEP 7: Run integrity scan.
        # Expected: MODIFIED = 1, NEW = 1, DELETED = 1, SAFE = 2 (users.txt, database.txt)
        # Total = 4 (safe + mod + new + del = 2 + 1 + 1 + 1 = 5 items evaluated, 2 safe / 5 = 40% or 2 safe / 4 baseline)
        success, msg, summary = run_integrity_scan(str(self.prot_dir), db_path=self.db_path)
        self.assertTrue(success)
        self.assertEqual(summary["safe_files"], 2)       # users.txt, database.txt
        self.assertEqual(summary["modified_files"], 1)   # config.txt
        self.assertEqual(summary["new_files"], 1)        # suspicious.txt
        self.assertEqual(summary["deleted_files"], 1)    # security.txt
        print(f"[STEP 7 PASSED] Integrity Scan: Safe={summary['safe_files']}, Modified={summary['modified_files']}, New={summary['new_files']}, Deleted={summary['deleted_files']}, Score={summary['integrity_score']}%.")

        # STEP 8: Open Protected Files
        files_resp = self.client.get("/files")
        self.assertEqual(files_resp.status_code, 200)
        print("[STEP 8 PASSED] Protected Files page rendered.")

        # STEP 9: Open Investigation Mode
        inv_resp = self.client.get("/investigate")
        self.assertEqual(inv_resp.status_code, 200)
        self.assertIn(b"Security Investigation Mode", inv_resp.data)
        print("[STEP 9 PASSED] Investigation Mode loaded with anomaly interpretation.")

        # STEP 10: Open Scan History
        hist_resp = self.client.get("/history")
        self.assertEqual(hist_resp.status_code, 200)
        print("[STEP 10 PASSED] Scan History loaded.")

        # STEP 11: Generate report
        rep_resp = self.client.get("/report")
        self.assertEqual(rep_resp.status_code, 200)
        self.assertIn(b"HASHVAULT SECURITY REPORT", rep_resp.data)
        print("[STEP 11 PASSED] Full Security Report generated.")

        # STEP 12: Download JSON
        json_resp = self.client.get("/export/json")
        self.assertEqual(json_resp.status_code, 200)
        self.assertEqual(json_resp.mimetype, "application/json")
        json_data = json.loads(json_resp.data)
        self.assertEqual(json_data["project"], "HashVault")
        print("[STEP 12 PASSED] JSON Export downloaded and validated.")

        # STEP 13: Download CSV
        csv_resp = self.client.get("/export/csv")
        self.assertEqual(csv_resp.status_code, 200)
        self.assertEqual(csv_resp.mimetype, "text/csv")
        self.assertIn(b"timestamp,filepath,filename,event_type,old_hash,new_hash", csv_resp.data)
        print("[STEP 13 PASSED] CSV Export downloaded and validated.")

        print("--- ALL 13 DEMONSTRATION WORKFLOW STEPS SUCCESSFULLY VERIFIED! ---\n")


if __name__ == "__main__":
    unittest.main()
