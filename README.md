# HashVault ⚡

> **"Detect unauthorized file changes before they become security incidents."**

[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://www.python.org/)
[![Flask 3.0+](https://img.shields.io/badge/Flask-3.0%2B-lightgrey.svg)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Tests: Passing](https://img.shields.io/badge/Tests-31%2F31%20Passed-brightgreen.svg)](#testing)

---

## 🛡️ Overview

**HashVault** is a defensive cybersecurity and file integrity monitoring (FIM) platform. It provides security administrators and SOC analysts with real-time cryptographic verification of critical assets using the **SHA-256** cryptographic hash algorithm.

By establishing an immutable, trusted baseline of protected configurations, binaries, and system files, HashVault detects unintended modifications, unauthorized file injections, or unexpected deletions before they escalate into serious security incidents.

---

## 🎯 Problem Statement & Objectives

### Problem
In modern infrastructure, stealthy configuration changes, unauthorized privilege escalation, and unintended file tampering often go unnoticed until a system failure or data breach occurs. Traditional logging systems may capture access attempts, but do not cryptographically verify whether files on storage match their authorized state.

### Objectives
1. **Cryptographic Verification**: Compute deterministic, memory-efficient SHA-256 fingerprints of monitored files.
2. **Deterministic Change Classification**: Categorize file states into `SAFE`, `MODIFIED`, `NEW`, and `DELETED`.
3. **Application Integrity Scoring**: Compute real-time health scores to measure compliance and fleet hygiene.
4. **Security Investigation**: Provide dedicated triage views with contextual recommendations.
5. **Auditing & Reporting**: Support on-demand JSON and CSV security exports for audit compliance.

---

## ✨ Key Features

- 🔐 **SHA-256 Chunked Cryptographic Engine**: Streams files in 64 KB chunks to protect memory and safely enforce a 50 MB scan threshold.
- ⚡ **Trusted Baseline Management**: Creates snapshots of protected assets with overwrite confirmation guards.
- 🔍 **Real-Time Integrity Scanning**: Compares the live filesystem against baseline records and logs forensic events.
- 📊 **Security Dashboard**: Features primary stat cards, status indicators, and interactive Chart.js visualizations (Status Distribution, Integrity Score Trend, Scan Activity).
- 🔬 **Investigation Mode**: Provides structured triage cards with neutral security interpretations and recommended next steps.
- 📑 **Comprehensive Reporting**: Generates printable HTML audit reports with instant JSON and CSV downloads.
- 📋 **Interactive UI**: Includes dark obsidian styling, 1-click clipboard hash copying, responsive tables, and instant search/filter controls.

---

## 🏗️ Architecture

```
                                Browser (HTML5 / CSS3 / Vanilla JS / Chart.js)
                                                      │
                                                      ▼
                                       Flask Web Application (app.py)
                                                      │
                       ┌──────────────────────────────┼──────────────────────────────┐
                       ▼                              ▼                              ▼
                 Hash Engine                   File Scanner                   Baseline Manager
             (core/hasher.py)                (core/scanner.py)               (core/baseline.py)
              • SHA-256 64KB Chunks           • Recursive Path Walk           • Initial Snapshot
              • 50MB Safety Limit             • Filter Rules (.git, db)       • Overwrite Protection
                       │                              │                              │
                       └──────────────────────────────┼──────────────────────────────┘
                                                      ▼
                                              Comparison Engine
                                            (core/comparator.py)
                                        • SAFE / MODIFIED / NEW / DELETED
                                        • Application Integrity Score
                                                      │
                       ┌──────────────────────────────┴──────────────────────────────┐
                       ▼                                                             ▼
                Event Logger & DB                                            Report Generator
               (core/database.py)                                           (core/reporter.py)
           • SQLite Parameterized SQL                                    • JSON Export
           • files, scans, events tables                                 • CSV Event Log
```

---

## 🧰 Technology Stack

- **Backend**: Python 3.9+, Flask 3.0+
- **Database**: SQLite (Zero configuration, parameterized queries)
- **Frontend**: HTML5, Vanilla CSS3 (Custom Dark Obsidian & Amber theme), Vanilla JavaScript
- **Data Visualization**: Chart.js 4.4+
- **Standard Libraries**: `hashlib`, `pathlib`, `os`, `datetime`, `json`, `csv`, `sqlite3`, `tempfile`, `unittest`

---

## 📁 Project Structure

```
HashVault/
├── app.py                      # Flask main application & REST API routes
├── requirements.txt            # Minimal Python dependencies
├── README.md                   # Complete system documentation
├── .gitignore                  # Git exclusion rules
│
├── database/
│   ├── .gitkeep                # Repository placeholder
│   └── hashvault.db            # Auto-generated SQLite database
│
├── core/
│   ├── __init__.py             # Core package initialization
│   ├── hasher.py               # SHA-256 chunked hashing & safety limits
│   ├── scanner.py              # Recursive file traversal & ignore filters
│   ├── database.py             # SQLite schema, queries & transaction management
│   ├── baseline.py             # Baseline creation & overwrite confirmation
│   ├── comparator.py           # Integrity scan, change detection & scoring
│   └── reporter.py             # Security report generator (HTML, JSON, CSV)
│
├── templates/
│   ├── base.html               # Master layout, navigation & toasts
│   ├── dashboard.html          # Stats cards, charts & scan summary
│   ├── files.html              # Protected files catalog & search filters
│   ├── file_details.html       # File timeline, hash history & metadata
│   ├── scan.html               # Baseline management & scan trigger
│   ├── events.html             # Security event audit log
│   ├── investigate.html        # Anomaly analysis & investigation mode
│   ├── history.html            # Chronological scan archive
│   ├── report.html             # Printable audit report
│   └── error.html              # Custom 404 & 500 error pages
│
├── static/
│   ├── css/
│   │   └── style.css           # Dark cybersecurity styling (amber/gold accents)
│   └── js/
│       ├── dashboard.js        # Modals, API dispatch, clipboard tools, search
│       └── charts.js           # Chart.js distribution, trend & activity charts
│
├── protected/
│   ├── config.txt              # Demo server configuration
│   ├── users.txt               # Demo access control permissions
│   ├── database.txt            # Demo database connection profile
│   └── security.txt            # Demo firewall & security policies
│
└── tests/
    ├── __init__.py             # Test package initialization
    ├── test_hasher.py          # Hasher unit tests
    ├── test_scanner.py         # Scanner & filter unit tests
    ├── test_baseline.py        # Baseline manager tests
    ├── test_comparator.py      # Comparator & score calculation tests
    ├── test_database.py        # Database parameterized CRUD tests
    ├── test_reporter.py        # JSON & CSV export tests
    └── test_app.py             # Flask integration tests
```

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
- Python 3.9 or higher
- Git

### 2. Clone the Repository
```bash
git clone https://github.com/Pragna73/hashvault.git
cd hashvault
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```
Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 🧪 Demonstration Workflow

To verify the end-to-end functionality of HashVault, follow this test workflow:

| Step | Action | Expected Result |
| :--- | :--- | :--- |
| **Step 1** | Run `python app.py` | Application starts on port 5000 |
| **Step 2** | Open `http://127.0.0.1:5000` | Dashboard loads with empty baseline message |
| **Step 3** | Click **CREATE BASELINE** | 4 demo files (`protected/`) protected with `SAFE` status |
| **Step 4** | Modify `protected/config.txt` | File contents altered on disk |
| **Step 5** | Create `protected/suspicious.txt` | Unmonitored file introduced to protected directory |
| **Step 6** | Delete `protected/security.txt` | Monitored file removed from storage |
| **Step 7** | Click **RUN INTEGRITY SCAN** | Detection: `MODIFIED=1`, `NEW=1`, `DELETED=1`, `SAFE=2` |
| **Step 8** | Open **Protected Files** | Inventory shows badges for all 4 statuses |
| **Step 9** | Open **Investigation Mode** | 3 triage cards appear with security interpretations |
| **Step 10** | Open **Scan History** | Historical entry shows 50% integrity score |
| **Step 11** | Open **Security Report** | Full audit summary with detected anomalies |
| **Step 12** | Click **EXPORT JSON** | Downloads valid structured JSON file |
| **Step 13** | Click **EXPORT CSV** | Downloads valid event log CSV file |

---

## 🗄️ Database Design

HashVault uses SQLite with 100% parameterized SQL queries:

### 1. `files` Table
Tracks monitored assets and baseline hashes.
- `id` (INTEGER, Primary Key)
- `filename` (TEXT)
- `filepath` (TEXT, Unique)
- `baseline_hash` (TEXT)
- `current_hash` (TEXT)
- `status` (TEXT: `SAFE`, `MODIFIED`, `NEW`, `DELETED`)
- `first_seen` (TEXT)
- `last_checked` (TEXT)
- `change_count` (INTEGER)

### 2. `scans` Table
Tracks scan executions and aggregate metrics.
- `id` (INTEGER, Primary Key)
- `scan_time` (TEXT)
- `total_files` (INTEGER)
- `safe_files` (INTEGER)
- `modified_files` (INTEGER)
- `new_files` (INTEGER)
- `deleted_files` (INTEGER)
- `integrity_score` (INTEGER)

### 3. `events` Table
Audit trail of every detected integrity change.
- `id` (INTEGER, Primary Key)
- `filepath` (TEXT)
- `filename` (TEXT)
- `event_type` (TEXT: `MODIFIED`, `NEW`, `DELETED`)
- `old_hash` (TEXT)
- `new_hash` (TEXT)
- `timestamp` (TEXT)

---

## 🔒 Security Considerations

- **Read-Only Inspection**: Monitored files are opened strictly in read-only binary mode (`rb`). The application never alters monitored assets.
- **Path Traversal Protection**: Relative paths are normalized using forward slashes and resolved against the protected root.
- **Resource Safety**: File reads use 64 KB streaming chunks and enforce a 50 MB file size limit to prevent memory exhaustion (DoS).
- **SQL Injection Prevention**: All database interactions use parameter placeholders (`?`).
- **XSS & Template Safety**: Jinja2 autoescaping is active on all dynamic user inputs.
- **No Arbitrary Execution**: Zero usage of `eval()`, `exec()`, or `shell=True`.

---

## 🧪 Automated Testing

HashVault includes a comprehensive test suite of 31 automated tests covering unit logic and end-to-end routes.

Run all tests via `unittest`:
```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Or via `pytest`:
```bash
pytest -v
```

---

## ⚠️ Disclaimer

HashVault is a defensive cybersecurity and file integrity monitoring system designed for security assessment, monitoring, and educational purposes. A cryptographic file modification indicates that file contents have changed relative to the baseline; it does not automatically denote malicious intent or malware infection.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
