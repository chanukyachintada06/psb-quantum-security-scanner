"""
Database Layer — Quantum-Proof Systems Scanner
Team CypherRed261 — PSB Hackathon 2026

Handles all MySQL operations:
  - scan_results      : Every TLS scan stored permanently
  - cbom_records      : Cryptographic Bill of Materials (CERT-IN Annexure-A)
  - audit_logs        : System event tracking (SRS Section 5.4)
  - classification_labels : PQC labels issued to assets (FR-17, FR-18)
"""

import mysql.connector
from mysql.connector import Error
from datetime import datetime, date, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

# ── DB CONFIG ──────────────────────────────────────────────────
DB_CONFIG = {
    'host':     os.getenv('DB_HOST', 'localhost'),
    'port':     int(os.getenv('DB_PORT', 3306)),
    'database': os.getenv('DB_NAME', 'quantum_scanner_db'),
    'user':     os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'root123'),
    'autocommit': True
}


def get_connection():
    """Create and return a MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


# ── TABLE CREATION ─────────────────────────────────────────────
def init_db():
    """
    Create all required tables if they don't exist.
    Called once on application startup.
    """
    conn = get_connection()
    cursor = conn.cursor()

    # Table 1 — scan_results
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_results (
            id                  INT AUTO_INCREMENT PRIMARY KEY,
            domain              VARCHAR(253) NOT NULL,
            scan_timestamp      DATETIME NOT NULL,
            tls_version         VARCHAR(20),
            cipher_suite        VARCHAR(150),
            key_exchange        VARCHAR(80),
            public_key_type     VARCHAR(30),
            key_size            VARCHAR(40),
            signature_hash      VARCHAR(80),
            cert_subject        VARCHAR(255),
            cert_issuer         VARCHAR(255),
            cert_valid_from     DATE,
            cert_valid_until    DATE,
            days_remaining      INT,
            is_expired          BOOLEAN DEFAULT FALSE,
            is_expiring_soon    BOOLEAN DEFAULT FALSE,
            risk_level          VARCHAR(10),
            risk_score          INT,
            pqc_readiness       INT,
            quantum_vulnerable  BOOLEAN DEFAULT TRUE,
            scan_duration_ms    INT,
            created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_domain (domain),
            INDEX idx_risk_level (risk_level),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # Table 2 — cbom_records
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cbom_records (
            id                      INT AUTO_INCREMENT PRIMARY KEY,
            scan_id                 INT NOT NULL,
            asset                   VARCHAR(253) NOT NULL,
            key_length              VARCHAR(30),
            cipher_suite            VARCHAR(150),
            tls_version             VARCHAR(20),
            certificate_authority   VARCHAR(150),
            quantum_safe            BOOLEAN DEFAULT FALSE,
            created_at              DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            INDEX idx_asset (asset),
            INDEX idx_quantum_safe (quantum_safe)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # Table 3 — audit_logs (SRS Section 5.4)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            event_type  VARCHAR(50) NOT NULL,
            domain      VARCHAR(253),
            user_ip     VARCHAR(45),
            description TEXT,
            created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_event_type (event_type),
            INDEX idx_created_at (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    # Table 4 — classification_labels (FR-17, FR-18)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS classification_labels (
            id          INT AUTO_INCREMENT PRIMARY KEY,
            scan_id     INT NOT NULL,
            domain      VARCHAR(253) NOT NULL,
            label       VARCHAR(30) NOT NULL,
            issued_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
            valid_until DATE,
            FOREIGN KEY (scan_id) REFERENCES scan_results(id) ON DELETE CASCADE,
            INDEX idx_domain (domain),
            INDEX idx_label (label)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """)

    cursor.close()
    conn.close()
    print("  ✅ Database tables initialized successfully.")


# ── SAVE SCAN RESULT ───────────────────────────────────────────
def save_scan_result(scan_data: dict) -> int:
    """
    Save a complete scan result to the database.

    Args:
        scan_data: The full scan result dict returned by scanner.py

    Returns:
        The auto-generated scan ID (used to link CBOM and label records)
    """
    conn = get_connection()
    cursor = conn.cursor()

    tls = scan_data.get('tls', {})
    cert = scan_data.get('certificate', {})
    pqc = scan_data.get('pqc', {})

    # Parse dates safely
    def parse_date(date_str):
        if not date_str or date_str == 'Unknown':
            return None
        try:
            return datetime.strptime(date_str, '%Y-%m-%d').date()
        except Exception:
            return None

    # Parse scan_timestamp
    try:
        ts = datetime.fromisoformat(
            scan_data.get('scan_timestamp', '').replace('Z', '+00:00')
        ).replace(tzinfo=None)
    except Exception:
        ts = datetime.now()

    sql = """
        INSERT INTO scan_results (
            domain, scan_timestamp,
            tls_version, cipher_suite, key_exchange,
            public_key_type, key_size, signature_hash,
            cert_subject, cert_issuer, cert_valid_from, cert_valid_until,
            days_remaining, is_expired, is_expiring_soon,
            risk_level, risk_score, pqc_readiness, quantum_vulnerable,
            scan_duration_ms
        ) VALUES (
            %s, %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s, %s, %s,
            %s, %s, %s, %s, %s
        )
    """
    values = (
        scan_data.get('domain'),
        ts,
        tls.get('version'),
        tls.get('cipher_suite'),
        tls.get('key_exchange'),
        tls.get('public_key_type'),
        tls.get('key_size'),
        tls.get('signature_hash'),
        cert.get('subject'),
        cert.get('issuer'),
        parse_date(cert.get('valid_from')),
        parse_date(cert.get('valid_until')),
        cert.get('days_remaining', 0),
        cert.get('is_expired', False),
        cert.get('is_expiring_soon', False),
        pqc.get('risk_level'),
        pqc.get('risk_score', 0),
        pqc.get('pqc_readiness', 0),
        pqc.get('quantum_vulnerable', True),
        scan_data.get('scan_duration_ms', 0)
    )

    cursor.execute(sql, values)
    scan_id = cursor.lastrowid

    cursor.close()
    conn.close()
    return scan_id


# ── SAVE CBOM RECORD ───────────────────────────────────────────
def save_cbom_record(scan_id: int, cbom_data: dict):
    """Save a CBOM entry linked to a scan result."""
    conn = get_connection()
    cursor = conn.cursor()

    sql = """
        INSERT INTO cbom_records (
            scan_id, asset, key_length, cipher_suite,
            tls_version, certificate_authority, quantum_safe
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """
    values = (
        scan_id,
        cbom_data.get('asset'),
        cbom_data.get('key_length'),
        cbom_data.get('cipher_suite'),
        cbom_data.get('tls_version'),
        cbom_data.get('certificate_authority'),
        cbom_data.get('quantum_safe', False)
    )

    cursor.execute(sql, values)
    cursor.close()
    conn.close()


# ── SAVE CLASSIFICATION LABEL ─────────────────────────────────
def save_classification_label(scan_id: int, domain: str, risk_level: str):
    """
    Issue and save a PQC classification label (FR-17, FR-18).

    Label mapping:
      LOW risk     → 'PQC Ready'
      MEDIUM risk  → 'Not Quantum Safe'
      HIGH risk    → 'Not Quantum Safe'
      CRITICAL     → 'Not Quantum Safe'
    """
    label_map = {
        'LOW':      'PQC Ready',
        'MEDIUM':   'Not Quantum Safe',
        'HIGH':     'Not Quantum Safe',
        'CRITICAL': 'Not Quantum Safe'
    }
    label = label_map.get(risk_level, 'Not Quantum Safe')
    valid_until = (datetime.now() + timedelta(days=365)).date()

    conn = get_connection()
    cursor = conn.cursor()

    sql = """
        INSERT INTO classification_labels (scan_id, domain, label, valid_until)
        VALUES (%s, %s, %s, %s)
    """
    cursor.execute(sql, (scan_id, domain, label, valid_until))
    cursor.close()
    conn.close()


# ── SAVE AUDIT LOG ─────────────────────────────────────────────
def save_audit_log(event_type: str, domain: str = None,
                   user_ip: str = None, description: str = None):
    """
    Save an audit log entry (SRS Section 5.4).

    Event types: SCAN_INITIATED, SCAN_COMPLETED, SCAN_FAILED,
                 REPORT_GENERATED, LABEL_ISSUED
    """
    conn = get_connection()
    cursor = conn.cursor()

    sql = """
        INSERT INTO audit_logs (event_type, domain, user_ip, description)
        VALUES (%s, %s, %s, %s)
    """
    cursor.execute(sql, (event_type, domain, user_ip, description))
    cursor.close()
    conn.close()


# ── QUERY: RECENT SCANS ────────────────────────────────────────
def get_recent_scans(limit: int = 20) -> list:
    """Get the most recent scan results."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT id, domain, scan_timestamp, tls_version,
               risk_level, risk_score, pqc_readiness, scan_duration_ms
        FROM scan_results
        ORDER BY created_at DESC
        LIMIT %s
    """, (limit,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results


# ── QUERY: SCAN BY DOMAIN ──────────────────────────────────────
def get_scans_by_domain(domain: str) -> list:
    """Get all scans for a specific domain."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM scan_results
        WHERE domain = %s
        ORDER BY created_at DESC
    """, (domain,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results


# ── QUERY: CBOM RECORDS ────────────────────────────────────────
def get_cbom_records(limit: int = 50) -> list:
    """Get recent CBOM records."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT c.*, s.scan_timestamp, s.risk_level
        FROM cbom_records c
        JOIN scan_results s ON c.scan_id = s.id
        ORDER BY c.created_at DESC
        LIMIT %s
    """, (limit,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results


# ── QUERY: AUDIT LOGS ──────────────────────────────────────────
def get_audit_logs(limit: int = 50) -> list:
    """Get recent audit log entries."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT * FROM audit_logs
        ORDER BY created_at DESC
        LIMIT %s
    """, (limit,))

    results = cursor.fetchall()
    cursor.close()
    conn.close()
    return results


# ── QUERY: DASHBOARD STATS ─────────────────────────────────────
def get_dashboard_stats() -> dict:
    """Get aggregated stats for the dashboard."""
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("""
        SELECT
            COUNT(*) as total_scans,
            COUNT(DISTINCT domain) as unique_domains,
            SUM(CASE WHEN risk_level = 'CRITICAL' THEN 1 ELSE 0 END) as critical_count,
            SUM(CASE WHEN risk_level = 'HIGH' THEN 1 ELSE 0 END) as high_count,
            SUM(CASE WHEN risk_level = 'MEDIUM' THEN 1 ELSE 0 END) as medium_count,
            SUM(CASE WHEN risk_level = 'LOW' THEN 1 ELSE 0 END) as low_count,
            AVG(pqc_readiness) as avg_pqc_readiness,
            SUM(CASE WHEN quantum_vulnerable = TRUE THEN 1 ELSE 0 END) as vulnerable_count
        FROM scan_results
    """)

    stats = cursor.fetchone()
    cursor.close()
    conn.close()
    return stats or {}


# ── TEST CONNECTION ────────────────────────────────────────────
def test_connection() -> bool:
    """Test if DB connection works. Returns True if successful."""
    try:
        conn = get_connection()
        conn.close()
        return True
    except Error as e:
        print(f"  ❌ Database connection failed: {e}")
        return False
