# Day 7 - Felix Chirchir
# PostgreSQL with Python - Security Findings Database

import psycopg2
import json
from datetime import datetime

# ============================================
# DATABASE CONNECTION
# ============================================
def connect():
    conn = psycopg2.connect(
        host="localhost",
        database="security_db",
        user="felix",
        password="felix1234"
    )
    return conn

# ============================================
# FUNCTION 1 - Create tables
# ============================================
def create_tables():
    conn = connect()
    cur = conn.cursor()

    # Create scans table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target_url VARCHAR(500) NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            total_findings INTEGER,
            passed_checks INTEGER,
            status VARCHAR(50)
        )
    """)

    # Create findings table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(id),
            title VARCHAR(500) NOT NULL,
            severity VARCHAR(50),
            description TEXT,
            risk TEXT,
            fixed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Tables created successfully")

# ============================================
# FUNCTION 2 - Save scan to database
# ============================================
def save_scan(target_url, total_findings, passed_checks):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (target_url, total_findings, passed_checks, status)
        VALUES (%s, %s, %s, %s)
        RETURNING id
    """, (target_url, total_findings, passed_checks, "completed"))

    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()

    return scan_id

# ============================================
# FUNCTION 3 - Save finding to database
# ============================================
def save_finding(scan_id, title, severity, description, risk):
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO findings (scan_id, title, severity, description, risk)
        VALUES (%s, %s, %s, %s, %s)
    """, (scan_id, title, severity, description, risk))

    conn.commit()
    cur.close()
    conn.close()

# ============================================
# FUNCTION 4 - Get all critical findings
# ============================================
def get_critical_findings():
    conn = connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT f.title, f.severity, f.description, s.target_url, s.scan_date
        FROM findings f
        JOIN scans s ON f.scan_id = s.id
        WHERE f.severity = 'CRITICAL' OR f.severity = 'HIGH'
        ORDER BY s.scan_date DESC
    """)

    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

# ============================================
# FUNCTION 5 - Get scan summary
# ============================================
def get_summary():
    conn = connect()
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM scans")
    total_scans = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM findings")
    total_findings = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL'")
    critical = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM findings WHERE severity = 'HIGH'")
    high = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "critical": critical,
        "high": high
    }

# ============================================
# MAIN PROGRAM
# ============================================
print("=" * 60)
print("SECURITY DATABASE SYSTEM")
print("Felix Chirchir - Cloud Security Journey")
print("=" * 60)

# Create tables
print("\nSetting up database...")
create_tables()

# Sample scan data from Day 6 results
scan_data = [
    {
        "url": "https://safaricom.co.ke",
        "findings": [
            {
                "title": "Missing X-Frame-Options",
                "severity": "HIGH",
                "description": "Prevents clickjacking attacks",
                "risk": "Site can be embedded in malicious iframes"
            },
            {
                "title": "Missing Content-Security-Policy",
                "severity": "HIGH",
                "description": "Prevents XSS and injection attacks",
                "risk": "Site vulnerable to cross-site scripting"
            },
            {
                "title": "Missing X-Content-Type-Options",
                "severity": "MEDIUM",
                "description": "Prevents MIME type sniffing",
                "risk": "Browser may misinterpret file types"
            },
            {
                "title": "Missing X-XSS-Protection",
                "severity": "MEDIUM",
                "description": "Enables browser XSS filter",
                "risk": "No browser-level XSS protection"
            },
            {
                "title": "Missing Referrer-Policy",
                "severity": "LOW",
                "description": "Controls referrer information",
                "risk": "Sensitive URLs may leak to third parties"
            }
        ],
        "passed": 1
    },
    {
        "url": "https://google.com",
        "findings": [
            {
                "title": "Missing Strict-Transport-Security",
                "severity": "HIGH",
                "description": "Forces browsers to use HTTPS only",
                "risk": "Attackers can downgrade to HTTP"
            },
            {
                "title": "Missing Content-Security-Policy",
                "severity": "HIGH",
                "description": "Prevents XSS and injection attacks",
                "risk": "Site vulnerable to cross-site scripting"
            },
            {
                "title": "Missing X-Content-Type-Options",
                "severity": "MEDIUM",
                "description": "Prevents MIME type sniffing",
                "risk": "Browser may misinterpret file types"
            },
            {
                "title": "Missing Referrer-Policy",
                "severity": "LOW",
                "description": "Controls referrer information",
                "risk": "Sensitive URLs may leak to third parties"
            }
        ],
        "passed": 2
    }
]

# Save all scans to database
print("\nSaving scan results to database...")
for scan in scan_data:
    scan_id = save_scan(
        scan["url"],
        len(scan["findings"]),
        scan["passed"]
    )
    print(f"Saved scan for {scan['url']} — ID: {scan_id}")

    for finding in scan["findings"]:
        save_finding(
            scan_id,
            finding["title"],
            finding["severity"],
            finding["description"],
            finding["risk"]
        )

print("\nAll findings saved to database")

# Get and display summary
print("\n" + "=" * 60)
print("DATABASE SUMMARY")
print("=" * 60)
summary = get_summary()
print(f"Total scans in database:    {summary['total_scans']}")
print(f"Total findings in database: {summary['total_findings']}")
print(f"Critical findings:          {summary['critical']}")
print(f"High findings:              {summary['high']}")

# Get critical and high findings
print("\n" + "=" * 60)
print("HIGH AND CRITICAL FINDINGS")
print("=" * 60)
critical_findings = get_critical_findings()
for finding in critical_findings:
    title, severity, description, url, scan_date = finding
    print(f"\n[{severity}] {title}")
    print(f"  Site: {url}")
    print(f"  Description: {description}")
    print(f"  Scan date: {scan_date.strftime('%Y-%m-%d %H:%M')}")

print("\n" + "=" * 60)
print("Database operations complete")
print("=" * 60)