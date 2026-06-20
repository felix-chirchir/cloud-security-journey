# security_scanner.py - Felix Chirchir
# Professional Security Scanner - Phase 1 Capstone Project
# Combines: HTTP scanning, PostgreSQL storage, JSON export, reporting

import requests
import psycopg2
import json
import os
from datetime import datetime
from config import DB_CONFIG, SECURITY_HEADERS, SEVERITY_SCORES, RISK_LEVELS

# ============================================
# LAYER 1 - DATABASE FUNCTIONS
# Everything related to storing data
# ============================================

def db_connect():
    """
    Creates and returns a database connection.
    Called every time we need to talk to the database.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    return conn

def db_setup():
    """
    Creates all database tables if they don't exist.
    Safe to run multiple times - IF NOT EXISTS prevents duplicates.
    """
    conn = db_connect()
    cur = conn.cursor()

    # Scans table - one row per website scanned
    cur.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY,
            target_url VARCHAR(500) NOT NULL,
            scan_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status_code INTEGER,
            server VARCHAR(200),
            total_findings INTEGER DEFAULT 0,
            passed_checks INTEGER DEFAULT 0,
            risk_score INTEGER DEFAULT 0,
            risk_level VARCHAR(50),
            scan_duration FLOAT
        )
    """)

    # Findings table - one row per security issue found
    cur.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id SERIAL PRIMARY KEY,
            scan_id INTEGER REFERENCES scans(id) ON DELETE CASCADE,
            title VARCHAR(500) NOT NULL,
            severity VARCHAR(50),
            description TEXT,
            risk TEXT,
            recommendation TEXT,
            fixed BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    cur.close()
    conn.close()
    print("Database ready")

def db_save_scan(target_url, status_code, server,
                 total_findings, passed_checks,
                 risk_score, risk_level, duration):
    """
    Saves a completed scan to the database.
    Returns the scan ID so we can link findings to it.
    """
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO scans (
            target_url, status_code, server,
            total_findings, passed_checks,
            risk_score, risk_level, scan_duration
        )
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING id
    """, (target_url, status_code, server,
          total_findings, passed_checks,
          risk_score, risk_level, duration))

    scan_id = cur.fetchone()[0]
    conn.commit()
    cur.close()
    conn.close()
    return scan_id

def db_save_finding(scan_id, title, severity,
                    description, risk, recommendation):
    """
    Saves one security finding linked to a scan.
    scan_id connects this finding to the correct scan.
    """
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO findings (
            scan_id, title, severity,
            description, risk, recommendation
        )
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (scan_id, title, severity,
          description, risk, recommendation))

    conn.commit()
    cur.close()
    conn.close()

def db_get_all_scans():
    """
    Retrieves all scans from database ordered by date.
    Used for the summary report.
    """
    conn = db_connect()
    cur = conn.cursor()

    cur.execute("""
        SELECT target_url, scan_date, status_code,
               total_findings, risk_score, risk_level
        FROM scans
        ORDER BY scan_date DESC
    """)

    results = cur.fetchall()
    cur.close()
    conn.close()
    return results

# ============================================
# LAYER 2 - SCANNER FUNCTIONS
# The actual security checking logic
# ============================================

def calculate_risk_score(findings):
    """
    Calculates total risk score from a list of findings.
    Uses SEVERITY_SCORES from config.py.
    Higher score = more dangerous.
    """
    score = 0
    for finding in findings:
        severity = finding["severity"]
        score += SEVERITY_SCORES.get(severity, 0)
    return score

def get_risk_level(score):
    """
    Converts a numeric score to a risk level label.
    Uses RISK_LEVELS thresholds from config.py.
    """
    for threshold in sorted(RISK_LEVELS.keys(), reverse=True):
        if score >= threshold:
            return RISK_LEVELS[threshold]
    return "LOW"

def scan_url(url):
    """
    Main scanning function. Takes a URL and:
    1. Sends HTTP GET request
    2. Reads response headers
    3. Checks for missing security headers
    4. Calculates risk score
    5. Returns structured results

    This is the heart of the scanner.
    """
    print(f"\n{'='*60}")
    print(f"Scanning: {url}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # Record start time for duration calculation
    start_time = datetime.now()

    try:
        # Send HTTP request with custom headers
        headers = {"User-Agent": "Felix-Security-Scanner/1.0"}
        response = requests.get(
            url,
            timeout=10,
            headers=headers,
            allow_redirects=True
        )

        # Calculate how long the scan took
        duration = (datetime.now() - start_time).total_seconds()

        # Extract basic information
        status_code = response.status_code
        server = response.headers.get("Server", "Not disclosed")

        print(f"Status: {status_code}")
        print(f"Server: {server}")
        print(f"Response time: {duration:.2f}s")
        print(f"\nChecking {len(SECURITY_HEADERS)} security headers...")

        findings = []
        passed = []

        # Check each security header
        for header_name, header_info in SECURITY_HEADERS.items():
            if header_name in response.headers:
                # Header is present - good
                passed.append(header_name)
                print(f"  PASS [{header_name}]")
            else:
                # Header is missing - security finding
                finding = {
                    "title": f"Missing {header_name}",
                    "severity": header_info["severity"],
                    "description": header_info["description"],
                    "risk": header_info["risk"],
                    "recommendation": header_info["recommendation"]
                }
                findings.append(finding)
                print(f"  FAIL [{header_info['severity']}] {header_name}")
                print(f"       Risk: {header_info['risk']}")

        # Calculate risk score and level
        risk_score = calculate_risk_score(findings)
        risk_level = get_risk_level(risk_score)

        print(f"\nResults:")
        print(f"  Passed: {len(passed)}/{len(SECURITY_HEADERS)} headers")
        print(f"  Findings: {len(findings)}")
        print(f"  Risk Score: {risk_score}")
        print(f"  Risk Level: {risk_level}")

        return {
            "url": url,
            "status_code": status_code,
            "server": server,
            "duration": duration,
            "passed": passed,
            "findings": findings,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "success": True
        }

    except requests.exceptions.ConnectionError:
        print(f"ERROR: Cannot connect to {url}")
        return {"url": url, "success": False, "error": "Connection failed"}

    except requests.exceptions.Timeout:
        print(f"ERROR: Connection timed out for {url}")
        return {"url": url, "success": False, "error": "Timeout"}

    except Exception as e:
        print(f"ERROR: {str(e)}")
        return {"url": url, "success": False, "error": str(e)}

# ============================================
# LAYER 3 - REPORTING FUNCTIONS
# Formatting results for humans
# ============================================

def generate_text_report(all_results, output_file):
    """
    Generates a professional text report from all scan results.
    This is what you send to clients.
    """
    with open(output_file, "w") as f:

        # Header section
        f.write("=" * 70 + "\n")
        f.write("PROFESSIONAL SECURITY ASSESSMENT REPORT\n")
        f.write("=" * 70 + "\n")
        f.write(f"Report Date:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Auditor:        Felix Chirchir\n")
        f.write(f"Tool:           Felix Security Scanner v1.0\n")
        f.write(f"Targets:        {len(all_results)} sites scanned\n")
        f.write("=" * 70 + "\n\n")

        # Executive summary
        total_findings = sum(len(r["findings"])
                            for r in all_results if r["success"])
        critical_sites = [r for r in all_results
                         if r.get("success") and r["risk_level"] in
                         ["CRITICAL", "HIGH"]]

        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total sites scanned:          {len(all_results)}\n")
        f.write(f"Total security findings:      {total_findings}\n")
        f.write(f"Sites requiring urgent action: {len(critical_sites)}\n\n")

        if critical_sites:
            f.write("Sites needing immediate attention:\n")
            for site in critical_sites:
                f.write(f"  - {site['url']} "
                       f"(Risk Level: {site['risk_level']}, "
                       f"Score: {site['risk_score']})\n")
        f.write("\n")

        # Detailed findings per site
        f.write("DETAILED FINDINGS\n")
        f.write("=" * 70 + "\n")

        for i, result in enumerate(all_results, 1):
            if not result["success"]:
                f.write(f"\nSite {i}: {result['url']}\n")
                f.write(f"Status: SCAN FAILED - {result.get('error')}\n")
                continue

            f.write(f"\nSite {i}: {result['url']}\n")
            f.write("-" * 50 + "\n")
            f.write(f"HTTP Status:    {result['status_code']}\n")
            f.write(f"Server:         {result['server']}\n")
            f.write(f"Scan Duration:  {result['duration']:.2f}s\n")
            f.write(f"Risk Score:     {result['risk_score']}\n")
            f.write(f"Risk Level:     {result['risk_level']}\n")
            f.write(f"Headers Passed: "
                   f"{len(result['passed'])}/{len(SECURITY_HEADERS)}\n\n")

            if result["findings"]:
                f.write("Security Findings:\n")
                for j, finding in enumerate(result["findings"], 1):
                    f.write(f"\n  Finding {j}:\n")
                    f.write(f"  Title:          {finding['title']}\n")
                    f.write(f"  Severity:       {finding['severity']}\n")
                    f.write(f"  Description:    {finding['description']}\n")
                    f.write(f"  Risk:           {finding['risk']}\n")
                    f.write(f"  Recommendation: {finding['recommendation']}\n")
            else:
                f.write("No security findings — all headers present.\n")

            f.write("\n")

        # Footer
        f.write("=" * 70 + "\n")
        f.write("END OF REPORT\n")
        f.write(f"Generated by Felix Security Scanner\n")
        f.write("=" * 70 + "\n")

    print(f"\nReport saved to: {output_file}")

def generate_json_export(all_results, output_file):
    """
    Exports all results as JSON.
    Used for feeding results into other tools
    or storing in external systems.
    """
    export_data = {
        "scan_date": datetime.now().isoformat(),
        "auditor": "Felix Chirchir",
        "total_sites": len(all_results),
        "results": all_results
    }

    with open(output_file, "w") as f:
        json.dump(export_data, f, indent=4)

    print(f"JSON export saved to: {output_file}")

def print_final_summary(all_results):
    """
    Prints a clean summary to the terminal
    after all scans are complete.
    """
    print("\n" + "=" * 60)
    print("SCAN COMPLETE — FINAL SUMMARY")
    print("=" * 60)

    successful = [r for r in all_results if r.get("success")]
    failed = [r for r in all_results if not r.get("success")]

    print(f"Sites scanned:     {len(all_results)}")
    print(f"Successful scans:  {len(successful)}")
    print(f"Failed scans:      {len(failed)}")

    if successful:
        total_findings = sum(len(r["findings"]) for r in successful)
        avg_score = sum(r["risk_score"] for r in successful) / len(successful)

        print(f"Total findings:    {total_findings}")
        print(f"Average risk score: {avg_score:.1f}")

        print("\nRisk breakdown by site:")
        for result in successful:
            print(f"  {result['url']}")
            print(f"    Risk Level: {result['risk_level']} "
                  f"(Score: {result['risk_score']}, "
                  f"Findings: {len(result['findings'])})")

    print("=" * 60)

# ============================================
# LAYER 4 - MAIN CONTROLLER
# Coordinates everything
# ============================================

def main():
    """
    Main function - the entry point of the scanner.
    Controls the order of operations:
    1. Setup database
    2. Run scans
    3. Save to database
    4. Generate reports
    5. Print summary
    """
    print("=" * 60)
    print("FELIX SECURITY SCANNER v1.0")
    print("Professional HTTP Security Assessment Tool")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Step 1 - Setup database
    print("\nInitializing database...")
    db_setup()

    # Step 2 - Define targets
    targets = [
        "https://httpbin.org",
        "https://safaricom.co.ke",
        "https://google.com",
        "https://equity.co.ke"
    ]

    print(f"\nTargets to scan: {len(targets)}")
    for target in targets:
        print(f"  - {target}")

    # Step 3 - Run scans
    all_results = []
    for target in targets:
        result = scan_url(target)
        all_results.append(result)

        # Step 4 - Save each result to database immediately
        if result["success"]:
            scan_id = db_save_scan(
                result["url"],
                result["status_code"],
                result["server"],
                len(result["findings"]),
                len(result["passed"]),
                result["risk_score"],
                result["risk_level"],
                result["duration"]
            )

            for finding in result["findings"]:
                db_save_finding(
                    scan_id,
                    finding["title"],
                    finding["severity"],
                    finding["description"],
                    finding["risk"],
                    finding["recommendation"]
                )

            print(f"Saved to database — Scan ID: {scan_id}")

    # Step 5 - Generate reports
    print("\nGenerating reports...")
    report_file = f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    json_file = f"scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

    generate_text_report(all_results, report_file)
    generate_json_export(all_results, json_file)

    # Step 6 - Print final summary
    print_final_summary(all_results)

    print(f"\nAll done. Check your files:")
    print(f"  Report: {report_file}")
    print(f"  JSON:   {json_file}")

# ============================================
# Entry point
# This runs main() when you execute the script
# ============================================
if __name__ == "__main__":
    main()