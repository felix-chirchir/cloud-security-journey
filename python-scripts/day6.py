# Day 6 - Felix Chirchir
# HTTP Security Header Checker
# Checks websites for missing security headers

import requests
import json
from datetime import datetime

# ============================================
# Security headers we check for
# ============================================
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Forces browsers to use HTTPS only",
        "risk": "Without this, attackers can downgrade to HTTP"
    },
    "X-Frame-Options": {
        "severity": "HIGH",
        "description": "Prevents clickjacking attacks",
        "risk": "Site can be embedded in malicious iframes"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME type sniffing",
        "risk": "Browser may misinterpret file types"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Prevents XSS and injection attacks",
        "risk": "Site vulnerable to cross-site scripting"
    },
    "X-XSS-Protection": {
        "severity": "MEDIUM",
        "description": "Enables browser XSS filter",
        "risk": "No browser-level XSS protection"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls referrer information",
        "risk": "Sensitive URLs may leak to third parties"
    }
}

# ============================================
# FUNCTION 1 - Check security headers
# ============================================
def check_security_headers(url):
    print(f"\nChecking: {url}")
    print("-" * 50)

    try:
        response = requests.get(url, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Server: {response.headers.get('Server', 'Not disclosed')}")

        findings = []
        passed = []

        for header, info in SECURITY_HEADERS.items():
            if header in response.headers:
                passed.append(header)
                print(f"  PASS - {header}")
            else:
                findings.append({
                    "title": f"Missing {header}",
                    "severity": info["severity"],
                    "description": info["description"],
                    "risk": info["risk"],
                    "fixed": False
                })
                print(f"  FAIL - {header} — {info['severity']}")

        return {
            "url": url,
            "status_code": response.status_code,
            "server": response.headers.get("Server", "Not disclosed"),
            "passed": len(passed),
            "failed": len(findings),
            "findings": findings
        }

    except requests.exceptions.ConnectionError:
        print(f"ERROR — Cannot connect to {url}")
        return None
    except requests.exceptions.Timeout:
        print(f"ERROR — Connection timed out for {url}")
        return None

# ============================================
# FUNCTION 2 - Generate report
# ============================================
def generate_report(results):
    print("\n" + "=" * 60)
    print("SECURITY HEADER AUDIT REPORT")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Auditor: Felix Chirchir")
    print("=" * 60)

    total_findings = 0
    critical_sites = []

    for result in results:
        if result is None:
            continue

        print(f"\nSite: {result['url']}")
        print(f"Passed: {result['passed']}/{result['passed'] + result['failed']} headers")
        print(f"Findings: {result['failed']}")

        total_findings += result["failed"]

        if result["failed"] >= 3:
            critical_sites.append(result["url"])

        if result["findings"]:
            print("Issues found:")
            for f in result["findings"]:
                print(f"  [{f['severity']}] {f['title']}")
                print(f"    Risk: {f['risk']}")

    print("\n" + "=" * 60)
    print("SUMMARY")
    print(f"Sites scanned: {len(results)}")
    print(f"Total findings: {total_findings}")
    print(f"Sites needing urgent attention: {len(critical_sites)}")
    if critical_sites:
        for site in critical_sites:
            print(f"  - {site}")
    print("=" * 60)

    return total_findings

# ============================================
# MAIN PROGRAM
# ============================================
print("=" * 60)
print("HTTP SECURITY HEADER CHECKER")
print("Felix Chirchir - Cloud Security Journey")
print("=" * 60)

# List of sites to check
targets = [
    "https://httpbin.org",
    "https://safaricom.co.ke",
    "https://google.com"
]

# Check each site
results = []
for target in targets:
    result = check_security_headers(target)
    results.append(result)

# Generate report
total = generate_report(results)

# Save results to JSON
with open("header_scan_results.json", "w") as f:
    json.dump(results, f, indent=4, default=str)
print(f"\nResults saved to header_scan_results.json")