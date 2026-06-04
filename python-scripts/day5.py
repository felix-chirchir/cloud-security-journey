# Day 5 - Felix Chirchir
# File handling and JSON for cloud security

import json
import os
from datetime import datetime

# ============================================
# FUNCTION 1 - Save findings to JSON file
# ============================================
def save_findings(findings, filename):
    with open(filename, "w") as f:
        json.dump(findings, f, indent=4)
    print(f"Findings saved to (filename)")

# ============================================
# FUNCTION 2 - Load findings from JSON file
# ============================================
def load_findings(filename):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            findings = json.load(f)
        print(f"Loaded {len(findings)} findings from {filename}")
        return findings
    else:
        print(f"File {filename} not found")
        return []

# ============================================
# FUNCTION # - Generate audit report
# ============================================
def generate_report(findings, output_file):
    critical = [f for f in findings if f["severity"] == "CRITICAL"]
    high = [f for f in findings if f["severity"] == "HIGH"]
    medium = [f for f in findings if f["severity"] == "MEDIUM"]

    with open(output_file, "w") as f:
        f.write("=" * 60 + "\n")
        f.write("CLOUD SECURITY AUDIT REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%H:%M:%S')}\n")
        f.write("Auditor: Felix Chirchir\n")
        f.write("=" * 60 + "\n\n")

        f.write(f"SUMMARY\n")
        f.write(f"Total findings: {len(findings)}\n")
        f.write(f"Critical: {len(critical)}\n")
        f.write(f"High: {len(high)}\n")
        f.write(f"Medium: {len(medium)}\n\n")

        f.write("DETAILED FINDINGS\n")
        f.write("-" * 40 + "\n")

        for i, finding in enumerate(findings, 1):
            f.write(f"\nFinding {i}:\n")
            f.write(f"  Title:  {finding['title']}\n")
            f.write(f"  Severity:   {finding['severity']}\n")
            f.write(f"  Description:    {finding['description']}\n")
            f.write(f"  Fixed:  {finding['fixed']}\n")

        f.write("\n" + "=" * 60 + "\n")
        f.write("END OF REPORT\n")
    print(f"Report saved to {output_file}")

# ============================================
# MAIN PROGRAM
# ============================================
print("=" * 50)
print("SECURITY AUDIT SYSTEM")
print("Felix Chirchir - Cloud Security Journey")
print("=" * 50)

# Create findings data
findings = [
    {
        "title": "Public S3 Bucket",
        "severity": "CRITICAL",
        "description": "Customer data bucket is publicly accessible",
        "fixed": False
    },
    {
        "title": "No MFA on Root Account",
        "severity": "CRITICAL",
        "description": "Root account has no MFA enabled",
        "fixed": False
    },
    {"title": "Weak IAM Password Policy",
     "severity": "HIGH",
     "description": "Minimum password length is only 6 characters",
     "fixed": False
     },
     {
         "title": "CloudTrail NOt enabled",
         "severity": "HIGH",
         "description": "No audit logging in af-south-1 region",
         "fixed": True
     },
     {
         "title": "Old Access Keys",
         "severity": "MEDIUM",
         "description": "IAM user has access keys older than 90 days",
         "fixed": False
     }
]

# Save findings to JSON file
save_findings(findings, "findings.json")

# Load them back
loaded = load_findings("findings.json")

# Generate proffesional report
generate_report(loaded, "audit_report.txt")

# show the JSON file content
print("\n=== RAW JSON FILE ===")
with open("findings.json", "r") as f:
          print(f.read())

# Show the report
print("\n=== AUDIT REPORT ===")
with open("audit_report.txt", "r") as f:
          print(f.read())