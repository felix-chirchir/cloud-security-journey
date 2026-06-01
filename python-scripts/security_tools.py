# Security Tools - Felix Chirchir
# Day 4 - Using variables, lists, dictionaries, loops, functions

# =============================================
# FUNCTION 1 - Calculate risk score
# =============================================
def calculate_risk(critical, high, medium, low):
    score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)

    if score >= 50:
        level = "CRITICAL"
    elif score >= 30:
        level = "HIGH"
    elif score >= 15:
        level = "MEDIUM"
    else:
        level = "LOW"
    
    return score, level

# ============================================
# FUNCTION 2 - Analyze a list of IP addresses
# ============================================
def analyze_ips(ip_list):
    print(f"Analyzing {len(ip_list)} IP addresses...")
    for ip in ip_list:
        if ip.startswith("192.168"):
            print(f" {ip} - Private network IP")
        elif ip.startswith("10."):
            print(f" {ip} - Private network IP")
        else:
            print(" {ip} - Public IP - investigate")

# ============================================
# FUNCTION 3 - Print a security finding
# ============================================
def print_finding(finding):
    print("\n=== SECURITY FINDING ===")
    print(f"Title:  {finding['title']}")
    print(f"Severity:   {finding['severity']}")
    print(f"Description:    {finding['description']}")
    print(f"Fixed:  {finding['fixed']}")
    print("====================")

# ============================================
# MAIN PROGRAM - Run everything
# ============================================
print("=" * 50)
print("SECURITY ASSESSMENT TOOL")
print("Felix Chirchir - Cloud Security Journey")
print("=" * 50)

# Test risk calculator
print("n=== RISK CALCULATOR ===")
score, level = calculate_risk(3, 2, 4, 1)
print(f"Risk Score: {score}")
print(f"Risk Level: {level}")

# Test IP analyzer
print("\n=== IP ANALYSIS ===")
suspicious_ips = [
    "192.168.1.1",
    "10.0.0.5",
    "45.223.28.17",
    "172.16.0.1",
    "8.8.8.8"
]
analyze_ips(suspicious_ips)

# Test findings printer
print("\n=== FINDINGS ===")
findings = [
    {
        "title": "Public S3 Bucket",
        "severity": "CRITICAL",
        "description": "Customer data exposed to internet",
        "fixed": False
    },
    {
        "title": "Weak IAM Password Policy",
        "severity": "HIGH",
        "description": "No MFA required for IAM users",
        "fixed": False
    },
    {
        "title": "CloudTrail Not Enabled",
        "severity": "HIGH",
        "description": "No audit logging in us-east-1 region",
        "fixed": True
     }
]

for finding in findings:
    print_finding(finding)

print("\n" + "=" * 50)
print("Assessment complete")
print("=" * 50)