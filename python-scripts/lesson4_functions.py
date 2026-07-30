# lesson4_functions.py
# Felix Chirchir
# Functions — reusable code blocks in Python

print("=" * 45)
print("LESSON 4 — FUNCTIONS")
print("=" * 45)

# ===========================
# BASIC FUNCTION
# ===========================

def welcome():
    """Prints a welcome message."""
    print("\nWelcome to Felix Security Scanner")
    print("Version 1.0")
    print("=" * 35)

welcome()

# ===========================
# FUNCTION WITH PARAMETERS
# ===========================

def greet_user(name, role):
    """Greets a user with their name and role."""
    print(f"\nHello {name}!")
    print(f"Your role: {role}")

greet_user("Felix Chirchir", "Cloud Security Engineer")
greet_user("John Doe", "System Administrator")

# ===========================
# FUNCTION WITH RETURN VALUE
# ===========================

def calculate_risk_score(critical, high, medium, low):
    """
    Calculates total risk score.
    
    Each severity has a weight:
    Critical = 10 points
    High     = 5 points
    Medium   = 2 points
    Low      = 1 point
    """
    score = (critical * 10) + (high * 5) + (medium * 2) + (low * 1)
    return score

score = calculate_risk_score(2, 3, 1, 2)
print(f"\nRisk Score: {score}")

# ===========================
# FUNCTION RETURNING MULTIPLE VALUES
# ===========================

def get_risk_level(score):
    """Returns risk level and recommended action based on score."""
    if score >= 50:
        level = "CRITICAL"
        action = "Stop all deployments. Fix immediately."
    elif score >= 30:
        level = "HIGH"
        action = "Fix within 24 hours."
    elif score >= 15:
        level = "MEDIUM"
        action = "Fix within 1 week."
    else:
        level = "LOW"
        action = "Fix at next maintenance window."
    
    return level, action

level, action = get_risk_level(score)
print(f"Risk Level: {level}")
print(f"Action: {action}")

# ===========================
# DEFAULT PARAMETERS
# ===========================

def check_port(ip, port=80, protocol="TCP"):
    """Checks if a port is in the dangerous list."""
    dangerous = [22, 23, 3306, 3389, 5432]
    
    if port in dangerous:
        status = "DANGEROUS"
    else:
        status = "SAFE"
    
    print(f"{protocol} {ip}:{port} — {status}")

print("\n--- PORT CHECKER ---")
check_port("192.168.1.1")
check_port("192.168.1.1", 22)
check_port("192.168.1.1", 443)
check_port("192.168.1.1", 3306, "TCP")

# ===========================
# FUNCTIONS CALLING FUNCTIONS
# ===========================

def print_finding(title, severity, description):
    """Prints a formatted security finding."""
    print(f"\n  [{severity}] {title}")
    print(f"  Description: {description}")

def run_security_audit(findings):
    """
    Runs a full security audit.
    Takes a list of findings and processes each one.
    """
    print("\n" + "=" * 45)
    print("SECURITY AUDIT REPORT")
    print("=" * 45)
    
    critical = 0
    high = 0
    total_score = 0
    
    for finding in findings:
        print_finding(
            finding["title"],
            finding["severity"],
            finding["description"]
        )
        total_score += finding["score"]
        
        if finding["severity"] == "CRITICAL":
            critical += 1
        elif finding["severity"] == "HIGH":
            high += 1
    
    print("\n--- SUMMARY ---")
    print(f"Total findings: {len(findings)}")
    print(f"Critical: {critical}")
    print(f"High: {high}")
    
    score = calculate_risk_score(critical, high, 0, 0)
    level, action = get_risk_level(score)
    
    print(f"Risk Score: {score}")
    print(f"Risk Level: {level}")
    print(f"Action: {action}")

# ===========================
# RUN THE AUDIT
# ===========================

my_findings = [
    {
        "title": "Missing MFA on root account",
        "severity": "CRITICAL",
        "description": "Root account has no multi-factor authentication",
        "score": 10
    },
    {
        "title": "Open S3 Bucket",
        "severity": "CRITICAL",
        "description": "Customer data is publicly accessible",
        "score": 10
    },
    {
        "title": "Weak Password Policy",
        "severity": "HIGH",
        "description": "Minimum password length is only 6 characters",
        "score": 5
    },
    {
        "title": "SSH open to internet",
        "severity": "HIGH",
        "description": "Port 22 accessible from 0.0.0.0/0",
        "score": 5
    }
]

run_security_audit(my_findings)