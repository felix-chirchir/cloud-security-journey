# lessons3_loops.py
# Felix Chirchir
# Loops - repeating code in Python

print("=" * 45)
print("LESSON3 - LOOPS")
print("=" * 45)

# ====================================
# BASIC for LOOP
# ====================================
print("\n---- BASIC for LOOP ---")

for i in range(1, 6):
    print(f"Day {i} of learning python")

# ====================================
# LOOP OVER LIST
# ====================================
print("\n--- PORT SECURITY SCAN ---")

ports = [80, 443, 22, 8080, 3306, 3389]
dangerous_ports = [22, 23, 3306, 3389, 3389, 5432, 6379]

for port in ports:
    if port in dangerous_ports:
        print(f" DANGER: Port {port} is dangerous and open")
    else:
        print(f" SAFE: Port {port} is open and safe")

# ====================================
# COUNTING IN LOOP
# ====================================
print("\n--- COUNTING FINDINGS")

findings = ["Missing MFA", "Open S3 Bucket", "Weak Password",
            "No Encription", "Old Access Keys"]

total = 0
for finding in findings:
    total += 1
    print(f" Findings {total}: {findings}")

print(f"\nTotal findings: {total}")

# ====================================
# break AND continue
# ====================================
print("\n--- WHILE LOOP ---")
print("Counting down to deployment:")

countdown = 5
while countdown > 0:
    print(f" {countdown} ....")
    countdown -= 1
print(" Deployed!")

# ====================================
# PRACTICAL - RISK CALCULATOR
# ====================================
print("\n--- RISK CALCULATOR ---")

security_findings = [
    {"title": "Missing MFA", "severity": "CRITICAL", "score": 10},
    {"title": "Open S3 Bucket", "severity": "CRITICAL", "score": 10},
    {"title": "Weak Password", "severity": "HIGH", "score": 5},
    {"title": "No Encryption", "severity": "HIGH", "score": 5},
    {"title": "Old Access Keys", "severity": "MEDIUM", "score": 2},
]

total_score = 0
critical_count = 0
high_count = 0

for findings in security_findings:
    total_score += findings["score"]
    if findings["severity"] == "CRITICAL":
        critical_count += 1
    elif findings["severity"] == "HIGH":
        high_count += 1
    print(f" [{findings['severity']}] {findings['title']} + {findings['score']} points")

print(f"\nTotal Risk Score: {total_score}")
print(f"Critical findings: {critical_count}")
print(f"High findings: {high_count}")

if total_score >= 30:
    print("Overall Risk: HIGH - Immediate actiuon requered")
elif total_score >= 15:
    print("Overall Risk: MEDIUM - Action required this week")
else:
    print("Overall Risk: LOW - Schedule for maintenance")