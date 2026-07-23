# lesson2_if_statements.py
# Felix Chirchir
# If statements - decision making in python

print("=" * 45)
print("LESSON 2 - IF STATEMENTS")
print("=" * 45)

# ===============================
# BASIC IF/ELSE
# ===============================
print("\n--- BASIC DECISION ---")

age = 20

if age >= 18:
    print(f"Age {age}: You are an adult")
else:
    print(f"Age {age}: You are a minor")

# ===============================
# IF/ELIF/ELSE - RISK SCORER
# ===============================

risk_score = 35

if risk_score >= 50:
    level = "CRITICAL"
    action = "Fix immediately"
elif risk_score >= 30:
    level = "HIGH"
    action = "Fix within 24 hours"
elif risk_score >= 15:
    level = "MEDIUM"
    action = "Fix within 1 week"
else:
    level = "LOW"
    action = "Fix at next maintenance"

print(f"Risk Score: {risk_score}")
print(f"Risk Level: {level}")
print(f"Action:     {action}") 

# ===============================
# LOGICAL OPERATORS
# ===============================
print("\n--- SECURITY ACCESS CHECK ---")

has_mfa = True
is_admin = True
password_age = 95

if is_admin and not has_mfa:
    print("CRITICAL: Admin without MFA")
elif is_admin and has_mfa:
    print("PASS: Admin with MFA - acces granted")
else:
    print("INFO: Regular user")

if password_age > 90:
    print(f"WARNING: Password is {password_age} days old - rotate now")

# ===============================
# in OPERATOR
# ===============================
print("\n--- PORT SECURITY CHECK ---")

dangerous_ports = [22, 23, 3306, 3389, 5432, 6379]
open_ports = [870, 443, 22, 8080]

for port in open_ports:
    if port in dangerous_ports:
        print(f" DANGER: Port {port} is open and dangerous")
    else:
        print(f" SAFE: Port {port} is open and safe")

# ===============================
# USER INPUT WITH DECISION
# ===============================
print("\n--- INTERACTIVE SECURITY CHECK ---")

findings = int(input("How many CRITICAL findings do you have? "))

if findings == 0:
    print("Excellent! No critical findings.")
elif findings <= 3:
    print(f"Warning: {findings} critical findings. Fix urgently.")
else:
    print(f"DANGER: {findings} critical findings. stop all deployments now.")