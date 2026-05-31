# Security Risk Calculator
# Felix Chirchir - Day 3

print("=== SECURITY RISK CALCULATOR ===")

critical = int(input("Number of CRITICAL findings:"))
high = int(input("Number of HIGH findings:"))
medium = int(input("Number of MEDIUM findings:"))
low = int(input("Number of LOW findings:"))

score = (critical * 10) + (medium * 2) + (low * 1)

print("\n=== RISK REPORT ===")
print(f"Critical: {critical} x 10 = {critical * 10} points")
print(f"High:   {high} x 5 = {high * 5} points")
print(f"Medium: {medium} x 2 = {medium * 2} points")
print(f"Low:    {low} x 1 = {low * 1} points")
print(f"\nTotal Risk Score: {score}")

if score >= 50:
    print("Risk Level: CRITICAL - Immediate action required")
elif score >= 30:
    print("Risk Level: HIGH - Action required within 24 hours")
elif score >= 15:
    print("Risk level: MEDIUM - Action required within 2 week")
else:
    print("Risk Level: LOW - Schedule for next maintenance window")