# Day 3 - Felix Chirchir
# My first python script

log_file = "../linux-practice/access.log"
total = 0
failed_logins = 0
forbidden = 0
ip_count = {}

with open(log_file, "r") as f;
    for line f;
        total += 1
    
    if "401" in line:
        failed_logins += 1
        if "403" in line:
            forbidden += 1

    ip = line.split()[0]
    if ip in ip_count:
        ip_count[ip] += 1
    else:
        ip_count[ip] = 1

print("=" * 40)
print("LOG ANALYSIS REPORT")
print("=" * 40)
print(f"Total requests: {total}")
print(f"Failed logins (401): {failed_logins}")
print(f"Forbidden access (403): {forbidden}")

print("\nTop IPs by request count:")
sorted_ips = sorted(ip_count.items(), key=lambda x: x[1], reverse=True)
for ip, count in sorted_ips[:5]:
    print(f" {ip}: {count} requests")

    print("=" * 40)