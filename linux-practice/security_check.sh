#!/bin/bash

echo "===================="
echo "SECURITY CHECK REPORT"
echo "Date: $(date)"
echo "Host: $(hostname)"
echo "===================="

echo ""
echo "--- SYTEM INFO ---"
echo "OS: $(cat / etc/ os-release | grep PRETTY_NAME | cut -d= -f2)"
echo "Uptime: $(uptime -p)"
echo "Logged in users: $(who | wc -l)"

echo ""
echo "--- NETWORK INFO ---"
echo "IP Adress: $(ip addr | grep 'inet' | grep -v '127.0.0.1' | awk '{print $2}')"
echo "Open ports:"
ss -tulnp | grep LISTEN

echo ""
echo "--- FAILED LOGINS ---"
echo "Count: $(grep -c '401' access.log 2>/ dev/null || echo '0')"

echo ""
echo "--- TOP ATTACKING IPs ---"
grep "401" access.log 2>/ dev/null | awk '{print $1}' | sort | uniq -c | sort -rn | head -5

echo ""
echo "===================="
echo "Check complete"
echo "===================="
