#!/bin/bash
TARGET=$1

if [ -z "$TARGET" ]; then
echo "usage: ./recon.sh <domain>"
exit 1

fi

echo "===================="
echo "RECON REPORT: $TARGET"
echo "===================="

echo ""
echo "--- IP ADDRESS ---"
dig $TARGET +short

echo ""
echo "--- PING TEST ---"
ping $TARGET -c 3

echo ""
echo "--- HTTP HEADERS ---"
curl -l https://$TARGET 2>/dev/null | head -10

echo ""
echo "--- MIX RECORDS ---"
dig $TARGET MIX +short

echo ""
echo "Recon complete."
