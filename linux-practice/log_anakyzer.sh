#!/bin/bash
echo "=== LOG ANALYZER ==="
echo "File:server.log"
echo "===================="

echo ""
echo "Total lines: $(wc -l <server.log)"
echo "ERROR count: $(grep -c 'ERROR' server.log)"
echo "WARNING count: $(grep -c 'WARNING' server.log)"
echo "INFO count: $(grep -c 'INFO' server.log)"

echo ""
echo "=== ERROR DETAILS ==="
grep "ERROR" server.log
