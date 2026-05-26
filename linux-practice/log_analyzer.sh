#!/bin/bash
echo "===LOG ANALYZER==="
echo "File: server.log"
echo "===================="

echo ""
echo "Total lines: $(wc -l <server.log)"
echo "ERROR count: $(grep -c `ERROR` server.log)"
echo "ERROR count: $(grep -c `WARMING` server.log)"

echo "===ERROR DETAILS==="
grep "ERROR" server.log

