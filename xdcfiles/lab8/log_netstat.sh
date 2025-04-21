#!/bin/bash

# Create output file
OUTFILE="netstat_log_$(date +%Y%m%d_%H%M%S).txt"

# Run netstat in a loop
while true
do
    echo "Timestamp: $(date +%Y-%m-%d\ %H:%M:%S)" >> "$OUTFILE"
    netstat -ant | grep -v "127.0.0.1" >> "$OUTFILE"
    echo "------------------------" >> "$OUTFILE"
    sleep 1
done
