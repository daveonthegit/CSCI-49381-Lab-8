import re
from datetime import datetime
import matplotlib.pyplot as plt

log_path = "netstat_log_20250421_015533.txt"  # Update with your filename

syn_recv_counts = []
current_time = None
syn_recv_count = 0

with open(log_path, 'r') as f:
    for line in f:
        if "Timestamp:" in line:
            if current_time:
                syn_recv_counts.append((current_time, syn_recv_count))
            current_time = line.strip().split("Timestamp: ")[1]
            syn_recv_count = 0
        elif "SYN_RECV" in line:
            syn_recv_count += 1

# Add final count
if current_time:
    syn_recv_counts.append((current_time, syn_recv_count))

# Output results
print("Time\t\tSYN_RECV Count")
for t, c in syn_recv_counts:
    print(f"{t}\t{c}")
