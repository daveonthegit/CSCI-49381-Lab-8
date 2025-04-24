import re
from collections import defaultdict

LOGFILE = "lab8_traffic.txt"
LEGIT_IP = "10.1.1.3"
ATTACK_IP = "10.1.1.4"

connections = defaultdict(dict)
legit_durations = []
attack_durations = []
all_durations = []

with open(LOGFILE, encoding="utf-8", errors="ignore") as f:
    for line in f:
        # Match tcpdump table lines like:
        # 1 0.000000 10.1.1.3 10.1.1.2 TCP 74 52526 → 80 [SYN]
        match = re.match(
            r"\s*\d+\s+([\d.]+)\s+([\d.]+)\s+([\d.]+)\s+TCP\s+\d+\s+(\d+)\s+→\s+(\d+)\s+\[(.*?)\]",
            line
        )
        if match:
            time, src, dst, sport, dport, flags = match.groups()
            ts = float(time)
            key = (src, dst, sport, dport)

            if "SYN" in flags and "ACK" not in flags:
                connections[key]['start'] = ts
                connections[key]['src'] = src
            elif "FIN" in flags:
                connections[key]['end'] = ts

# Process durations
for conn, meta in connections.items():
    if 'start' in meta and 'end' in meta:
        duration = meta['end'] - meta['start']
        all_durations.append(duration)
        if meta['src'] == LEGIT_IP:
            legit_durations.append(duration)
        elif meta['src'] == ATTACK_IP:
            attack_durations.append(duration)

# Output
def avg(lst):
    return sum(lst) / len(lst) if lst else 0

print("Legitimate Connection Durations:")
print(f"  Count: {len(legit_durations)}")
print(f"  Average Duration: {avg(legit_durations):.2f} s")

print("\nAttack Connection Durations:")
print(f"  Count: {len(attack_durations)}")
print(f"  Average Duration: {avg(attack_durations):.2f} s")

print("\nAll Successful Connections:")
print(f"  Count: {len(all_durations)}")
print(f"  Average Duration: {avg(all_durations):.2f} s")
