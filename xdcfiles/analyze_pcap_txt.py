import re
from datetime import datetime

pcap_txt_path = "lab8_traffic.txt"  # Update with your filename

# Regex to extract useful fields
pattern = re.compile(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*IP (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): Flags \[([^\]]+)\]')

connections = {}

with open(pcap_txt_path, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        match = pattern.search(line)
        if match:
            ts, src_ip, src_port, dst_ip, dst_port, flags = match.groups()
            key = (src_ip, src_port, dst_ip, dst_port)
            timestamp = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S.%f")
            if "S" in flags:  # SYN
                connections[key] = {"start": timestamp, "end": None}
            elif "F" in flags or "R" in flags:  # FIN or RST
                if key in connections:
                    connections[key]["end"] = timestamp

# Print connection durations
print("Src IP\tDst IP\tDuration (s)")
for key, times in connections.items():
    if times["start"] and times["end"]:
        duration = (times["end"] - times["start"]).total_seconds()
        print(f"{key[0]}\t{key[2]}\t{duration:.3f}")
