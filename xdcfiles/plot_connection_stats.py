import pyshark
import matplotlib.pyplot as plt
from collections import defaultdict

# Define IPs
LEGIT_IP = "10.1.1.3"
ATTACK_IP = "10.1.1.4"

# Load capture
cap = pyshark.FileCapture("lab8_traffic.pcap", display_filter="tcp")

# Track connection stats
success_legit = defaultdict(int)
fail_legit = defaultdict(int)
success_attack = defaultdict(int)
fail_attack = defaultdict(int)

# For each IP, map src_port to the last state seen
conn_tracker = {}

for pkt in cap:
    try:
        ip = pkt.ip.src
        dst = pkt.ip.dst
        time_sec = int(float(pkt.sniff_timestamp))
        flags = pkt.tcp.flags

        key = (ip, pkt.tcp.srcport, dst, pkt.tcp.dstport)

        if '0x0002' in flags:  # SYN
            if key in conn_tracker and conn_tracker[key] == 'SYN':
                if ip == LEGIT_IP:
                    fail_legit[time_sec] += 1
                elif ip == ATTACK_IP:
                    fail_attack[time_sec] += 1
            else:
                conn_tracker[key] = 'SYN'
        elif '0x0011' in flags or '0x0010' in flags:  # FIN or ACK (completion)
            if ip == LEGIT_IP:
                success_legit[time_sec] += 1
            elif ip == ATTACK_IP:
                success_attack[time_sec] += 1
            conn_tracker[key] = 'DONE'
    except Exception:
        continue

# Prepare plot
times = sorted(set(success_legit) | set(fail_legit) | set(success_attack) | set(fail_attack))
x = list(times)

y1 = [success_legit.get(t, 0) for t in x]
y2 = [fail_legit.get(t, 0) for t in x]
y3 = [success_attack.get(t, 0) for t in x]
y4 = [fail_attack.get(t, 0) for t in x]

plt.figure()
plt.plot(x, y1, label='Success Legit', marker='o')
plt.plot(x, y2, label='Fail Legit', marker='x')
plt.plot(x, y3, label='Success Attack', marker='o')
plt.plot(x, y4, label='Fail Attack', marker='x')
plt.xlabel('Time (s)')
plt.ylabel('Connections per second')
plt.title('Connection Success/Failure per IP Type')
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.show()

