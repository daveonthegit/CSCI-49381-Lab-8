#!/usr/bin/env python3
import re
import json
from collections import defaultdict
import sys

def parse_netstat_file(file_path):
    """Parse netstat output file and extract connection information over time."""
    with open(file_path, 'r') as f:
        content = f.read()
    
    # Split by timestamp sections
    timestamp_pattern = r'Timestamp: (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})'
    sections = re.split(timestamp_pattern, content)
    
    # Skip the initial empty section if any
    if not sections[0].strip():
        sections = sections[1:]
    
    results = []
    
    # Process each timestamp and its content
    for i in range(0, len(sections), 2):
        if i+1 >= len(sections):
            break
            
        timestamp = sections[i]
        data = sections[i+1]
        
        # Extract connection information
        connections = []
        lines = data.strip().split('\n')
        
        # Skip the header lines
        for line in lines:
            if 'Proto' in line or 'Active Internet' in line or not line.strip():
                continue
                
            parts = re.split(r'\s+', line.strip())
            if len(parts) >= 6:
                proto = parts[0]
                recv_q = int(parts[1])
                send_q = int(parts[2])
                local_addr = parts[3]
                foreign_addr = parts[4]
                state = parts[5] if len(parts) > 5 else "UNKNOWN"
                
                # Parse IP and port
                local_parts = local_addr.split(':')
                local_ip = ':'.join(local_parts[:-1]) if len(local_parts) > 1 else local_parts[0]
                local_port = local_parts[-1] if len(local_parts) > 1 else ""
                
                foreign_parts = foreign_addr.split(':')
                foreign_ip = ':'.join(foreign_parts[:-1]) if len(foreign_parts) > 1 else foreign_parts[0]
                foreign_port = foreign_parts[-1] if len(foreign_parts) > 1 else ""
                
                connections.append({
                    'proto': proto,
                    'recv_q': recv_q,
                    'send_q': send_q,
                    'local_ip': local_ip,
                    'local_port': local_port,
                    'foreign_ip': foreign_ip,
                    'foreign_port': foreign_port,
                    'state': state
                })
        
        # Count connections by state
        states = defaultdict(int)
        ports = defaultdict(int)
        ips = defaultdict(int)
        
        for conn in connections:
            states[conn['state']] += 1
            if conn['local_port']:
                ports[conn['local_port']] += 1
            if conn['foreign_ip'] != '0.0.0.0' and conn['foreign_ip'] != '::':
                ips[conn['foreign_ip']] += 1
        
        # Count specific connection patterns for attack detection
        http_connections = sum(1 for c in connections if c['local_port'] == '80' and c['state'] == 'ESTABLISHED')
        ssh_connections = sum(1 for c in connections if c['local_port'] == '22' and c['state'] == 'ESTABLISHED')
        syn_recv_connections = sum(1 for c in connections if c['state'] == 'SYN_RECV' or c['state'] == 'SYN-RECV')
        
        # Count unique source IPs connecting to web server
        web_sources = set(c['foreign_ip'] for c in connections if c['local_port'] == '80' and c['state'] == 'ESTABLISHED')
        
        results.append({
            'timestamp': timestamp,
            'states': dict(states),
            'ports': dict(ports),
            'ips': dict(ips),
            'connections': len(connections),
            'http_connections': http_connections,
            'ssh_connections': ssh_connections,
            'syn_recv_connections': syn_recv_connections,
            'unique_web_sources': len(web_sources),
            'web_sources': list(web_sources)
        })
    
    return results

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python netstat_parser.py <netstat_log_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    results = parse_netstat_file(file_path)
    
    # Output JSON for visualization
    with open('netstat_data.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Parsed {len(results)} timestamps from netstat log")
    print(f"Data saved to netstat_data.json")