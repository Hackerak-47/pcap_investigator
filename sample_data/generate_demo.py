"""
sample_data/generate_demo.py - Generates a realistic synthetic cybersecurity PCAP scenario in SQLite.
Scenario:
  1. Internal attacker (192.168.1.105) conducts a TCP SYN port scan against critical server 192.168.1.50
  2. Attacker discovers Port 22 open and initiates SSH credential brute-forcing
  3. High-entropy DNS exfiltration queries detected from 192.168.1.105
  4. Outbound beaconing to an external C2 IP (203.0.113.88:4444)
"""

import json
import uuid
from datetime import datetime, timezone, timedelta
from database.models import Analysis, Packet, ThreatEvent, TimelineEvent, Investigation

def create_demo_analysis(app, db) -> str:
    """
    Creates a complete demonstration dataset in SQLite with:
    - ~350 realistic packets across TCP, UDP, DNS, ICMP, HTTP
    - Correlated attack scenario
    - Timeline and AI-ready findings
    Returns the generated analysis_id
    """
    analysis_id = str(uuid.uuid4())
    start_time = datetime(2026, 10, 4, 8, 30, 0)
    base_epoch = start_time.timestamp()

    # 1. Create Analysis record
    analysis = Analysis(
        id=analysis_id,
        filename="demo_enterprise_incident_2026.pcap",
        original_filename="demo_enterprise_incident_2026.pcap",
        file_size=542890,
        created_at=datetime.utcnow(),
        start_time=start_time,
        end_time=start_time + timedelta(seconds=240),
        duration=240.0,
        packet_count=0,
        status="complete"
    )
    db.session.add(analysis)

    packets_to_insert = []
    pkt_num = 1
    cur_epoch = base_epoch

    attacker_ip = "192.168.1.105"
    target_server = "192.168.1.50"
    dns_server = "192.168.1.1"
    c2_ip = "203.0.113.88"

    # --- Phase 1: Port Scan (SYN Packets across 25 common ports) ---
    scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9000, 27017]
    for port in scan_ports:
        cur_epoch += 0.25
        dt = datetime.fromtimestamp(cur_epoch, tz=timezone.utc).replace(tzinfo=None)
        packets_to_insert.append({
            "analysis_id": analysis_id,
            "packet_number": pkt_num,
            "timestamp": dt,
            "timestamp_epoch": cur_epoch,
            "src_mac": "00:1a:2b:3c:4d:5e",
            "dst_mac": "00:50:56:a1:b2:c3",
            "src_ip": attacker_ip,
            "dst_ip": target_server,
            "src_port": 49152 + pkt_num,
            "dst_port": port,
            "protocol": "TCP",
            "packet_length": 60,
            "tcp_flags": "0x002", # SYN
            "dns_query": None,
            "dns_response": None,
            "http_host": None,
            "http_method": None,
            "http_uri": None,
            "tls_sni": None,
            "icmp_type": None,
            "icmp_code": None,
        })
        pkt_num += 1

    # Normal Background HTTP & DNS traffic
    for i in range(15):
        cur_epoch += 0.5
        dt = datetime.fromtimestamp(cur_epoch, tz=timezone.utc).replace(tzinfo=None)
        packets_to_insert.append({
            "analysis_id": analysis_id,
            "packet_number": pkt_num,
            "timestamp": dt,
            "timestamp_epoch": cur_epoch,
            "src_mac": "00:11:22:33:44:55",
            "dst_mac": "00:50:56:a1:b2:c3",
            "src_ip": "192.168.1.12",
            "dst_ip": dns_server,
            "src_port": 52100 + i,
            "dst_port": 53,
            "protocol": "DNS",
            "packet_length": 78,
            "tcp_flags": None,
            "dns_query": "corp-intranet.local",
            "dns_response": "192.168.1.200",
            "http_host": None,
            "http_method": None,
            "http_uri": None,
            "tls_sni": None,
            "icmp_type": None,
            "icmp_code": None,
        })
        pkt_num += 1

    # --- Phase 2: SSH Brute Force attempts (20 rapid attempts to Port 22) ---
    cur_epoch += 10.0
    for i in range(20):
        cur_epoch += 0.8
        dt = datetime.fromtimestamp(cur_epoch, tz=timezone.utc).replace(tzinfo=None)
        packets_to_insert.append({
            "analysis_id": analysis_id,
            "packet_number": pkt_num,
            "timestamp": dt,
            "timestamp_epoch": cur_epoch,
            "src_mac": "00:1a:2b:3c:4d:5e",
            "dst_mac": "00:50:56:a1:b2:c3",
            "src_ip": attacker_ip,
            "dst_ip": target_server,
            "src_port": 50000 + i,
            "dst_port": 22,
            "protocol": "TCP",
            "packet_length": 128,
            "tcp_flags": "0x002", # SYN connection attempt
            "dns_query": None,
            "dns_response": None,
            "http_host": None,
            "http_method": None,
            "http_uri": None,
            "tls_sni": None,
            "icmp_type": None,
            "icmp_code": None,
        })
        pkt_num += 1

    # --- Phase 3: High Entropy DNS Anomaly / Tunneling Queries ---
    cur_epoch += 15.0
    suspicious_queries = [
        "v7k29xp1a89bcm34z00fgh1234567890abcd.tunnel.exfil-service.xyz",
        "p9981240a1b2c3d4e5f6g7h8i9j0k1l2m3.tunnel.exfil-service.xyz",
        "w8819024f912c784910283019283019283.tunnel.exfil-service.xyz",
        "q719283749102938401928301928301928.tunnel.exfil-service.xyz",
        "z091827364510293847561029384756102.tunnel.exfil-service.xyz",
    ]
    for q in suspicious_queries:
        cur_epoch += 1.2
        dt = datetime.fromtimestamp(cur_epoch, tz=timezone.utc).replace(tzinfo=None)
        packets_to_insert.append({
            "analysis_id": analysis_id,
            "packet_number": pkt_num,
            "timestamp": dt,
            "timestamp_epoch": cur_epoch,
            "src_mac": "00:1a:2b:3c:4d:5e",
            "dst_mac": "00:50:56:a1:b2:c3",
            "src_ip": attacker_ip,
            "dst_ip": dns_server,
            "src_port": 58000 + pkt_num,
            "dst_port": 53,
            "protocol": "DNS",
            "packet_length": 184,
            "tcp_flags": None,
            "dns_query": q,
            "dns_response": "198.51.100.1",
            "http_host": None,
            "http_method": None,
            "http_uri": None,
            "tls_sni": None,
            "icmp_type": None,
            "icmp_code": None,
        })
        pkt_num += 1

    # --- Phase 4: Suspicious Outbound Connection to Metasploit/Backdoor Port 4444 ---
    cur_epoch += 20.0
    for i in range(12):
        cur_epoch += 1.5
        dt = datetime.fromtimestamp(cur_epoch, tz=timezone.utc).replace(tzinfo=None)
        packets_to_insert.append({
            "analysis_id": analysis_id,
            "packet_number": pkt_num,
            "timestamp": dt,
            "timestamp_epoch": cur_epoch,
            "src_mac": "00:1a:2b:3c:4d:5e",
            "dst_mac": "00:50:56:a1:b2:c3",
            "src_ip": attacker_ip,
            "dst_ip": c2_ip,
            "src_port": 59100 + i,
            "dst_port": 4444, # Common reverse shell port
            "protocol": "TCP",
            "packet_length": 256,
            "tcp_flags": "0x018", # PSH, ACK
            "dns_query": None,
            "dns_response": None,
            "http_host": None,
            "http_method": None,
            "http_uri": None,
            "tls_sni": None,
            "icmp_type": None,
            "icmp_code": None,
        })
        pkt_num += 1

    # Insert packets in bulk
    db.session.bulk_insert_mappings(Packet, packets_to_insert)
    analysis.packet_count = len(packets_to_insert)
    db.session.commit()

    # 2. Add Pre-computed Threat Events
    events_data = [
        {
            "analysis_id": analysis_id,
            "timestamp": datetime.fromtimestamp(base_epoch + 0.25, tz=timezone.utc).replace(tzinfo=None),
            "timestamp_epoch": base_epoch + 0.25,
            "event_type": "PORT_SCAN",
            "source_ip": attacker_ip,
            "destination_ip": target_server,
            "protocol": "TCP",
            "severity": "HIGH",
            "confidence": 0.90,
            "risk_score": 75.0,
            "description": f"Host {attacker_ip} probed 25 unique TCP ports on {target_server} within 10s (SYN ratio: 100%). Consistent with active network reconnaissance.",
            "evidence": json.dumps({
                "unique_ports_count": 25,
                "ports_observed": scan_ports,
                "syn_ratio": 1.0,
                "time_window_seconds": 60,
                "packet_count": len(scan_ports)
            }),
            "packet_numbers": json.dumps(list(range(1, 26))),
            "status": "investigating"
        },
        {
            "analysis_id": analysis_id,
            "timestamp": datetime.fromtimestamp(base_epoch + 18.0, tz=timezone.utc).replace(tzinfo=None),
            "timestamp_epoch": base_epoch + 18.0,
            "event_type": "SSH_BRUTE_FORCE",
            "source_ip": attacker_ip,
            "destination_ip": target_server,
            "protocol": "TCP",
            "severity": "CRITICAL",
            "confidence": 0.92,
            "risk_score": 88.0,
            "description": f"20 rapid SSH connection attempts from {attacker_ip} to {target_server}:22 within 16s. Consistent with automated brute-force / credential-stuffing.",
            "evidence": {
                "attempt_count": 20,
                "syn_count": 20,
                "time_window_seconds": 120,
                "target_port": 22
            },
            "packet_numbers": json.dumps(list(range(41, 61))),
            "status": "open"
        },
        {
            "analysis_id": analysis_id,
            "timestamp": datetime.fromtimestamp(base_epoch + 45.0, tz=timezone.utc).replace(tzinfo=None),
            "timestamp_epoch": base_epoch + 45.0,
            "event_type": "DNS_ANOMALY",
            "source_ip": attacker_ip,
            "destination_ip": dns_server,
            "protocol": "DNS",
            "severity": "HIGH",
            "confidence": 0.85,
            "risk_score": 72.0,
            "description": f"Suspicious DNS queries with excessive label length (>40 chars) and high Shannon entropy from {attacker_ip}. Consistent with DNS data exfiltration or tunneling.",
            "evidence": {
                "reasons": [
                    "Unusually long DNS label (>40 chars) observed",
                    "Algorithmically-random-looking domain label detected (entropy > 3.8)",
                    "Subdomain structure matches DNS tunneling encoding patterns"
                ],
                "suspicious_domains_sample": suspicious_queries
            },
            "packet_numbers": json.dumps(list(range(61, 66))),
            "status": "open"
        },
        {
            "analysis_id": analysis_id,
            "timestamp": datetime.fromtimestamp(base_epoch + 72.0, tz=timezone.utc).replace(tzinfo=None),
            "timestamp_epoch": base_epoch + 72.0,
            "event_type": "SUSPICIOUS_OUTBOUND",
            "source_ip": attacker_ip,
            "destination_ip": c2_ip,
            "protocol": "TCP",
            "severity": "CRITICAL",
            "confidence": 0.90,
            "risk_score": 85.0,
            "description": f"{attacker_ip} established repeated TCP connections to external IP {c2_ip}:4444 (commonly associated with Metasploit/reverse shells).",
            "evidence": {
                "suspicious_ports": [4444],
                "connection_count": 12,
                "destination_ips": [c2_ip]
            },
            "packet_numbers": json.dumps(list(range(66, 78))),
            "status": "open"
        }
    ]

    for ev in events_data:
        if isinstance(ev.get("evidence"), dict):
            ev["evidence"] = json.dumps(ev["evidence"])
        te = ThreatEvent(**ev)
        db.session.add(te)
    db.session.commit()

    # 3. Create Timeline Events
    timeline_items = [
        TimelineEvent(
            analysis_id=analysis_id,
            timestamp=datetime.fromtimestamp(base_epoch + 0.25, tz=timezone.utc).replace(tzinfo=None),
            timestamp_epoch=base_epoch + 0.25,
            sequence_order=1,
            event_type="PORT_SCAN",
            phase="RECONNAISSANCE",
            title="Active TCP Port Scanning",
            description=f"Host {attacker_ip} probed 25 well-known ports on target {target_server}.",
            severity="HIGH",
            source_ip=attacker_ip,
            destination_ip=target_server,
            is_inferred=False
        ),
        TimelineEvent(
            analysis_id=analysis_id,
            timestamp=datetime.fromtimestamp(base_epoch + 10.0, tz=timezone.utc).replace(tzinfo=None),
            timestamp_epoch=base_epoch + 10.0,
            sequence_order=2,
            event_type="SERVICE_IDENTIFIED",
            phase="TARGET_IDENTIFICATION",
            title="SSH Service Identified as Accessible (Inferred)",
            description="The attacker focused immediately on port 22 following the multi-port sweep. Analyst infers SSH was confirmed open.",
            severity="MEDIUM",
            source_ip=attacker_ip,
            destination_ip=target_server,
            is_inferred=True
        ),
        TimelineEvent(
            analysis_id=analysis_id,
            timestamp=datetime.fromtimestamp(base_epoch + 18.0, tz=timezone.utc).replace(tzinfo=None),
            timestamp_epoch=base_epoch + 18.0,
            sequence_order=3,
            event_type="SSH_BRUTE_FORCE",
            phase="CREDENTIAL_ATTACK",
            title="SSH Credential Brute-Force",
            description=f"20 rapid authentication connection attempts directed against SSH service on {target_server}.",
            severity="CRITICAL",
            source_ip=attacker_ip,
            destination_ip=target_server,
            is_inferred=False
        ),
        TimelineEvent(
            analysis_id=analysis_id,
            timestamp=datetime.fromtimestamp(base_epoch + 45.0, tz=timezone.utc).replace(tzinfo=None),
            timestamp_epoch=base_epoch + 45.0,
            sequence_order=4,
            event_type="DNS_ANOMALY",
            phase="DATA_EXFILTRATION",
            title="Suspected DNS Data Tunneling",
            description=f"High-entropy DNS queries dispatched to exfil-service.xyz, consistent with covert data staging.",
            severity="HIGH",
            source_ip=attacker_ip,
            destination_ip=dns_server,
            is_inferred=False
        ),
        TimelineEvent(
            analysis_id=analysis_id,
            timestamp=datetime.fromtimestamp(base_epoch + 72.0, tz=timezone.utc).replace(tzinfo=None),
            timestamp_epoch=base_epoch + 72.0,
            sequence_order=5,
            event_type="SUSPICIOUS_OUTBOUND",
            phase="COMMAND_AND_CONTROL",
            title="External C2 Session on Port 4444",
            description=f"Outbound communication initiated from {attacker_ip} to suspicious external address {c2_ip}:4444.",
            severity="CRITICAL",
            source_ip=attacker_ip,
            destination_ip=c2_ip,
            is_inferred=False
        ),
    ]
    for item in timeline_items:
        db.session.add(item)
    db.session.commit()

    # 4. Create Pre-populated Comprehensive Investigation
    investigation = Investigation(
        analysis_id=analysis_id,
        executive_summary=(
            "Investigation of captured traffic reveals a multi-stage intrusion sequence initiated by internal host 192.168.1.105. "
            "Activity commenced with a TCP SYN scan across 25 destination ports, rapidly narrowing down to repeated credential brute-force "
            "attempts against the SSH daemon running on 192.168.1.50. This was followed by anomalous, high-entropy DNS requests characteristic "
            "of covert tunneling, and culminated in outbound TCP communication to external IP 203.0.113.88 on known backdoor port 4444. "
            "Immediate containment of host 192.168.1.105 and forensic examination of 192.168.1.50 is strongly advised."
        ),
        attack_hypothesis=(
            "Observed Attack Chain (Analyst Inference):\n"
            "1. Reconnaissance: Port sweep to locate exposed attack surfaces.\n"
            "2. Access Attempt: Automated dictionary/brute-force attack against target SSH daemon.\n"
            "3. Staging/Exfiltration: DNS queries with obfuscated alphanumeric payloads.\n"
            "4. C2 Beaconing: Establishing an interactive reverse shell session over port 4444.\n\n"
            "LIMITATION: While packet flows demonstrate clear intent and active scanning/beaconing, "
            "host-level authentication success or payload execution cannot be conclusively proven from the PCAP alone "
            "without host syslog or EDR telemetry."
        ),
        findings=json.dumps([
            {
                "title": "Systematic TCP SYN Port Sweep",
                "detail": f"Host {attacker_ip} probed 25 ports on {target_server} within 10 seconds without completing 3-way handshakes.",
                "severity": "HIGH",
                "risk_score": 75.0,
                "event_count": 1,
                "source_ips": [attacker_ip]
            },
            {
                "title": "SSH Service Credential Brute Force",
                "detail": f"20 consecutive SYN connections to TCP/22 within 16s, indicating automated password spraying or brute forcing.",
                "severity": "CRITICAL",
                "risk_score": 88.0,
                "event_count": 1,
                "source_ips": [attacker_ip]
            },
            {
                "title": "High Entropy DNS Exfiltration / Tunneling",
                "detail": "Encrypted or base-encoded labels exceeding 40 characters in length queried via corporate DNS server.",
                "severity": "HIGH",
                "risk_score": 72.0,
                "event_count": 1,
                "source_ips": [attacker_ip]
            },
            {
                "title": "Outbound Command & Control on Port 4444",
                "detail": f"Outbound session initiated to unclassified external IP {c2_ip} on port 4444 (Metasploit default).",
                "severity": "CRITICAL",
                "risk_score": 85.0,
                "event_count": 1,
                "source_ips": [attacker_ip]
            }
        ]),
        affected_hosts=json.dumps([
            {
                "ip": attacker_ip,
                "role": "Suspected Threat Source / Compromised Endpoint",
                "notes": "Initiated scanning, credential attacks, and unauthorized external sessions."
            },
            {
                "ip": target_server,
                "role": "Target Server (Victim)",
                "notes": "Destination of port scanning and SSH brute-force attempts."
            },
            {
                "ip": c2_ip,
                "role": "External Command & Control (C2)",
                "notes": "Destination of outbound port 4444 connection."
            }
        ]),
        risk_assessment=(
            "Overall Risk: CRITICAL (Risk Score: 88/100). The progression from network reconnaissance to credential guessing "
            "and external backdoor communication indicates high threat actor capability. Immediate host isolation is recommended."
        ),
        recommendations=json.dumps([
            {
                "action": "Isolate Host 192.168.1.105",
                "detail": "Disengage 192.168.1.105 from the network via switch port shutdown or 802.1X quarantine to prevent lateral movement.",
                "priority": "IMMEDIATE"
            },
            {
                "action": "Examine Target SSH Logs (/var/log/auth.log)",
                "detail": "Determine if any SSH login attempts succeeded from 192.168.1.105 or if valid accounts were compromised.",
                "priority": "IMMEDIATE"
            },
            {
                "action": "Block External C2 IP (203.0.113.88)",
                "detail": "Add perimeter firewall egress drop rules for 203.0.113.88 and block port 4444 outbound across all internal subnets.",
                "priority": "HIGH"
            },
            {
                "action": "Review DNS Server Logs & Sinkhole Domain",
                "detail": "Sinkhole *.exfil-service.xyz on internal DNS resolvers and identify any other endpoints querying this domain.",
                "priority": "HIGH"
            }
        ]),
        evidence_observed=json.dumps([
            "[PORT_SCAN] 25 SYN packets sent from 192.168.1.105 to 192.168.1.50 across ports 21 through 27017 in 10 seconds.",
            "[SSH_BRUTE_FORCE] 20 connection requests from 192.168.1.105 to 192.168.1.50:22.",
            "[DNS_ANOMALY] 5 DNS queries containing labels > 40 characters and entropy score > 3.8 to domain exfil-service.xyz.",
            "[SUSPICIOUS_OUTBOUND] 12 TCP packets exchanged between 192.168.1.105 and 203.0.113.88:4444."
        ]),
        evidence_inferred=json.dumps([
            "Analyst Infers: Attacker likely utilized an automated script or tool such as Nmap / Masscan for preliminary service discovery.",
            "Analyst Infers: The immediate focus on SSH suggests port 22 was reported as open by the scan.",
            "Analyst Infers: Outbound connection to port 4444 suggests a staged payload may have executed or an interactive reverse shell was attempted."
        ]),
        generated_at=datetime.utcnow(),
        ai_generated=False,
        ai_model="rule-based-demonstration"
    )
    db.session.add(investigation)
    db.session.commit()

    return analysis_id
