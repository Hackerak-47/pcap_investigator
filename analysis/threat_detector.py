"""
analysis/threat_detector.py - Modular rule-based threat detection engine.
detect suspicious activities using predefined rules 
Each detector is independent and returns a list of structured threat event dicts.
All thresholds come from config.py.
"""

import json
import logging
import math
import re
import ipaddress
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from database.database import db
from database.models import Packet
import config

logger = logging.getLogger(__name__)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def _severity_from_score(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def _is_syn(flags_hex: Optional[str]) -> bool:
    """Return True if the TCP flags indicate SYN (not SYN-ACK)."""
    if not flags_hex:
        return False
    try:
        val = int(flags_hex, 16)
        SYN = 0x002
        ACK = 0x010
        return bool(val & SYN) and not bool(val & ACK)
    except Exception:
        return False


def _domain_entropy(label: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not label:
        return 0.0
    freq = Counter(label)
    length = len(label)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return entropy


def _looks_random(label: str) -> bool:
    """Heuristic: does this domain label look algorithmically generated?"""
    if len(label) < 8:
        return False
    entropy = _domain_entropy(label)
    vowel_ratio = sum(1 for c in label if c in 'aeiouAEIOU') / len(label)
    consonant_ratio = sum(1 for c in label if c.isalpha() and c not in 'aeiouAEIOU') / len(label)
    # DGA-like: high entropy, low vowels, looks random
    return entropy >= config.DNS_ENTROPY_THRESHOLD and vowel_ratio < 0.2


def _make_event(
    analysis_id: str,
    event_type: str,
    source_ip: str,
    destination_ip: str,
    protocol: str,
    severity: str,
    confidence: float,
    risk_score: float,
    description: str,
    evidence: dict,
    packet_numbers: list,
    timestamp_epoch: Optional[float] = None,
) -> dict:
    ts = None
    if timestamp_epoch:
        ts = datetime.fromtimestamp(timestamp_epoch, tz=timezone.utc).replace(tzinfo=None)
    return {
        "analysis_id": analysis_id,
        "timestamp": ts,
        "timestamp_epoch": timestamp_epoch,
        "event_type": event_type,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "severity": severity,
        "confidence": round(confidence, 2),
        "risk_score": round(risk_score, 1),
        "description": description,
        "evidence": json.dumps(evidence),
        "packet_numbers": json.dumps(packet_numbers[:100]),  # cap stored pkt numbers
        "status": "open",
    }


# ─── Port Scan Detector ───────────────────────────────────────────────────────

def detect_port_scans(analysis_id: str) -> List[dict]:
    """
    Detect hosts that attempt connections to many unique destination ports
    within a configurable time window.
    """
    events = []
    packets = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.protocol.in_(["TCP", "UDP"]))
        .filter(Packet.src_ip.isnot(None))
        .filter(Packet.dst_ip.isnot(None))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    # Group by (src_ip, dst_ip)
    flow_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in packets:
        key = f"{p.src_ip}->{p.dst_ip}"
        flow_map[key].append(p)

    # Also check per source IP across all destinations (horizontal scan)
    src_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in packets:
        src_map[p.src_ip].append(p)

    checked_pairs = set()

    # Vertical scan: one src, one dst, many ports
    for key, pkts in flow_map.items():
        src_ip = pkts[0].src_ip
        dst_ip = pkts[0].dst_ip
        pair = (src_ip, dst_ip)
        if pair in checked_pairs:
            continue

        # Sliding window
        for i, start_pkt in enumerate(pkts):
            window = [p for p in pkts[i:]
                      if p.timestamp_epoch and start_pkt.timestamp_epoch and
                      p.timestamp_epoch - start_pkt.timestamp_epoch <= config.PORT_SCAN_TIME_WINDOW]

            unique_ports = set(p.dst_port for p in window if p.dst_port)
            if len(unique_ports) >= config.PORT_SCAN_UNIQUE_PORTS:
                checked_pairs.add(pair)
                syn_count = sum(1 for p in window if _is_syn(p.tcp_flags))
                syn_ratio = syn_count / len(window) if window else 0
                confidence = min(0.95, 0.5 + (len(unique_ports) / 50))
                # Higher score for SYN-only scans
                base = 50 + (len(unique_ports) / 2)
                if syn_ratio >= config.PORT_SCAN_SYN_RATIO:
                    base += 15
                risk_score = min(95, base)
                severity = _severity_from_score(risk_score)
                port_list = sorted(unique_ports)[:50]

                events.append(_make_event(
                    analysis_id=analysis_id,
                    event_type="PORT_SCAN",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP/UDP",
                    severity=severity,
                    confidence=confidence,
                    risk_score=risk_score,
                    description=(
                        f"Host {src_ip} connected to {len(unique_ports)} unique ports on {dst_ip} "
                        f"within {config.PORT_SCAN_TIME_WINDOW}s "
                        f"(SYN ratio: {syn_ratio:.0%}). "
                        "This pattern is consistent with a port scan."
                    ),
                    evidence={
                        "unique_ports_count": len(unique_ports),
                        "ports_observed": port_list,
                        "syn_ratio": round(syn_ratio, 2),
                        "time_window_seconds": config.PORT_SCAN_TIME_WINDOW,
                        "packet_count": len(window),
                        "time_range_start": start_pkt.timestamp_epoch,
                        "time_range_end": window[-1].timestamp_epoch if window else None,
                    },
                    packet_numbers=[p.packet_number for p in window],
                    timestamp_epoch=start_pkt.timestamp_epoch,
                ))
                break  # one event per pair

    for src_ip, pkts in src_map.items():
        probes = [p for p in pkts if p.protocol == "UDP" or _is_syn(p.tcp_flags)]
        for start in probes:
            if start.timestamp_epoch is None:
                continue
            window = [p for p in probes if p.timestamp_epoch is not None and 0 <= p.timestamp_epoch-start.timestamp_epoch <= config.PORT_SCAN_TIME_WINDOW]
            destinations = {p.dst_ip for p in window}
            if len(destinations) >= config.PORT_SCAN_UNIQUE_PORTS:
                events.append(_make_event(analysis_id, "PORT_SCAN", src_ip, None, "TCP/UDP", "HIGH", .7, 60,
                    f"{src_ip} probed {len(destinations)} destinations in {config.PORT_SCAN_TIME_WINDOW}s; possible horizontal scan.",
                    {"destination_ips": sorted(destinations), "unique_destinations": len(destinations), "time_range_end": window[-1].timestamp_epoch},
                    [p.packet_number for p in window], start.timestamp_epoch))
                break

    logger.info("Port scan detection: %d events", len(events))
    return events


# ─── SSH Brute Force Detector ─────────────────────────────────────────────────

def detect_ssh_brute_force(analysis_id: str) -> List[dict]:
    """Detect repeated SSH (port 22) connection attempts from same source."""
    events = []
    ssh_pkts = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.dst_port == config.SSH_PORT)
        .filter(Packet.src_ip.isnot(None))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    # Group by (src_ip, dst_ip)
    flow_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in ssh_pkts:
        key = f"{p.src_ip}->{p.dst_ip}"
        flow_map[key].append(p)

    for key, pkts in flow_map.items():
        src_ip = pkts[0].src_ip
        dst_ip = pkts[0].dst_ip

        for i, start_pkt in enumerate(pkts):
            if not start_pkt.timestamp_epoch:
                continue
            window = [p for p in pkts[i:]
                      if p.timestamp_epoch and
                      p.timestamp_epoch - start_pkt.timestamp_epoch <= config.SSH_BRUTE_FORCE_TIME_WINDOW]

            if len(window) >= config.SSH_BRUTE_FORCE_ATTEMPTS:
                # Count unique connections (SYN packets)
                syn_count = sum(1 for p in window if _is_syn(p.tcp_flags))
                attempts = len({(p.src_port, p.dst_ip, p.dst_port) for p in window if _is_syn(p.tcp_flags)})
                if attempts < config.SSH_BRUTE_FORCE_ATTEMPTS:
                    continue
                confidence = min(0.95, 0.6 + (attempts / 100))
                risk_score = min(95, 55 + (attempts / 5))
                severity = _severity_from_score(risk_score)

                events.append(_make_event(
                    analysis_id=analysis_id,
                    event_type="SSH_BRUTE_FORCE",
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    protocol="TCP",
                    severity=severity,
                    confidence=confidence,
                    risk_score=risk_score,
                    description=(
                        f"{attempts} SSH connection attempts from {src_ip} to {dst_ip}:22 "
                        f"within {config.SSH_BRUTE_FORCE_TIME_WINDOW}s. "
                        "This pattern is consistent with an SSH brute-force or credential-stuffing attempt."
                    ),
                    evidence={
                        "attempt_count": attempts,
                        "syn_count": syn_count,
                        "time_window_seconds": config.SSH_BRUTE_FORCE_TIME_WINDOW,
                        "time_range_start": start_pkt.timestamp_epoch,
                        "time_range_end": window[-1].timestamp_epoch if window else None,
                    },
                    packet_numbers=[p.packet_number for p in window],
                    timestamp_epoch=start_pkt.timestamp_epoch,
                ))
                break

    logger.info("SSH brute-force detection: %d events", len(events))
    return events


# ─── DNS Anomaly Detector ─────────────────────────────────────────────────────

def detect_dns_anomalies(analysis_id: str) -> List[dict]:
    """Detect suspicious DNS traffic patterns."""
    events = []
    dns_pkts = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.dns_query.isnot(None))
        .filter(Packet.dns_is_response.is_not(True))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    if not dns_pkts:
        return events

    # Group by source IP
    src_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in dns_pkts:
        if p.src_ip:
            src_map[p.src_ip].append(p)

    for src_ip, pkts in src_map.items():
        reasons = []
        suspicious_domains = []
        pkt_nums = []

        # 1. High query frequency
        if pkts[0].timestamp_epoch and pkts[-1].timestamp_epoch:
            duration = max(1, pkts[-1].timestamp_epoch - pkts[0].timestamp_epoch)
            peak = max((sum(1 for p in pkts if p.timestamp_epoch is not None and start.timestamp_epoch is not None and 0 <= p.timestamp_epoch-start.timestamp_epoch <= config.DNS_TIME_WINDOW) for start in pkts), default=0)
            rate_per_min = peak * 60 / config.DNS_TIME_WINDOW
            if rate_per_min >= config.DNS_QUERY_THRESHOLD:
                reasons.append(f"High DNS query rate: {rate_per_min:.0f} queries/min")

        # 2. Unique subdomain count
        unique_domains = set(p.dns_query for p in pkts if p.dns_query)
        if len(unique_domains) >= config.DNS_SUBDOMAIN_THRESHOLD:
            reasons.append(f"{len(unique_domains)} unique domain queries (possible exfiltration via DNS)")

        # 3. Long domain labels / DGA-like
        for p in pkts:
            if not p.dns_query:
                continue
            labels = p.dns_query.split(".")
            for label in labels:
                if len(label) >= config.DNS_LONG_LABEL_LENGTH:
                    reasons.append(f"Unusually long DNS label ({len(label)} chars): {label[:60]}...")
                    suspicious_domains.append(p.dns_query[:100])
                    pkt_nums.append(p.packet_number)
                    break
                if _looks_random(label):
                    reasons.append(f"Algorithmically-random-looking domain label: {label[:60]}")
                    suspicious_domains.append(p.dns_query[:100])
                    pkt_nums.append(p.packet_number)
                    break

        if reasons:
            # Deduplicate reasons
            reasons = list(dict.fromkeys(reasons))[:5]
            num_reasons = len(reasons)
            confidence = min(0.9, 0.4 + num_reasons * 0.15)
            risk_score = min(85, 35 + num_reasons * 12)
            severity = _severity_from_score(risk_score)

            events.append(_make_event(
                analysis_id=analysis_id,
                event_type="DNS_ANOMALY",
                source_ip=src_ip,
                destination_ip=pkts[0].dst_ip,
                protocol="DNS",
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                description=(
                    f"Suspicious DNS activity from {src_ip}. "
                    + " ".join(reasons[:2]) +
                    " Requires further investigation."
                ),
                evidence={
                    "reasons": reasons,
                    "total_queries": len(pkts),
                    "unique_domains": len(unique_domains),
                    "suspicious_domains_sample": list(set(suspicious_domains))[:10],
                },
                packet_numbers=pkt_nums[:100] or [p.packet_number for p in pkts[:20]],
                timestamp_epoch=pkts[0].timestamp_epoch,
            ))

    logger.info("DNS anomaly detection: %d events", len(events))
    return events


# ─── Suspicious Outbound Detector ─────────────────────────────────────────────

def detect_suspicious_outbound(analysis_id: str) -> List[dict]:
    """Detect unusual outbound communication patterns."""
    events = []
    packets = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.src_ip.isnot(None))
        .filter(Packet.dst_ip.isnot(None))
        .filter(Packet.dst_port.isnot(None))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    # Track per-source destination counts
    src_dst_map: Dict[str, set] = defaultdict(set)
    src_suspicious_ports: Dict[str, list] = defaultdict(list)
    src_pkts: Dict[str, List[Packet]] = defaultdict(list)

    networks = [ipaddress.ip_network(n.strip()) for n in config.SCHOOL_NETWORKS.split(",") if n.strip()]
    for p in packets:
        try:
            if not any(ipaddress.ip_address(p.src_ip) in n for n in networks) or any(ipaddress.ip_address(p.dst_ip) in n for n in networks):
                continue
        except ValueError:
            continue
        src_dst_map[p.src_ip].add(p.dst_ip)
        src_pkts[p.src_ip].append(p)
        if p.dst_port in config.SUSPICIOUS_PORTS:
            src_suspicious_ports[p.src_ip].append(p)

    # Check for high outbound fan-out
    for src_ip, dst_ips in src_dst_map.items():
        candidates = src_pkts[src_ip]
        best = max(([p for p in candidates if p.timestamp_epoch is not None and start.timestamp_epoch is not None and 0 <= p.timestamp_epoch-start.timestamp_epoch <= config.OUTBOUND_TIME_WINDOW] for start in candidates), key=lambda w: len({p.dst_ip for p in w}), default=[])
        dst_ips = {p.dst_ip for p in best}
        if len(dst_ips) >= config.OUTBOUND_CONNECTION_THRESHOLD:
            pkts = best
            reasons = [f"Communicated with {len(dst_ips)} unique destination IPs"]
            confidence = min(0.85, 0.45 + len(dst_ips) / 200)
            risk_score = min(80, 40 + len(dst_ips) / 5)
            severity = _severity_from_score(risk_score)

            events.append(_make_event(
                analysis_id=analysis_id,
                event_type="SUSPICIOUS_OUTBOUND",
                source_ip=src_ip,
                destination_ip=f"{len(dst_ips)} hosts",
                protocol="TCP/UDP",
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                description=(
                    f"{src_ip} communicated with {len(dst_ips)} unique destinations. "
                    "This high fan-out pattern may indicate scanning, beaconing, or data exfiltration. "
                    "Requires further investigation."
                ),
                evidence={
                    "unique_destinations": len(dst_ips),
                    "destination_sample": sorted(dst_ips)[:20],
                    "reasons": reasons,
                },
                packet_numbers=[p.packet_number for p in pkts[:100]],
                timestamp_epoch=pkts[0].timestamp_epoch if pkts else None,
            ))

    # Check for connections to suspicious ports
    for src_ip, sus_pkts in src_suspicious_ports.items():
        if sus_pkts:
            sus_ports = list(set(p.dst_port for p in sus_pkts))
            risk_score = min(90, 50 + len(sus_ports) * 10)
            severity = _severity_from_score(risk_score)
            events.append(_make_event(
                analysis_id=analysis_id,
                event_type="SUSPICIOUS_OUTBOUND",
                source_ip=src_ip,
                destination_ip=sus_pkts[0].dst_ip or "unknown",
                protocol="TCP/UDP",
                severity=severity,
                confidence=0.7,
                risk_score=risk_score,
                description=(
                    f"{src_ip} connected to port(s) {sus_ports} which are "
                    "commonly associated with remote access tools, backdoors, or command-and-control. "
                    "Requires further investigation."
                ),
                evidence={
                    "suspicious_ports": sus_ports,
                    "connection_count": len(sus_pkts),
                    "destination_ips": list(set(p.dst_ip for p in sus_pkts))[:10],
                },
                packet_numbers=[p.packet_number for p in sus_pkts[:100]],
                timestamp_epoch=sus_pkts[0].timestamp_epoch if sus_pkts else None,
            ))

    logger.info("Suspicious outbound detection: %d events", len(events))
    return events


# ─── ICMP Anomaly Detector ────────────────────────────────────────────────────

def detect_icmp_anomalies(analysis_id: str) -> List[dict]:
    """Detect abnormal ICMP traffic patterns."""
    events = []
    icmp_pkts = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.protocol == "ICMP")
        .filter(Packet.src_ip.isnot(None))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    if not icmp_pkts:
        return events

    src_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in icmp_pkts:
        src_map[p.src_ip].append(p)

    for src_ip, pkts in src_map.items():
        for i, start_pkt in enumerate(pkts):
            if not start_pkt.timestamp_epoch:
                continue
            window = [p for p in pkts[i:]
                      if p.timestamp_epoch and
                      p.timestamp_epoch - start_pkt.timestamp_epoch <= config.ICMP_TIME_WINDOW]

            if len(window) >= config.ICMP_BURST_THRESHOLD:
                unique_dsts = set(p.dst_ip for p in window if p.dst_ip)
                risk_score = min(75, 40 + len(window) / 5)
                severity = _severity_from_score(risk_score)
                events.append(_make_event(
                    analysis_id=analysis_id,
                    event_type="ICMP_ANOMALY",
                    source_ip=src_ip,
                    destination_ip=f"{len(unique_dsts)} hosts",
                    protocol="ICMP",
                    severity=severity,
                    confidence=0.65,
                    risk_score=risk_score,
                    description=(
                        f"{len(window)} ICMP packets from {src_ip} within {config.ICMP_TIME_WINDOW}s "
                        f"targeting {len(unique_dsts)} host(s). "
                        "Could indicate ICMP sweep or flood."
                    ),
                    evidence={
                        "packet_count": len(window),
                        "unique_destinations": len(unique_dsts),
                        "time_window": config.ICMP_TIME_WINDOW,
                        "icmp_types": list(set(p.icmp_type for p in window if p.icmp_type is not None)),
                    },
                    packet_numbers=[p.packet_number for p in window],
                    timestamp_epoch=start_pkt.timestamp_epoch,
                ))
                break

    logger.info("ICMP anomaly detection: %d events", len(events))
    return events


# ─── HTTP Anomaly Detector ────────────────────────────────────────────────────

def detect_http_anomalies(analysis_id: str) -> List[dict]:
    """Detect suspicious HTTP traffic."""
    events = []
    http_pkts = (
        db.session.query(Packet)
        .filter_by(analysis_id=analysis_id)
        .filter(Packet.protocol == "HTTP")
        .filter(Packet.src_ip.isnot(None))
        .order_by(Packet.timestamp_epoch)
        .all()
    )

    if not http_pkts:
        return events

    src_map: Dict[str, List[Packet]] = defaultdict(list)
    for p in http_pkts:
        src_map[p.src_ip].append(p)

    for src_ip, pkts in src_map.items():
        reasons = []
        sus_method_pkts = []

        # High request frequency
        peak = max((sum(1 for p in pkts if p.http_method and p.timestamp_epoch is not None and start.timestamp_epoch is not None and 0 <= p.timestamp_epoch-start.timestamp_epoch <= config.HTTP_TIME_WINDOW) for start in pkts), default=0)
        if peak >= config.HTTP_REQUEST_THRESHOLD:
            reasons.append(f"High HTTP request volume: {peak} requests within {config.HTTP_TIME_WINDOW}s")

        # Suspicious methods
        for p in pkts:
            if p.http_method and p.http_method.upper() in config.SUSPICIOUS_HTTP_METHODS:
                sus_method_pkts.append(p)
                reasons.append(f"Suspicious HTTP method: {p.http_method}")

        if reasons:
            reasons = list(dict.fromkeys(reasons))[:5]
            confidence = min(0.8, 0.4 + len(reasons) * 0.1)
            risk_score = min(75, 35 + len(reasons) * 10)
            severity = _severity_from_score(risk_score)
            events.append(_make_event(
                analysis_id=analysis_id,
                event_type="HTTP_ANOMALY",
                source_ip=src_ip,
                destination_ip=pkts[0].dst_ip or "unknown",
                protocol="HTTP",
                severity=severity,
                confidence=confidence,
                risk_score=risk_score,
                description=f"Suspicious HTTP activity from {src_ip}. " + "; ".join(reasons[:2]),
                evidence={
                    "reasons": reasons,
                    "request_count": len(pkts),
                    "suspicious_method_packets": len(sus_method_pkts),
                    "hosts_contacted": list(set(p.http_host for p in pkts if p.http_host))[:10],
                },
                packet_numbers=[p.packet_number for p in pkts[:100]],
                timestamp_epoch=pkts[0].timestamp_epoch,
            ))

    logger.info("HTTP anomaly detection: %d events", len(events))
    return events


# ─── Main Detection Runner ────────────────────────────────────────────────────

def run_all_detectors(analysis_id: str) -> List[dict]:
    """Run all detection engines and return combined list of threat events."""
    all_events = []
    detectors = [
        ("Port Scan", detect_port_scans),
        ("SSH Brute Force", detect_ssh_brute_force),
        ("DNS Anomaly", detect_dns_anomalies),
        ("Suspicious Outbound", detect_suspicious_outbound),
        ("ICMP Anomaly", detect_icmp_anomalies),
        ("HTTP Anomaly", detect_http_anomalies),
    ]
    for name, detector_fn in detectors:
        try:
            events = detector_fn(analysis_id)
            all_events.extend(events)
            logger.info("%s detector returned %d events", name, len(events))
        except Exception as e:
            logger.error("Detector '%s' failed: %s", name, e, exc_info=True)

    return all_events
