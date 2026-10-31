"""
analysis/traffic_analyzer.py - High-level traffic statistics
"""

import logging
from collections import Counter
from database.database import db
from database.models import Packet

logger = logging.getLogger(__name__)


def get_traffic_stats(analysis_id: str) -> dict:
    """
    Compute aggregate traffic statistics for an analysis.
    Returns protocol distribution, top IPs, top ports, etc.
    """
    packets = db.session.query(Packet).filter_by(analysis_id=analysis_id).all()

    if not packets:
        return _empty_stats()

    protocol_counter = Counter()
    src_ip_counter = Counter()
    dst_ip_counter = Counter()
    dst_port_counter = Counter()
    src_ips = set()
    dst_ips = set()
    total_bytes = 0

    for p in packets:
        proto = p.protocol or "UNKNOWN"
        protocol_counter[proto] += 1

        if p.src_ip:
            src_ip_counter[p.src_ip] += 1
            src_ips.add(p.src_ip)
        if p.dst_ip:
            dst_ip_counter[p.dst_ip] += 1
            dst_ips.add(p.dst_ip)
        if p.dst_port:
            dst_port_counter[p.dst_port] += 1
        if p.packet_length:
            total_bytes += p.packet_length

    return {
        "protocol_distribution": dict(protocol_counter.most_common(10)),
        "top_src_ips": dict(src_ip_counter.most_common(10)),
        "top_dst_ips": dict(dst_ip_counter.most_common(10)),
        "top_dst_ports": {str(k): v for k, v in dst_port_counter.most_common(10)},
        "unique_src_ips": len(src_ips),
        "unique_dst_ips": len(dst_ips),
        "total_bytes": total_bytes,
        "src_ip_list": sorted(src_ips),
        "dst_ip_list": sorted(dst_ips),
    }


def _empty_stats() -> dict:
    return {
        "protocol_distribution": {},
        "top_src_ips": {},
        "top_dst_ips": {},
        "top_dst_ports": {},
        "unique_src_ips": 0,
        "unique_dst_ips": 0,
        "total_bytes": 0,
        "src_ip_list": [],
        "dst_ip_list": [],
    }
