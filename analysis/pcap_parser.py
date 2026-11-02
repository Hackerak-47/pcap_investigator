"""
analysis/pcap_parser.py - PCAP file parsing using PyShark
Extracts packet metadata and stores in SQLite via SQLAlchemy.
"""
#read pcap file and extract packet info
import logging
import os
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)


def _safe_get(pkt, *layers_and_field):
    """Safely extract a field from a PyShark packet without raising."""
    try:
        obj = pkt
        for attr in layers_and_field:
            obj = getattr(obj, attr)
        return str(obj)
    except Exception:
        return None


def _safe_int(val):
    try:
        return int(val)
    except Exception:
        return None


def _parse_timestamp(pkt):
    """Return (datetime, float_epoch) from packet sniff_time."""
    try:
        ts = float(pkt.sniff_timestamp)
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
        return dt, ts
    except Exception:
        return None, None


def _extract_packet_data(pkt, packet_number: int, analysis_id: str) -> dict:
    """Extract all useful fields from a single PyShark packet."""
    data = {
        "analysis_id": analysis_id,
        "packet_number": packet_number,
        "timestamp": None,
        "timestamp_epoch": None,
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": None,
        "packet_length": None,
        "tcp_flags": None,
        "dns_query": None,
        "dns_response": None,
        "http_host": None,
        "http_method": None,
        "http_uri": None,
        "tls_sni": None,
        "icmp_type": None,
        "icmp_code": None,
    }

    dt, ts = _parse_timestamp(pkt)
    data["timestamp"] = dt
    data["timestamp_epoch"] = ts

    # Ethernet
    if hasattr(pkt, "eth"):
        data["src_mac"] = _safe_get(pkt, "eth", "src")
        data["dst_mac"] = _safe_get(pkt, "eth", "dst")

    # IP
    if hasattr(pkt, "ip"):
        data["src_ip"] = _safe_get(pkt, "ip", "src")
        data["dst_ip"] = _safe_get(pkt, "ip", "dst")
        data["protocol"] = "IP"
    elif hasattr(pkt, "ipv6"):
        data["src_ip"] = _safe_get(pkt, "ipv6", "src")
        data["dst_ip"] = _safe_get(pkt, "ipv6", "dst")
        data["protocol"] = "IPv6"

    # Packet length
    try:
        data["packet_length"] = int(pkt.length)
    except Exception:
        pass

    # TCP
    if hasattr(pkt, "tcp"):
        data["protocol"] = "TCP"
        data["src_port"] = _safe_int(_safe_get(pkt, "tcp", "srcport"))
        data["dst_port"] = _safe_int(_safe_get(pkt, "tcp", "dstport"))
        # TCP flags as hex string e.g. '0x002'
        data["transport_protocol"] = "TCP"
        flags = _safe_get(pkt, "tcp", "flags")
        if flags:
            data["tcp_flags"] = flags

    # UDP
    elif hasattr(pkt, "udp"):
        data["protocol"] = "UDP"
        data["transport_protocol"] = "UDP"
        data["src_port"] = _safe_int(_safe_get(pkt, "udp", "srcport"))
        data["dst_port"] = _safe_int(_safe_get(pkt, "udp", "dstport"))

    # ICMP
    if hasattr(pkt, "icmp"):
        data["protocol"] = "ICMP"
        data["icmp_type"] = _safe_int(_safe_get(pkt, "icmp", "type"))
        data["icmp_code"] = _safe_int(_safe_get(pkt, "icmp", "code"))

    # DNS
    if hasattr(pkt, "dns"):
        if data["protocol"] not in ("ICMP",):
            data["protocol"] = "DNS"
        data["dns_is_response"] = _safe_get(pkt, "dns", "flags_response") == "1"
        qname = _safe_get(pkt, "dns", "qry_name")
        if qname:
            data["dns_query"] = qname[:512]
        rdata = _safe_get(pkt, "dns", "a")
        if rdata:
            data["dns_response"] = rdata[:512]

    # HTTP
    if hasattr(pkt, "http"):
        data["protocol"] = "HTTP"
        data["http_host"] = _safe_get(pkt, "http", "host")
        data["http_method"] = _safe_get(pkt, "http", "request_method")
        uri = _safe_get(pkt, "http", "request_uri")
        if uri:
            data["http_uri"] = uri[:512]

    # TLS
    if hasattr(pkt, "tls"):
        if data["protocol"] not in ("HTTP", "DNS", "ICMP"):
            data["protocol"] = "TLS"
        data["tls_handshake"] = _safe_get(pkt, "tls", "handshake_type")
        # Only ServerHello establishes negotiated protocol/cipher.
        if data["tls_handshake"] == "2":
            data["tls_version"] = (_safe_get(pkt, "tls", "handshake_extensions_supported_version") or _safe_get(pkt, "tls", "handshake_version"))
            data["tls_cipher"] = _safe_get(pkt, "tls", "handshake_ciphersuite")
        sni = _safe_get(pkt, "tls", "handshake_extensions_server_name")
        if sni:
            data["tls_sni"] = sni[:255]

    # ARP
    if hasattr(pkt, "arp"):
        data["protocol"] = "ARP"

    return data


def parse_pcap(filepath: str, analysis_id: str, app) -> dict:
    """
    Parse a PCAP file and insert extracted packet metadata into the database.

    Returns a summary dict with metadata about the capture.
    Raises RuntimeError if tshark is not found or file cannot be read.
    """
    import pyshark
    from database.database import db
    from database.models import Packet, Analysis

    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"PCAP file not found: {filepath}")

    logger.info("Parsing PCAP: %s (analysis_id=%s)", filepath, analysis_id)

    packets_data = []
    first_ts = None
    last_ts = None
    packet_count = 0
    BATCH_SIZE = 500

    try:
        cap = pyshark.FileCapture(
            filepath,
            use_json=True,
            include_raw=False,
            keep_packets=False,
        )

        for pkt in cap:
            try:
                packet_count += 1
                pkt_data = _extract_packet_data(pkt, packet_count, analysis_id)

                ts = pkt_data.get("timestamp_epoch")
                if ts is not None:
                    if first_ts is None or ts < first_ts:
                        first_ts = ts
                    if last_ts is None or ts > last_ts:
                        last_ts = ts

                packets_data.append(pkt_data)

                # Batch insert to avoid huge memory usage
                if len(packets_data) >= BATCH_SIZE:
                    _batch_insert(packets_data, app)
                    packets_data = []

            except Exception as pkt_err:
                logger.warning("Skipped malformed packet #%d: %s", packet_count, pkt_err)
                continue

        cap.close()

        # Insert remaining
        if packets_data:
            _batch_insert(packets_data, app)

    except Exception as e:
        error_msg = str(e)
        logger.warning("PyShark capture failed (%s). Attempting Scapy parser fallback...", error_msg)
        try:
            try:
                cap.close()
            except Exception:
                pass
            with app.app_context():
                db.session.rollback()
                db.session.query(Packet).filter_by(analysis_id=analysis_id).delete()
                db.session.commit()
            return _parse_pcap_scapy(filepath, analysis_id, app)
        except Exception as scapy_err:
            logger.error("Scapy parser also failed: %s", scapy_err, exc_info=True)
            if "tshark" in error_msg.lower() or "not found" in error_msg.lower():
                raise RuntimeError(
                    "PyShark failed (tshark not found) and Scapy parser failed: "
                    f"{scapy_err}"
                ) from e
            raise RuntimeError(f"Failed to parse PCAP file: {error_msg}") from e

    duration = 0.0
    if first_ts is not None and last_ts is not None:
        duration = last_ts - first_ts

    summary = {
        "packet_count": packet_count,
        "start_time": datetime.fromtimestamp(first_ts, tz=timezone.utc).replace(tzinfo=None) if first_ts else None,
        "end_time": datetime.fromtimestamp(last_ts, tz=timezone.utc).replace(tzinfo=None) if last_ts else None,
        "duration": duration,
    }

    logger.info("PCAP parsing complete: %d packets, %.2fs duration", packet_count, duration)
    return summary


def _extract_packet_data_scapy(pkt, packet_number: int, analysis_id: str) -> dict:
    """Extract packet fields from a Scapy packet matching the Packet schema."""
    from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, Raw

    data = {
        "analysis_id": analysis_id,
        "packet_number": packet_number,
        "timestamp": None,
        "timestamp_epoch": None,
        "src_mac": None,
        "dst_mac": None,
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
        "protocol": "OTHER",
        "packet_length": len(pkt),
        "tcp_flags": None,
        "dns_query": None,
        "dns_response": None,
        "http_host": None,
        "http_method": None,
        "http_uri": None,
        "tls_sni": None,
        "icmp_type": None,
        "icmp_code": None,
    }

    try:
        ts = float(pkt.time)
        data["timestamp_epoch"] = ts
        data["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc).replace(tzinfo=None)
    except Exception:
        pass

    if Ether in pkt:
        data["src_mac"] = pkt[Ether].src
        data["dst_mac"] = pkt[Ether].dst

    if IP in pkt:
        data["src_ip"] = pkt[IP].src
        data["dst_ip"] = pkt[IP].dst
        data["protocol"] = "IP"
    elif IPv6 in pkt:
        data["src_ip"] = pkt[IPv6].src
        data["dst_ip"] = pkt[IPv6].dst
        data["protocol"] = "IPv6"

    if TCP in pkt:
        data["protocol"] = "TCP"
        data["src_port"] = int(pkt[TCP].sport)
        data["dst_port"] = int(pkt[TCP].dport)
        data["tcp_flags"] = f"0x{int(pkt[TCP].flags):03x}"
        data["transport_protocol"] = "TCP"
    elif UDP in pkt:
        data["protocol"] = "UDP"
        data["transport_protocol"] = "UDP"
        data["src_port"] = int(pkt[UDP].sport)
        data["dst_port"] = int(pkt[UDP].dport)

    if ICMP in pkt:
        data["protocol"] = "ICMP"
        data["icmp_type"] = int(pkt[ICMP].type)
        data["icmp_code"] = int(pkt[ICMP].code)

    if DNS in pkt:
        data["dns_is_response"] = bool(pkt[DNS].qr)
        if data["protocol"] != "ICMP":
            data["protocol"] = "DNS"
        if DNSQR in pkt:
            try:
                qname = pkt[DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="ignore").rstrip(".")
                data["dns_query"] = str(qname)[:512]
            except Exception:
                pass
        if DNSRR in pkt:
            try:
                rdata = pkt[DNSRR].rdata
                if isinstance(rdata, bytes):
                    rdata = rdata.decode("utf-8", errors="ignore")
                data["dns_response"] = str(rdata)[:512]
            except Exception:
                pass

    # Scapy can decode complete TLS records without decrypting application data.
    if TCP in pkt and Raw in pkt:
        try:
            from scapy.layers.tls.record import TLS
            from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
            raw = bytes(pkt[Raw].load)
            if len(raw) >= 5 and raw[0] in (20, 21, 22, 23) and raw[1] == 3:
                record = TLS(raw)
                data["protocol"] = "TLS"
                if TLSServerHello in record:
                    hello = record[TLSServerHello]
                    data["tls_handshake"] = "2"
                    version = int(hello.version)
                    for extension in hello.ext or []:
                        if getattr(extension, "type", None) == 43 and getattr(extension, "version", None):
                            version = int(extension.version)
                    data["tls_version"] = f"0x{version:04x}"
                    data["tls_cipher"] = f"0x{int(hello.cipher):04x}"
                elif TLSClientHello in record:
                    data["tls_handshake"] = "1"
                    for extension in record[TLSClientHello].ext or []:
                        names = getattr(extension, "servernames", None)
                        if names:
                            data["tls_sni"] = bytes(names[0].servername).decode("ascii", errors="replace")[:255]
        except Exception:
            pass  # Partial records remain unknown; no protocol weakness is inferred.

    if Raw in pkt:
        raw_bytes = bytes(pkt[Raw].load)
        try:
            header_part = raw_bytes.split(b"\r\n\r\n")[0].decode("latin-1", errors="ignore")
            lines = header_part.split("\r\n")
            first_line = lines[0] if lines else ""
            parts = first_line.split(" ")
            if len(parts) >= 2 and parts[0] in (
                "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH",
                "TRACE", "CONNECT", "TRACK"
            ):
                data["protocol"] = "HTTP"
                data["http_method"] = parts[0]
                data["http_uri"] = parts[1][:512]
                for line in lines[1:]:
                    if line.lower().startswith("host:"):
                        data["http_host"] = line.split(":", 1)[1].strip()[:255]
                        break
        except Exception:
            pass

    return data


def _parse_pcap_scapy(filepath: str, analysis_id: str, app) -> dict:
    """Dissect PCAP using Scapy when PyShark/tshark is unavailable."""
    from scapy.all import PcapReader

    logger.info("Parsing PCAP via Scapy fallback: %s (analysis_id=%s)", filepath, analysis_id)
    packets_data = []
    first_ts = None
    last_ts = None
    packet_count = 0
    BATCH_SIZE = 500

    with PcapReader(filepath) as reader:
        for pkt in reader:
            try:
                packet_count += 1
                pkt_data = _extract_packet_data_scapy(pkt, packet_count, analysis_id)

                ts = pkt_data.get("timestamp_epoch")
                if ts is not None:
                    if first_ts is None or ts < first_ts:
                        first_ts = ts
                    if last_ts is None or ts > last_ts:
                        last_ts = ts

                packets_data.append(pkt_data)

                if len(packets_data) >= BATCH_SIZE:
                    _batch_insert(packets_data, app)
                    packets_data = []
            except Exception as pkt_err:
                logger.warning("Scapy skipped malformed packet #%d: %s", packet_count, pkt_err)
                continue

    if packets_data:
        _batch_insert(packets_data, app)

    duration = 0.0
    if first_ts is not None and last_ts is not None:
        duration = last_ts - first_ts

    summary = {
        "packet_count": packet_count,
        "start_time": datetime.fromtimestamp(first_ts, tz=timezone.utc).replace(tzinfo=None) if first_ts else None,
        "end_time": datetime.fromtimestamp(last_ts, tz=timezone.utc).replace(tzinfo=None) if last_ts else None,
        "duration": duration,
    }

    logger.info("Scapy PCAP parsing complete: %d packets, %.2fs duration", packet_count, duration)
    return summary


def _batch_insert(packets_data: list, app):
    """Bulk insert packet records."""
    from database.database import db
    from database.models import Packet

    with app.app_context():
        db.session.bulk_insert_mappings(Packet, packets_data)
        db.session.commit()
