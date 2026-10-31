"""
analysis/timeline_builder.py - Build attack timeline from threat events.
"""

import logging
from datetime import datetime, timezone
from typing import List
from database.database import db
from database.models import TimelineEvent, ThreatEvent

logger = logging.getLogger(__name__)

# Mapping of event types to human-readable titles
EVENT_TITLES = {
    "PORT_SCAN": "Port Scan Detected",
    "SSH_BRUTE_FORCE": "SSH Brute Force Attempt",
    "DNS_ANOMALY": "DNS Anomaly Detected",
    "SUSPICIOUS_OUTBOUND": "Suspicious Outbound Traffic",
    "ICMP_ANOMALY": "ICMP Anomaly Detected",
    "HTTP_ANOMALY": "HTTP Anomaly Detected",
}

PHASE_MAP = {
    "PORT_SCAN": "RECONNAISSANCE",
    "ICMP_ANOMALY": "RECONNAISSANCE",
    "DNS_ANOMALY": "INFORMATION_GATHERING",
    "SSH_BRUTE_FORCE": "CREDENTIAL_ATTACK",
    "HTTP_ANOMALY": "EXPLOITATION_ATTEMPT",
    "SUSPICIOUS_OUTBOUND": "SUSPICIOUS_COMMUNICATION",
}


def build_timeline(analysis_id: str, threat_events: List[ThreatEvent]) -> List[TimelineEvent]:
    """
    Convert stored ThreatEvent records into TimelineEvent records.
    Returns list of TimelineEvent objects (not yet committed).
    """
    timeline_events = []
    sorted_events = sorted(threat_events, key=lambda e: e.timestamp_epoch or 0)

    for i, te in enumerate(sorted_events):
        title = EVENT_TITLES.get(te.event_type, te.event_type.replace("_", " ").title())
        phase = PHASE_MAP.get(te.event_type, "UNKNOWN")

        tle = TimelineEvent(
            analysis_id=analysis_id,
            timestamp=te.timestamp,
            timestamp_epoch=te.timestamp_epoch,
            sequence_order=i + 1,
            event_type=te.event_type,
            phase=phase,
            title=title,
            description=te.description,
            severity=te.severity,
            source_ip=te.source_ip,
            destination_ip=te.destination_ip,
            threat_event_id=te.id,
            is_inferred=False,
        )
        timeline_events.append(tle)

    # Add inferred timeline entries for correlation
    src_event_types = {}
    for te in sorted_events:
        if te.source_ip not in src_event_types:
            src_event_types[te.source_ip] = []
        src_event_types[te.source_ip].append(te.event_type)

    for src_ip, etypes in src_event_types.items():
        if "PORT_SCAN" in etypes and "SSH_BRUTE_FORCE" in etypes:
            # Add inferred phase between recon and brute force
            scan_event = next((te for te in sorted_events
                               if te.source_ip == src_ip and te.event_type == "PORT_SCAN"), None)
            ssh_event = next((te for te in sorted_events
                              if te.source_ip == src_ip and te.event_type == "SSH_BRUTE_FORCE"), None)

            if scan_event and ssh_event and scan_event.timestamp_epoch is not None and ssh_event.timestamp_epoch is not None and 0 <= ssh_event.timestamp_epoch - scan_event.timestamp_epoch <= 600 and scan_event.destination_ip == ssh_event.destination_ip:
                mid_ts_epoch = None
                mid_ts = None
                if scan_event.timestamp_epoch and ssh_event.timestamp_epoch:
                    mid_ts_epoch = (scan_event.timestamp_epoch + ssh_event.timestamp_epoch) / 2
                    mid_ts = datetime.fromtimestamp(mid_ts_epoch, tz=timezone.utc).replace(tzinfo=None)

                inferred = TimelineEvent(
                    analysis_id=analysis_id,
                    timestamp=mid_ts,
                    timestamp_epoch=mid_ts_epoch,
                    sequence_order=999,  # will be re-sorted
                    event_type="SERVICE_IDENTIFIED",
                    phase="TARGET_IDENTIFICATION",
                    title="Target Service Identified (Inferred)",
                    description=(
                        f"Based on the port scan followed by SSH brute force from {src_ip}, "
                        "the analyst infers that the source identified SSH (port 22) as an accessible service. "
                        "NOTE: This is an analyst inference, not a directly observed event."
                    ),
                    severity="MEDIUM",
                    source_ip=src_ip,
                    destination_ip=ssh_event.destination_ip,
                    is_inferred=True,
                )
                timeline_events.append(inferred)

    # Re-sort and renumber
    timeline_events.sort(key=lambda e: e.timestamp_epoch or 0)
    for i, tle in enumerate(timeline_events):
        tle.sequence_order = i + 1

    return timeline_events
