"""
analysis/correlator.py - Event correlation engine.

Correlates related threat events from the same source IP within a time window
and assigns attack phases based on observed patterns.

Important: This module infers probable attack sequences.
It does NOT confirm that an attack succeeded.
"""

import logging
from collections import defaultdict
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Attack phase mappings
PHASE_MAP = {
    "PORT_SCAN": "RECONNAISSANCE",
    "ICMP_ANOMALY": "RECONNAISSANCE",
    "DNS_ANOMALY": "RECONNAISSANCE_OR_EXFILTRATION",
    "SSH_BRUTE_FORCE": "CREDENTIAL_ATTACK",
    "HTTP_ANOMALY": "EXPLOITATION_ATTEMPT",
    "SUSPICIOUS_OUTBOUND": "COMMAND_AND_CONTROL_OR_EXFILTRATION",
}

# Typical attack chain progression
ATTACK_CHAINS = [
    # Recon -> Brute Force -> C2
    ["PORT_SCAN", "SSH_BRUTE_FORCE", "SUSPICIOUS_OUTBOUND"],
    # Recon -> Exploitation
    ["PORT_SCAN", "HTTP_ANOMALY"],
    # DNS exfil chain
    ["DNS_ANOMALY", "SUSPICIOUS_OUTBOUND"],
    # ICMP recon -> brute force
    ["ICMP_ANOMALY", "SSH_BRUTE_FORCE"],
]

CORRELATION_TIME_WINDOW = 600  # 10 minutes


def correlate_events(events: List[dict]) -> List[dict]:
    """
    Group and correlate related threat events.
    Adds 'phase', 'correlation_group', and 'correlated_with' fields.
    Returns augmented event list.
    """
    if not events:
        return events

    # Add phase to each event
    for event in events:
        event["phase"] = PHASE_MAP.get(event.get("event_type", ""), "UNKNOWN")
        event["correlation_group"] = None
        event["correlated_with"] = []

    # Group by source IP
    src_map: Dict[str, List[dict]] = defaultdict(list)
    for i, event in enumerate(events):
        event["_idx"] = i
        src = event.get("source_ip") or "unknown"
        src_map[src].append(event)

    group_id = 0
    for src_ip, src_events in src_map.items():
        if len(src_events) < 2:
            continue

        # Sort by timestamp
        src_events.sort(key=lambda e: e.get("timestamp_epoch") or 0)

        # Check if events form a chain
        event_types = [e["event_type"] for e in src_events]
        for chain in ATTACK_CHAINS:
            if all(et in event_types for et in chain):
                group_id += 1
                group_name = f"CORR-{group_id:03d}"
                chain_events = [e for e in src_events if e["event_type"] in chain]
                timestamps = [e.get("timestamp_epoch") for e in chain_events]
                if any(t is None for t in timestamps) or max(timestamps)-min(timestamps) > CORRELATION_TIME_WINDOW:
                    continue
                first_by_type = {et: min(e["timestamp_epoch"] for e in chain_events if e["event_type"] == et) for et in chain}
                if [first_by_type[et] for et in chain] != sorted(first_by_type.values()):
                    continue
                for ce in chain_events:
                    ce["correlation_group"] = group_name
                    ce["correlated_with"] = [
                        other["event_type"] for other in chain_events
                        if other["_idx"] != ce["_idx"]
                    ]
                logger.info(
                    "Correlated attack chain %s for source %s: %s",
                    group_name, src_ip, " -> ".join(chain)
                )
                break

        # Also group any remaining events from same source within time window
        if len(src_events) >= 3:
            first_ts = src_events[0].get("timestamp_epoch") or 0
            last_ts = src_events[-1].get("timestamp_epoch") or 0
            if last_ts - first_ts <= CORRELATION_TIME_WINDOW:
                group_id += 1
                group_name = f"CORR-{group_id:03d}"
                for se in src_events:
                    if se["correlation_group"] is None:
                        se["correlation_group"] = group_name

    # Remove internal index
    for event in events:
        event.pop("_idx", None)

    return events


def get_attack_narrative(events: List[dict]) -> str:
    """
    Generate a brief attack narrative string from correlated events.
    This is an analyst inference based on observed patterns.
    """
    if not events:
        return "No threat events detected."

    phases = []
    seen_phases = set()
    sorted_events = sorted(events, key=lambda e: e.get("timestamp_epoch") or 0)

    for event in sorted_events:
        phase = event.get("phase", "UNKNOWN")
        if phase not in seen_phases:
            phases.append(phase)
            seen_phases.add(phase)

    if not phases:
        return "Threat events detected but narrative could not be determined."

    chain = " → ".join(phases)
    return f"Observed attack phase sequence (analyst inference): {chain}"
