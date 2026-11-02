"""
ai/investigator.py - AI-assisted investigation module.
ai report
Supports gemini-compatible LLM API (when API key configured).
Falls back to deterministic rule-based summary if no API key.
"""

import json
import logging
from datetime import datetime
from typing import List, Optional

import config
from ai.prompts import SYSTEM_PROMPT, INVESTIGATION_PROMPT_TEMPLATE

logger = logging.getLogger(__name__)


def _format_metadata(analysis) -> str:
    return json.dumps({
        "filename": analysis.original_filename,
        "packet_count": analysis.packet_count,
        "duration_seconds": analysis.duration,
        "start_time": analysis.start_time.isoformat() if analysis.start_time else None,
        "end_time": analysis.end_time.isoformat() if analysis.end_time else None,
        "analysis_id": analysis.id,
    }, indent=2)


def _format_threats(threat_events) -> str:
    events = []
    for te in threat_events:
        d = te.to_dict() if hasattr(te, 'to_dict') else te
        events.append({
            "type": d.get("event_type"),
            "severity": d.get("severity"),
            "risk_score": d.get("risk_score"),
            "source_ip": d.get("source_ip"),
            "destination_ip": d.get("destination_ip"),
            "description": d.get("description"),
            "confidence": d.get("confidence"),
            "timestamp": d.get("timestamp"),
            "evidence": d.get("evidence"),
            "packet_numbers": d.get("packet_numbers"),
        })
    return json.dumps(events, indent=2, default=str)


def _format_timeline(timeline_events) -> str:
    tl = []
    for te in timeline_events:
        d = te.to_dict() if hasattr(te, 'to_dict') else te
        tl.append({
            "order": d.get("sequence_order"),
            "phase": d.get("phase"),
            "title": d.get("title"),
            "timestamp": d.get("timestamp"),
            "evidence": d.get("evidence"),
            "packet_numbers": d.get("packet_numbers"),
            "severity": d.get("severity"),
            "is_inferred": d.get("is_inferred", False),
        })
    return json.dumps(tl, indent=2, default=str)


def generate_investigation(
    analysis,
    threat_events,
    timeline_events,
    traffic_stats: dict,
) -> dict:
    """
    Generate an investigation report.
    Uses OpenAI API if configured, otherwise deterministic fallback.
    Returns a dict with investigation fields.
    """
    if config.AI_PROVIDER == "openai" and config.OPENAI_API_KEY:
        try:
            return _generate_with_openai(analysis, threat_events, timeline_events, traffic_stats)
        except Exception as e:
            logger.error("OpenAI API call failed: %s — falling back to deterministic", e)

    return _generate_deterministic(analysis, threat_events, timeline_events, traffic_stats)


def _generate_with_openai(
    analysis,
    threat_events,
    timeline_events,
    traffic_stats: dict,
) -> dict:
    """Call OpenAI-compatible API to generate investigation."""
    from openai import OpenAI

    client = OpenAI(
        api_key=config.OPENAI_API_KEY,
        base_url=config.OPENAI_BASE_URL,
        timeout=25,
        max_retries=1,
    )

    prompt = INVESTIGATION_PROMPT_TEMPLATE.format(
        metadata=_format_metadata(analysis),
        threat_events=_format_threats(threat_events),
        timeline=_format_timeline(timeline_events),
        traffic_stats=json.dumps(traffic_stats, indent=2, default=str),
    )

    response = client.chat.completions.create(
        model=config.OPENAI_MODEL,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=0.3,
        response_format={"type": "json_object"},
        max_tokens=3000,
    )

    raw = response.choices[0].message.content
    result = json.loads(raw)
    required = {"executive_summary": str, "attack_hypothesis": str, "findings": list, "affected_hosts": list, "risk_assessment": str, "recommendations": list, "evidence_observed": list, "evidence_inferred": list}
    if not isinstance(result, dict) or any(not isinstance(result.get(k), t) for k, t in required.items()):
        raise ValueError("Invalid investigation response schema")
    result["ai_generated"] = True
    result["ai_model"] = config.OPENAI_MODEL
    return result


def _generate_deterministic(
    analysis,
    threat_events,
    timeline_events,
    traffic_stats: dict,
) -> dict:
    """
    Deterministic fallback investigation generator.
    Produces a structured report from detected evidence without an AI API.
    """
    events = [te.to_dict() if hasattr(te, 'to_dict') else te for te in threat_events]
    tl_items = [te.to_dict() if hasattr(te, 'to_dict') else te for te in timeline_events]

    critical = [e for e in events if e.get("severity") == "CRITICAL"]
    high = [e for e in events if e.get("severity") == "HIGH"]
    medium = [e for e in events if e.get("severity") == "MEDIUM"]

    # Executive Summary
    total_events = len(events)
    unique_sources = list(set(e.get("source_ip") for e in events if e.get("source_ip")))
    event_types = list(set(e.get("event_type") for e in events))

    if total_events == 0:
        exec_summary = (
            f"Analysis of {analysis.original_filename} completed. "
            "No significant threat indicators were detected in this PCAP capture. "
            f"The capture contains {analysis.packet_count} packets over {analysis.duration:.1f} seconds. "
            "The traffic appears to show normal network activity based on the applied detection rules. "
            "This does not guarantee the absence of threats; manual review is recommended."
        )
    else:
        exec_summary = (
            f"Analysis of '{analysis.original_filename}' ({analysis.packet_count} packets, "
            f"{analysis.duration:.1f}s duration) identified {total_events} threat indicator(s) "
            f"involving {len(unique_sources)} source IP(s). "
        )
        if critical:
            exec_summary += f"{len(critical)} CRITICAL-severity event(s) require immediate attention. "
        if high:
            exec_summary += f"{len(high)} HIGH-severity event(s) were detected. "
        exec_summary += (
            "The detected patterns are consistent with suspicious network activity and warrant "
            "further investigation. "
            "NOTE: This report was generated using rule-based analysis without AI assistance."
        )

    # Attack Hypothesis
    if not events:
        hypothesis = "No suspicious patterns were detected that suggest a specific attack sequence."
    else:
        phases_seen = []
        if "PORT_SCAN" in event_types or "ICMP_ANOMALY" in event_types:
            phases_seen.append("Reconnaissance (scanning activity observed)")
        if "SSH_BRUTE_FORCE" in event_types:
            phases_seen.append("Credential Attack (SSH brute force observed)")
        if "HTTP_ANOMALY" in event_types:
            phases_seen.append("Exploitation Attempt (HTTP anomalies observed)")
        if "DNS_ANOMALY" in event_types:
            phases_seen.append("Possible Information Gathering or DNS-based Exfiltration")
        if "SUSPICIOUS_OUTBOUND" in event_types:
            phases_seen.append("Post-Compromise Activity or Command-and-Control (possible)")

        if phases_seen:
            hypothesis = (
                "Based on the correlated evidence, the most likely attack sequence is: \n" +
                " → ".join(phases_seen) +
                ".\n\nIMPORTANT: This hypothesis is based on observed network patterns and analyst inference. "
                "It does not confirm a successful compromise. Further investigation of endpoint logs, "
                "authentication records, and firewall logs is required."
            )
        else:
            hypothesis = "Suspicious activity detected, but insufficient correlated evidence to reconstruct a specific attack chain."

    # Findings
    findings = []
    event_type_groups = {}
    for e in events:
        et = e.get("event_type", "UNKNOWN")
        if et not in event_type_groups:
            event_type_groups[et] = []
        event_type_groups[et].append(e)

    finding_templates = {
        "PORT_SCAN": (
            "Port Scanning Activity Detected",
            "One or more source IPs were observed connecting to an unusually large number of destination ports. "
            "This is consistent with port scanning behavior, which is commonly used during the reconnaissance "
            "phase of an intrusion attempt to identify open services."
        ),
        "SSH_BRUTE_FORCE": (
            "SSH Brute Force Attempts Detected",
            "Repeated connection attempts to TCP port 22 (SSH) were observed from one or more source IPs. "
            "This pattern is consistent with automated credential stuffing or brute force attacks against "
            "SSH services. A successful brute force would require access to authentication logs for confirmation."
        ),
        "DNS_ANOMALY": (
            "DNS Traffic Anomalies Detected",
            "Unusual DNS query patterns were observed, including high query rates, long domain labels, or "
            "algorithmically random-looking domain names. These patterns may indicate DNS-based "
            "command-and-control communication or data exfiltration via DNS tunneling. "
            "Further investigation of DNS logs is recommended."
        ),
        "SUSPICIOUS_OUTBOUND": (
            "Suspicious Outbound Traffic Detected",
            "Internal hosts were observed communicating with an unusually large number of external destinations "
            "or connecting to ports commonly associated with remote access or command-and-control activity. "
            "This may indicate a compromised host or unauthorized software. Endpoint investigation is recommended."
        ),
        "ICMP_ANOMALY": (
            "ICMP Traffic Anomaly Detected",
            "An abnormal volume of ICMP packets was observed from one or more source IPs. "
            "This may indicate ICMP-based network sweeping or a flood condition."
        ),
        "HTTP_ANOMALY": (
            "HTTP Traffic Anomaly Detected",
            "Suspicious HTTP traffic patterns were observed, including unusual request methods or "
            "high request volumes. This may indicate web scanning or exploitation attempts."
        ),
    }

    for et, evts in event_type_groups.items():
        title, detail = finding_templates.get(et, (et, "Suspicious activity detected."))
        max_risk = max(e.get("risk_score", 0) for e in evts)
        sev = evts[0].get("severity", "MEDIUM")
        findings.append({
            "title": title,
            "detail": detail,
            "severity": sev,
            "risk_score": max_risk,
            "event_count": len(evts),
            "source_ips": list(set(e.get("source_ip") for e in evts if e.get("source_ip"))),
        })

    # Affected hosts
    affected_hosts = []
    all_src = set(e.get("source_ip") for e in events if e.get("source_ip"))
    all_dst = set(e.get("destination_ip") for e in events if e.get("destination_ip"))
    for ip in all_src:
        affected_hosts.append({
            "ip": ip,
            "role": "suspected threat source",
            "notes": "IP appeared as source of suspicious activity. "
                    "This does not confirm malicious intent without additional investigation."
        })
    for ip in all_dst:
        if ip and ip not in all_src and not ip.startswith("DNS"):
            affected_hosts.append({
                "ip": str(ip)[:45],
                "role": "potential target",
                "notes": "IP appeared as destination of suspicious traffic."
            })

    # Risk Assessment
    if not events:
        risk_assessment = "Overall risk level: LOW. No significant threat indicators detected."
    elif critical:
        risk_assessment = (
            f"Overall risk level: CRITICAL. {len(critical)} critical-severity indicator(s) detected. "
            "Immediate investigation is recommended. Isolation of suspected hosts should be considered "
            "pending investigation."
        )
    elif high:
        risk_assessment = (
            f"Overall risk level: HIGH. {len(high)} high-severity indicator(s) detected. "
            "Prompt investigation of affected hosts is recommended."
        )
    else:
        risk_assessment = (
            f"Overall risk level: MEDIUM. {total_events} suspicious indicator(s) detected. "
            "Investigation is recommended to determine the nature and intent of the observed activity."
        )

    # Recommendations
    recommendations = []
    if "PORT_SCAN" in event_types:
        recommendations.append({
            "action": "Investigate Source of Port Scan",
            "detail": f"Review firewall logs for connections from scanning source IP(s): {unique_sources[:3]}. "
                     "Consider blocking if scan is confirmed as malicious after investigation.",
            "priority": "HIGH"
        })
    if "SSH_BRUTE_FORCE" in event_types:
        recommendations.append({
            "action": "Review SSH Authentication Logs",
            "detail": "Check /var/log/auth.log or equivalent for failed authentication attempts. "
                     "Verify that no successful logins occurred from suspicious sources. "
                     "Consider implementing fail2ban or SSH key-based authentication.",
            "priority": "IMMEDIATE"
        })
    if "DNS_ANOMALY" in event_types:
        recommendations.append({
            "action": "Inspect DNS Logs",
            "detail": "Review DNS server logs for the queried domains. "
                     "Check against threat intelligence feeds. "
                     "Consider DNS monitoring or RPZ (Response Policy Zone) implementation.",
            "priority": "HIGH"
        })
    if "SUSPICIOUS_OUTBOUND" in event_types:
        recommendations.append({
            "action": "Investigate Affected Endpoint",
            "detail": "Perform endpoint investigation on the source host. "
                     "Review running processes, network connections, and recently installed software. "
                     "Consider network isolation pending investigation.",
            "priority": "IMMEDIATE"
        })
    recommendations.append({
        "action": "Review Firewall Rules",
        "detail": "Ensure firewall rules are correctly configured to limit exposure of internal services. "
                 "Block unnecessary inbound connections to sensitive ports.",
        "priority": "MEDIUM"
    })
    recommendations.append({
        "action": "Manual PCAP Review in Wireshark",
        "detail": "Validate findings by reviewing the original PCAP in Wireshark using the suggested "
                 "display filters provided in the threat events section.",
        "priority": "HIGH"
    })

    # Evidence separation
    evidence_observed = []
    evidence_inferred = []

    for e in events:
        desc = e.get("description", "")
        evidence_observed.append(
            f"[{e.get('event_type')}] {desc[:200]}"
        )

    if "PORT_SCAN" in event_types and "SSH_BRUTE_FORCE" in event_types:
        evidence_inferred.append(
            "The progression from port scan to SSH brute force suggests the attacker "
            "identified SSH as an accessible service and subsequently attempted credential access. "
            "This is an analyst inference — it is possible these events are unrelated."
        )
    if "SUSPICIOUS_OUTBOUND" in event_types:
        evidence_inferred.append(
            "Suspicious outbound connections may indicate a compromised host communicating "
            "with command-and-control infrastructure. "
            "This is an analyst inference that requires endpoint investigation to confirm."
        )
    if "DNS_ANOMALY" in event_types:
        evidence_inferred.append(
            "DNS anomalies may indicate DNS tunneling or C2 communication. "
            "This is an analyst inference — legitimate software can also generate unusual DNS patterns."
        )

    return {
        "executive_summary": exec_summary,
        "attack_hypothesis": hypothesis,
        "findings": findings,
        "affected_hosts": affected_hosts,
        "risk_assessment": risk_assessment,
        "recommendations": recommendations,
        "evidence_observed": evidence_observed,
        "evidence_inferred": evidence_inferred,
        "ai_generated": False,
        "ai_model": "rule-based-fallback",
    }
