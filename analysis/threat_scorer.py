"""
analysis/threat_scorer.py - Risk scoring for detected threat events.

Scoring methodology (documented):
  Base score: from event type and initial detection severity
  Modifiers:
    +10 if confidence >= 0.8
    +5 per additional corroborating indicator
    +10 if multiple targets are involved
    +15 if temporal concentration is high (many events in short time)
    -10 if confidence <= 0.3 (low-confidence observation)

Final score capped at 0-100.
Severity labels:
  CRITICAL: 80-100
  HIGH:     60-79
  MEDIUM:   30-59
  LOW:       0-29
"""

import logging
from typing import List
import config

logger = logging.getLogger(__name__)

# Base risk scores per event type
BASE_SCORES = {
    "PORT_SCAN": 55,
    "SSH_BRUTE_FORCE": 65,
    "DNS_ANOMALY": 40,
    "SUSPICIOUS_OUTBOUND": 50,
    "ICMP_ANOMALY": 35,
    "HTTP_ANOMALY": 40,
}


def compute_risk_score(event: dict) -> float:
    """
    Compute a final risk score for a threat event.
    Returns a float 0-100.
    """
    event_type = event.get("event_type", "UNKNOWN")
    confidence = event.get("confidence", 0.5)
    existing_score = event.get("risk_score", 0)
    evidence = event.get("evidence", {})
    if isinstance(evidence, str):
        import json
        try:
            evidence = json.loads(evidence)
        except Exception:
            evidence = {}

    # Start from existing score (set by detector) or base
    score = existing_score if existing_score > 0 else BASE_SCORES.get(event_type, 50)

    # Confidence modifier
    if confidence >= 0.8:
        score += 10
    elif confidence <= 0.3:
        score -= 10

    # Evidence depth modifier
    port_count = evidence.get("unique_ports_count", 0)
    if port_count >= 100:
        score += 15
    elif port_count >= 50:
        score += 10
    elif port_count >= 20:
        score += 5

    attempt_count = evidence.get("attempt_count", 0)
    if attempt_count >= 100:
        score += 15
    elif attempt_count >= 50:
        score += 10

    unique_dests = evidence.get("unique_destinations", 0)
    if unique_dests >= 100:
        score += 10
    elif unique_dests >= 20:
        score += 5

    reasons_count = len(evidence.get("reasons", []))
    score += reasons_count * 3

    return max(0.0, min(100.0, round(score, 1)))


def severity_label(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def rescore_events(events: List[dict]) -> List[dict]:
    """Apply final scoring pass to a list of events."""
    for event in events:
        score = compute_risk_score(event)
        event["risk_score"] = score
        event["severity"] = severity_label(score)
    return events
