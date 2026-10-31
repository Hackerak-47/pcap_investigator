"""
utils/helpers.py - Utility functions used throughout the application.
"""


def format_bytes(num_bytes: int) -> str:
    """Human-readable byte size."""
    if num_bytes is None:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if num_bytes < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def format_duration(seconds: float) -> str:
    """Human-readable duration from seconds."""
    if seconds is None:
        return "0s"
    if seconds < 60:
        return f"{seconds:.2f}s"
    if seconds < 3600:
        minutes = int(seconds // 60)
        secs = seconds % 60
        return f"{minutes}m {secs:.0f}s"
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    return f"{hours}h {minutes}m"


def severity_badge_class(severity: str) -> str:
    """Return Bootstrap badge class for a severity level."""
    mapping = {
        "CRITICAL": "badge-critical",
        "HIGH": "badge-high",
        "MEDIUM": "badge-medium",
        "LOW": "badge-low",
        "INFO": "badge-info",
    }
    return mapping.get(str(severity).upper(), "badge-secondary")


def get_wireshark_filter(event_type: str, source_ip: str, destination_ip: str,
                          src_port: str = None, dst_port: str = None) -> str:
    """Generate a Wireshark display filter for an event."""
    filters = []

    if source_ip and not source_ip.startswith("DNS") and "hosts" not in str(source_ip):
        filters.append(f"ip.addr == {source_ip}")

    if event_type == "PORT_SCAN":
        filters = [f"ip.src == {source_ip}"] if source_ip else []
        if destination_ip and "hosts" not in str(destination_ip):
            filters.append(f"ip.dst == {destination_ip}")
        filters.append("tcp.flags.syn == 1 && tcp.flags.ack == 0")

    elif event_type == "SSH_BRUTE_FORCE":
        filters = []
        if source_ip:
            filters.append(f"ip.src == {source_ip}")
        filters.append("tcp.port == 22")

    elif event_type == "DNS_ANOMALY":
        filters = []
        if source_ip:
            filters.append(f"ip.src == {source_ip}")
        filters.append("dns")

    elif event_type == "ICMP_ANOMALY":
        filters = []
        if source_ip:
            filters.append(f"ip.src == {source_ip}")
        filters.append("icmp")

    elif event_type == "HTTP_ANOMALY":
        filters = []
        if source_ip:
            filters.append(f"ip.src == {source_ip}")
        filters.append("http")

    elif event_type == "SUSPICIOUS_OUTBOUND":
        filters = []
        if source_ip:
            filters.append(f"ip.src == {source_ip}")

    return " && ".join(filters) if filters else f"ip.addr == {source_ip or '0.0.0.0'}"


def risk_score_color(score: float) -> str:
    """CSS color class for a risk score."""
    if score >= 80:
        return "text-critical"
    if score >= 60:
        return "text-high"
    if score >= 30:
        return "text-medium"
    return "text-low"


def truncate(text: str, max_len: int = 80) -> str:
    if not text:
        return ""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "..."
