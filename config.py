"""
config.py - Central configuration for PCAP Investigator
All thresholds and settings are centralized here for easy tuning.
"""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── Flask ───────────────────────────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY") or __import__('secrets').token_hex(32)
DEBUG = os.getenv("DEBUG", "False").lower() == "true"
HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))

# ─── Upload ───────────────────────────────────────────────────────────────────
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
REPORTS_FOLDER = os.path.join(BASE_DIR, "reports_output")
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", 200))
MAX_CONTENT_LENGTH = MAX_UPLOAD_MB * 1024 * 1024
ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

# ─── Database ─────────────────────────────────────────────────────────────────
DATABASE_PATH = os.path.join(BASE_DIR, "pcap_investigator.db")
DATABASE_URI = os.getenv("DATABASE_URL", f"sqlite:///{DATABASE_PATH}")

FLOW_WINDOW = int(os.getenv("FLOW_WINDOW", "60"))
FLOW_IDLE_TIMEOUT = int(os.getenv("FLOW_IDLE_TIMEOUT", "30"))
MODEL_FOLDER = os.path.join(BASE_DIR, "models_store")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "")
REPORT_AES_KEY = os.getenv("REPORT_AES_KEY", "")
SIGNING_KEY_PATH = os.getenv("SIGNING_KEY_PATH", "")
SIGNING_KEY_PASSWORD = os.getenv("SIGNING_KEY_PASSWORD", "")
SCHOOL_NETWORKS = os.getenv("SCHOOL_NETWORKS", "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12")

# ─── AI Provider ─────────────────────────────────────────────────────────────
# Options: "gemini" (default) | "openai" | "none"
AI_PROVIDER = os.getenv("AI_PROVIDER", "gemini").lower()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_KEY", "")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")

# ─── Port Scan Detection ──────────────────────────────────────────────────────
PORT_SCAN_UNIQUE_PORTS = int(os.getenv("PORT_SCAN_UNIQUE_PORTS", 10))
PORT_SCAN_TIME_WINDOW = int(os.getenv("PORT_SCAN_TIME_WINDOW", 60))      # seconds
PORT_SCAN_SYN_RATIO = float(os.getenv("PORT_SCAN_SYN_RATIO", 0.7))

# ─── SSH Brute Force Detection ────────────────────────────────────────────────
SSH_BRUTE_FORCE_ATTEMPTS = int(os.getenv("SSH_BRUTE_FORCE_ATTEMPTS", 10))
SSH_BRUTE_FORCE_TIME_WINDOW = int(os.getenv("SSH_BRUTE_FORCE_TIME_WINDOW", 120))  # seconds
SSH_PORT = int(os.getenv("SSH_PORT", 22))

# ─── DNS Anomaly Detection ────────────────────────────────────────────────────
DNS_QUERY_THRESHOLD = int(os.getenv("DNS_QUERY_THRESHOLD", 100))          # per minute
DNS_LONG_LABEL_LENGTH = int(os.getenv("DNS_LONG_LABEL_LENGTH", 40))
DNS_SUBDOMAIN_THRESHOLD = int(os.getenv("DNS_SUBDOMAIN_THRESHOLD", 50))
DNS_ENTROPY_THRESHOLD = float(os.getenv("DNS_ENTROPY_THRESHOLD", 3.8))
DNS_TIME_WINDOW = int(os.getenv("DNS_TIME_WINDOW", 60))

# ─── Suspicious Outbound ──────────────────────────────────────────────────────
OUTBOUND_CONNECTION_THRESHOLD = int(os.getenv("OUTBOUND_CONNECTION_THRESHOLD", 50))
OUTBOUND_TIME_WINDOW = int(os.getenv("OUTBOUND_TIME_WINDOW", 60))
SUSPICIOUS_PORTS = {
    4444, 4445, 5555, 6666, 7777, 8888, 9999,          # common shell/RAT ports
    1234, 31337, 12345, 54321,                           # common backdoor ports
    6667, 6668, 6669,                                    # IRC
    3389,                                                # RDP
}

# ─── ICMP Anomaly ─────────────────────────────────────────────────────────────
ICMP_BURST_THRESHOLD = int(os.getenv("ICMP_BURST_THRESHOLD", 50))
ICMP_TIME_WINDOW = int(os.getenv("ICMP_TIME_WINDOW", 10))

# ─── HTTP Anomaly ─────────────────────────────────────────────────────────────
HTTP_REQUEST_THRESHOLD = int(os.getenv("HTTP_REQUEST_THRESHOLD", 200))
HTTP_TIME_WINDOW = int(os.getenv("HTTP_TIME_WINDOW", 60))
SUSPICIOUS_HTTP_METHODS = {"CONNECT", "TRACE", "TRACK"}

# ─── Risk Scoring ─────────────────────────────────────────────────────────────
SEVERITY_WEIGHTS = {
    "CRITICAL": 90,
    "HIGH": 70,
    "MEDIUM": 45,
    "LOW": 20,
    "INFO": 5,
}

# ─── Pagination ───────────────────────────────────────────────────────────────
PACKETS_PER_PAGE = 50
EVENTS_PER_PAGE = 25

# ─── Logging ──────────────────────────────────────────────────────────────────
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FILE = os.path.join(BASE_DIR, "pcap_investigator.log")

# Ensure required directories exist
for _dir in [UPLOAD_FOLDER, REPORTS_FOLDER]:
    os.makedirs(_dir, exist_ok=True)
