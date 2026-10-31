"""
utils/validators.py - Input validation and security utilities.
"""

import os
import re
import uuid
import logging

logger = logging.getLogger(__name__)

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}
MAX_FILENAME_LENGTH = 200


def validate_pcap_file(filepath: str, max_mb: int = 200) -> tuple:
    """
    Validate that a file is an acceptable PCAP for analysis.
    Returns (is_valid: bool, error_message: str).
    """
    if not os.path.isfile(filepath):
        return False, "File not found."

    size = os.path.getsize(filepath)
    max_bytes = max_mb * 1024 * 1024
    if size > max_bytes:
        return False, f"File too large. Maximum allowed size is {max_mb} MB."

    if size < 24:
        return False, "File is empty or has a truncated capture header."

    # Check file magic bytes
    try:
        with open(filepath, "rb") as f:
            header = f.read(4)
        # PCAP magic: d4 c3 b2 a1 (little endian) or a1 b2 c3 d4 (big endian)
        # PCAPNG magic: 0a 0d 0d 0a
        valid_magic = [
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x0a\x0d\x0d\x0a",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\xd4\xc3\xb2\xa1",
        ]
        if header not in valid_magic:
            return False, "File does not appear to be a valid PCAP/PCAPNG file (invalid magic bytes)."
    except Exception as e:
        logger.error("Could not read file header: %s", e)
        return False, "Could not read file for validation."

    return True, ""


def secure_filename_safe(filename: str) -> str:
    """
    Return a secure filename: strip path components, replace dangerous chars,
    keep only alphanumeric + dots + hyphens + underscores.
    Prepend a UUID to guarantee uniqueness.
    """
    # Strip path components
    filename = os.path.basename(filename)

    # Keep only safe characters
    safe = re.sub(r"[^\w\.\-]", "_", filename)

    # Limit length
    if len(safe) > MAX_FILENAME_LENGTH:
        # Keep extension
        root, ext = os.path.splitext(safe)
        safe = root[:MAX_FILENAME_LENGTH - len(ext)] + ext

    if not safe or safe.startswith("."):
        safe = "upload" + safe

    # Prefix with UUID to prevent collisions
    unique_id = str(uuid.uuid4())
    return f"{unique_id}_{safe}"


def allowed_file(filename: str) -> bool:
    """Check if the filename extension is in the allowed list."""
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS
