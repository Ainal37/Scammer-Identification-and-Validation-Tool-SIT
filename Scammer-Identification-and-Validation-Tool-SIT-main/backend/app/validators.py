"""
Input Validation – OWASP-minded defenses
─────────────────────────────────────────
"""

import os
import re
from urllib.parse import urlparse
from pathlib import Path

from fastapi import HTTPException

# Allow 127.0.0.1/localhost for demo scam URLs (e.g. shared samples)
try:
    from dotenv import load_dotenv
    load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")
except Exception:
    pass
ALLOW_LOCALHOST_URLS = os.getenv("ALLOW_LOCALHOST_URLS", "false").lower() in ("1", "true", "yes")

MAX_URL_LENGTH = 2048
MAX_MESSAGE_LENGTH = 5000

PRIVATE_IP_RE = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^0\."),
    re.compile(r"^169\.254\."),
    re.compile(r"^fc00:", re.IGNORECASE),
    re.compile(r"^fe80:", re.IGNORECASE),
    re.compile(r"^::1$"),
    re.compile(r"^localhost$", re.IGNORECASE),
]
LOCALHOST_PATS = {PRIVATE_IP_RE[0], PRIVATE_IP_RE[8], PRIVATE_IP_RE[9]}  # 127.x, ::1, localhost


def validate_url(url: str) -> str:
    """Validate and normalise a URL. Raises HTTPException on bad input."""
    url = url.strip()
    if not url:
        raise HTTPException(400, "URL cannot be empty")
    if len(url) > MAX_URL_LENGTH:
        raise HTTPException(400, f"URL too long (max {MAX_URL_LENGTH} characters)")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.netloc or "").split(":")[0].lower()

    for pat in PRIVATE_IP_RE:
        if pat.search(host):
            if ALLOW_LOCALHOST_URLS and pat in LOCALHOST_PATS:
                break  # Allow 127.x, ::1, localhost when enabled
            raise HTTPException(400, "Private / reserved addresses are not allowed")

    return url


def validate_message(msg: str) -> str:
    """Validate message text for NLP analysis."""
    msg = msg.strip()
    if not msg:
        raise HTTPException(400, "Message cannot be empty")
    if len(msg) > MAX_MESSAGE_LENGTH:
        raise HTTPException(400, f"Message too long (max {MAX_MESSAGE_LENGTH} characters)")
    return msg
