"""
Heuristic URL Scanner – returns structured breakdown.
"""

import re
from urllib.parse import urlparse

SHORTENERS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd",
    "cutt.ly", "ow.ly", "buff.ly", "rb.gy", "shorturl.at",
}

KEYWORDS = [
    "login", "verify", "otp", "update", "secure", "bank", "wallet",
    "claim", "free", "bonus", "gift", "prize", "password",
    "confirm", "suspend", "account", "urgent",
]

SUSPICIOUS_TLDS = {".tk", ".ml", ".cf", ".gq", ".ga"}


def heuristic_scan(link: str) -> dict:
    """
    Analyse a URL using heuristic rules.
    Returns: {"breakdown": [{"source","rule","points","detail"}, ...]}
    """
    link = link.strip()
    if not re.match(r"^https?://", link):
        link = "http://" + link

    p = urlparse(link)
    host = (p.netloc or "").lower()
    scheme = (p.scheme or "").lower()
    breakdown = []

    # HTTPS missing
    if scheme != "https":
        breakdown.append({
            "source": "heuristic", "rule": "HTTPS missing",
            "points": 12, "detail": "Connection not encrypted (HTTP)",
        })

    # URL shortener
    clean_host = host.split(":")[0]
    if clean_host in SHORTENERS:
        breakdown.append({
            "source": "heuristic", "rule": "URL shortener",
            "points": 18, "detail": f"Known shortener: {clean_host}",
        })

    # IP address as domain (Rule A: IP Address Hostname, +20)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_host):
        breakdown.append({
            "source": "heuristic", "rule": "IP Address Hostname",
            "points": 20, "detail": f"IP address as hostname: {clean_host}",
        })

    # @ userinfo trick in URL (Rule B: URL Userinfo (@) Trick, +15)
    if "@" in host:
        breakdown.append({
            "source": "heuristic", "rule": "URL Userinfo (@) Trick",
            "points": 15, "detail": "URL contains @ - real destination may be hidden",
        })

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if clean_host.endswith(tld):
            breakdown.append({
                "source": "heuristic", "rule": "Suspicious TLD",
                "points": 16, "detail": f"Free/abused TLD: {tld}",
            })
            break

    # Suspicious keywords in path/query
    text = (p.path + " " + (p.query or "")).lower()
    hits = [k for k in KEYWORDS if k in text]
    if hits:
        pts = min(len(hits) * 7, 28)
        breakdown.append({
            "source": "heuristic", "rule": "Suspicious keywords",
            "points": pts, "detail": "Keywords: " + ", ".join(hits[:6]),
        })
        # High concentration (4+ keywords) indicates targeted phishing
        if len(hits) >= 4:
            breakdown.append({
                "source": "heuristic", "rule": "High keyword concentration",
                "points": 20, "detail": f"{len(hits)} phishing-related keywords in URL",
            })

    # Too many subdomains (exclude IP addresses)
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", clean_host) and clean_host.count(".") >= 3:
        breakdown.append({
            "source": "heuristic", "rule": "Excessive subdomains",
            "points": 10, "detail": f"{clean_host.count('.') + 1} domain levels",
        })

    # URL very long
    if len(link) > 100:
        breakdown.append({
            "source": "heuristic", "rule": "Long URL",
            "points": 8, "detail": f"{len(link)} characters",
        })

    return {"breakdown": breakdown}


# ── Legacy wrapper (backward compat) ──
def scan_link(link: str):
    """Returns (verdict, score, reason) for backward compatibility."""
    h = heuristic_scan(link)
    score = min(sum(b["points"] for b in h["breakdown"]), 100)
    reason = "; ".join(b["detail"] for b in h["breakdown"]) or "No red flags"
    if score >= 75:
        verdict = "scam"
    elif score >= 50:
        verdict = "suspicious"
    else:
        verdict = "safe"
    return verdict, score, reason
