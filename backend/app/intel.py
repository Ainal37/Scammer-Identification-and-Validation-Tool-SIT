"""
Threat Intelligence Layer
─────────────────────────
Providers: VirusTotal (optional key) + URLhaus (free, no key).
Each provider: timeout, retry, in-memory TTL cache, safe errors.
"""

import os
import time
import base64
import logging
from pathlib import Path
from typing import Dict, Any, Optional

import requests as http_req
from dotenv import load_dotenv

logger = logging.getLogger("sit.intel")

env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
CACHE_TTL = int(os.getenv("INTEL_CACHE_TTL", "300"))

# ── In-memory TTL cache ──
_cache: Dict[str, tuple] = {}


def _cget(key: str) -> Optional[dict]:
    if key in _cache:
        val, ts = _cache[key]
        if time.time() - ts < CACHE_TTL:
            return val
        del _cache[key]
    return None


def _cset(key: str, val: dict):
    _cache[key] = (val, time.time())


# ── VirusTotal ──
def query_virustotal(url: str) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "provider": "virustotal",
        "available": False,
        "found": False,
        "positives": 0,
        "total": 0,
        "threat_label": None,
        "score_contribution": 0,
    }
    if not VT_API_KEY:
        r["error"] = "API key not configured (optional)"
        return r

    ck = f"vt:{url}"
    cached = _cget(ck)
    if cached:
        cached["cached"] = True
        return cached

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    for attempt in range(2):
        try:
            resp = http_req.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers={"x-apikey": VT_API_KEY},
                timeout=8,
            )
            r["available"] = True
            if resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                mal = stats.get("malicious", 0)
                sus = stats.get("suspicious", 0)
                r["found"] = True
                r["positives"] = mal + sus
                r["total"] = sum(stats.values()) if stats else 0
                if mal > 0:
                    for _eng, info in attrs.get("last_analysis_results", {}).items():
                        if info.get("category") == "malicious" and info.get("result"):
                            r["threat_label"] = info["result"]
                            break
                if r["positives"] >= 10:
                    r["score_contribution"] = 30
                elif r["positives"] >= 5:
                    r["score_contribution"] = 22
                elif r["positives"] >= 2:
                    r["score_contribution"] = 14
            elif resp.status_code == 404:
                r["found"] = False
            else:
                r["error"] = f"HTTP {resp.status_code}"
            break
        except http_req.Timeout:
            r["error"] = "Timeout"
        except Exception as exc:
            r["error"] = str(exc)[:120]
            if attempt == 0:
                time.sleep(1)

    _cset(ck, r)
    return r


# ── URLhaus (abuse.ch – free, no key) ──
def query_urlhaus(url: str) -> Dict[str, Any]:
    r: Dict[str, Any] = {
        "provider": "urlhaus",
        "available": False,
        "found": False,
        "threat": None,
        "tags": [],
        "score_contribution": 0,
    }
    ck = f"uh:{url}"
    cached = _cget(ck)
    if cached:
        cached["cached"] = True
        return cached

    for attempt in range(2):
        try:
            resp = http_req.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=8,
            )
            r["available"] = True
            if resp.status_code == 200:
                data = resp.json()
                if data.get("query_status") == "ok":
                    r["found"] = True
                    r["threat"] = data.get("threat", "unknown")
                    r["tags"] = (data.get("tags") or [])[:10]
                    r["score_contribution"] = 28
            break
        except http_req.Timeout:
            r["error"] = "Timeout"
        except Exception as exc:
            r["error"] = str(exc)[:120]
            if attempt == 0:
                time.sleep(1)

    _cset(ck, r)
    return r


# ── Combined query ──
def query_all(url: str) -> Dict[str, Any]:
    vt = query_virustotal(url)
    uh = query_urlhaus(url)

    breakdown = []
    if vt.get("found") and vt["score_contribution"] > 0:
        detail = f"VirusTotal: {vt['positives']}/{vt['total']} engines flagged"
        if vt.get("threat_label"):
            detail += f" ({vt['threat_label']})"
        breakdown.append({"source": "intel", "rule": "VirusTotal", "points": vt["score_contribution"], "detail": detail})

    if uh.get("found") and uh["score_contribution"] > 0:
        detail = f"URLhaus: {uh.get('threat', 'malicious')}"
        if uh.get("tags"):
            detail += f" [{', '.join(uh['tags'][:5])}]"
        breakdown.append({"source": "intel", "rule": "URLhaus", "points": uh["score_contribution"], "detail": detail})

    return {
        "breakdown": breakdown,
        "summary": {
            "virustotal": {k: v for k, v in vt.items() if k != "cached"},
            "urlhaus": {k: v for k, v in uh.items() if k != "cached"},
        },
    }
