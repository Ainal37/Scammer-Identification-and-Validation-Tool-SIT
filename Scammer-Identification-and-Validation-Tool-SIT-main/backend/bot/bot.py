"""
SIT Telegram Bot – Enterprise MVP
──────────────────────────────────
Authenticates with backend, caches JWT, auto-scans URLs, /scan, /report.
"""

import io
import json
import os, sys, re, time, atexit
from pathlib import Path
from urllib.parse import urlsplit, unquote

import requests
from dotenv import load_dotenv
import telebot
from telebot import types

BOT_DIR  = Path(__file__).resolve().parent
BACKEND_DIR = BOT_DIR.parent
LOCK_FILE = BOT_DIR / ".bot.lock"

# Load env: bot/.env first (overrides), then backend/.env (fallback for shared vars)
_bot_env = BOT_DIR / ".env"
_backend_env = BACKEND_DIR / ".env"
if _backend_env.is_file():
    load_dotenv(dotenv_path=_backend_env, override=False)
if _bot_env.is_file():
    load_dotenv(dotenv_path=_bot_env, override=True)
if not _backend_env.is_file() and not _bot_env.is_file():
    print("[WARN] No .env found. Set TELEGRAM_BOT_TOKEN in backend/bot/.env")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
BACKEND_URL        = os.getenv("BACKEND_URL", "http://127.0.0.1:8001").strip()
BOT_ADMIN_EMAIL    = os.getenv("BOT_ADMIN_EMAIL", "bot@example.com").strip()
BOT_ADMIN_PASSWORD = os.getenv("BOT_ADMIN_PASSWORD", "bot123").strip()
BOT_API_KEY        = os.getenv("BOT_API_KEY", "").strip()

# ── Startup diagnostics (no secrets printed) ──
print(f"[Bot] BACKEND_URL = {BACKEND_URL}")
print(f"[Bot] Telegram token loaded = {'yes' if TELEGRAM_BOT_TOKEN else 'no'}")
print(f"[Bot] BOT_API_KEY loaded = {'yes' if BOT_API_KEY else 'no'}")

# ── Validate token ──
if not TELEGRAM_BOT_TOKEN or ":" not in TELEGRAM_BOT_TOKEN:
    print("[ERROR] TELEGRAM_BOT_TOKEN missing or invalid (must contain ':').")
    print("        Fix: Set TELEGRAM_BOT_TOKEN=123456:ABC... in backend/bot/.env")
    print(f"        Looked in: {_bot_env} and {_backend_env}")
    sys.exit(1)

# ── Lock file ──
def _acquire_lock():
    if LOCK_FILE.exists():
        try:
            old = int(LOCK_FILE.read_text().strip())
            if _alive(old): print(f"[ERROR] Bot already running PID {old}"); sys.exit(1)
            else: print(f"[WARN] Stale lock PID {old}")
        except: pass
    LOCK_FILE.write_text(str(os.getpid()))

def _release_lock():
    try:
        if LOCK_FILE.exists() and LOCK_FILE.read_text().strip() == str(os.getpid()): LOCK_FILE.unlink()
    except: pass

def _alive(pid):
    if sys.platform == "win32":
        import ctypes; h = ctypes.windll.kernel32.OpenProcess(0x00100000, False, pid)
        if h: ctypes.windll.kernel32.CloseHandle(h); return True
        return False
    try: os.kill(pid, 0); return True
    except: return False

# ── Backend auth ──
_token = None; _token_ts = 0
_API_TIMEOUT = 20  # seconds (increased from 10 so slow first requests don't fail)

def _wait_for_backend(max_attempts=30):
    """Block until backend /health responds. Uses exponential backoff."""
    delays = [1, 1, 2, 2, 3, 3, 5, 5, 10]  # then 10s forever
    for attempt in range(1, max_attempts + 1):
        delay = delays[min(attempt - 1, len(delays) - 1)]
        try:
            r = requests.get(f"{BACKEND_URL}/health", timeout=3)
            if r.status_code == 200:
                data = r.json()
                print(f"[Bot] Backend healthy (db={data.get('db')}, v={data.get('version')})")
                return True
        except Exception:
            pass
        print(f"[Bot] Waiting for backend... attempt {attempt}, retry in {delay}s")
        time.sleep(delay)
    print("[Bot] Backend never became healthy after max attempts")
    return False


def _get_token():
    """Authenticate with backend. Retries with backoff on failure."""
    global _token, _token_ts
    if _token and time.time() - _token_ts < 21600:
        return _token
    delays = [1, 2, 3, 5, 10]
    for attempt in range(1, 11):
        delay = delays[min(attempt - 1, len(delays) - 1)]
        try:
            r = requests.post(
                f"{BACKEND_URL}/auth/login",
                json={"email": BOT_ADMIN_EMAIL, "password": BOT_ADMIN_PASSWORD},
                timeout=_API_TIMEOUT,
            )
            r.raise_for_status()
            data = r.json()
            if "access_token" in data:
                _token = data["access_token"]
                _token_ts = time.time()
                print("[Bot] Auth success")
                return _token
            if data.get("requires_2fa"):
                print("[Bot] Auth failed: user has 2FA. Use bot@example.com / bot123 in backend/bot/.env")
            else:
                print("[Bot] Auth failed: no access_token in response")
        except requests.exceptions.RequestException as e:
            print(f"[Bot] Auth failed (attempt {attempt}): {e}")
        except Exception as e:
            print(f"[Bot] Auth failed (attempt {attempt}): {e}")
        if attempt < 10:
            print(f"[Bot] Auth retry in {delay}s...")
            time.sleep(delay)
    print("[Bot] Auth: all retries exhausted")
    return None


_last_api_error = None  # For user-facing hint
_last_api_error_detail = None  # Extra detail (e.g. 400 body)

def _auth_headers():
    """Return auth headers: prefer BOT_API_KEY, fall back to JWT."""
    if BOT_API_KEY:
        return {"X-BOT-KEY": BOT_API_KEY}
    t = _get_token()
    if t:
        return {"Authorization": f"Bearer {t}"}
    return {}


def api_post(path, payload):
    """POST to backend API with automatic token refresh on 401."""
    global _token, _token_ts, _last_api_error, _last_api_error_detail
    _last_api_error = None
    _last_api_error_detail = None
    headers = _auth_headers()
    if not headers:
        _last_api_error = "auth"
        return None
    try:
        url = f"{BACKEND_URL}{path}"
        r = requests.post(url, json=payload, headers=headers, timeout=_API_TIMEOUT)
        if r.status_code == 401 and not BOT_API_KEY:
            _token = None; _token_ts = 0
            headers = _auth_headers()
            if not headers:
                _last_api_error = "auth"
                return None
            r = requests.post(url, json=payload, headers=headers, timeout=_API_TIMEOUT)
        if r.status_code == 400:
            try:
                body = r.json()
                detail = body.get("detail", r.text or "Bad request")
                if isinstance(detail, list) and detail:
                    detail = "; ".join(str(d.get("msg", d)) for d in detail if isinstance(d, dict)) or str(detail[0])
                elif not isinstance(detail, str):
                    detail = str(detail)
            except Exception:
                detail = r.text or "Bad request"
            _last_api_error = "bad_request"
            _last_api_error_detail = detail
            return None
        r.raise_for_status()
        return r.json()
    except Exception as e:
        _last_api_error = str(e).lower()
        print(f"[API] {path} -> {e}")
        return None


def _backend_unreachable_msg():
    """User-friendly message based on last API error."""
    if _last_api_error == "auth":
        return "Backend auth failed. Check BOT_ADMIN_EMAIL/password in backend/bot/.env (use bot@example.com / bot123, no 2FA)."
    if _last_api_error == "bad_request" and _last_api_error_detail:
        return f"URL rejected: {_last_api_error_detail}"
    if _last_api_error and ("refused" in _last_api_error or "connection" in _last_api_error):
        return "Backend unreachable. Run .\\run_all.ps1 to start the backend on port 8002."
    if _last_api_error and "timeout" in _last_api_error:
        return "Backend timeout. The server may be slow or unresponsive."
    return "Backend unreachable. Run .\\run_all.ps1 to start the backend."


def api_get(path, binary=False):
    """GET from backend API. Returns Response (binary) or dict (JSON). None on failure."""
    global _token, _token_ts, _last_api_error
    _last_api_error = None
    headers = _auth_headers()
    if not headers:
        _last_api_error = "auth"
        return None
    try:
        r = requests.get(f"{BACKEND_URL}{path}", headers=headers, timeout=_API_TIMEOUT)
        if r.status_code == 401 and not BOT_API_KEY:
            _token = None; _token_ts = 0
            headers = _auth_headers()
            if not headers:
                _last_api_error = "auth"
                return None
            r = requests.get(f"{BACKEND_URL}{path}", headers=headers, timeout=_API_TIMEOUT)
        if binary:
            return r if r.status_code == 200 else None
        r.raise_for_status()
        return r.json()
    except Exception as e:
        _last_api_error = str(e).lower()
        print(f"[API] GET {path} -> {e}")
        return None


# ── Bot ──
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN, parse_mode="HTML")
URL_RE = re.compile(r"https?://\S+", re.I)

_CARD_SEP = "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500"
_LAST_SCANS_MAX = 5
_last_scans_by_chat: dict = {}

_FLAG_RULE_LABELS = {
    "HTTPS missing": ("\U0001f513", "Unencrypted connection (HTTP)"),
    "URL Userinfo (@) Trick": ("\U0001f575\ufe0f", "\u201c@\u201d trick detected (real host may be hidden)"),
    "Suspicious keywords": ("\U0001f9e9", None),
    "High keyword concentration": ("\U0001f9e9", "Multiple phishing-related keywords in URL"),
    "URL shortener": ("\U0001f517", None),
    "IP Address Hostname": ("\U0001f4bb", None),
    "IP-based URL": ("\U0001f4bb", None),
    "Suspicious TLD": ("\u26a0\ufe0f", None),
    "Excessive subdomains": ("\U0001f9f1", None),
    "Long URL": ("\U0001f4cf", None),
    "VirusTotal": ("\U0001f50d", None),
    "URLhaus": ("\U0001f50d", None),
}


def html_escape(text: str) -> str:
    return (
        str(text or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def truncate(text: str, max_len: int) -> str:
    t = str(text or "")
    if max_len <= 0:
        return ""
    if len(t) <= max_len:
        return t
    if max_len <= 1:
        return t[:max_len]
    return t[: max_len - 1] + "\u2026"


def extract_domain(url: str) -> str:
    if not (url or "").strip():
        return ""
    u = url.strip()
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    parts = urlsplit(u)
    netloc = parts.netloc or ""
    if "@" in netloc:
        hostport = netloc.rsplit("@", 1)[-1]
    else:
        hostport = netloc
    hostport = unquote(hostport)
    if hostport.startswith("[") and "]" in hostport:
        return hostport.split("]", 1)[0][1:] + "]"
    if ":" in hostport and not hostport.startswith("["):
        host = hostport.rsplit(":", 1)[0]
    else:
        host = hostport
    return (host or "").lower()


def score_bar(score: int, width: int = 20) -> str:
    score = min(max(int(score), 0), 100)
    filled = width if score == 100 else int(score / 100.0 * width)
    filled = max(0, min(filled, width))
    empty = width - filled
    inner = "\u2588" * filled + "\u2591" * empty
    return f"RISK \u2595{inner}\u258F {score}%"


def verdict_badge(verdict: str) -> str:
    v = (verdict or "safe").lower()
    if v == "scam":
        return "\U0001f6d1"
    if v == "suspicious":
        return "\u26a0\ufe0f"
    return "\u2705"


def verdict_actions(verdict: str) -> list:
    v = (verdict or "safe").lower()
    if v == "scam":
        return [
            "Do not visit or login on this link.",
            "Change passwords immediately if you entered details.",
            "Contact your bank if banking info was involved.",
        ]
    if v == "suspicious":
        return [
            "Do not log in or submit credentials on this page.",
            "Scan the URL with VirusTotal or URLhaus first.",
            "Report suspicious links to your admin or IT security.",
        ]
    return [
        "Proceed, but stay alert.",
        "Verify the official domain carefully.",
        "Never share OTP, passwords, or banking details via links.",
    ]


def format_connection(url: str) -> str:
    u = (url or "").strip()
    if not re.match(r"^https?://", u, re.I):
        u = "http://" + u
    scheme = (urlsplit(u).scheme or "http").lower()
    if scheme == "https":
        return "HTTPS (encrypted)"
    return "HTTP (not encrypted)"


def _threat_display(level) -> str:
    s = str(level or "N/A").strip().upper()
    if s == "MEDIUM":
        return "MED"
    return s


def _normalize_intel(scan: dict) -> dict:
    raw = scan.get("intel_summary")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = {}
    return raw if isinstance(raw, dict) else {}


def _intel_status_line(intel: dict) -> str:
    vt = intel.get("virustotal") or {}
    uh = intel.get("urlhaus") or {}

    if not vt:
        vt_txt = "not configured"
    elif not vt.get("available"):
        err_l = (vt.get("error") or "").lower()
        vt_txt = "not configured" if ("key" in err_l or "not configured" in err_l) else "not checked"
    elif vt.get("error"):
        vt_txt = truncate(str(vt["error"]), 40)
    elif not vt.get("found"):
        vt_txt = "no match"
    else:
        pos, tot = vt.get("positives", 0), vt.get("total", 0)
        vt_txt = f"{pos}/{tot} engines flagged" if tot else "flagged"

    if not uh:
        uh_txt = "not checked"
    elif not uh.get("available"):
        uh_txt = "not checked" if not uh.get("error") else truncate(str(uh["error"]), 40)
    elif uh.get("error"):
        uh_txt = truncate(str(uh["error"]), 40)
    elif not uh.get("found"):
        uh_txt = "no match"
    else:
        uh_txt = f"match ({uh.get('threat', 'threat')})"

    return f"\u2022 URLhaus: {html_escape(uh_txt)} \u2022 VirusTotal: {html_escape(vt_txt)}"


def _get_breakdown(scan: dict) -> list:
    bd = scan.get("breakdown")
    if isinstance(bd, str):
        try:
            bd = json.loads(bd)
        except (json.JSONDecodeError, TypeError):
            bd = []
    return bd if isinstance(bd, list) else []


def _format_flag_line(item: dict) -> str:
    rule = (item.get("rule") or "").strip()
    detail = (item.get("detail") or "").strip()
    emoji, fixed = _FLAG_RULE_LABELS.get(rule, ("\U0001f4cc", None))
    if fixed:
        return f"{emoji} {html_escape(fixed)}"
    if rule == "Suspicious keywords" and detail:
        m = re.search(r"Keywords:\s*(.+)", detail, re.I)
        if m:
            kw_list = [k.strip() for k in m.group(1).split(",") if k.strip()]
            kw_display = ", ".join(kw_list[:6])
            label = "Phishing keywords" if len(kw_list) > 1 else "Phishing keyword"
            return f"\U0001f9e9 {label}: {html_escape(truncate(kw_display, 60))}"
    if detail:
        return f"{emoji} {html_escape(truncate(detail, 90))}"
    return f"{emoji} {html_escape(truncate(rule, 90))}"


_RULE_DISPLAY_PRIORITY = {
    "HTTPS missing": 100,
    "URL Userinfo (@) Trick": 95,
    "IP Address Hostname": 90,
    "IP-based URL": 90,
    "URL shortener": 85,
    "Suspicious TLD": 80,
    "Suspicious keywords": 75,
    "VirusTotal": 70,
    "URLhaus": 70,
    "High keyword concentration": 50,
    "Excessive subdomains": 40,
    "Long URL": 30,
}


def _display_sort_key(row: dict) -> int:
    rule = (row.get("rule") or "").strip()
    return _RULE_DISPLAY_PRIORITY.get(rule, 10)


def _why_flagged_lines(scan: dict, n: int = 3) -> list:
    items = [x for x in _get_breakdown(scan) if isinstance(x, dict)]
    items.sort(key=_display_sort_key, reverse=True)
    seen_rules = set()
    deduped = []
    for it in items:
        rule = (it.get("rule") or "").strip()
        if rule == "High keyword concentration" and any(
            (x.get("rule") or "").strip() == "Suspicious keywords" for x in deduped
        ):
            continue
        if rule not in seen_rules:
            seen_rules.add(rule)
            deduped.append(it)
    lines = [_format_flag_line(it) for it in deduped[:n]]
    if lines:
        return lines
    reason = scan.get("reason") or ""
    if not reason or reason == "No red flags":
        return ["\u2705 No significant red flags."]
    parts = [s.strip() for s in re.split(r"[;,\n]+", reason) if s.strip()]
    for p in parts[:n]:
        lines.append(f"\U0001f4cc {html_escape(truncate(p, 90))}")
    return lines


def _short_url_path(url: str, max_len: int = 50) -> str:
    """Shorten long path segments in the URL for display."""
    parts = urlsplit(url if re.match(r"^https?://", url, re.I) else "http://" + url)
    scheme_host = f"{parts.scheme}://{parts.netloc}"
    path = parts.path or ""
    if len(scheme_host + path) <= max_len:
        return url if len(url) <= max_len else scheme_host + path
    segs = [s for s in path.split("/") if s]
    if len(segs) <= 2:
        return truncate(url, max_len)
    short_path = f"/{segs[0]}/.../{segs[-1]}"
    return truncate(scheme_host + short_path, max_len)


def build_scan_message(scan: dict) -> str:
    url = scan.get("link") or scan.get("url") or ""
    score = min(max(int(scan.get("score") or 0), 0), 100)
    verdict = (scan.get("verdict") or "safe").lower()
    vlabel = verdict.upper()
    threat = _threat_display(scan.get("threat_level"))
    ts = scan.get("created_at") or ""
    ts_short = str(ts)[:19] if ts else ""
    domain = extract_domain(url)

    badge = verdict_badge(verdict)
    bar_inner = html_escape(score_bar(score, 20))

    lines = [_CARD_SEP]

    if threat == "HIGH":
        lines.append(f"\U0001f6a8 <b>HIGH THREAT DETECTED</b>")
        lines.append("")

    lines.append(f"{badge} <b>{html_escape(vlabel)}</b>  \u2022  <b>{html_escape(threat)}</b>  \u2022  <code>{score}/100</code>")
    lines.append(f"<code>{bar_inner}</code>")

    lines.append("")
    lines.append("<b>Quick summary</b>")
    lines.append(f"\u2022 Domain: {html_escape(domain or 'N/A')}")
    lines.append(f"\u2022 Connection: {html_escape(format_connection(url))}")
    if ts_short:
        lines.append(f"\u2022 Time: {html_escape(ts_short)}")

    lines.append("")
    lines.append("<b>Top reasons</b>")
    for row in _why_flagged_lines(scan, 3):
        lines.append(row)

    lines.append("")
    lines.append("<b>What to do</b>")
    for a in verdict_actions(verdict):
        lines.append(f"\u2022 {html_escape(a)}")

    lines.append("")
    lines.append("<b>URL</b>")
    short_u = _short_url_path(url, 55)
    lines.append(f"<code>{html_escape(short_u)}</code>")
    lines.append("Tap to copy full URL.")
    lines.append(_CARD_SEP)
    return "\n".join(lines)


def build_scan_details(scan: dict) -> str:
    url = scan.get("link") or scan.get("url") or ""
    score = min(max(int(scan.get("score") or 0), 0), 100)
    verdict = (scan.get("verdict") or "safe").lower()
    intel = _normalize_intel(scan)
    bd = _get_breakdown(scan)
    parts = [
        "<b>SIT Scan \u2014 Full details</b>",
        _CARD_SEP,
        f"<b>ID:</b> {html_escape(str(scan.get('id', '?')))}",
        f"<b>Verdict:</b> {verdict_badge(verdict)} {html_escape(verdict.upper())}",
        f"<b>Score:</b> <code>{score}/100</code>  \u2022  <b>Threat:</b> {html_escape(_threat_display(scan.get('threat_level')))}",
        f"<b>URL:</b> <code>{html_escape(truncate(url, 200))}</code>",
        f"<b>Time:</b> {html_escape(str(scan.get('created_at') or ''))}",
        "",
        "<b>Reason (full)</b>",
        html_escape(scan.get("reason") or "\u2014"),
        "",
        "<b>Breakdown</b>",
    ]
    if not bd:
        parts.append(html_escape("No breakdown rows."))
    else:
        for i, row in enumerate(bd, 1):
            if not isinstance(row, dict):
                parts.append(f"{i}. {html_escape(str(row))}")
                continue
            rule = row.get("rule") or row.get("factor") or "factor"
            pts = row.get("points") or row.get("score") or ""
            ev = row.get("detail") or row.get("evidence") or row.get("reason") or ""
            parts.append(
                f"{i}. <b>{html_escape(str(rule))}</b> ({html_escape(str(pts))} pts)"
            )
            parts.append(f"   {html_escape(str(ev))}")
    parts.extend(["", "<b>Intel (summary JSON)</b>"])
    try:
        intel_txt = json.dumps(intel, indent=2, ensure_ascii=False, default=str)
    except Exception:
        intel_txt = str(intel)
    parts.append(f"<pre>{html_escape(truncate(intel_txt, 3500))}</pre>")
    parts.append(_CARD_SEP)
    return "\n".join(parts)


def _remember_scan(chat_id: int, scan_dict: dict):
    if chat_id is None:
        return
    payload = dict(scan_dict)
    lst = _last_scans_by_chat.setdefault(chat_id, [])
    sid = payload.get("id")
    lst.insert(0, {"id": sid, "payload": payload})
    del lst[_LAST_SCANS_MAX:]


def _scan_from_cache(chat_id: int, scan_id: int):
    for entry in _last_scans_by_chat.get(chat_id, []):
        if entry.get("id") == scan_id:
            return entry.get("payload")
    return None


def _scan_reply_options(scan_id: int):
    return {
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
        "reply_markup": _scan_keyboard(scan_id),
    }


def _scan_keyboard(scan_id: int):
    kb = types.InlineKeyboardMarkup(row_width=2)
    kb.add(
        types.InlineKeyboardButton(text="Download PDF Report", callback_data=f"pdf:{scan_id}"),
        types.InlineKeyboardButton(text="View Details", callback_data=f"view_details:{scan_id}"),
    )
    return kb


@bot.message_handler(commands=["start"])
def cmd_start(m):
    bot.send_message(m.chat.id,
        "<b>Welcome to SIT Bot!</b>\n\n"
        "/scan <code>&lt;url&gt;</code> \u2013 Scan a URL\n"
        "/report <code>&lt;url&gt; &lt;reason&gt;</code> \u2013 Report\n"
        "/pdf \u2013 Get PDF of latest scan\n"
        "/help \u2013 Help\n\n"
        "Or paste any URL to auto-scan!")

@bot.message_handler(commands=["help"])
def cmd_help(m):
    bot.send_message(m.chat.id,
        "<b>SIT Bot</b>\n"
        "/scan &lt;url&gt; \u2013 Analyse URL\n"
        "/report &lt;url&gt; &lt;reason&gt; \u2013 Report scam\n"
        "/pdf \u2013 Get PDF of latest scan\n"
        "Paste a URL \u2013 Auto-scan")

@bot.message_handler(commands=["scan"])
def cmd_scan(m):
    parts = m.text.split(maxsplit=1)
    if len(parts) < 2:
        bot.reply_to(m, "Usage: /scan &lt;url&gt;"); return
    link = parts[1].strip()
    if not re.match(r"^https?://", link, re.I): link = "http://" + link
    bot.send_chat_action(m.chat.id, "typing")
    msg_text = m.text if len(m.text) > len(link) + 10 else None
    d = api_post("/scans", {"telegram_user_id": m.from_user.id, "telegram_username": m.from_user.username, "link": link, "message": msg_text})
    if not d: bot.reply_to(m, _backend_unreachable_msg()); return
    _remember_scan(m.chat.id, d)
    bot.reply_to(m, build_scan_message(d), **_scan_reply_options(d["id"]))

@bot.message_handler(commands=["report"])
def cmd_report(m):
    parts = m.text.split(maxsplit=2)
    if len(parts) < 3:
        bot.reply_to(m, "Usage: /report &lt;url&gt; &lt;reason&gt;"); return
    link, reason = parts[1].strip(), parts[2].strip()
    if not re.match(r"^https?://", link, re.I): link = "http://" + link
    bot.send_chat_action(m.chat.id, "typing")
    d = api_post("/reports", {"telegram_user_id": m.from_user.id, "telegram_username": m.from_user.username, "link": link, "report_type": "scam", "description": reason})
    if not d: bot.reply_to(m, "Could not submit."); return
    bot.reply_to(m, f"\u2705 <b>Report #{d['id']}</b> submitted ({d['status']})")

@bot.message_handler(func=lambda m: m.text and URL_RE.search(m.text))
def auto_scan(m):
    link = URL_RE.search(m.text).group(0)
    bot.send_chat_action(m.chat.id, "typing")
    d = api_post("/scans", {"telegram_user_id": m.from_user.id, "telegram_username": m.from_user.username, "link": link, "message": m.text})
    if not d: bot.reply_to(m, _backend_unreachable_msg()); return
    _remember_scan(m.chat.id, d)
    bot.reply_to(m, build_scan_message(d), **_scan_reply_options(d["id"]))


@bot.callback_query_handler(func=lambda c: c.data and c.data.startswith("view_details:"))
def cb_view_details(c):
    try:
        scan_id = int(c.data.split(":", 1)[1])
    except (ValueError, IndexError):
        bot.answer_callback_query(c.id, "Invalid request.")
        return
    data = _scan_from_cache(c.message.chat.id, scan_id)
    if not data:
        remote = api_get(f"/scans/{scan_id}")
        data = remote if isinstance(remote, dict) else None
    if not data:
        bot.answer_callback_query(c.id, "Scan not found.")
        return
    bot.send_message(
        c.message.chat.id,
        build_scan_details(data),
        parse_mode="HTML",
        disable_web_page_preview=True,
    )
    bot.answer_callback_query(c.id, "Details sent.")


@bot.callback_query_handler(func=lambda c: c.data and c.data.startswith("pdf:"))
def cb_pdf(c):
    """Handle Download PDF Report button."""
    try:
        scan_id = c.data.split(":")[1]
    except IndexError:
        bot.answer_callback_query(c.id, "Invalid request.")
        return
    bot.send_chat_action(c.message.chat.id, "upload_document")
    r = api_get(f"/scans/{scan_id}/report.pdf", binary=True)
    if not r or r.status_code != 200:
        bot.answer_callback_query(c.id, _backend_unreachable_msg() if not r else "Scan not found."); return
    pdf_bytes = r.content
    bot.send_document(
        c.message.chat.id,
        io.BytesIO(pdf_bytes),
        caption=f"SIT Scan Report #{scan_id}",
        visible_file_name=f"SIT-Report-{scan_id}.pdf",
    )
    bot.answer_callback_query(c.id, "PDF sent.")


@bot.message_handler(commands=["pdf"])
def cmd_pdf(m):
    """Get PDF of latest scan for this user."""
    bot.send_chat_action(m.chat.id, "typing")
    d = api_get(f"/scans/latest?telegram_user_id={m.from_user.id}")
    if not d:
        bot.reply_to(m, _backend_unreachable_msg()); return
    scan_id = d.get("id")
    if not scan_id:
        bot.reply_to(m, "No scans yet. Use /scan &lt;url&gt; first."); return
    bot.send_chat_action(m.chat.id, "upload_document")
    r = api_get(f"/scans/{scan_id}/report.pdf", binary=True)
    if not r or r.status_code != 200:
        bot.reply_to(m, "Could not generate PDF."); return
    bot.send_document(
        m.chat.id,
        io.BytesIO(r.content),
        caption=f"SIT Scan Report #{scan_id}",
        visible_file_name=f"SIT-Report-{scan_id}.pdf",
    )
    bot.reply_to(m, f"\u2705 PDF sent for scan #{scan_id}.")


if __name__ == "__main__":
    _acquire_lock(); atexit.register(_release_lock)
    try:
        print("[Bot] Removing webhook..."); bot.remove_webhook()
    except Exception as ex:
        print(f"[Bot] Webhook remove: {ex} (may be OK if first run)")
    try:
        me = bot.get_me()
        print(f"[Bot] Telegram: @{me.username} (id={me.id})")
    except Exception as ex:
        print(f"[Bot] Telegram error: {ex} - check TELEGRAM_BOT_TOKEN in backend/.env")
    print(f"[Bot] Backend: {BACKEND_URL}  PID: {os.getpid()}")
    if BOT_API_KEY:
        print(f"[Bot] Auth: BOT_API_KEY (no login needed)")
    else:
        print(f"[Bot] Auth: {BOT_ADMIN_EMAIL} login (no 2FA)")

    # Wait for backend to be healthy before trying to authenticate
    _wait_for_backend(max_attempts=30)

    if BOT_API_KEY:
        print("[Bot] Auth: OK (using BOT_API_KEY)")
    else:
        t = _get_token()
        if not t:
            print("[Bot] WARNING: Auth failed. Fix: set BOT_API_KEY in backend/.env")
            print("[Bot] Starting polling anyway (will retry auth on each request)")
        else:
            print("[Bot] Auth: OK")

    print("[Bot] Polling...")
    try:
        bot.infinity_polling(timeout=30, long_polling_timeout=25)
    except KeyboardInterrupt:
        print("\n[Bot] Stopped.")
    finally:
        _release_lock()
