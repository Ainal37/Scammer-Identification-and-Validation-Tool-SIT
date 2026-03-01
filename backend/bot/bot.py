"""
SIT Telegram Bot – Enterprise MVP
──────────────────────────────────
Authenticates with backend, caches JWT, auto-scans URLs, /scan, /report.
"""

import io
import json
import os, sys, re, time, atexit
from pathlib import Path

import requests
from dotenv import load_dotenv
import telebot
from telebot import types

BOT_DIR  = Path(__file__).resolve().parent
ENV_PATH = BOT_DIR / ".env"
LOCK_FILE = BOT_DIR / ".bot.lock"

if not ENV_PATH.is_file():
    print(f"[ERROR] .env not found: {ENV_PATH}"); sys.exit(1)

load_dotenv(dotenv_path=ENV_PATH)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
BACKEND_URL        = os.getenv("BACKEND_URL", "http://127.0.0.1:8002").strip()
BOT_ADMIN_EMAIL    = os.getenv("BOT_ADMIN_EMAIL", "bot@example.com").strip()
BOT_ADMIN_PASSWORD = os.getenv("BOT_ADMIN_PASSWORD", "admin123").strip()

if not TELEGRAM_BOT_TOKEN:
    print("[ERROR] TELEGRAM_BOT_TOKEN not set"); sys.exit(1)

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

def api_post(path, payload):
    """POST to backend API with automatic token refresh on 401."""
    global _token, _token_ts, _last_api_error, _last_api_error_detail
    _last_api_error = None
    _last_api_error_detail = None
    t = _get_token()
    if not t:
        _last_api_error = "auth"
        return None
    try:
        url = f"{BACKEND_URL}{path}"
        r = requests.post(
            url, json=payload,
            headers={"Authorization": f"Bearer {t}"}, timeout=_API_TIMEOUT,
        )
        if r.status_code == 401:
            _token = None; _token_ts = 0
            t = _get_token()
            if not t:
                _last_api_error = "auth"
                return None
            r = requests.post(
                f"{BACKEND_URL}{path}", json=payload,
                headers={"Authorization": f"Bearer {t}"}, timeout=_API_TIMEOUT,
            )
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
    t = _get_token()
    if not t:
        _last_api_error = "auth"
        return None
    try:
        r = requests.get(
            f"{BACKEND_URL}{path}",
            headers={"Authorization": f"Bearer {t}"},
            timeout=_API_TIMEOUT,
        )
        if r.status_code == 401:
            _token = None; _token_ts = 0
            t = _get_token()
            if not t:
                _last_api_error = "auth"
                return None
            r = requests.get(
                f"{BACKEND_URL}{path}",
                headers={"Authorization": f"Bearer {t}"},
                timeout=_API_TIMEOUT,
            )
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
EMOJI = {"safe": "\u2705", "suspicious": "\u26a0\ufe0f", "scam": "\U0001f6a8"}


def _score_meter(score: int) -> str:
    """Emoji meter: 10 blocks. 🟩 green (0-4), 🟨 yellow (5-6), 🟥 red (7-9), ⬜ empty."""
    score = min(max(score, 0), 100)
    n = min(10, (score + 9) // 10)  # filled blocks (0-10)
    blocks = []
    for i in range(10):
        if i < n:
            blocks.append("\U0001F7E9" if i < 5 else ("\U0001F7E8" if i < 7 else "\U0001F7E5"))
        else:
            blocks.append("\u2B1C")
    return "".join(blocks)


def _score_display(score: int) -> str:
    """Score text + meter for Telegram. Example: 'Score: 51/100' + meter."""
    score = min(max(score, 0), 100)
    return f"Score: {score}/100\n{_score_meter(score)}"


def fmt(d):
    e = EMOJI.get(d.get("verdict",""), "\u2753")
    tl = d.get("threat_level", "")
    score = d.get("score", 0)
    verdict = d.get("verdict", "?").upper()
    reason = (d.get("reason") or "N/A")[:200]
    ts = d.get("created_at", "")

    score_display = _score_display(score)

    if tl == "HIGH":
        return (
            f"\U0001f6a8\U0001f6a8\U0001f6a8 <b>HIGH THREAT DETECTED</b> \U0001f6a8\U0001f6a8\U0001f6a8\n"
            f"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"\u26a0\ufe0f <b>Verdict:</b> {verdict}\n"
            f"\U0001f4ca {score_display}\n"
            f"\U0001f534 <b>Threat Level:</b> {tl}\n"
            f"\U0001f50d <b>Reasons:</b> {reason}\n"
            f"\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
            f"\u26d4 <b>DO NOT visit this URL.</b>\n"
            f"<i>{ts}</i>"
        )

    return (f"{e} <b>Verdict: {verdict}</b>\n"
            f"Threat Level: {tl}\n"
            f"{score_display}\n"
            f"Reasons: {reason}\n"
            f"<i>{ts}</i>")


def _pdf_keyboard(scan_id):
    """Inline keyboard with Download PDF Report button."""
    kb = types.InlineKeyboardMarkup()
    kb.add(types.InlineKeyboardButton(text="Download PDF Report", callback_data=f"pdf:{scan_id}"))
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
    bot.reply_to(m, fmt(d), reply_markup=_pdf_keyboard(d["id"]))

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
    bot.reply_to(m, "Auto-scan:\n\n" + fmt(d), reply_markup=_pdf_keyboard(d["id"]))


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
        print(f"[Bot] Telegram error: {ex} - check TELEGRAM_BOT_TOKEN in backend/bot/.env")
    print(f"[Bot] Backend: {BACKEND_URL}  PID: {os.getpid()}")
    print(f"[Bot] Using: {BOT_ADMIN_EMAIL} (must be bot user, no 2FA)")

    # Wait for backend to be healthy before trying to authenticate
    _wait_for_backend(max_attempts=30)

    t = _get_token()
    if not t:
        print("[Bot] WARNING: Auth failed. Fix: BOT_ADMIN_EMAIL=bot@example.com, BOT_ADMIN_PASSWORD=bot123 in backend/bot/.env")
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
