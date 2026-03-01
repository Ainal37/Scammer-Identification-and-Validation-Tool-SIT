"""
Telegram Alert Module
─────────────────────
Sends alert to admin Telegram group/channel when threat_level == HIGH.
"""

import os
import logging
from pathlib import Path

import requests
from dotenv import load_dotenv

logger = logging.getLogger("sit.alerts")

bot_env = Path(__file__).resolve().parent.parent / "bot" / ".env"
load_dotenv(dotenv_path=bot_env)

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
ALERT_CHAT_ID = os.getenv("ALERT_CHAT_ID", "").strip()


def send_high_threat_alert(scan_data: dict) -> bool:
    """Send Telegram alert for HIGH-threat scans. Returns True if sent."""
    if not BOT_TOKEN or not ALERT_CHAT_ID:
        return False

    text = (
        "\U0001f6a8 <b>HIGH THREAT DETECTED</b>\n"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
        f"<b>Scan ID:</b> #{scan_data.get('id', '?')}\n"
        f"<b>URL:</b> <code>{scan_data.get('link', '?')}</code>\n"
        f"<b>Score:</b> {scan_data.get('score', '?')}/100\n"
        f"<b>Threat:</b> {scan_data.get('threat_level', '?')}\n"
        f"<b>Reasons:</b> {scan_data.get('reason', 'N/A')[:300]}\n"
        "\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\n"
        "Dashboard: http://127.0.0.1:5500/scans.html"
    )

    try:
        resp = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": ALERT_CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=5,
        )
        if resp.ok:
            logger.info("Alert sent for scan #%s", scan_data.get("id"))
            return True
        logger.warning("Alert API returned %s", resp.status_code)
    except Exception as exc:
        logger.warning("Alert send failed: %s", exc)
    return False
