"""Email OTP for 2FA – send 6-digit codes via SMTP."""

import os
import random
import smtplib
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).resolve().parent.parent / ".env")

# In-memory store: temp_token -> {"code": str, "email": str, "expires_at": datetime}
_email_otp_store: dict = {}

OTP_EXPIRE_MINUTES = 5
OTP_LENGTH = 6


def _smtp_config():
    host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER", "")
    password = os.getenv("SMTP_PASSWORD", "")
    return host, port, user, password


def is_email_otp_configured() -> bool:
    """True if SMTP is configured."""
    _, _, user, password = _smtp_config()
    return bool(user and password)


def generate_and_store_otp(temp_token: str, email: str) -> str:
    """Generate 6-digit OTP, store it, return the code."""
    code = "".join(str(random.randint(0, 9)) for _ in range(OTP_LENGTH))
    expires = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
    _email_otp_store[temp_token] = {"code": code, "email": email, "expires_at": expires}
    return code


def verify_email_otp(temp_token: str, code: str) -> bool:
    """Verify email OTP. Removes from store on success."""
    entry = _email_otp_store.get(temp_token)
    if not entry:
        return False
    if datetime.now(timezone.utc) > entry["expires_at"]:
        del _email_otp_store[temp_token]
        return False
    if entry["code"] != code:
        return False
    del _email_otp_store[temp_token]
    return True


def send_otp_email(to_email: str, code: str) -> bool:
    """Send OTP code via SMTP. Returns True on success."""
    host, port, user, password = _smtp_config()
    if not user or not password:
        return False

    subject = "SIT Admin – Your 2FA code"
    body = f"""Your one-time verification code is:

  {code}

This code expires in {OTP_EXPIRE_MINUTES} minutes. Do not share it with anyone.

— SIT Admin (Scammer Identification & Validation Tool)
"""

    msg = MIMEMultipart()
    msg["From"] = user
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(host, port) as server:
            server.starttls()
            server.login(user, password)
            server.sendmail(user, to_email, msg.as_string())
        return True
    except Exception:
        return False
