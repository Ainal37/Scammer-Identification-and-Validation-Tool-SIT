"""Email OTP for 2FA - send 6-digit codes via SMTP."""

import os
import random
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

from dotenv import load_dotenv

_BACKEND_DIR = Path(__file__).resolve().parent.parent
_ENV_PATHS = [_BACKEND_DIR / ".env", _BACKEND_DIR / ".env.local"]
for _env_path in _ENV_PATHS:
    if _env_path.exists():
        # Force values from backend/.env to be used consistently.
        load_dotenv(dotenv_path=_env_path, override=True)

# In-memory store: temp_token -> {"code": str, "email": str, "expires_at": datetime}
_email_otp_store: dict = {}

OTP_EXPIRE_MINUTES = 5
OTP_LENGTH = 6


def _clean_env_value(value: str | None) -> str:
    if value is None:
        return ""
    cleaned = value.strip().strip('"').strip("'")
    return cleaned


def _env_first(*names: str, default: str = "") -> str:
    """Return the first non-empty environment value from the given names."""
    for name in names:
        value = _clean_env_value(os.getenv(name))
        if value:
            return value
    return default


def _smtp_config():
    """Load SMTP config from backend/.env with compatible aliases."""
    host = _env_first("SMTP_HOST", "MAIL_HOST", "EMAIL_HOST", default="smtp.gmail.com")
    port_raw = _env_first("SMTP_PORT", "MAIL_PORT", "EMAIL_PORT", default="587")
    user = _env_first(
        "SMTP_USER",
        "SMTP_USERNAME",
        "MAIL_USER",
        "MAIL_USERNAME",
        "EMAIL_USER",
        "EMAIL_USERNAME",
        "GMAIL_USER",
    )
    password = _env_first(
        "SMTP_PASSWORD",
        "SMTP_PASS",
        "MAIL_PASSWORD",
        "MAIL_PASS",
        "EMAIL_PASSWORD",
        "EMAIL_PASS",
        "GMAIL_APP_PASSWORD",
    )
    from_email = _env_first("SMTP_FROM", "MAIL_FROM", "EMAIL_FROM", default=user)

    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        port = 587

    return host, port, user, password, from_email


def is_email_otp_configured() -> bool:
    """True if required SMTP settings are configured."""
    host, port, user, password, _ = _smtp_config()
    return bool(host and port and user and password)


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
    host, port, user, password, from_email = _smtp_config()
    if not is_email_otp_configured():
        return False

    subject = "SIT Admin - Your 2FA code"
    body = f"""Your one-time verification code is:

  {code}

This code expires in {OTP_EXPIRE_MINUTES} minutes. Do not share it with anyone.

- SIT Admin (Scammer Identification & Validation Tool)
"""

    msg = MIMEMultipart()
    msg["From"] = from_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        if port == 465:
            with smtplib.SMTP_SSL(host, port) as server:
                server.login(user, password)
                server.sendmail(from_email or user, to_email, msg.as_string())
        else:
            with smtplib.SMTP(host, port) as server:
                server.starttls()
                server.login(user, password)
                server.sendmail(from_email or user, to_email, msg.as_string())
        return True
    except Exception:
        return False
