"""Authentication & authorization utilities (JWT + bcrypt + TOTP)."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import bcrypt
import pyotp
from dotenv import load_dotenv
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from .database import get_db
from .models import AdminUser

# ── Load env ──
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(dotenv_path=env_path)

JWT_SECRET = os.getenv("JWT_SECRET", "changeme-super-secret-key-2026")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES = int(os.getenv("JWT_EXPIRE_MINUTES", "480"))

# ── Bearer scheme ──
bearer_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    """Hash password using bcrypt (avoids passlib/bcrypt compatibility issues)."""
    pwd_bytes = password.encode("utf-8")
    if len(pwd_bytes) > 72:
        pwd_bytes = pwd_bytes[:72]
    return bcrypt.hashpw(pwd_bytes, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify password against bcrypt hash."""
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    exp_min = expires_minutes if expires_minutes is not None else JWT_EXPIRE_MINUTES
    expire = datetime.now(timezone.utc) + timedelta(minutes=exp_min)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode a JWT and return the payload. Raises on invalid/expired."""
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])


# ── TOTP helpers ──
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "SIT Admin") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def get_current_admin(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> AdminUser:
    """FastAPI dependency – extracts & validates JWT, returns AdminUser."""
    token = credentials.credentials
    auth_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: Optional[str] = payload.get("sub")
        if email is None:
            raise auth_exc
        # Reject 2FA-pending tokens used as full tokens
        if payload.get("2fa_pending"):
            raise auth_exc
    except JWTError:
        raise auth_exc

    admin = db.query(AdminUser).filter(AdminUser.email == email).first()
    if admin is None:
        raise auth_exc
    return admin
