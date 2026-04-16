"""Security endpoints: password change, 2FA, and session controls."""

from datetime import datetime, timedelta, timezone
import json
import secrets
import hashlib

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AdminUser, UserSecurity, AuditLog
from ..security import (
    get_current_admin, verify_password, hash_password,
    generate_totp_secret, get_totp_uri, verify_totp_code,
)
from ..schemas import (
    ChangePasswordRequest, TwoFASetupResponse, TwoFAConfirmRequest,
    TwoFADisableRequest,
)

router = APIRouter(prefix="/security", tags=["security"])

_LOCKOUT_THRESHOLD = 5
_LOCKOUT_MINUTES = 5


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _hash_code(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _ensure_user_security(db: Session, admin: AdminUser) -> UserSecurity:
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    if not sec:
        sec = UserSecurity(user_id=admin.id)
        db.add(sec)
        db.commit()
        db.refresh(sec)
    return sec


def _check_lockout(sec: UserSecurity):
    if sec.twofa_locked_until and sec.twofa_locked_until > _now_utc():
        raise HTTPException(429, "Too many attempts. Try again later.")


def _request_meta(request: Request) -> tuple:
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    return ip, ua


def _register_failure(db: Session, sec: UserSecurity, admin: AdminUser, ip=None, ua=None):
    sec.twofa_failed_attempts = (sec.twofa_failed_attempts or 0) + 1
    if sec.twofa_failed_attempts >= _LOCKOUT_THRESHOLD:
        sec.twofa_locked_until = _now_utc() + timedelta(minutes=_LOCKOUT_MINUTES)
        db.add(AuditLog(actor_email=admin.email, action="2FA_LOCKED", ip_address=ip, user_agent=ua))
    else:
        db.add(AuditLog(actor_email=admin.email, action="2FA_VERIFY_FAILED", ip_address=ip, user_agent=ua))
    db.commit()


def _reset_failures(sec: UserSecurity):
    sec.twofa_failed_attempts = 0
    sec.twofa_locked_until = None


def _mask_hint(hint: str | None) -> str:
    if not hint or not hint.strip():
        return ""
    h = hint.strip()
    if len(h) <= 2:
        return "*" * len(h)
    return h[0] + "*" * (len(h) - 2) + h[-1]


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    ip, ua = _request_meta(request)
    if not verify_password(body.current_password, admin.password_hash):
        db.add(AuditLog(actor_email=admin.email, action="PASSWORD_CHANGE_FAILED", ip_address=ip, user_agent=ua))
        db.commit()
        raise HTTPException(400, "Current password is incorrect")
    if body.confirm_new_password is not None and body.new_password != body.confirm_new_password:
        raise HTTPException(400, "New password and confirmation do not match")
    if body.password_hint and body.password_hint.strip().lower() == body.new_password.lower():
        raise HTTPException(400, "Password hint must not equal your new password")
    admin.password_hash = hash_password(body.new_password)
    sec = _ensure_user_security(db, admin)
    if body.password_hint is not None:
        sec.password_hint = body.password_hint.strip()[:80] if body.password_hint.strip() else None
    db.add(AuditLog(actor_email=admin.email, action="PASSWORD_CHANGED", ip_address=ip, user_agent=ua))
    db.commit()
    hint_plain = (sec.password_hint or "").strip()
    hint_masked = _mask_hint(sec.password_hint) if sec.password_hint else ""
    return {"ok": True, "message": "Password changed successfully", "hint": hint_plain if hint_plain else None, "hint_masked": hint_masked}


@router.post("/2fa/setup", response_model=TwoFASetupResponse)
def setup_2fa(
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    sec = _ensure_user_security(db, admin)
    if sec.totp_enabled:
        raise HTTPException(400, "2FA is already enabled")

    secret = generate_totp_secret()
    uri = get_totp_uri(secret, admin.email)

    sec.totp_secret = secret
    sec.totp_enabled = False  # Not yet confirmed
    _reset_failures(sec)
    ip, ua = _request_meta(request)
    db.add(AuditLog(actor_email=admin.email, action="2FA_SETUP_STARTED", ip_address=ip, user_agent=ua))
    db.commit()

    return TwoFASetupResponse(secret=secret, otpauth_uri=uri, otpauth_url=uri, qr_svg="")


@router.post("/2fa/confirm")
def confirm_2fa(
    body: TwoFAConfirmRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    sec = _ensure_user_security(db, admin)
    if not sec.totp_secret:
        raise HTTPException(400, "2FA setup not started. Call POST /security/2fa/setup first.")

    _check_lockout(sec)
    ip, ua = _request_meta(request)

    if not verify_totp_code(sec.totp_secret, body.code):
        _register_failure(db, sec, admin, ip, ua)
        raise HTTPException(400, "Invalid TOTP code. Please try again.")

    # Generate one-time recovery codes (10)
    codes: list[str] = []
    for _ in range(10):
        # human-friendly 10-char code: XXXX-XXXX style
        part = secrets.token_hex(4)[:8].upper()
        codes.append(part)

    sec.totp_enabled = True
    sec.recovery_codes_hash = json.dumps([_hash_code(c) for c in codes])
    _reset_failures(sec)

    db.add(AuditLog(actor_email=admin.email, action="2FA_ENABLED", ip_address=ip, user_agent=ua))
    db.commit()
    return {"ok": True, "message": "2FA enabled successfully", "recovery_codes": codes}


@router.post("/2fa/disable")
def disable_2fa(
    body: TwoFADisableRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    ip, ua = _request_meta(request)
    # DEV: FORCE 2FA ON - reject disable for demo. Remove to allow disabling.
    raise HTTPException(403, "2FA cannot be disabled in dev mode. Remove DEV block in security_router.py to restore.")

    sec = _ensure_user_security(db, admin)
    if not sec.totp_enabled:
        raise HTTPException(400, "2FA is not enabled")

    _check_lockout(sec)

    ok = False
    raw = body.code_or_recovery.strip()

    # 1. Try as TOTP code
    if len(raw) >= 6 and verify_totp_code(sec.totp_secret or "", raw):
        ok = True

    # 2. Try as recovery code (one-time use)
    if not ok and sec.recovery_codes_hash:
        try:
            hashes = json.loads(sec.recovery_codes_hash)
        except Exception:
            hashes = []
        h = _hash_code(raw)
        if h in hashes:
            ok = True
            hashes.remove(h)
            sec.recovery_codes_hash = json.dumps(hashes)
            db.add(AuditLog(actor_email=admin.email, action="RECOVERY_CODE_USED", ip_address=ip, user_agent=ua))

    if not ok:
        _register_failure(db, sec, admin, ip, ua)
        raise HTTPException(400, "Invalid code or recovery code.")

    # Success – disable 2FA and clear secrets / lockouts
    sec.totp_enabled = False
    sec.totp_secret = None
    sec.recovery_codes_hash = None
    _reset_failures(sec)

    db.add(AuditLog(actor_email=admin.email, action="2FA_DISABLED", ip_address=ip, user_agent=ua))
    db.commit()
    return {"ok": True, "message": "2FA disabled"}


@router.get("/2fa/status")
def get_2fa_status(
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    hint_plain = (sec.password_hint or "").strip() if sec else ""
    return {
        "totp_enabled": bool(sec and sec.totp_enabled),
        "mfa_required": bool(sec and sec.mfa_required),
        "session_timeout_minutes": sec.session_timeout_minutes if sec else 480,
        "password_hint": hint_plain if hint_plain else None,
        "password_hint_masked": _mask_hint(sec.password_hint) if sec and sec.password_hint else "",
    }
