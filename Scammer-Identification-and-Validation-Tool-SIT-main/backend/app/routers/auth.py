"""Auth endpoints: login + 2FA verify + current user + change-password + security-status."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AdminUser, UserSecurity, AuditLog
from ..security import (
    verify_password, hash_password, create_access_token, get_current_admin,
    decode_token, verify_totp_code,
)
from ..email_otp import (
    is_email_otp_configured,
    generate_and_store_otp,
    verify_email_otp,
    send_otp_email,
)
from ..schemas import LoginRequest, TokenResponse, AdminResponse, Verify2FARequest, ChangePasswordRequest

router = APIRouter(prefix="/auth", tags=["auth"])


def _mask_hint(hint: str | None) -> str:
    """Mask hint: first char + asterisks + last char. e.g. 'kucing' -> 'k****g'."""
    if not hint or not hint.strip():
        return ""
    h = hint.strip()
    if len(h) <= 2:
        return "*" * len(h)
    return h[0] + "*" * (len(h) - 2) + h[-1]


def _mask_email(email: str | None) -> str:
    """Mask email for UI display without exposing the full address."""
    if not email or "@" not in email:
        return ""
    local_part, domain = email.split("@", 1)
    visible_chars = 2 if len(local_part) > 2 else 1
    return local_part[:visible_chars] + "***@" + domain


def _ensure_user_security(db: Session, admin: AdminUser) -> UserSecurity:
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    if not sec:
        sec = UserSecurity(user_id=admin.id)
        db.add(sec)
        db.commit()
        db.refresh(sec)
    return sec


class SendEmailOtpRequest(BaseModel):
    temp_token: str


class PasswordHintRequest(BaseModel):
    email: str


@router.post("/password-hint")
def get_password_hint(body: PasswordHintRequest, db: Session = Depends(get_db)):
    """Return masked password hint. Always 200, never reveals if email exists."""
    email = body.email.strip().lower()
    admin = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not admin:
        return {"ok": True, "hint_masked": None}
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    hint = sec.password_hint if sec else None
    if not hint or not hint.strip():
        return {"ok": True, "hint_masked": None}
    h = hint.strip()
    if len(h) < 3:
        return {"ok": True, "hint_masked": "***"}
    masked = h[0] + "*" * (len(h) - 2) + h[-1]
    return {"ok": True, "hint_masked": masked}


@router.get("/public/password-hint")
def get_public_password_hint(email: str, db: Session = Depends(get_db)):
    """Public endpoint: return plain password hint for login page display.
    Always 200 regardless of whether email exists (security – no user enumeration via timing)."""
    if not email or not email.strip():
        return {"hint": None}
    admin = db.query(AdminUser).filter(AdminUser.email == email.strip().lower()).first()
    if not admin:
        return {"hint": None}
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    hint = (sec.password_hint or "").strip() if sec else ""
    return {"hint": hint if hint else None}


class PasswordHintUpdate(BaseModel):
    hint: str | None = None


@router.get("/password-hint/me")
def get_my_password_hint(
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Return the current user's plain password hint."""
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    hint = (sec.password_hint or "").strip() if sec else ""
    return {"hint": hint if hint else None}


@router.patch("/password-hint")
def update_my_password_hint(
    body: PasswordHintUpdate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Save a new password hint (plain text, max 80 chars)."""
    sec = _ensure_user_security(db, admin)
    sec.password_hint = body.hint.strip()[:80] if body.hint and body.hint.strip() else None
    db.commit()
    hint_plain = (sec.password_hint or "").strip()
    return {"ok": True, "hint": hint_plain if hint_plain else None}


def _get_request_meta(request: Request) -> tuple:
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500]
    return ip, ua


@router.post("/login")
def login(body: LoginRequest, request: Request, db: Session = Depends(get_db)):
    admin = db.query(AdminUser).filter(AdminUser.email == body.email).first()
    if not admin or not verify_password(body.password, admin.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    mfa_required = bool(sec and (sec.mfa_required or sec.totp_enabled))
    if mfa_required:
        totp_available = bool(sec and sec.totp_enabled and sec.totp_secret and sec.totp_secret.strip())
        email_otp_available = is_email_otp_configured()
        if not totp_available and not email_otp_available:
            raise HTTPException(
                status_code=503,
                detail="Two-factor authentication is required, but no verification method is available. Contact an administrator.",
            )

        temp_token = create_access_token(
            {"sub": admin.email, "role": admin.role, "2fa_pending": True},
            expires_minutes=5,
        )
        if totp_available and email_otp_available:
            mfa_method = "totp_or_email"
        elif totp_available:
            mfa_method = "totp"
        else:
            mfa_method = "email"

        return {
            "requires_2fa": True,
            "temp_token": temp_token,
            "email_otp_available": email_otp_available,
            "masked_email": _mask_email(admin.email),
            "mfa_method": mfa_method,
        }

    ip, ua = _get_request_meta(request)
    admin.last_login_at = datetime.now(timezone.utc)
    admin.last_login_ip = ip
    admin.last_user_agent = ua or None
    db.add(AuditLog(actor_email=admin.email, action="LOGIN_SUCCESS", ip_address=ip, user_agent=ua or None))
    db.commit()
    token = create_access_token({"sub": admin.email, "role": admin.role})
    return TokenResponse(access_token=token)


@router.post("/send-email-otp")
def send_email_otp(body: SendEmailOtpRequest, db: Session = Depends(get_db)):
    """Send 6-digit OTP to user's email. Requires temp_token from login."""
    if not is_email_otp_configured():
        raise HTTPException(
            status_code=503,
            detail="Email OTP not configured. Add SMTP_HOST/SMTP_PORT plus SMTP_USER and SMTP_PASSWORD to backend/.env",
        )
    try:
        payload = decode_token(body.temp_token)
    except Exception:
        raise HTTPException(401, "Invalid or expired temp token")
    if not payload.get("2fa_pending"):
        raise HTTPException(400, "Not a 2FA pending token")

    email = payload.get("sub")
    admin = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not admin:
        raise HTTPException(401, "User not found")

    code = generate_and_store_otp(body.temp_token, email)
    if not send_otp_email(email, code):
        raise HTTPException(503, "Unable to send email OTP right now. Please try again later.")
    return {
        "ok": True,
        "message": "Verification code sent to " + _mask_email(email),
        "masked_email": _mask_email(email),
        "email_otp_available": True,
    }


@router.post("/verify-2fa", response_model=TokenResponse)
def verify_2fa(body: Verify2FARequest, request: Request, db: Session = Depends(get_db)):
    try:
        payload = decode_token(body.temp_token)
    except Exception:
        raise HTTPException(401, "Invalid or expired temp token")

    if not payload.get("2fa_pending"):
        raise HTTPException(400, "Not a 2FA pending token")

    email = payload.get("sub")
    admin = db.query(AdminUser).filter(AdminUser.email == email).first()
    if not admin:
        raise HTTPException(401, "User not found")

    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    totp_available = bool(sec and sec.totp_enabled and sec.totp_secret)
    email_otp_ok = verify_email_otp(body.temp_token, body.code)
    totp_ok = False

    if not email_otp_ok:
        if totp_available:
            totp_ok = verify_totp_code(sec.totp_secret, body.code)

    if not email_otp_ok and not totp_ok:
        if not totp_available and not is_email_otp_configured():
            raise HTTPException(
                status_code=503,
                detail="Two-factor authentication is currently unavailable. Contact an administrator.",
            )
        raise HTTPException(401, "Invalid or expired 2FA code")

    ip, ua = _get_request_meta(request)
    admin.last_login_at = datetime.now(timezone.utc)
    admin.last_login_ip = ip
    admin.last_user_agent = ua or None
    db.add(AuditLog(actor_email=admin.email, action="LOGIN_SUCCESS", ip_address=ip, user_agent=ua or None))
    db.commit()
    token = create_access_token({"sub": admin.email, "role": admin.role})
    return TokenResponse(access_token=token)


@router.get("/me", response_model=AdminResponse)
def me(db: Session = Depends(get_db), admin: AdminUser = Depends(get_current_admin)):
    last_login_at = str(admin.last_login_at) if admin.last_login_at else None
    return AdminResponse(
        id=admin.id,
        email=admin.email,
        role=admin.role,
        created_at=str(admin.created_at) if admin.created_at else None,
        last_login_at=last_login_at,
    )


@router.post("/change-password")
def change_password(
    body: ChangePasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    ip, ua = _get_request_meta(request)
    if not verify_password(body.current_password, admin.password_hash):
        db.add(AuditLog(actor_email=admin.email, action="PASSWORD_CHANGE_FAILED", ip_address=ip, user_agent=ua or None))
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
    db.add(AuditLog(actor_email=admin.email, action="PASSWORD_CHANGED", ip_address=ip, user_agent=ua or None))
    db.commit()
    hint_plain = sec.password_hint.strip() if sec.password_hint else ""
    hint_masked = _mask_hint(sec.password_hint) if sec.password_hint else ""
    return {"ok": True, "message": "Password updated", "hint": hint_plain, "hint_masked": hint_masked}


@router.get("/security-status")
def get_security_status(
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
    hint_plain = (sec.password_hint or "").strip() if sec else ""
    return {
        "totp_enabled": bool(sec and sec.totp_enabled),
        "mfa_required": bool(sec and sec.mfa_required),
        "session_timeout_minutes": sec.session_timeout_minutes if sec else 480,
        "password_hint": hint_plain,
        "password_hint_masked": _mask_hint(sec.password_hint) if sec and sec.password_hint else "",
    }
