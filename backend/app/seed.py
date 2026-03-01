"""Seed default admin user and system settings on startup."""

from .database import SessionLocal
from .models import AdminUser, SystemSetting, UserSecurity
from .security import hash_password


_DEFAULT_SETTINGS = {
    "system_name": "SIT Admin Panel",
    "timezone": "Asia/Kuala_Lumpur",
    "backup_schedule": "Daily 3:00 AM",
    "auto_backup": "true",
    "automatic_backup_enabled": "true",
    "backup_time_of_day": "03:00",
    "retention_days": "7",
}

# Default admin 2FA secret – add to Google Authenticator before first login
_DEFAULT_2FA_SECRET = "JBSWY3DPEHPK3PXP"


def seed_admin():
    db = SessionLocal()
    try:
        # Bot user: no 2FA (Telegram bot cannot complete 2FA flow)
        bot_user = db.query(AdminUser).filter(AdminUser.email == "bot@example.com").first()
        if not bot_user:
            bot_user = AdminUser(
                email="bot@example.com",
                password_hash=hash_password("bot123"),
                role="admin",
            )
            db.add(bot_user)
            db.commit()
            print("[SIT] Bot user seeded: bot@example.com / bot123 (no 2FA)")
        else:
            print("[SIT] Bot user already exists.")

        # nalcsbaru@gmail.com: with 2FA (primary user)
        extra_admin = db.query(AdminUser).filter(AdminUser.email == "nalcsbaru@gmail.com").first()
        if not extra_admin:
            extra_admin = AdminUser(
                email="nalcsbaru@gmail.com",
                password_hash=hash_password("admin123"),
                role="admin",
            )
            db.add(extra_admin)
            db.commit()
            print("[SIT] Admin seeded: nalcsbaru@gmail.com / admin123")
        else:
            print("[SIT] nalcsbaru@gmail.com already exists.")
        # Enable 2FA for nalcsbaru@gmail.com
        sec_extra = db.query(UserSecurity).filter(UserSecurity.user_id == extra_admin.id).first()
        if not sec_extra:
            sec_extra = UserSecurity(user_id=extra_admin.id)
            db.add(sec_extra)
        if not sec_extra.totp_secret:
            sec_extra.totp_secret = _DEFAULT_2FA_SECRET
            sec_extra.totp_enabled = True
            sec_extra.mfa_required = True
            db.commit()
            print("[SIT] 2FA enabled for nalcsbaru@gmail.com (secret: " + _DEFAULT_2FA_SECRET + ")")

        # Seed system settings (default toggles ON: auto_backup=true)
        for key, value in _DEFAULT_SETTINGS.items():
            row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
            if not row:
                db.add(SystemSetting(key=key, value=value))
            elif key == "auto_backup" and row.value == "false":
                row.value = "true"
        db.commit()
        print("[SIT] System settings seeded.")

    except Exception as e:
        print(f"[SIT] Seed error: {e}")
        db.rollback()
    finally:
        db.close()
