"""SQLAlchemy ORM models."""

from sqlalchemy import (
    Column, Integer, String, Text, BigInteger, Boolean,
    Enum, TIMESTAMP, ForeignKey,
)
from sqlalchemy.sql import func
from .database import Base


# ── Existing models (unchanged) ─────────────────────────────

class AdminUser(Base):
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="admin")
    created_at = Column(TIMESTAMP, server_default=func.now())
    last_login_at = Column(TIMESTAMP, nullable=True)
    last_login_ip = Column(String(45), nullable=True)
    last_user_agent = Column(String(500), nullable=True)


class Scan(Base):
    __tablename__ = "scans"
    id = Column(Integer, primary_key=True, index=True)
    telegram_user_id = Column(BigInteger, nullable=True)
    telegram_username = Column(String(80), nullable=True)
    link = Column(Text, nullable=False)
    verdict = Column(Enum("safe", "suspicious", "scam"), nullable=False)
    score = Column(Integer, nullable=False)
    threat_level = Column(String(10), nullable=True)
    reason = Column(Text, nullable=True)
    breakdown = Column(Text, nullable=True)
    intel_summary = Column(Text, nullable=True)
    message = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())


class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    telegram_user_id = Column(BigInteger, nullable=True)
    telegram_username = Column(String(80), nullable=True)
    link = Column(Text, nullable=True)
    report_type = Column(String(50), nullable=False, default="scam")
    description = Column(Text, nullable=False)
    status = Column(
        Enum("new", "investigating", "resolved"),
        nullable=False,
        default="new",
    )
    assignee = Column(String(255), nullable=True)
    notes = Column(Text, nullable=True)
    priority = Column(
        Enum("low", "medium", "high", "critical"),
        nullable=False,
        default="medium",
    )
    due_at = Column(TIMESTAMP, nullable=True)
    linked_scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor_email = Column(String(255), nullable=True)
    action = Column(String(100), nullable=False)
    target = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    detail = Column(Text, nullable=True)
    user_agent = Column(String(500), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())


# ── Enterprise models (new) ─────────────────────────────────

class User(Base):
    """Managed users for the enterprise admin panel."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=False)
    role = Column(Enum("admin", "editor", "viewer"), nullable=False, default="viewer")
    status = Column(Enum("active", "inactive", "suspended"), nullable=False, default="active")
    password_hash = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    last_login_at = Column(TIMESTAMP, nullable=True)


class UserSecurity(Base):
    __tablename__ = "user_security"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("admin_users.id"), nullable=False, unique=True)
    totp_enabled = Column(Boolean, nullable=False, default=False)
    totp_secret = Column(String(255), nullable=True)
    mfa_required = Column(Boolean, nullable=False, default=False)
    session_timeout_minutes = Column(Integer, nullable=False, default=480)
    # JSON list of SHA256 hashes for one-time recovery codes
    recovery_codes_hash = Column(Text, nullable=True)
    # Lockout + abuse protection for 2FA and step-up operations
    twofa_failed_attempts = Column(Integer, nullable=False, default=0)
    twofa_locked_until = Column(TIMESTAMP, nullable=True)
    password_hint = Column(String(80), nullable=True)


class Notification(Base):
    __tablename__ = "notifications"
    id = Column(Integer, primary_key=True, index=True)
    recipient_scope = Column(
        Enum("all", "admin", "editor", "viewer", "selected"),
        nullable=False, default="all",
    )
    recipient_user_id = Column(Integer, nullable=True)
    type = Column(Enum("info", "warning", "alert", "success"), nullable=False, default="info")
    title = Column(String(255), nullable=False)
    body = Column(Text, nullable=True)
    is_read = Column(Boolean, nullable=False, default=False)
    created_at = Column(TIMESTAMP, server_default=func.now())


class Backup(Base):
    __tablename__ = "backups"
    id = Column(Integer, primary_key=True, index=True)
    created_by_email = Column(String(255), nullable=True)
    scope_json = Column(Text, nullable=True)
    status = Column(
        Enum("queued", "running", "done", "failed"),
        nullable=False, default="queued",
    )
    file_path = Column(String(500), nullable=True)
    created_at = Column(TIMESTAMP, server_default=func.now())
    finished_at = Column(TIMESTAMP, nullable=True)


class BackupHistory(Base):
    """Real backup records: zip files with checksum, used by new backup system."""
    __tablename__ = "backup_history"
    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(TIMESTAMP, server_default=func.now())
    finished_at = Column(TIMESTAMP, nullable=True)
    status = Column(
        Enum("success", "failed", "running"),
        nullable=False,
        default="running",
    )
    size_bytes = Column(BigInteger, nullable=True)
    file_path = Column(String(500), nullable=True)
    checksum_sha256 = Column(String(64), nullable=True)
    error_message = Column(Text, nullable=True)
    type = Column(String(20), nullable=False, default="db_only")  # db_only | full
    summary_file_path = Column(String(500), nullable=True)  # backup-summary.json path


class SystemSetting(Base):
    __tablename__ = "system_settings"
    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
