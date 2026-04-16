"""SIT Backend – FastAPI application entry point."""

import logging
import os
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from .database import Base, engine, SessionLocal
from .seed import seed_admin
from .middleware import RateLimitMiddleware, AuditLogMiddleware
from .routers import (
    auth, scans, reports, dashboard, evaluation,
    users_router, notifications_router, settings_router,
    security_router, backup_router, audit_router, analytics_router,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(name)-18s  %(levelname)-5s  %(message)s")
logger = logging.getLogger("sit")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: auto-migrate schema if outdated, create tables, seed admin, start backup scheduler.

    Wrapped in try/except so the app starts even if MySQL is down.
    /health will report db=false until the database becomes available.
    """
    try:
        from sqlalchemy import inspect as sa_inspect

        inspector = sa_inspect(engine)
        needs_rebuild = False

        if inspector.has_table("scans"):
            cols = {c["name"] for c in inspector.get_columns("scans")}
            if "threat_level" not in cols or "breakdown" not in cols:
                needs_rebuild = True

        if inspector.has_table("reports"):
            cols = {c["name"] for c in inspector.get_columns("reports")}
            if "description" not in cols or "assignee" not in cols or "priority" not in cols or "due_at" not in cols or "linked_scan_id" not in cols:
                needs_rebuild = True

        # Check new enterprise tables
        for tbl in ("users", "user_security", "notifications", "backups", "backup_history", "system_settings"):
            if not inspector.has_table(tbl):
                needs_rebuild = True

        if inspector.has_table("audit_logs"):
            cols = {c["name"] for c in inspector.get_columns("audit_logs")}
            if "user_agent" not in cols:
                needs_rebuild = True

        if inspector.has_table("backup_history"):
            cols = {c["name"] for c in inspector.get_columns("backup_history")}
            if "summary_file_path" not in cols:
                needs_rebuild = True

        if inspector.has_table("user_security"):
            cols = {c["name"] for c in inspector.get_columns("user_security")}
            if "password_hint" not in cols:
                needs_rebuild = True

        # Safe migration: add admin_users login columns without drop_all
        if inspector.has_table("admin_users"):
            admin_cols = {c["name"] for c in inspector.get_columns("admin_users")}
            try:
                with engine.connect() as conn:
                    if "last_login_at" not in admin_cols:
                        conn.execute(text("ALTER TABLE admin_users ADD COLUMN last_login_at TIMESTAMP NULL"))
                        conn.commit()
                    if "last_login_ip" not in admin_cols:
                        conn.execute(text("ALTER TABLE admin_users ADD COLUMN last_login_ip VARCHAR(45) NULL"))
                        conn.commit()
                    if "last_user_agent" not in admin_cols:
                        conn.execute(text("ALTER TABLE admin_users ADD COLUMN last_user_agent VARCHAR(500) NULL"))
                        conn.commit()
            except Exception as mig_err:
                logger.warning("[SIT] Admin users migration skipped: %s", mig_err)

        if needs_rebuild:
            logger.info("[SIT] Schema outdated – rebuilding tables…")
            Base.metadata.drop_all(bind=engine)

        Base.metadata.create_all(bind=engine)
        seed_admin()
        logger.info("[SIT] Database ready.")
        from .backup_scheduler import start_scheduler
        start_scheduler()
    except Exception as exc:
        logger.error("[SIT] Database unavailable at startup: %s", exc)
        logger.warning("[SIT] App will start anyway. /health will report db=false.")

    yield
    from .backup_scheduler import stop_scheduler
    stop_scheduler()


app = FastAPI(
    title="SIT Backend API",
    description="Scammer Identification & Validation Tool – Enterprise MVP",
    version="2.0.0",
    lifespan=lifespan,
)


# ── Exception handler: 503 when MySQL down (clear UX vs generic 500) ──
from fastapi import HTTPException
from fastapi.responses import JSONResponse


@app.exception_handler(Exception)
async def catch_all_exception_handler(request, exc):
    if isinstance(exc, HTTPException):
        raise exc
    exc_str = str(exc).lower()
    if "can't connect to mysql" in exc_str or "connection refused" in exc_str:
        return JSONResponse(
            status_code=503,
            content={"detail": "Database unavailable. Start XAMPP MySQL and ensure 'sit_db' exists."},
        )
    if "unknown database" in exc_str or "sit_db" in exc_str:
        return JSONResponse(
            status_code=503,
            content={"detail": "Database 'sit_db' not found. Create it in phpMyAdmin or run run_all.ps1 (it auto-creates)."},
        )
    raise exc  # Let FastAPI return default 500


# ── Middleware (order matters: first added = outermost) ──
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.add_middleware(AuditLogMiddleware)
app.add_middleware(RateLimitMiddleware, global_limit=120, window=60)

# ── Routers ──
app.include_router(auth.router)
app.include_router(scans.router)
app.include_router(reports.router)
app.include_router(dashboard.router)
app.include_router(evaluation.router)
app.include_router(users_router.router)
app.include_router(notifications_router.router)
app.include_router(settings_router.router)
app.include_router(security_router.router)
app.include_router(backup_router.router)
app.include_router(audit_router.router)
app.include_router(analytics_router.router)


@app.get("/", tags=["health"])
def root():
    return {"status": "ok", "version": "2.0.0", "service": "SIT Backend API"}


@app.get("/public/password-hint", tags=["public"])
def public_password_hint(email: str):
    """Unauthenticated – return the plain password hint for a given email.
    Always 200 to avoid user-enumeration via status codes."""
    from sqlalchemy.orm import Session as _Ses
    from .models import AdminUser, UserSecurity
    db: _Ses = SessionLocal()
    try:
        admin = db.query(AdminUser).filter(AdminUser.email == email.strip().lower()).first()
        if not admin:
            return {"email": email.strip().lower(), "hint": None}
        sec = db.query(UserSecurity).filter(UserSecurity.user_id == admin.id).first()
        hint = (sec.password_hint or "").strip() if sec else ""
        return {"email": email.strip().lower(), "hint": hint if hint else None}
    finally:
        db.close()


@app.get("/health", tags=["health"])
def health_check():
    """Unauthenticated health probe – used by frontend, run_all.ps1, and bot.

    Designed to respond in <50ms even if the database is down.
    Uses the connection pool with pool_pre_ping so dead connections are recycled.
    Wrapped in a tight try/except so it never crashes.
    """
    db_ok = False
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db_ok = True
        db.close()
    except Exception:
        try:
            db.close()
        except Exception:
            pass

    intel_configured = bool(os.getenv("VIRUSTOTAL_API_KEY", "").strip())

    return {
        "ok": True,
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "version": "2.0.0",
        "db": db_ok,
        "intel": intel_configured,
    }
