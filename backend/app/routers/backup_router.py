"""Backup management: real mysqldump+zip backups, download, restore, history."""

import json
import logging
import subprocess
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..backup_service import (
    BACKUP_DIR,
    run_backup as do_run_backup,
    compute_checksum,
    verify_checksum,
    get_backup_dir,
    get_running_job_id,
    get_job_step,
)
from ..database import get_db, DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME
from ..models import AdminUser, AuditLog, Backup, BackupHistory, Report, SystemSetting
from ..rbac import require_role
from ..schemas import (
    BackupHistoryItem,
    BackupResponse,
    BackupRestoreRequest,
    BackupRestoreResponse,
    BackupRunRequest,
)

router = APIRouter(prefix="/backup", tags=["backup"])
logger = logging.getLogger("sit.backup")


def _ensure_backups_dir() -> Path:
    get_backup_dir()
    return BACKUP_DIR


def _canonical_path(file_path: Optional[str]) -> Optional[Path]:
    if not file_path:
        return None
    p = Path(file_path)
    if p.is_absolute():
        return p if p.exists() else None
    return BACKUP_DIR / p.name if (BACKUP_DIR / p.name).exists() else None


# ── New backup system (BackupHistory + zip) ─────────────────────

def _run_backup_thread(backup_id: int, backup_type: str, admin_email: str):
    """Background thread: run backup and update DB."""
    from ..database import SessionLocal
    db = SessionLocal()
    try:
        zip_path, summary_path, summary_data = do_run_backup(
            backup_type=backup_type, db=db, backup_id=backup_id
        )
        size_bytes = zip_path.stat().st_size
        checksum = summary_data.get("checksum_sha256") or compute_checksum(zip_path)

        rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
        if rec:
            rec.file_path = str(zip_path.resolve())
            rec.summary_file_path = str(summary_path.resolve())
            rec.size_bytes = size_bytes
            rec.checksum_sha256 = checksum
            rec.status = "success"
            rec.finished_at = datetime.now(timezone.utc)
            db.commit()

            now_iso = datetime.now(timezone.utc).isoformat()
            row = db.query(SystemSetting).filter(SystemSetting.key == "last_backup_at").first()
            if row:
                row.value = now_iso
            else:
                db.add(SystemSetting(key="last_backup_at", value=now_iso))
            db.commit()
    except Exception as e:
        logger.exception("Backup failed")
        rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
        if rec:
            rec.status = "failed"
            rec.error_message = str(e)
            rec.finished_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()


def _request_meta(request: Request) -> tuple:
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    return ip, ua


@router.post("/run")
def run_backup(
    body: BackupRunRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Start backup job. Returns immediately with {id, status:"running"}. Poll GET /{id}/status for progress."""
    from ..backup_service import get_running_job_id
    if get_running_job_id() is not None:
        raise HTTPException(409, "backup_already_running")

    running = db.query(BackupHistory).filter(BackupHistory.status == "running").first()
    if running:
        raise HTTPException(409, "backup_already_running")

    backup_type = (body.type or "db_only").lower()
    if backup_type not in ("db_only", "full"):
        backup_type = "db_only"

    rec = BackupHistory(
        status="running",
        type=backup_type,
        started_at=datetime.now(timezone.utc),
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    ip, ua = _request_meta(request)
    db.add(AuditLog(
        actor_email=admin.email,
        action="RUN_BACKUP",
        target=f"backup_id={rec.id}",
        detail=json.dumps({"type": backup_type}),
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()

    t = threading.Thread(
        target=_run_backup_thread,
        args=(rec.id, backup_type, admin.email),
        daemon=True,
    )
    t.start()

    return {"id": rec.id, "status": "running"}


@router.get("/{backup_id}/status")
def get_backup_job_status(
    backup_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Poll backup job status. Returns status, step, message, and final data when done."""
    if backup_id >= 100000:
        raise HTTPException(404, "Backup not found")
    rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not rec:
        raise HTTPException(404, "Backup not found")

    step_info = get_job_step(backup_id)
    step = step_info.get("step", "") if step_info else ""
    message = step_info.get("message", "") if step_info else ""

    if rec.status == "running":
        step_msg = message or "Dumping DB → Zipping → Computing checksum → Writing summary"
        return {
            "id": rec.id,
            "status": "running",
            "step": step,
            "message": step_msg,
            "started_at": str(rec.started_at) if rec.started_at else None,
        }

    summary_data = None
    if rec.status == "success" and rec.summary_file_path:
        path = Path(rec.summary_file_path)
        if path.is_file():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    summary_data = json.load(f)
            except Exception:
                pass

    key_tables = {}
    if summary_data and "key_tables_highlight" in summary_data:
        key_tables = summary_data["key_tables_highlight"]

    return {
        "id": rec.id,
        "status": rec.status,
        "step": step,
        "message": message,
        "finished_at": str(rec.finished_at) if rec.finished_at else None,
        "size_bytes": rec.size_bytes,
        "checksum_sha256": rec.checksum_sha256,
        "key_tables": key_tables,
        "summary_file": rec.summary_file_path,
        "zip_file": rec.file_path,
        "error_message": rec.error_message,
    }


@router.get("/latest")
def get_latest_backup(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Return latest successful backup from backup_history."""
    rec = db.query(BackupHistory).filter(BackupHistory.status == "success").order_by(BackupHistory.id.desc()).first()
    if not rec:
        # Fallback to old Backup table
        old = db.query(Backup).filter(Backup.status == "done").order_by(Backup.id.desc()).first()
        if old:
            return {
                "id": old.id + 100000,  # Offset for download/restore routing
                "source": "legacy",
                "status": old.status,
                "file_path": old.file_path,
                "created_at": str(old.created_at) if old.created_at else None,
                "finished_at": str(old.finished_at) if old.finished_at else None,
            }
        raise HTTPException(404, "No backups found")
    return {
        "id": rec.id,
        "source": "backup_history",
        "status": rec.status,
        "file_path": rec.file_path,
        "size_bytes": rec.size_bytes,
        "checksum_sha256": rec.checksum_sha256,
        "type": rec.type,
        "started_at": str(rec.started_at) if rec.started_at else None,
        "finished_at": str(rec.finished_at) if rec.finished_at else None,
    }


@router.get("/history")
def list_backup_history(
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """List backup history (new zip backups first, then legacy JSON)."""
    rows = db.query(BackupHistory).order_by(BackupHistory.id.desc()).limit(limit).all()
    result = []
    for r in rows:
        result.append(BackupHistoryItem(
            id=r.id,
            started_at=str(r.started_at) if r.started_at else None,
            finished_at=str(r.finished_at) if r.finished_at else None,
            status=r.status,
            size_bytes=r.size_bytes,
            file_path=r.file_path,
            checksum_sha256=r.checksum_sha256,
            error_message=r.error_message,
            type=r.type,
        ))
    # Append legacy backups if we have room
    if len(result) < limit:
        legacy = db.query(Backup).filter(Backup.status == "done").order_by(Backup.id.desc()).limit(limit - len(result)).all()
        for b in legacy:
            result.append(BackupHistoryItem(
                id=b.id + 100000,  # Offset to distinguish from BackupHistory ids
                started_at=str(b.created_at) if b.created_at else None,
                finished_at=str(b.finished_at) if b.finished_at else None,
                status="success",
                size_bytes=None,
                file_path=b.file_path,
                checksum_sha256=None,
                error_message=None,
                type="legacy",
            ))
    return result


@router.get("/latest-summary")
def get_latest_summary(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Return summary JSON for latest successful backup."""
    rec = db.query(BackupHistory).filter(BackupHistory.status == "success").order_by(BackupHistory.id.desc()).first()
    if not rec:
        raise HTTPException(404, "No backups found")
    return _get_summary_for_rec(rec)


def _get_summary_for_rec(rec: BackupHistory) -> dict:
    """Load and return summary JSON for a BackupHistory record."""
    path = rec.summary_file_path or (Path(rec.file_path).parent / Path(rec.file_path).name.replace(".zip", "-summary.json") if rec.file_path else None)
    if not path:
        return {
            "backup_id": rec.id,
            "status": rec.status,
            "size_bytes": rec.size_bytes,
            "checksum_sha256": rec.checksum_sha256,
            "finished_at": str(rec.finished_at) if rec.finished_at else None,
            "tables": [],
            "key_tables_highlight": {},
        }
    p = Path(path)
    if not p.is_file():
        return {
            "backup_id": rec.id,
            "status": rec.status,
            "size_bytes": rec.size_bytes,
            "checksum_sha256": rec.checksum_sha256,
            "finished_at": str(rec.finished_at) if rec.finished_at else None,
            "tables": [],
            "key_tables_highlight": {},
        }
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


@router.get("/{backup_id}/summary")
def get_backup_summary(
    backup_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Return summary JSON for a specific backup."""
    if backup_id >= 100000:
        raise HTTPException(404, "Summary not available for legacy backups")
    rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not rec:
        raise HTTPException(404, "Backup not found")
    return _get_summary_for_rec(rec)


@router.get("/download/{backup_id}")
def download_backup(
    backup_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Stream backup file. Supports both BackupHistory (zip) and legacy Backup (json)."""
    if backup_id >= 100000:
        # Legacy backup
        legacy_id = backup_id - 100000
        b = db.query(Backup).filter(Backup.id == legacy_id).first()
        if not b or not b.file_path:
            raise HTTPException(404, "Backup not found")
        full_path = _canonical_path(b.file_path)
        if not full_path or not full_path.is_file():
            raise HTTPException(404, "Backup file not found on disk")
        return FileResponse(full_path, media_type="application/json", filename=full_path.name)
    rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not rec or not rec.file_path:
        raise HTTPException(404, "Backup not found")
    full_path = Path(rec.file_path)
    if not full_path.is_file():
        raise HTTPException(404, "Backup file not found on disk")
    return FileResponse(full_path, media_type="application/zip", filename=full_path.name)


@router.get("/download/{backup_id}/summary")
def download_backup_summary(
    backup_id: int,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Download summary file (JSON or TXT) for a backup."""
    if backup_id >= 100000:
        raise HTTPException(404, "Summary not available for legacy backups")
    rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not rec:
        raise HTTPException(404, "Backup not found")
    fmt = "json"  # default
    path = rec.summary_file_path or (str(Path(rec.file_path).parent / Path(rec.file_path).name.replace(".zip", "-summary.json")) if rec.file_path else None)
    if not path:
        raise HTTPException(404, "Summary file not found")
    p = Path(path)
    if not p.is_file():
        txt_path = p.parent / p.name.replace("-summary.json", "-summary.txt")
        if txt_path.is_file():
            p = txt_path
            fmt = "txt"
        else:
            raise HTTPException(404, "Summary file not found on disk")
    media = "application/json" if fmt == "json" else "text/plain"
    return FileResponse(p, media_type=media, filename=p.name)


@router.post("/restore/{backup_id}", response_model=BackupRestoreResponse)
def restore_backup(
    backup_id: int,
    body: BackupRestoreRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Restore from backup. For zip: creates pre-restore snapshot, verifies checksum, runs mysql import."""
    ip, ua = _request_meta(request)
    if backup_id >= 100000:
        return _restore_legacy_json(backup_id - 100000, body, db, admin, ip, ua)
    return _restore_zip(backup_id, body, db, admin, ip, ua)


def _restore_zip(backup_id: int, body: BackupRestoreRequest, db: Session, admin, ip=None, ua=None) -> BackupRestoreResponse:
    rec = db.query(BackupHistory).filter(BackupHistory.id == backup_id).first()
    if not rec or not rec.file_path or rec.status != "success":
        raise HTTPException(404, "Backup not found or not successful")
    full_path = Path(rec.file_path)
    if not full_path.is_file():
        raise HTTPException(404, "Backup file not found on disk")
    if rec.checksum_sha256 and not verify_checksum(full_path, rec.checksum_sha256):
        raise HTTPException(400, "Backup file checksum mismatch – file may be corrupted")
    # Create snapshot before restore
    try:
        snapshot_path, _, _ = do_run_backup(backup_type="db_only", db=db)
        db.add(AuditLog(
            actor_email=admin.email,
            action="BACKUP_RESTORE_SNAPSHOT",
            detail=json.dumps({"before_restore_id": backup_id, "snapshot": str(snapshot_path)}),
            ip_address=ip,
            user_agent=ua,
        ))
        db.commit()
    except Exception as e:
        logger.warning("Pre-restore snapshot failed: %s", e)
    # Run mysql import (extract dump.sql from zip and pipe to mysql)
    import tempfile
    enc_key = __import__("os").getenv("BACKUP_ENCRYPTION_KEY", "").strip()
    with tempfile.TemporaryDirectory() as tmp:
        try:
            import pyzipper
            with pyzipper.AESZipFile(full_path, "r") as zf:
                if enc_key:
                    zf.setpassword(enc_key.encode("utf-8"))
                zf.extract("dump.sql", tmp)
        except (ImportError, RuntimeError):
            import zipfile
            with zipfile.ZipFile(full_path, "r") as zf:
                zf.extract("dump.sql", tmp)
        dump_file = Path(tmp) / "dump.sql"
        mysql_candidates = ["mysql", r"C:\xampp\mysql\bin\mysql.exe"]
        cmd = None
        for c in mysql_candidates:
            if c == "mysql":
                try:
                    subprocess.run([c, "--version"], capture_output=True, check=True, timeout=5)
                    cmd = c
                    break
                except (FileNotFoundError, subprocess.CalledProcessError):
                    continue
            elif Path(c).exists():
                cmd = c
                break
        if not cmd:
            raise HTTPException(500, "mysql client not found. Install MySQL or XAMPP.")
        args = [cmd, "--host", DB_HOST, "--port", str(DB_PORT), "--user", DB_USER, DB_NAME]
        if DB_PASS:
            args.insert(-1, f"--password={DB_PASS}")
        try:
            with open(dump_file, "r", encoding="utf-8", errors="replace") as f:
                subprocess.run(args, stdin=f, capture_output=True, timeout=120, check=True)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or b"").decode("utf-8", errors="replace")
            raise HTTPException(500, f"Restore failed: {err}") from e
    db.add(AuditLog(
        actor_email=admin.email,
        action="BACKUP_RESTORED_ZIP",
        detail=json.dumps({"backup_id": backup_id, "restart_required": True}),
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return BackupRestoreResponse(
        ok=True,
        mode="full",
        restored_counts={"database": "replaced"},
        restart_required=True,
    )


def _restore_legacy_json(backup_id: int, body: BackupRestoreRequest, db: Session, admin, ip=None, ua=None) -> BackupRestoreResponse:
    b = db.query(Backup).filter(Backup.id == backup_id).first()
    if not b or not b.file_path:
        raise HTTPException(404, "Backup not found")
    full_path = _canonical_path(b.file_path)
    if not full_path or not full_path.is_file():
        raise HTTPException(404, "Backup file not found on disk")
    try:
        with open(full_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        raise HTTPException(400, f"Invalid backup file: {e}")
    if "meta" not in data or "system_settings" not in data:
        raise HTTPException(400, "Invalid backup format")
    mode = (body.mode or "safe").lower()
    if mode not in ("safe", "full"):
        mode = "safe"
    restored = {"system_settings": 0, "admin_users": 0, "reports": 0, "audit_logs": 0}
    for item in data.get("system_settings") or []:
        if not isinstance(item, dict) or "key" not in item:
            continue
        key, value = item.get("key"), item.get("value")
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(SystemSetting(key=key, value=value))
        restored["system_settings"] += 1
    if mode == "full":
        for item in data.get("admin_users") or []:
            if not isinstance(item, dict) or "email" not in item:
                continue
            email = item.get("email")
            existing = db.query(AdminUser).filter(AdminUser.email == email).first()
            if existing:
                existing.role = item.get("role", existing.role)
                if item.get("password_hash") and len(str(item["password_hash"])) == 60:
                    existing.password_hash = item["password_hash"]
            else:
                pw = item.get("password_hash")
                if not pw or len(str(pw)) != 60:
                    continue
                db.add(AdminUser(email=email, role=item.get("role", "admin"), password_hash=pw))
            restored["admin_users"] += 1
        for item in data.get("reports") or []:
            if not isinstance(item, dict):
                continue
            existing_ids = {r.id for r in db.query(Report.id).all()}
            rid = item.get("id")
            if rid is not None and rid in existing_ids:
                r = db.query(Report).filter(Report.id == rid).first()
                if r:
                    r.telegram_user_id = item.get("telegram_user_id")
                    r.telegram_username = item.get("telegram_username")
                    r.link = item.get("link")
                    r.report_type = item.get("report_type", "scam")
                    r.description = item.get("description", "")
                    r.status = item.get("status", "new")
                    r.assignee = item.get("assignee")
                    r.notes = item.get("notes")
            else:
                db.add(Report(
                    telegram_user_id=item.get("telegram_user_id"),
                    telegram_username=item.get("telegram_username"),
                    link=item.get("link"),
                    report_type=item.get("report_type", "scam"),
                    description=item.get("description", ""),
                    status=item.get("status", "new"),
                    assignee=item.get("assignee"),
                    notes=item.get("notes"),
                ))
            restored["reports"] += 1
        for item in data.get("audit_logs") or []:
            if not isinstance(item, dict) or "action" not in item:
                continue
            db.add(AuditLog(
                actor_email=item.get("actor_email"),
                action=item.get("action", ""),
                target=item.get("target"),
                ip_address=item.get("ip_address"),
                detail=item.get("detail"),
                user_agent=item.get("user_agent"),
            ))
            restored["audit_logs"] += 1
    db.add(AuditLog(
        actor_email=admin.email,
        action="BACKUP_RESTORED_SAFE" if mode == "safe" else "BACKUP_RESTORED_FULL",
        detail=json.dumps({"backup_id": backup_id, "mode": mode, "restored": restored}),
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return BackupRestoreResponse(ok=True, mode=mode, restored_counts=restored)


@router.get("/status")
def get_backup_status(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """Return last_backup_at, next_scheduled_backup, latest backup info."""
    def _get(k):
        r = db.query(SystemSetting).filter(SystemSetting.key == k).first()
        return r.value if r else None
    last = _get("last_backup_at")
    time_str = _get("backup_time_of_day") or _get("backup_time") or "03:00"
    enabled = _get("automatic_backup_enabled") or _get("auto_backup_enabled") or _get("auto_backup")
    enabled = enabled and str(enabled).lower() in ("1", "true", "yes", "on")
    next_at = None
    if enabled and ":" in time_str:
        from datetime import date
        parts = time_str.strip().split(":")
        h, m = int(parts[0]) if parts[0].isdigit() else 3, int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        today = date.today()
        from datetime import datetime as dt
        next_at = dt(today.year, today.month, today.day, h, m).isoformat() + " (local)"
    latest = db.query(BackupHistory).filter(BackupHistory.status == "success").order_by(BackupHistory.id.desc()).first()
    latest_summary = None
    if latest:
        latest_summary = _get_summary_for_rec(latest)
    return {
        "last_backup_at": last,
        "next_scheduled_backup": next_at,
        "automatic_backup_enabled": enabled,
        "backup_time_of_day": time_str,
        "latest": {
            "id": latest.id,
            "size_bytes": latest.size_bytes,
            "status": latest.status,
            "checksum_sha256": latest.checksum_sha256,
            "finished_at": str(latest.finished_at) if latest else None,
            "summary": latest_summary,
        } if latest else None,
    }


# ── Legacy list (for backward compatibility) ────────────────────

@router.get("")
def list_backups(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    """List backups: prefer backup_history, fallback to legacy Backup."""
    rows = db.query(BackupHistory).order_by(BackupHistory.id.desc()).offset(skip).limit(limit).all()
    result = []
    for r in rows:
        result.append({
            "id": r.id,
            "source": "backup_history",
            "status": r.status,
            "file_path": r.file_path,
            "size_bytes": r.size_bytes,
            "checksum_sha256": r.checksum_sha256,
            "type": r.type,
            "created_at": str(r.started_at) if r.started_at else None,
            "finished_at": str(r.finished_at) if r.finished_at else None,
        })
    if len(result) < limit:
        legacy = db.query(Backup).filter(Backup.status == "done").order_by(Backup.id.desc()).limit(limit - len(result)).all()
        for b in legacy:
            result.append({
                "id": b.id + 100000,
                "source": "legacy",
                "status": b.status,
                "file_path": b.file_path,
                "created_at": str(b.created_at) if b.created_at else None,
                "finished_at": str(b.finished_at) if b.finished_at else None,
            })
    return result
