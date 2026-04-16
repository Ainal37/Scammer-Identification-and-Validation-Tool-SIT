"""APScheduler for daily backups at configured time. Retention cleanup."""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from .database import SessionLocal
from .models import BackupHistory, SystemSetting
from .backup_service import run_backup, get_backup_dir

logger = logging.getLogger("sit.backup.scheduler")
_scheduler = None


def _get_setting(db, key: str, default=None):
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    return row.value if row else default


def _run_scheduled_backup():
    """Called by scheduler. Run db_only backup and apply retention."""
    db = SessionLocal()
    try:
        enabled = _get_setting(db, "automatic_backup_enabled") or _get_setting(db, "auto_backup_enabled") or _get_setting(db, "auto_backup")
        if enabled and str(enabled).lower() not in ("1", "true", "yes", "on"):
            return
        zip_path, summary_path, summary_data = run_backup(backup_type="db_only", db=db)
        rec = BackupHistory(
            status="success",
            type="db_only",
            started_at=datetime.now(timezone.utc),
            finished_at=datetime.now(timezone.utc),
            file_path=str(zip_path.resolve()),
            summary_file_path=str(summary_path.resolve()),
            size_bytes=zip_path.stat().st_size,
            checksum_sha256=summary_data.get("checksum_sha256"),
        )
        db.add(rec)
        now_iso = datetime.now(timezone.utc).isoformat()
        row = db.query(SystemSetting).filter(SystemSetting.key == "last_backup_at").first()
        if row:
            row.value = now_iso
        else:
            db.add(SystemSetting(key="last_backup_at", value=now_iso))
        db.commit()
        logger.info("Scheduled backup completed: %s", zip_path.name)
        _apply_retention(db)
    except Exception as e:
        logger.exception("Scheduled backup failed: %s", e)
        db.rollback()
    finally:
        db.close()


def _apply_retention(db):
    """Delete backup files and history records older than retention_days."""
    days = 7
    try:
        val = _get_setting(db, "retention_days") or _get_setting(db, "retention_count")
        if val:
            days = int(val)
    except (TypeError, ValueError):
        pass
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    rows = db.query(BackupHistory).filter(BackupHistory.finished_at < cutoff).all()
    for r in rows:
        paths_to_del = []
        if r.file_path:
            paths_to_del.append(Path(r.file_path))
        if r.summary_file_path:
            paths_to_del.append(Path(r.summary_file_path))
            txt = Path(r.summary_file_path).parent / Path(r.summary_file_path).name.replace("-summary.json", "-summary.txt")
            paths_to_del.append(txt)
        for p in paths_to_del:
            if not p.exists():
                p = get_backup_dir() / p.name
            if p.exists():
                try:
                    p.unlink()
                    logger.info("Retention: deleted %s", p.name)
                except OSError as e:
                    logger.warning("Retention: could not delete %s: %s", p, e)
        db.delete(r)
    db.commit()


def start_scheduler():
    """Start APScheduler with daily backup job. Load time from settings."""
    global _scheduler
    if _scheduler:
        return
    db = SessionLocal()
    try:
        enabled = _get_setting(db, "automatic_backup_enabled") or _get_setting(db, "auto_backup_enabled") or _get_setting(db, "auto_backup")
        time_str = _get_setting(db, "backup_time_of_day") or _get_setting(db, "backup_time") or "03:00"
        if ":" in time_str:
            parts = time_str.strip().split(":")
            hour, minute = int(parts[0]) if parts[0].isdigit() else 3, int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        else:
            hour, minute = 3, 0
    finally:
        db.close()

    _scheduler = BackgroundScheduler()
    if enabled and str(enabled).lower() in ("1", "true", "yes", "on"):
        _scheduler.add_job(_run_scheduled_backup, CronTrigger(hour=hour, minute=minute), id="daily_backup")
        logger.info("Backup scheduler: daily at %02d:%02d", hour, minute)
    else:
        logger.info("Backup scheduler: disabled (auto_backup off)")
    _scheduler.start()


def stop_scheduler():
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None


def reschedule():
    """Reschedule job when settings change."""
    stop_scheduler()
    start_scheduler()
