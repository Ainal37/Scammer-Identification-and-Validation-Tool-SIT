"""Real backup service: mysqldump, zip, checksum, summary, optional encryption."""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy.orm import Session
from sqlalchemy import text

from .database import DB_USER, DB_PASS, DB_HOST, DB_PORT, DB_NAME

logger = logging.getLogger("sit.backup")

APP_DIR = Path(__file__).resolve().parent
BACKEND_DIR = APP_DIR.parent
BACKUP_DIR = BACKEND_DIR / "backups"
_BACKUP_LOCK = False
_RUNNING_JOB_ID: Optional[int] = None
_RUNNING_JOB_STEP: Dict[str, Any] = {}  # {backup_id: {"step": str, "message": str}}

# Tables to report row counts (order: key tables first, then others)
_KEY_TABLES = ["scans", "reports", "audit_logs", "admin_users", "user_security", "system_settings"]
_ALL_TABLES = [
    "admin_users", "user_security", "scans", "reports", "audit_logs",
    "system_settings", "notifications", "users", "backups", "backup_history",
]


def _ensure_backups_dir() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    return BACKUP_DIR


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_mysqldump(out_path: Path) -> bool:
    """Run mysqldump to dump MySQL database. Returns True on success."""
    import subprocess
    mysqldump_candidates = [
        "mysqldump",
        r"C:\xampp\mysql\bin\mysqldump.exe",
        r"C:\lampp\mysql\bin\mysqldump.exe",
        r"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysqldump.exe",
        r"C:\Program Files\MySQL\MySQL Server 8.4\bin\mysqldump.exe",
        r"C:\Program Files\MariaDB 10.6\bin\mysqldump.exe",
        r"C:\Program Files\MariaDB 11.0\bin\mysqldump.exe",
    ]
    cmd = None
    for c in mysqldump_candidates:
        if c == "mysqldump":
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
        raise RuntimeError("mysqldump not found. Install MySQL or XAMPP.")
    args = [
        cmd,
        "--host", DB_HOST,
        "--port", str(DB_PORT),
        "--user", DB_USER,
        "--single-transaction",
        "--routines",
        "--triggers",
        DB_NAME,
    ]
    if DB_PASS:
        args.insert(-1, f"--password={DB_PASS}")
    try:
        with open(out_path, "w", encoding="utf-8", errors="replace") as f:
            subprocess.run(args, stdout=f, stderr=subprocess.PIPE, timeout=300, check=True)
        return True
    except subprocess.CalledProcessError as e:
        err = (e.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"mysqldump failed: {err}") from e


def _get_row_counts(db: Session) -> List[Dict[str, Any]]:
    """Get row count for each table. Returns list of {name, row_count}."""
    result = []
    for tbl in _ALL_TABLES:
        try:
            r = db.execute(text(f"SELECT COUNT(*) as c FROM `{tbl}`")).scalar()
            result.append({"name": tbl, "row_count": r or 0})
        except Exception:
            result.append({"name": tbl, "row_count": 0})
    return result


def _get_retention_days(db: Session) -> int:
    """Get retention_days from system_settings."""
    from .models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == "retention_days").first()
    if row and row.value:
        try:
            return int(row.value)
        except (TypeError, ValueError):
            pass
    row = db.query(SystemSetting).filter(SystemSetting.key == "retention_count").first()
    if row and row.value:
        try:
            return int(row.value)
        except (TypeError, ValueError):
            pass
    return 7


def _add_to_zip(zf, src: Path, arcname: str) -> None:
    if src.is_file():
        zf.write(src, arcname)
    elif src.is_dir():
        for p in src.rglob("*"):
            if p.is_file():
                zf.write(p, str(Path(arcname) / p.relative_to(src)))


def _set_step(backup_id: Optional[int], step: str, message: str) -> None:
    global _RUNNING_JOB_STEP
    if backup_id is not None:
        _RUNNING_JOB_STEP[backup_id] = {"step": step, "message": message}


def get_running_job_id() -> Optional[int]:
    return _RUNNING_JOB_ID


def get_job_step(backup_id: int) -> Optional[Dict[str, Any]]:
    return _RUNNING_JOB_STEP.get(backup_id)


def run_backup(
    backup_type: str = "db_only",
    db: Optional[Session] = None,
    backup_id: Optional[int] = None,
    on_step: Optional[Any] = None,
) -> Tuple[Path, Path, Dict[str, Any]]:
    """
    Create backup: mysqldump → zip (optional encryption), summary files, SHA-256.
    Returns (zip_path, summary_json_path, summary_data).
    Raises on error.
    """
    global _BACKUP_LOCK, _RUNNING_JOB_ID
    if _BACKUP_LOCK:
        raise RuntimeError("Another backup is already running")
    _BACKUP_LOCK = True
    _RUNNING_JOB_ID = backup_id
    def step(s: str, m: str) -> None:
        _set_step(backup_id, s, m)
        if on_step:
            on_step(s, m)
    try:
        _ensure_backups_dir()
        ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        base_name = f"backup-{ts}"
        zip_name = f"{base_name}.zip"
        zip_path = BACKUP_DIR / zip_name
        dump_path = BACKUP_DIR / f"dump-{ts}.sql"
        summary_json_path = BACKUP_DIR / f"{base_name}-summary.json"
        summary_txt_path = BACKUP_DIR / f"{base_name}-summary.txt"

        # 1. Run mysqldump
        step("dumping_db", "Dumping DB")
        _run_mysqldump(dump_path)

        # 2. Get row counts (before zip, so we can include in summary)
        step("zipping", "Zipping")
        tables = []
        key_highlight = {}
        if db:
            tables = _get_row_counts(db)
            for t in tables:
                if t["name"] in _KEY_TABLES:
                    key_highlight[t["name"]] = t["row_count"]
        retention_days = _get_retention_days(db) if db else 7

        # 3. Create zip (with optional AES encryption)
        enc_key = os.getenv("BACKUP_ENCRYPTION_KEY", "").strip()

        def _write_zip(zf):
            zf.write(dump_path, "dump.sql")
            if backup_type == "full":
                uploads = BACKEND_DIR / "uploads"
                logs = BACKEND_DIR / "logs"
                if uploads.exists():
                    _add_to_zip(zf, uploads, "uploads")
                if logs.exists():
                    _add_to_zip(zf, logs, "logs")

        if enc_key:
            import pyzipper
            with pyzipper.AESZipFile(zip_path, "w", pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(enc_key.encode("utf-8"))
                _write_zip(zf)
        else:
            import zipfile
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                _write_zip(zf)

        # 4. Remove temp dump
        if dump_path.exists():
            dump_path.unlink(missing_ok=True)

        # 5. Compute checksum
        step("computing_checksum", "Computing checksum")
        checksum = _sha256_file(zip_path)
        size_bytes = zip_path.stat().st_size

        # 6. Build summary data
        created_at = datetime.now(timezone.utc).isoformat()
        summary_data = {
            "backup_id": backup_id,
            "created_at": created_at,
            "db_type": "mysql",
            "db_name": DB_NAME,
            "dump_file_name": "dump.sql",
            "zip_file_name": zip_name,
            "size_bytes": size_bytes,
            "checksum_sha256": checksum,
            "tables": tables,
            "key_tables_highlight": key_highlight,
            "retention_days": retention_days,
            "backup_type": backup_type,
            "status": "success",
            "error_message": None,
            "encrypted": bool(enc_key),
        }

        # 7. Write backup-summary.json
        step("writing_summary", "Writing summary")
        with open(summary_json_path, "w", encoding="utf-8") as f:
            json.dump(summary_data, f, indent=2, default=str)

        # 8. Write backup-summary.txt (human-friendly)
        lines = [
            "=" * 60,
            "SIT-System Backup Summary Report",
            "=" * 60,
            "",
            "Generated: " + created_at,
            "Backup ID: " + str(backup_id or "N/A"),
            "Database: " + DB_NAME + " (MySQL)",
            "Backup type: " + backup_type,
            "Zip file: " + zip_name,
            "Size: " + str(size_bytes) + " bytes",
            "SHA-256: " + checksum,
            "Encrypted: " + ("Yes" if enc_key else "No"),
            "Retention: " + str(retention_days) + " days",
            "",
            "=" * 60,
            "What is backed up",
            "=" * 60,
            "",
            "1) Accounts & Security: admin_users, user_security",
            "2) SIT Core Data: scans, reports",
            "3) System Config & Audit: system_settings, audit_logs",
            "4) Other tables: notifications, users, backups, backup_history",
            "",
            "=" * 60,
            "Row counts per table",
            "=" * 60,
            "",
        ]
        for t in tables:
            lines.append(f"  {t['name']}: {t['row_count']} rows")
        lines.append("")
        lines.append("Generated at: " + created_at)
        with open(summary_txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        return zip_path, summary_json_path, summary_data
    finally:
        _BACKUP_LOCK = False
        _RUNNING_JOB_ID = None
        if backup_id is not None:
            _RUNNING_JOB_STEP.pop(backup_id, None)


def compute_checksum(path: Path) -> str:
    return _sha256_file(path)


def verify_checksum(path: Path, expected: str) -> bool:
    return _sha256_file(path) == expected


def get_backup_dir() -> Path:
    return _ensure_backups_dir()
