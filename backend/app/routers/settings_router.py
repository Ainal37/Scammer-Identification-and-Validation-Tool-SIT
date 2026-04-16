"""System settings endpoints (enterprise)."""

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import SystemSetting, AuditLog
from ..security import get_current_admin
from ..rbac import require_role
from ..schemas import SettingsResponse, SettingsUpdate

router = APIRouter(prefix="/settings", tags=["settings"])

_ALLOWED_KEYS = {
    "system_name",
    "timezone",
    "backup_schedule",
    "auto_backup",
    # extended enterprise keys
    "session_timeout_min",
    "auto_backup_enabled",
    "backup_time",
    "backup_time_of_day",
    "retention_count",
    "retention_days",
    "last_backup_at",
    "next_scheduled_backup",
}


@router.get("", response_model=SettingsResponse)
def get_settings(
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    rows = db.query(SystemSetting).filter(SystemSetting.key.in_(_ALLOWED_KEYS)).all()
    kv = {r.key: r.value for r in rows}

    # normalise types for response
    def _to_bool(val: str | None) -> bool | None:
        if val is None:
            return None
        return val.lower() in {"1", "true", "yes", "on"}

    def _to_int(val: str | None) -> int | None:
        try:
            return int(val) if val is not None else None
        except Exception:
            return None

    return SettingsResponse(
        system_name=kv.get("system_name"),
        timezone=kv.get("timezone"),
        backup_schedule=kv.get("backup_schedule"),
        auto_backup=kv.get("auto_backup"),
        session_timeout_min=_to_int(kv.get("session_timeout_min")),
        auto_backup_enabled=_to_bool(kv.get("auto_backup_enabled")),
        backup_time=kv.get("backup_time"),
        backup_time_of_day=kv.get("backup_time_of_day") or kv.get("backup_time"),
        retention_count=_to_int(kv.get("retention_count")),
        retention_days=_to_int(kv.get("retention_days")) or _to_int(kv.get("retention_count")) or 7,
        last_backup_at=kv.get("last_backup_at"),
        next_scheduled_backup=kv.get("next_scheduled_backup"),
    )


@router.patch("", response_model=SettingsResponse)
def update_settings(
    body: SettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    updates = body.model_dump(exclude_none=True)
    if not updates:
        raise HTTPException(400, "No fields to update")

    for key, value in updates.items():
        if key not in _ALLOWED_KEYS:
            continue
        row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
        if row:
            row.value = str(value)
        else:
            db.add(SystemSetting(key=key, value=str(value)))

    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    db.add(AuditLog(
        actor_email=admin.email,
        action="UPDATE_SETTINGS",
        detail=str(updates),
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()

    # Reschedule backup job if backup settings changed
    if any(k in updates for k in ("auto_backup", "automatic_backup_enabled", "backup_time", "backup_time_of_day")):
        try:
            from ..backup_scheduler import reschedule
            reschedule()
        except Exception:
            pass

    return get_settings(db=db, admin=admin)
