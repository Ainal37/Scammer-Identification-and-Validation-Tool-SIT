"""Audit log endpoints (enterprise)."""

from typing import Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import AuditLog
from ..rbac import require_role

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("")
def list_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = Query(None),
    actor_email: Optional[str] = Query(None, description="Filter by actor. Use 'me' for current admin."),
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    q = db.query(AuditLog)
    if actor_email == "me":
        q = q.filter(AuditLog.actor_email == admin.email)
    if search:
        pattern = f"%{search}%"
        from sqlalchemy import or_
        q = q.filter(or_(
            AuditLog.action.ilike(pattern),
            AuditLog.actor_email.ilike(pattern),
            AuditLog.target.ilike(pattern),
        ))
    rows = q.order_by(AuditLog.id.desc()).offset(skip).limit(limit).all()
    return [_to_dict(a) for a in rows]


def _to_dict(a: AuditLog) -> dict:
    return {
        "id": a.id,
        "actor_email": a.actor_email,
        "action": a.action,
        "target": a.target,
        "ip_address": a.ip_address,
        "user_agent": a.user_agent,
        "detail": a.detail,
        "created_at": str(a.created_at) if a.created_at else None,
    }
