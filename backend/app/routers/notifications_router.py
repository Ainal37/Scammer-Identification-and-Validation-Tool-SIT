"""Notification endpoints (enterprise)."""

from typing import Optional, List
from fastapi import APIRouter, Depends, Query, HTTPException, Request, Body
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import Notification, AuditLog
from ..security import get_current_admin
from ..rbac import require_role
from ..schemas import NotificationCreate, NotificationResponse

router = APIRouter(prefix="/notifications", tags=["notifications"])


def _scope_filter(q, admin):
    """Single-admin: return all notifications (admin sees everything)."""
    return q


def _request_meta(request: Request):
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    return ip, ua


@router.post("", response_model=NotificationResponse)
def create_notification(
    body: NotificationCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    n = Notification(
        recipient_scope=body.recipient_scope,
        recipient_user_id=body.recipient_user_id,
        type=body.type,
        title=body.title,
        body=body.body,
    )
    db.add(n)
    db.commit()
    db.refresh(n)
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    db.add(AuditLog(
        actor_email=admin.email,
        action="CREATE_NOTIFICATION",
        target=f"notification_id={n.id}",
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return _to_resp(n)


@router.get("")
def list_notifications(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=200),
    unread_only: bool = Query(False),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    q = db.query(Notification)
    q = _scope_filter(q, admin)
    if unread_only:
        q = q.filter(Notification.is_read == False)
    rows = q.order_by(Notification.created_at.desc()).offset(skip).limit(limit).all()
    return [_to_resp(n) for n in rows]


@router.get("/unread-count")
def get_unread_count(
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    q = db.query(func.count(Notification.id)).filter(Notification.is_read == False)
    cnt = q.scalar() or 0
    return {"unread_count": cnt}


@router.post("/mark-read")
def mark_notifications_read(
    request: Request,
    ids: Optional[List[int]] = Body(default=None),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    ip, ua = _request_meta(request)
    ids = ids or []
    if ids:
        q = db.query(Notification).filter(Notification.id.in_(ids))
        q.update({Notification.is_read: True}, synchronize_session=False)
        target = ",".join(f"notification_id={i}" for i in ids[:5])
        if len(ids) > 5:
            target += f",+{len(ids) - 5} more"
    else:
        db.query(Notification).filter(Notification.is_read == False).update(
            {Notification.is_read: True}, synchronize_session=False
        )
        target = "mark_all"
    db.commit()
    db.add(AuditLog(
        actor_email=admin.email,
        action="MARK_READ" if ids else "MARK_ALL_READ",
        target=target,
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return {"ok": True}


@router.post("/mark-all-read")
def mark_all_read(
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    ip, ua = _request_meta(request)
    db.query(Notification).filter(Notification.is_read == False).update(
        {Notification.is_read: True}, synchronize_session=False
    )
    db.commit()
    db.add(AuditLog(
        actor_email=admin.email,
        action="MARK_ALL_READ",
        target="mark_all",
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return {"ok": True, "unread_count": 0}


@router.post("/{notification_id}/mark-read")
def mark_one_read(
    notification_id: int,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    q = db.query(Notification).filter(Notification.id == notification_id)
    n = q.first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    db.commit()
    ip, ua = _request_meta(request)
    db.add(AuditLog(
        actor_email=admin.email,
        action="MARK_READ",
        target=f"notification_id={notification_id}",
        ip_address=ip,
        user_agent=ua,
    ))
    db.commit()
    return {"ok": True}


def _to_resp(n: Notification) -> NotificationResponse:
    return NotificationResponse(
        id=n.id, recipient_scope=n.recipient_scope, type=n.type,
        title=n.title, body=n.body, is_read=n.is_read,
        created_at=str(n.created_at) if n.created_at else None,
    )
