"""User management endpoints (enterprise)."""

import json
from typing import Optional
from fastapi import APIRouter, Depends, Query, HTTPException, Request
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User, AuditLog
from ..security import get_current_admin, hash_password
from ..rbac import require_role
from ..schemas import UserCreate, UserUpdate, UserResponse

router = APIRouter(prefix="/users", tags=["users"])

VALID_ROLES = {"admin", "editor", "viewer"}
VALID_STATUSES = {"active", "inactive", "suspended"}


def _request_meta(request: Request) -> tuple:
    ip = request.client.host if request.client else None
    ua = (request.headers.get("user-agent") or "")[:500] or None
    return ip, ua


@router.post("", response_model=UserResponse)
def create_user(
    body: UserCreate,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    if body.role not in VALID_ROLES:
        raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")
    if body.status not in VALID_STATUSES:
        raise HTTPException(400, f"Invalid status. Must be one of: {VALID_STATUSES}")
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(409, "User with this email already exists")

    password = body.password or "changeme123"
    u = User(
        email=body.email,
        full_name=body.full_name,
        role=body.role,
        status=body.status,
        password_hash=hash_password(password),
    )
    ip, ua = _request_meta(request)
    db.add(u)
    db.add(AuditLog(actor_email=admin.email, action="CREATE_USER", target=body.email, ip_address=ip, user_agent=ua))
    db.commit()
    db.refresh(u)
    return _to_resp(u)


@router.get("")
def list_users(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    q = db.query(User)
    if search:
        pattern = f"%{search}%"
        from sqlalchemy import or_
        q = q.filter(or_(User.email.ilike(pattern), User.full_name.ilike(pattern)))
    if role and role in VALID_ROLES:
        q = q.filter(User.role == role)
    if status and status in VALID_STATUSES:
        q = q.filter(User.status == status)
    rows = q.order_by(User.id.desc()).offset(skip).limit(limit).all()
    return [_to_resp(u) for u in rows]


@router.get("/{user_id}")
def get_user(user_id: int, db: Session = Depends(get_db), admin=Depends(require_role("admin"))):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    return _to_resp(u)


@router.patch("/{user_id}", response_model=UserResponse)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin=Depends(require_role("admin")),
):
    u = db.query(User).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(404, "User not found")
    if body.full_name is not None:
        u.full_name = body.full_name
    if body.email is not None:
        u.email = body.email
    if body.role is not None:
        if body.role not in VALID_ROLES:
            raise HTTPException(400, f"Invalid role. Must be one of: {VALID_ROLES}")
        u.role = body.role
    if body.status is not None:
        if body.status not in VALID_STATUSES:
            raise HTTPException(400, f"Invalid status. Must be one of: {VALID_STATUSES}")
        u.status = body.status
    ip, ua = _request_meta(request)
    db.add(AuditLog(actor_email=admin.email, action="UPDATE_USER", target=str(user_id), ip_address=ip, user_agent=ua))
    db.commit()
    db.refresh(u)
    return _to_resp(u)


def _to_resp(u: User) -> UserResponse:
    return UserResponse(
        id=u.id, email=u.email, full_name=u.full_name,
        role=u.role, status=u.status,
        created_at=str(u.created_at) if u.created_at else None,
        last_login_at=str(u.last_login_at) if u.last_login_at else None,
    )
