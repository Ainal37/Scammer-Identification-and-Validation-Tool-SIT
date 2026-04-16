"""Report endpoints: create + list + detail + PATCH + PUT + bulk-update + case.pdf."""

from datetime import datetime, timezone, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..database import get_db
from ..models import Report, Scan, AuditLog
from ..security import get_current_admin
from ..schemas import ReportRequest, ReportResponse, ReportUpdate, ReportBulkUpdate
from ..pdf_report import generate_case_pdf

router = APIRouter(prefix="/reports", tags=["reports"])

VALID_STATUSES = {"new", "investigating", "resolved"}
VALID_PRIORITIES = {"low", "medium", "high", "critical"}

PRIORITY_SLA_HOURS = {"low": 24 * 7, "medium": 24 * 3, "high": 24, "critical": 6}


def _compute_due_at(priority: str) -> Optional[datetime]:
    hours = PRIORITY_SLA_HOURS.get(priority)
    if not hours:
        return None
    return datetime.now(timezone.utc) + timedelta(hours=hours)


@router.post("", response_model=ReportResponse)
def create_report(
    payload: ReportRequest,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    link = payload.link
    description = payload.description
    linked_scan_id = payload.linked_scan_id
    priority = (payload.priority or "medium").lower()
    if priority not in VALID_PRIORITIES:
        priority = "medium"

    if linked_scan_id:
        scan = db.query(Scan).filter(Scan.id == linked_scan_id).first()
        if not scan:
            raise HTTPException(400, "Linked scan not found")
        if not link:
            link = scan.link
        if not description or description.strip() == "":
            reason = (scan.reason or "N/A")[:200]
            description = f"Scan #{scan.id}: {scan.verdict} (score {scan.score}) – {reason}"

    due_at = _compute_due_at(priority)

    r = Report(
        telegram_user_id=payload.telegram_user_id,
        telegram_username=payload.telegram_username,
        link=link,
        report_type=payload.report_type,
        description=description,
        priority=priority,
        due_at=due_at,
        linked_scan_id=linked_scan_id,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return _to_resp(r)


@router.post("/bulk-update")
def bulk_update_reports(
    body: ReportBulkUpdate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Bulk update status, assignee, or priority for selected reports."""
    updated = 0
    for rid in body.report_ids:
        r = db.query(Report).filter(Report.id == rid).first()
        if not r:
            continue
        if body.status is not None and body.status in VALID_STATUSES:
            r.status = body.status
        if body.assignee is not None:
            r.assignee = body.assignee
        if body.priority is not None and body.priority in VALID_PRIORITIES:
            r.priority = body.priority
            r.due_at = _compute_due_at(body.priority)
        updated += 1
    db.commit()
    return {"ok": True, "updated": updated}


@router.get("")
def list_reports(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None, description="Filter by status: new/investigating/resolved"),
    priority: Optional[str] = Query(None, description="Filter by priority: low/medium/high/critical"),
    assignee: Optional[str] = Query(None, description="Filter by assignee (exact or 'unassigned')"),
    search: Optional[str] = Query(None, description="Search by link or description"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    q = db.query(Report)
    if status and status in VALID_STATUSES:
        q = q.filter(Report.status == status)
    if priority and priority in VALID_PRIORITIES:
        q = q.filter(Report.priority == priority)
    if assignee is not None:
        if assignee.lower() == "unassigned":
            q = q.filter((Report.assignee == None) | (Report.assignee == ""))
        else:
            q = q.filter(Report.assignee == assignee)
    if search:
        pattern = f"%{search}%"
        q = q.filter(or_(
            Report.link.ilike(pattern),
            Report.description.ilike(pattern),
        ))
    rows = q.order_by(Report.id.desc()).offset(skip).limit(limit).all()
    return [_to_dict(r) for r in rows]


@router.get("/{report_id}")
def get_report(report_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(404, "Report not found")
    return _to_dict(r)


@router.get("/{report_id}/case.pdf")
def get_report_case_pdf(
    report_id: int,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Generate case PDF: report + linked scan + audit entries."""
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(404, "Report not found")

    scan = None
    if r.linked_scan_id:
        scan = db.query(Scan).filter(Scan.id == r.linked_scan_id).first()

    report_pattern = f"%/reports/{report_id}%"
    conditions = [
        AuditLog.action.ilike(report_pattern),
        AuditLog.target.ilike(report_pattern),
    ]
    if scan:
        scan_pattern = f"%/scans/{scan.id}%"
        conditions.extend([
            AuditLog.action.ilike(scan_pattern),
            AuditLog.target.ilike(scan_pattern),
        ])
    audit_entries = (
        db.query(AuditLog)
        .filter(or_(*conditions))
        .order_by(AuditLog.id.desc())
        .limit(100)
        .all()
    )

    pdf_bytes = generate_case_pdf(r, scan, audit_entries)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SIT-Case-{report_id}.pdf"'},
    )


@router.patch("/{report_id}", response_model=ReportResponse)
def update_report(
    report_id: int,
    body: ReportUpdate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(404, "Report not found")
    _apply_update(r, body)
    db.commit()
    db.refresh(r)
    return _to_resp(r)


@router.put("/{report_id}", response_model=ReportResponse)
def put_report(
    report_id: int,
    body: ReportUpdate,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Same as PATCH: update status, assignee, notes, priority, due_at."""
    r = db.query(Report).filter(Report.id == report_id).first()
    if not r:
        raise HTTPException(404, "Report not found")
    _apply_update(r, body)
    db.commit()
    db.refresh(r)
    return _to_resp(r)


def _apply_update(r: Report, body: ReportUpdate) -> None:
    if body.status is not None:
        if body.status not in VALID_STATUSES:
            raise HTTPException(400, f"Invalid status. Must be one of: {VALID_STATUSES}")
        r.status = body.status
    if body.assignee is not None:
        r.assignee = body.assignee
    if body.notes is not None:
        r.notes = body.notes
    if body.priority is not None and body.priority in VALID_PRIORITIES:
        r.priority = body.priority
        r.due_at = _compute_due_at(body.priority)


def _to_resp(r: Report) -> ReportResponse:
    return ReportResponse(
        id=r.id, link=r.link, report_type=r.report_type,
        description=r.description, status=r.status,
        assignee=r.assignee, notes=r.notes,
        priority=r.priority, due_at=str(r.due_at) if r.due_at else None,
        linked_scan_id=r.linked_scan_id,
        telegram_user_id=r.telegram_user_id,
        telegram_username=r.telegram_username,
        created_at=str(r.created_at) if r.created_at else None,
    )


def _to_dict(r: Report) -> dict:
    return {
        "id": r.id, "telegram_user_id": r.telegram_user_id,
        "telegram_username": r.telegram_username, "link": r.link,
        "report_type": r.report_type, "description": r.description,
        "status": r.status, "assignee": r.assignee, "notes": r.notes,
        "priority": r.priority, "due_at": str(r.due_at) if r.due_at else None,
        "linked_scan_id": r.linked_scan_id,
        "created_at": str(r.created_at) if r.created_at else None,
    }
