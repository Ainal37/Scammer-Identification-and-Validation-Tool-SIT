"""Scan endpoints: create + list + detail + analyze-message + PDF report."""

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Query, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..database import get_db
from ..models import Scan, Report
from ..scoring import compute_risk_score
from ..alerts import send_high_threat_alert
from ..validators import validate_url, validate_message
from ..security import get_current_admin
from ..schemas import ScanRequest, ScanResponse, MessageRequest
from ..nlp import analyze_message
from ..pdf_report import generate_scan_pdf

router = APIRouter(prefix="/scans", tags=["scans"])
REPORTS_DIR = Path(__file__).resolve().parent.parent.parent / "reports"

PRIORITY_SLA_HOURS = {"low": 24 * 7, "medium": 24 * 3, "high": 24, "critical": 6}


def _compute_due_at(priority: str) -> Optional[datetime]:
    hours = PRIORITY_SLA_HOURS.get(priority)
    if not hours:
        return None
    return datetime.now(timezone.utc) + timedelta(hours=hours)


@router.post("", response_model=ScanResponse)
def create_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    link = validate_url(payload.link)
    msg = payload.message.strip() if payload.message else None

    result = compute_risk_score(link, message=msg)

    s = Scan(
        telegram_user_id=payload.telegram_user_id,
        telegram_username=payload.telegram_username,
        link=link,
        verdict=result["verdict"],
        score=result["score"],
        threat_level=result["threat_level"],
        reason=result["reason"][:2000],
        breakdown=json.dumps(result["breakdown"]),
        intel_summary=json.dumps(result.get("intel_summary", {})),
        message=msg,
    )
    db.add(s)
    db.commit()
    db.refresh(s)

    # Alert on HIGH threat
    if result["threat_level"] == "HIGH":
        send_high_threat_alert({
            "id": s.id, "link": s.link, "score": s.score,
            "threat_level": s.threat_level, "reason": s.reason,
        })

    # Auto-report on high risk: verdict=scam OR threat_level=HIGH OR score>=75
    auto_report_id = None
    is_high_risk = (
        result["verdict"] == "scam"
        or result["threat_level"] == "HIGH"
        or result["score"] >= 75
    )
    if is_high_risk:
        domain = ""
        try:
            domain = urlparse(s.link).netloc or ""
        except Exception:
            pass
        # Duplicate check: same link or same domain, status new/investigating
        dup_conditions = [Report.link == s.link]
        if domain:
            dup_conditions.append(Report.link.ilike(f"%{domain}%"))
        dup = (
            db.query(Report)
            .filter(Report.status.in_(["new", "investigating"]))
            .filter(or_(*dup_conditions))
            .first()
        )
        if dup:
            # Append note about duplicate scan
            note = f"Duplicate scan #{s.id}"
            dup.notes = (dup.notes or "").rstrip() + ("\n" + note if dup.notes else note)
            db.commit()
            auto_report_id = dup.id
        else:
            priority = "critical" if result["score"] >= 90 else "high"
            desc_parts = [
                f"Verdict: {result['verdict']}",
                f"Score: {result['score']}",
                f"Threat: {result.get('threat_level', 'N/A')}",
                f"Reasons: {(result.get('reason') or 'N/A')[:500]}",
                f"Scan #{s.id} at {s.created_at}",
            ]
            description = " | ".join(desc_parts)
            r = Report(
                link=s.link,
                report_type="scam",
                description=description,
                status="new",
                linked_scan_id=s.id,
                priority=priority,
                due_at=_compute_due_at(priority),
                telegram_user_id=payload.telegram_user_id,
                telegram_username=payload.telegram_username,
            )
            db.add(r)
            db.commit()
            db.refresh(r)
            auto_report_id = r.id

    return _scan_to_response(s, result["breakdown"], auto_report_id)


@router.get("")
def list_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    search: Optional[str] = Query(None, description="Search by link text"),
    verdict: Optional[str] = Query(None, description="Filter by verdict: safe/suspicious/scam"),
    threat_level: Optional[str] = Query(None, description="Filter by threat level: LOW/MED/HIGH"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    q = db.query(Scan)
    if search:
        q = q.filter(Scan.link.ilike(f"%{search}%"))
    if verdict and verdict in ("safe", "suspicious", "scam"):
        q = q.filter(Scan.verdict == verdict)
    if threat_level and threat_level in ("LOW", "MED", "HIGH"):
        q = q.filter(Scan.threat_level == threat_level)
    rows = q.order_by(Scan.id.desc()).offset(skip).limit(limit).all()
    scan_ids = [s.id for s in rows]
    report_map = {}
    if scan_ids:
        for r in db.query(Report).filter(Report.linked_scan_id.in_(scan_ids)).all():
            report_map[r.linked_scan_id] = {"id": r.id, "status": r.status}
    out = []
    for s in rows:
        d = _scan_to_dict(s)
        d["linked_report"] = report_map.get(s.id)
        out.append(d)
    return out


@router.get("/latest")
def get_latest_scan(
    telegram_user_id: Optional[int] = Query(None, description="Filter by Telegram user"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Return the latest scan, optionally filtered by telegram_user_id."""
    q = db.query(Scan).order_by(Scan.id.desc())
    if telegram_user_id is not None:
        q = q.filter(Scan.telegram_user_id == telegram_user_id)
    s = q.first()
    if not s:
        raise HTTPException(404, "No scans found")
    d = _scan_to_dict(s)
    r = db.query(Report).filter(Report.linked_scan_id == s.id).first()
    d["linked_report"] = {"id": r.id, "status": r.status} if r else None
    return d


@router.get("/recent")
def get_recent_scans(
    limit: int = Query(20, ge=1, le=50, description="Max scans to return"),
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Return recent scans for dropdown. Minimal payload: id, link, verdict, score, reason, created_at."""
    rows = db.query(Scan).order_by(Scan.id.desc()).limit(limit).all()
    return [
        {
            "id": s.id,
            "link": s.link,
            "verdict": s.verdict,
            "score": s.score,
            "reason": (s.reason or "")[:500],
            "created_at": str(s.created_at) if s.created_at else None,
        }
        for s in rows
    ]


@router.get("/{scan_id}/report.pdf")
def get_scan_report_pdf(
    scan_id: int,
    db: Session = Depends(get_db),
    admin=Depends(get_current_admin),
):
    """Generate and return PDF report for a scan. Caches to backend/reports/ if dir exists."""
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(404, "Scan not found")

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    cache_path = REPORTS_DIR / f"scan_{scan_id}.pdf"
    if cache_path.is_file():
        return FileResponse(
            cache_path,
            media_type="application/pdf",
            filename=f"SIT-Report-{scan_id}.pdf",
        )

    pdf_bytes = generate_scan_pdf(s)
    cache_path.write_bytes(pdf_bytes)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="SIT-Report-{scan_id}.pdf"'},
    )


@router.get("/{scan_id}")
def get_scan(scan_id: int, db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    s = db.query(Scan).filter(Scan.id == scan_id).first()
    if not s:
        raise HTTPException(404, "Scan not found")
    d = _scan_to_dict(s)
    r = db.query(Report).filter(Report.linked_scan_id == scan_id).first()
    d["linked_report"] = {"id": r.id, "status": r.status} if r else None
    return d


@router.post("/analyze-message")
def analyze_message_endpoint(body: MessageRequest, admin=Depends(get_current_admin)):
    text = validate_message(body.message)
    return analyze_message(text)


def _scan_to_response(s: Scan, breakdown=None, auto_report_id: Optional[int] = None) -> ScanResponse:
    bd = breakdown
    if bd is None and s.breakdown:
        try:
            bd = json.loads(s.breakdown)
        except Exception:
            bd = []
    intel = {}
    if s.intel_summary:
        try:
            intel = json.loads(s.intel_summary)
        except Exception:
            pass
    return ScanResponse(
        id=s.id, link=s.link, verdict=s.verdict, score=s.score,
        threat_level=s.threat_level, reason=s.reason or "",
        breakdown=bd, intel_summary=intel,
        telegram_user_id=s.telegram_user_id,
        telegram_username=s.telegram_username,
        created_at=str(s.created_at) if s.created_at else None,
        auto_report_id=auto_report_id,
    )


def _scan_to_dict(s: Scan) -> dict:
    bd = []
    if s.breakdown:
        try:
            bd = json.loads(s.breakdown)
        except Exception:
            pass
    intel = {}
    if s.intel_summary:
        try:
            intel = json.loads(s.intel_summary)
        except Exception:
            pass
    return {
        "id": s.id,
        "telegram_user_id": s.telegram_user_id,
        "telegram_username": s.telegram_username,
        "link": s.link,
        "verdict": s.verdict,
        "score": s.score,
        "threat_level": s.threat_level,
        "reason": s.reason,
        "breakdown": bd,
        "intel_summary": intel,
        "message": s.message,
        "created_at": str(s.created_at) if s.created_at else None,
    }
