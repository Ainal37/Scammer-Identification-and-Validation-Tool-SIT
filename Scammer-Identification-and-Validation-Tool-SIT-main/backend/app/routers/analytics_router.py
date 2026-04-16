"""Analytics endpoints (enterprise)."""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func as sqlfunc

from ..database import get_db
from ..models import Scan, Report, User, AuditLog
from ..security import get_current_admin

router = APIRouter(prefix="/analytics", tags=["analytics"])


@router.get("/stats")
def analytics_stats(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    total_scans = db.query(sqlfunc.count(Scan.id)).scalar() or 0
    total_reports = db.query(sqlfunc.count(Report.id)).scalar() or 0
    total_users = db.query(sqlfunc.count(User.id)).scalar() or 0

    # Verdict breakdown
    verdict_rows = (
        db.query(Scan.verdict, sqlfunc.count(Scan.id))
        .group_by(Scan.verdict)
        .all()
    )
    verdict_breakdown = {v: c for v, c in verdict_rows}

    # Threat level breakdown
    threat_rows = (
        db.query(Scan.threat_level, sqlfunc.count(Scan.id))
        .filter(Scan.threat_level.isnot(None))
        .group_by(Scan.threat_level)
        .all()
    )
    threat_breakdown = {t: c for t, c in threat_rows}

    # Report status breakdown
    report_status_rows = (
        db.query(Report.status, sqlfunc.count(Report.id))
        .group_by(Report.status)
        .all()
    )
    report_status = {s: c for s, c in report_status_rows}

    # Recent scans (last 7 days)
    from datetime import datetime, timedelta, timezone
    week_ago = datetime.now(timezone.utc) - timedelta(days=7)
    scans_this_week = (
        db.query(sqlfunc.count(Scan.id))
        .filter(Scan.created_at >= week_ago)
        .scalar() or 0
    )

    # Average score
    avg_score = db.query(sqlfunc.avg(Scan.score)).scalar()
    avg_score = round(float(avg_score), 1) if avg_score else 0

    return {
        "total_scans": total_scans,
        "total_reports": total_reports,
        "total_users": total_users,
        "scans_this_week": scans_this_week,
        "avg_score": avg_score,
        "verdict_breakdown": verdict_breakdown,
        "threat_breakdown": threat_breakdown,
        "report_status": report_status,
    }
