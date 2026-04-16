"""Dashboard statistics – rich data for Command Center UI."""

import json
from datetime import date, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func as sqlfunc

from ..database import get_db
from ..models import Scan, Report, AuditLog
from ..security import get_current_admin

router = APIRouter(prefix="/dashboard", tags=["dashboard"])

METRICS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "evaluation" / "metrics.json"


@router.get("/stats")
def stats(db: Session = Depends(get_db), admin=Depends(get_current_admin)):
    total_scans = db.query(sqlfunc.count(Scan.id)).scalar() or 0
    total_reports = db.query(sqlfunc.count(Report.id)).scalar() or 0

    scam = db.query(sqlfunc.count(Scan.id)).filter(Scan.verdict == "scam").scalar() or 0
    suspicious = db.query(sqlfunc.count(Scan.id)).filter(Scan.verdict == "suspicious").scalar() or 0
    safe = db.query(sqlfunc.count(Scan.id)).filter(Scan.verdict == "safe").scalar() or 0

    high = db.query(sqlfunc.count(Scan.id)).filter(Scan.threat_level == "HIGH").scalar() or 0
    med = db.query(sqlfunc.count(Scan.id)).filter(Scan.threat_level == "MED").scalar() or 0
    low = db.query(sqlfunc.count(Scan.id)).filter(Scan.threat_level == "LOW").scalar() or 0

    # Latest
    latest_scans = db.query(Scan).order_by(Scan.id.desc()).limit(10).all()
    latest_reports = db.query(Report).order_by(Report.id.desc()).limit(10).all()

    # 7-day trend
    today = date.today()
    trend = {"labels": [], "scam": [], "suspicious": [], "safe": []}
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        trend["labels"].append(d.strftime("%a"))
        for v, arr in [("scam", trend["scam"]), ("suspicious", trend["suspicious"]), ("safe", trend["safe"])]:
            c = db.query(sqlfunc.count(Scan.id)).filter(
                sqlfunc.date(Scan.created_at) == d,
                Scan.verdict == v,
            ).scalar() or 0
            arr.append(c)

    # Top triggers (parse reasons)
    from collections import Counter
    triggers = Counter()
    reason_rows = db.query(Scan.reason).filter(Scan.reason.isnot(None)).limit(500).all()
    for (reason,) in reason_rows:
        for part in (reason or "").split(";"):
            part = part.strip()
            if part:
                rule = part.split(":")[0].strip()
                if len(rule) > 2:
                    triggers[rule] += 1
    top_triggers = [{"rule": r, "count": c} for r, c in triggers.most_common(8)]

    # Recent activity
    recent_logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(15).all()
    recent_activity = [
        {
            "action": a.action, "actor": a.actor_email or "system",
            "target": (a.target or "")[:80],
            "time": str(a.created_at) if a.created_at else "",
        }
        for a in recent_logs
    ]

    # Evaluation metrics
    metrics = None
    if METRICS_PATH.exists():
        try:
            metrics = json.loads(METRICS_PATH.read_text())
        except Exception:
            pass

    return {
        "total_scans": total_scans,
        "total_reports": total_reports,
        "breakdown": {"scam": scam, "suspicious": suspicious, "safe": safe},
        "threat_breakdown": {"HIGH": high, "MED": med, "LOW": low},
        "latest_scans": [
            {
                "id": s.id, "link": s.link, "verdict": s.verdict,
                "score": s.score, "threat_level": s.threat_level,
                "created_at": str(s.created_at) if s.created_at else None,
            }
            for s in latest_scans
        ],
        "latest_reports": [
            {
                "id": r.id, "link": r.link, "report_type": r.report_type,
                "description": r.description, "status": r.status,
                "created_at": str(r.created_at) if r.created_at else None,
            }
            for r in latest_reports
        ],
        "trend": trend,
        "top_triggers": top_triggers,
        "recent_activity": recent_activity,
        "metrics": metrics,
    }
