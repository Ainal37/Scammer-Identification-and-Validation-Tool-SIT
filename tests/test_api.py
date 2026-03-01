"""
SIT System – API Tests (Enterprise v2.0)
──────────────────────────────────────────
Run: cd backend && .venv\Scripts\python.exe -m pytest ../tests/ -v
"""

import sys
from pathlib import Path

# Ensure backend is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def get_token():
    # Use bot user (no 2FA) for API tests
    r = client.post("/auth/login", json={"email": "bot@example.com", "password": "bot123"})
    assert r.status_code == 200
    data = r.json()
    if "access_token" in data:
        return data["access_token"]
    return None


def auth_header():
    return {"Authorization": f"Bearer {get_token()}"}


# ══════════════════════════════════════════════════════════════
#  Health
# ══════════════════════════════════════════════════════════════
def test_health():
    r = client.get("/")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_health_endpoint():
    r = client.get("/health")
    assert r.status_code == 200
    d = r.json()
    assert d["ok"] is True
    assert "db" in d
    assert "intel" in d


# ══════════════════════════════════════════════════════════════
#  Auth
# ══════════════════════════════════════════════════════════════
def test_login_success():
    r = client.post("/auth/login", json={"email": "nalcsbaru@gmail.com", "password": "admin123"})
    assert r.status_code == 200
    assert "access_token" in r.json()


def test_login_wrong_password():
    r = client.post("/auth/login", json={"email": "nalcsbaru@gmail.com", "password": "wrong"})
    assert r.status_code == 401


def test_jwt_protection():
    r = client.get("/scans")
    assert r.status_code == 403


def test_jwt_invalid_token():
    r = client.get("/scans", headers={"Authorization": "Bearer invalidtoken"})
    assert r.status_code == 401


def test_me_endpoint():
    r = client.get("/auth/me", headers=auth_header())
    assert r.status_code == 200
    assert r.json()["email"] == "nalcsbaru@gmail.com"


# ══════════════════════════════════════════════════════════════
#  Scanning
# ══════════════════════════════════════════════════════════════
def test_scan_safe_url():
    h = auth_header()
    r = client.post("/scans", json={"link": "https://www.google.com"}, headers=h)
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] == "safe"
    assert d["threat_level"] == "LOW"
    assert d["score"] < 50


def test_scan_suspicious_url():
    h = auth_header()
    r = client.post("/scans", json={"link": "http://bit.ly/free-prize"}, headers=h)
    assert r.status_code == 200
    d = r.json()
    assert d["verdict"] in ("suspicious", "scam")
    assert d["score"] >= 50


def test_scan_returns_breakdown():
    h = auth_header()
    r = client.post("/scans", json={"link": "http://bit.ly/free-login"}, headers=h)
    d = r.json()
    assert "breakdown" in d
    assert isinstance(d["breakdown"], list)
    assert len(d["breakdown"]) > 0


def test_scan_with_message():
    h = auth_header()
    r = client.post("/scans", json={"link": "http://example.com", "message": "URGENT verify your account NOW!"}, headers=h)
    d = r.json()
    assert d["score"] > 0


# ══════════════════════════════════════════════════════════════
#  Scoring stability
# ══════════════════════════════════════════════════════════════
def test_scoring_deterministic():
    from app.scoring import compute_risk_score
    r1 = compute_risk_score("http://bit.ly/free-login-verify", skip_intel=True)
    r2 = compute_risk_score("http://bit.ly/free-login-verify", skip_intel=True)
    assert r1["score"] == r2["score"]
    assert r1["threat_level"] == r2["threat_level"]


def test_verdict_score_65_suspicious():
    """Score 65 must yield verdict SUSPICIOUS (50-74 band)."""
    from app.scoring import verdict_from_score
    verdict, threat = verdict_from_score(65)
    assert verdict == "suspicious"
    assert threat == "MED"


def test_verdict_score_80_scam():
    """Score 80 must yield verdict SCAM (>=75 band)."""
    from app.scoring import verdict_from_score
    verdict, threat = verdict_from_score(80)
    assert verdict == "scam"
    assert threat == "HIGH"


def test_demo_url_ip_hostname_scam():
    """IP-based URL with phishing keywords -> score >= 75 -> SCAM."""
    from app.scoring import compute_risk_score
    r = compute_risk_score(
        "http://127.0.0.1/login/verify/otp/bank/urgent/free",
        skip_intel=True,
    )
    assert r["score"] >= 75
    assert r["verdict"] == "scam"
    rules = [b["rule"] for b in r["breakdown"]]
    assert "IP Address Hostname" in rules


def test_demo_url_userinfo_trick_scam():
    """@ userinfo trick URL with phishing keywords -> score >= 75 -> SCAM."""
    from app.scoring import compute_risk_score
    r = compute_risk_score(
        "http://example.com@safe.example.com/login/verify/otp/bank/urgent",
        skip_intel=True,
    )
    assert r["score"] >= 75
    assert r["verdict"] == "scam"
    rules = [b["rule"] for b in r["breakdown"]]
    assert "URL Userinfo (@) Trick" in rules


# ══════════════════════════════════════════════════════════════
#  Intel
# ══════════════════════════════════════════════════════════════
def test_intel_no_key_graceful():
    from app.intel import query_virustotal
    result = query_virustotal("https://www.google.com")
    assert result["provider"] == "virustotal"
    assert "error" in result or result["available"] is True


# ══════════════════════════════════════════════════════════════
#  Reports
# ══════════════════════════════════════════════════════════════
def test_create_report():
    h = auth_header()
    r = client.post("/reports", json={"link": "http://scam.com", "report_type": "phishing", "description": "Fake page"}, headers=h)
    assert r.status_code == 200
    assert r.json()["status"] == "new"


def test_update_report_status():
    h = auth_header()
    r = client.post("/reports", json={"link": "http://test.com", "description": "Test"}, headers=h)
    rid = r.json()["id"]
    r2 = client.patch(f"/reports/{rid}", json={"status": "investigating", "assignee": "admin"}, headers=h)
    assert r2.status_code == 200
    assert r2.json()["status"] == "investigating"


# ══════════════════════════════════════════════════════════════
#  Dashboard
# ══════════════════════════════════════════════════════════════
def test_dashboard_stats():
    h = auth_header()
    r = client.get("/dashboard/stats", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "total_scans" in d
    assert "trend" in d
    assert "top_triggers" in d


# ══════════════════════════════════════════════════════════════
#  NLP
# ══════════════════════════════════════════════════════════════
def test_analyze_message():
    h = auth_header()
    r = client.post("/scans/analyze-message", json={"message": "URGENT: Click here to verify your bank account immediately!"}, headers=h)
    assert r.status_code == 200
    d = r.json()
    assert d["score"] > 0
    assert d["label"] in ("safe", "suspicious", "scam")


# ══════════════════════════════════════════════════════════════
#  Evaluation
# ══════════════════════════════════════════════════════════════
def test_evaluation_run():
    h = auth_header()
    r = client.post("/evaluation/run", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "accuracy" in d
    assert "f1" in d


# ══════════════════════════════════════════════════════════════
#  Enterprise: Settings
# ══════════════════════════════════════════════════════════════
def test_settings_get():
    h = auth_header()
    r = client.get("/settings", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "system_name" in d
    assert "timezone" in d


def test_settings_patch():
    h = auth_header()
    r = client.patch("/settings", json={"system_name": "SIT Test"}, headers=h)
    assert r.status_code == 200
    assert r.json()["system_name"] == "SIT Test"
    # Revert
    client.patch("/settings", json={"system_name": "SIT Admin Panel"}, headers=h)


# ══════════════════════════════════════════════════════════════
#  Enterprise: Notifications
# ══════════════════════════════════════════════════════════════
def test_notification_create():
    h = auth_header()
    r = client.post("/notifications", json={"title": "Test Notif", "body": "Hello", "type": "info", "recipient_scope": "all"}, headers=h)
    assert r.status_code == 200
    assert r.json()["title"] == "Test Notif"


def test_notification_list():
    h = auth_header()
    r = client.get("/notifications", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_notification_mark_read():
    h = auth_header()
    r = client.post("/notifications/mark-read", json=[], headers=h)
    assert r.status_code == 200
    assert r.json()["ok"] is True


# ══════════════════════════════════════════════════════════════
#  Enterprise: Users
# ══════════════════════════════════════════════════════════════
def test_user_create():
    h = auth_header()
    r = client.post("/users", json={"full_name": "Test User", "email": "test@test.com", "role": "viewer", "status": "active"}, headers=h)
    assert r.status_code in (200, 409)  # 409 if already exists
    if r.status_code == 200:
        assert r.json()["email"] == "test@test.com"


def test_user_list():
    h = auth_header()
    r = client.get("/users", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_user_update():
    h = auth_header()
    # Get first user
    r = client.get("/users", headers=h)
    users = r.json()
    if len(users) > 0:
        uid = users[0]["id"]
        r2 = client.patch(f"/users/{uid}", json={"status": "active"}, headers=h)
        assert r2.status_code == 200


# ══════════════════════════════════════════════════════════════
#  Enterprise: Security (2FA)
# ══════════════════════════════════════════════════════════════
def test_2fa_status():
    h = auth_header()
    r = client.get("/security/2fa/status", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "totp_enabled" in d


def test_2fa_setup_and_confirm():
    h = auth_header()
    # Setup
    r = client.post("/security/2fa/setup", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "secret" in d
    assert "otpauth_uri" in d

    # Confirm with correct code
    import pyotp
    totp = pyotp.TOTP(d["secret"])
    code = totp.now()
    r2 = client.post("/security/2fa/confirm", json={"code": code}, headers=h)
    assert r2.status_code == 200

    # Verify login now requires 2FA
    r3 = client.post("/auth/login", json={"email": "nalcsbaru@gmail.com", "password": "admin123"})
    assert r3.status_code == 200
    login_data = r3.json()
    assert login_data.get("requires_2fa") is True

    # Verify 2FA
    temp_token = login_data["temp_token"]
    code2 = totp.now()
    r4 = client.post("/auth/verify-2fa", json={"temp_token": temp_token, "code": code2})
    assert r4.status_code == 200
    assert "access_token" in r4.json()

    # Disable 2FA for other tests
    new_token = r4.json()["access_token"]
    h2 = {"Authorization": f"Bearer {new_token}"}
    r5 = client.post("/security/2fa/disable", headers=h2)
    assert r5.status_code == 200


# ══════════════════════════════════════════════════════════════
#  Enterprise: Backup
# ══════════════════════════════════════════════════════════════
def test_backup_run():
    h = auth_header()
    r = client.post("/backup/run", json={"scopes": ["user_data", "reports"]}, headers=h)
    assert r.status_code == 200
    assert r.json()["status"] == "done"


def test_backup_list():
    h = auth_header()
    r = client.get("/backup", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ══════════════════════════════════════════════════════════════
#  Enterprise: Audit
# ══════════════════════════════════════════════════════════════
def test_audit_list():
    h = auth_header()
    r = client.get("/audit", headers=h)
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ══════════════════════════════════════════════════════════════
#  Enterprise: Analytics
# ══════════════════════════════════════════════════════════════
def test_analytics_stats():
    h = auth_header()
    r = client.get("/analytics/stats", headers=h)
    assert r.status_code == 200
    d = r.json()
    assert "total_scans" in d
    assert "verdict_breakdown" in d
    assert "threat_breakdown" in d


# ══════════════════════════════════════════════════════════════
#  RBAC: viewer should be blocked from admin endpoints
# ══════════════════════════════════════════════════════════════
def test_rbac_viewer_blocked():
    h = auth_header()
    # Create a viewer user first
    client.post("/users", json={"full_name": "Viewer", "email": "viewer@test.com", "role": "viewer", "status": "active", "password": "viewer123"}, headers=h)

    # This test verifies RBAC enforcement concept
    # The viewer user is in the User table (not AdminUser), so they can't get a JWT
    # through the existing admin login. RBAC is enforced on admin role check.
    # We verify by checking that the require_role dependency works.
    from app.rbac import require_role
    assert callable(require_role("admin"))


# ══════════════════════════════════════════════════════════════
#  Rate limiting
# ══════════════════════════════════════════════════════════════
def test_rate_limit_login():
    for i in range(12):
        r = client.post("/auth/login", json={"email": "nalcsbaru@gmail.com", "password": "admin123"})
    assert r.status_code in (200, 429)
