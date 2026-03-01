# FYP-project: SIT-System – Scammer Identification & Validation Tool

Enterprise MVP v2.0 for detecting, analysing, and reporting scam/phishing URLs using heuristic rules, threat intelligence (VirusTotal + URLhaus), NLP message analysis, and a Telegram bot interface. Includes enterprise admin features: user management, 2FA/TOTP, RBAC, notifications, settings, backup, audit logs, and analytics.

---

## Architecture

Project root = folder containing `run_all.ps1` (no SIT-System subfolder).

```
SIT-System/
  backend/
    app/               FastAPI (routers, models, scoring, intel, NLP, security, RBAC)
      routers/         auth, scans, reports, dashboard, evaluation,
                       users_router, notifications_router, settings_router,
                       security_router, backup_router, audit_router, analytics_router
    bot/               Telegram bot (polling, authenticated)
    .venv/             Python virtual env (not committed)
    .env               Backend secrets (not committed)
    requirements.txt
  frontend/admin/      Admin dashboard (HTML/CSS/JS)
    assets/css/        style.css (monochrome premium enterprise theme)
    assets/js/         api.js, dashboard.js, scans.js, reports.js, login.js,
                       settings.js, users.js, analytics.js
    dashboard.html     Dashboard with quick actions, charts, activity
    scans.html         Scan history + quick scan
    reports.html       Reports with Kanban view
    users.html         User management (CRUD)
    analytics.html     Analytics with charts
    settings.html      System settings, security (2FA), backup
    login.html         Login with 2FA step
  datasets/            Evaluation CSVs (scam_urls.csv, scam_messages.csv)
  evaluation/          Evaluation pipeline (evaluate.py, metrics.json)
  tests/               API tests (pytest)
  run_all.ps1          One-click launcher (Windows)
```

## Prerequisites

| Component | Notes |
|-----------|-------|
| Python 3.11+ | With pip |
| MySQL 8.x | Via XAMPP |
| XAMPP | MySQL module running |
| PowerShell 5.1+ | Windows built-in |
| Telegram Bot | Create via @BotFather |

### Optional API Keys

| Key | Purpose | Required? |
|-----|---------|-----------|
| `VIRUSTOTAL_API_KEY` | URL reputation from VirusTotal | No (graceful fallback) |
| `ALERT_CHAT_ID` | Telegram group for HIGH-threat alerts | No |

## Quick Start

```powershell
# 1. Start XAMPP MySQL
# 2. Create database
mysql -u root -e "CREATE DATABASE IF NOT EXISTS sit_db;"

# 3. Setup (one-time)
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
.venv\Scripts\python.exe -m pip install -r bot\requirements.txt

# 4. Configure .env files (see below)

# 5. Launch everything (from project root – folder containing run_all.ps1)
cd ..
powershell -ExecutionPolicy Bypass -File .\run_all.ps1
```

### backend/.env

```
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_DB=sit_db
JWT_SECRET=changeme-super-secret-key-2026
VIRUSTOTAL_API_KEY=           # optional

# Backup encryption – optional; if set, backup zips are AES-encrypted
# BACKUP_ENCRYPTION_KEY=your-secret-key

# Email OTP (2FA via email) – optional; if set, "Send code via email" appears on 2FA page
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

For Gmail: use an [App Password](https://support.google.com/accounts/answer/185833), not your regular password.

### backend/bot/.env

```
TELEGRAM_BOT_TOKEN=<from @BotFather>
BACKEND_URL=http://127.0.0.1:8001
BOT_ADMIN_EMAIL=bot@example.com
BOT_ADMIN_PASSWORD=admin123
ALERT_CHAT_ID=                # optional: Telegram group/channel ID
```

## Default Admin

| Field | Value |
|-------|-------|
| Email | nalcsbaru@gmail.com |
| Password | admin123 |

Auto-seeded on first startup.

## API Endpoints

### Core

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /auth/login | Public | JWT token (supports 2FA) |
| POST | /auth/verify-2fa | Public | Verify TOTP code, get full token |
| GET | /auth/me | Bearer | Current user |
| GET | /health | Public | Health check (DB, Intel status) |
| POST | /scans | Bearer | Scan URL (+ optional message) |
| GET | /scans | Bearer | List scans |
| GET | /scans/{id} | Bearer | Scan detail + breakdown |
| POST | /scans/analyze-message | Bearer | NLP message analysis |
| POST | /reports | Bearer | Create report |
| GET | /reports | Bearer | List reports |
| PATCH | /reports/{id} | Bearer | Update status/assignee/notes |
| GET | /dashboard/stats | Bearer | Dashboard data (trend, triggers, metrics) |
| GET | /evaluation/metrics | Bearer | Latest evaluation metrics |
| POST | /evaluation/run | Bearer | Run evaluation pipeline |

### Enterprise (v2.0)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /users | Bearer (admin) | Create user |
| GET | /users | Bearer (admin) | List/search users |
| PATCH | /users/{id} | Bearer (admin) | Update user role/status |
| GET | /settings | Bearer (admin) | Get system settings |
| PATCH | /settings | Bearer (admin) | Update system settings |
| POST | /security/change-password | Bearer | Change own password |
| POST | /security/2fa/setup | Bearer | Start 2FA setup (returns secret) |
| POST | /security/2fa/confirm | Bearer | Confirm 2FA with TOTP code |
| POST | /security/2fa/disable | Bearer | Disable 2FA |
| GET | /security/2fa/status | Bearer | Get 2FA status |
| POST | /notifications | Bearer (admin) | Create notification |
| GET | /notifications | Bearer | List notifications (scoped) |
| POST | /notifications/mark-read | Bearer | Mark notifications read |
| POST | /backup/run | Bearer (admin) | Run backup |
| GET | /backup | Bearer (admin) | List backups |
| GET | /audit | Bearer (admin) | List audit logs |
| GET | /analytics/stats | Bearer | Analytics overview |

## Scoring Engine

| Component | Max Points | Source |
|-----------|-----------|--------|
| Heuristic rules | ~60 | URL structure, TLD, keywords, shorteners |
| Threat Intelligence | ~35 | VirusTotal, URLhaus |
| NLP message analysis | ~25 | Rule-based + optional ML |

**Threat Levels:** LOW (<25) | MED (25-54) | HIGH (>=55)

## OWASP Mapping

| Control | Implementation |
|---------|---------------|
| A01 Broken Access Control | JWT auth on all endpoints |
| A02 Cryptographic Failures | bcrypt password hashing, JWT HS256 |
| A03 Injection | SQLAlchemy ORM (parameterized queries) |
| A04 Insecure Design | Input validation, private IP rejection |
| A05 Security Misconfiguration | .env not committed, CORS configured |
| A07 XSS | Server returns JSON only, frontend escapes |
| Rate Limiting | Per-IP + per-endpoint middleware |
| Audit Logging | All mutations logged (actor, action, IP) |

## Running Tests

```powershell
cd backend
.venv\Scripts\python.exe -m pytest ../tests/ -v
```

## Running Evaluation

```powershell
# Via API
curl -X POST http://127.0.0.1:8001/evaluation/run -H "Authorization: Bearer <token>"

# Or directly (from project root)
backend\.venv\Scripts\python.exe evaluation\evaluate.py
```

## Enterprise Features (v2.0)

### User Management
- Admin can create, list, search, and update users via `/users` endpoints
- Roles: **admin** (full access), **editor** (limited writes), **viewer** (read-only)
- User table visible at `http://127.0.0.1:5500/users.html`

### Two-Factor Authentication (2FA / TOTP)
1. Go to Settings → Security → Enable 2FA toggle
2. Copy the TOTP secret to your authenticator app (Google Authenticator, Authy, etc.)
3. Enter the 6-digit code and click Confirm
4. Next login will require the code after email/password

To disable: Settings → Security → toggle off 2FA

### Notifications
- Admin can send notifications (scoped to all users or specific roles)
- Bell icon in the top bar shows unread count
- Click bell to see dropdown with recent notifications

### System Settings
- System name, timezone (Asia/Kuala_Lumpur or Asia/Singapore)
- Backup schedule and auto-backup toggle
- All settings stored in `system_settings` table

### Backup
- Manual backup via Settings page or Dashboard Quick Actions
- Backup records stored in `backups` table

### Audit Logs
- Every sensitive action (login, user create/update, settings change, 2FA, backup) is logged
- Accessible via `GET /audit` (admin only)

### Timezone
- All timestamps stored in UTC in the database
- System timezone configurable via Settings (default: Asia/Kuala_Lumpur, UTC+8)
- Both Asia/Kuala_Lumpur and Asia/Singapore options available

## Demo Flow (Viva)

1. Run `.\run_all.ps1` – backend, frontend, bot all start
2. Login at `http://127.0.0.1:5500/login.html`
3. Dashboard shows charts, triggers, metrics, live activity, quick actions
4. Quick Actions: Add User, Generate Report, Send Notification, Backup
5. Scan page: enter URL → see score, threat level, breakdown
6. Click a scan row → Evidence modal (copy, export PDF, create report)
7. Reports page: Kanban view, status workflow
8. Users page: manage users with RBAC
9. Analytics page: charts for verdict, threat, report status
10. Settings page: system settings, 2FA setup, backup
11. Telegram: send URL to bot → auto-scan with formatted result
12. Press Ctrl+K → Command palette for quick navigation
13. Click bell icon → Notification dropdown

## Security Reminders

- **NEVER** commit `.env` files
- Change `JWT_SECRET` for production
- Change default admin password after first login
- Rate limiter is in-memory (resets on restart)

## Troubleshooting

| Issue | Fix |
|-------|-----|
| MySQL connection refused | Start XAMPP MySQL, ensure `sit_db` exists |
| Schema errors after update | `DROP DATABASE sit_db; CREATE DATABASE sit_db;` |
| Telegram 409 conflict | See detailed fix below |
| VirusTotal errors | Key is optional – system works without it |
| Rate limit 429 | Wait 60 seconds or restart backend |
| Backend offline banner | See detailed fix below |
| `/docs` slow or stuck | This is normal – see below |

### Verifying the backend is running

**The `/health` endpoint is the real check**, not `/docs`.

```powershell
# Quick health check (no auth required, responds in <50ms)
Invoke-WebRequest -Uri http://127.0.0.1:8001/health -UseBasicParsing

# Expected response: {"ok":true,"time":"...","version":"2.0.0","db":true,"intel":false}
```

- `/health` returns `{ ok, db, intel, version, time }` without authentication.
- It never crashes even if MySQL is down (returns `db: false`).
- The frontend pings this every few seconds for the status chips.
- `run_all.ps1` waits up to 20 seconds for `/health` before launching frontend and bot.

### Why is `/docs` slow?

Swagger UI (`/docs`) loads the full OpenAPI schema, which can take 5-15 seconds
on first access because FastAPI must inspect every route and build the JSON spec.
This is **normal** and does not mean the backend is broken. Use `/health` to
verify the backend is running.

### "Backend offline" banner in admin UI

**Causes:**

1. Backend not running (uvicorn crashed or didn't start)
2. Port 8001 blocked or used by another process
3. CORS issue (frontend on `localhost:5500` vs backend on `127.0.0.1:8001`)
4. MySQL not started (backend starts but DB queries fail)

**Diagnosis:**

```powershell
# 1. Check /health (the real readiness probe, no auth needed)
Invoke-WebRequest -Uri http://127.0.0.1:8001/health -UseBasicParsing

# 2. Check what process is on port 8001
netstat -ano | findstr :8001

# 3. Verify MySQL is running (XAMPP)
mysql -u root -e "SELECT 1;"
```

**Fix:** Start XAMPP MySQL, then run `.\run_all.ps1`. The launcher waits
up to 20 seconds for `/health` to respond before starting the frontend and bot.

### How to kill a process on port 8001 or 5500

```powershell
# Find the PID using port 8001
netstat -ano | findstr :8001

# Kill it (replace <PID> with the number from the last column)
taskkill /PID <PID> /F

# Same for port 5500
netstat -ano | findstr :5500
taskkill /PID <PID> /F
```

`run_all.ps1` automatically detects port conflicts and auto-kills Python
processes from previous runs. For non-Python processes it prints the PID
and a kill command.

### "C:\Users\Ainal : The term is not recognized" (paths with spaces)

This happens when a PowerShell script does not quote paths that contain spaces.
The `run_all.ps1` launcher avoids this entirely by using `-EncodedCommand`, which
encodes the full command as Base64 so no quoting or escaping is needed at all.

If you run commands manually, always wrap paths in quotes:

```powershell
# WRONG – breaks at the space in "Ainal Aiman"
C:\Users\Ainal Aiman\Documents\Scammer Identification and Validation Tool\backend\.venv\Scripts\python.exe -m uvicorn ...

# CORRECT – wrap the path in quotes
& "C:\Users\Ainal Aiman\Documents\Scammer Identification and Validation Tool\backend\.venv\Scripts\python.exe" -m uvicorn ...

# CORRECT – use Set-Location -LiteralPath
Set-Location -LiteralPath "C:\Users\Ainal Aiman\Documents\Scammer Identification and Validation Tool\backend"
```

### Telegram 409 "Conflict: terminated by other getUpdates request"

This means two bot instances are polling Telegram simultaneously. Only one is allowed.

1. **Automatic fix**: `run_all.ps1` kills old bot.py processes and removes `.bot.lock`
   on every launch.

2. **Manual fix**:

```powershell
# Find and kill all bot.py processes
Get-CimInstance Win32_Process -Filter "Name='python.exe'" |
  Where-Object { $_.CommandLine -like "*bot.py*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# Remove stale lock
Remove-Item -LiteralPath "backend\bot\.bot.lock" -Force -ErrorAction SilentlyContinue

# Now start the bot again
```

### Bot sends spam or wrong messages (token compromised)

If your bot sends content like "http://bit.ly/...", "Life Time Free Access", or other spam, the token is for a different/compromised bot. Fix:

1. In Telegram, open **BotFather** and send `/newbot`
2. Create a new bot (e.g. "SIT Scam Detector") and get the **new token**
3. Send `/revoke` to BotFather for the old bot to invalidate the old token
4. Put the new token in `backend/bot/.env` as `TELEGRAM_BOT_TOKEN=...`
5. Restart the system (`.\run_all.ps1`)

### Bot shows "Auth: FAILED" or "Read timed out"

The bot now waits for the backend `/health` endpoint before authenticating,
and retries authentication with exponential backoff (1s, 2s, 3s, 5s, 10s).
The API timeout is 20 seconds (up from 10).

If you see persistent failures:

1. Verify backend is healthy: `Invoke-WebRequest -Uri http://127.0.0.1:8001/health -UseBasicParsing`
2. Check `backend/bot/.env` has correct `BOT_ADMIN_EMAIL` and `BOT_ADMIN_PASSWORD`
3. Restart via `.\run_all.ps1` (kills old bot instances automatically)
