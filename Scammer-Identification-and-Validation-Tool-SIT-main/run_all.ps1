# ============================================================
#  SIT-System v2.0 - Single-Terminal Launcher
#  Compatible: Windows PowerShell 5.1+
#  Runs ALL services (Backend, Frontend, Bot) in ONE terminal.
#  Backend & Frontend run as background processes; Bot in foreground.
#  Press Ctrl+C to stop everything.
# ============================================================

$ErrorActionPreference = "Stop"

$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ROOT

$BACKEND_DIR  = Join-Path $ROOT "backend"
$FRONTEND_DIR = Join-Path $ROOT "frontend\admin"
$BOT_DIR      = Join-Path $BACKEND_DIR "bot"
$VENV_PY      = Join-Path $BACKEND_DIR ".venv\Scripts\python.exe"
$BOT_LOCK     = Join-Path $BOT_DIR ".bot.lock"
$LOG_DIR      = Join-Path $ROOT "logs"

# Track background PIDs for cleanup
$script:bgPids = @()

function Cleanup-All {
    Write-Host ""
    Write-Host "[SIT] Shutting down all services..." -ForegroundColor Yellow
    foreach ($p in $script:bgPids) {
        try {
            if (-not (Get-Process -Id $p -ErrorAction SilentlyContinue)) { continue }
            $tree = Get-CimInstance Win32_Process -Filter "ParentProcessId=$p" -ErrorAction SilentlyContinue
            Stop-Process -Id $p -Force -ErrorAction SilentlyContinue
            foreach ($child in $tree) {
                Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
            }
        } catch {}
    }
    if (Test-Path -LiteralPath $BOT_LOCK) {
        Remove-Item -LiteralPath $BOT_LOCK -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[SIT] All services stopped." -ForegroundColor Green
}

function Test-Port {
    param([string]$HostName, [int]$Port)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne(2000, $false)
        if ($ok) { $tcp.EndConnect($ar) }
        $tcp.Close()
        return $ok
    } catch { return $false }
}

function Test-PortConflict {
    param([int]$Port)
    $found = $false
    try {
        $lines = netstat -ano 2>$null | Select-String (":" + $Port + " ")
        foreach ($line in $lines) {
            $parts = $line.ToString().Trim() -split '\s+'
            if ($parts.Count -ge 5 -and $parts[1] -match (":$Port$")) {
                $pid = [int]$parts[4]
                if ($pid -eq 0) { continue }
                $procName = "unknown"
                try {
                    $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                    if ($proc) { $procName = $proc.ProcessName }
                } catch {}
                $found = $true
                Write-Host ("  WARNING: Port " + $Port + " in use by PID " + $pid + " (" + $procName + ")") -ForegroundColor Red
                if ($procName -eq "python" -or $procName -eq "python3") {
                    Write-Host ("  Auto-killing PID " + $pid) -ForegroundColor Yellow
                    try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch {}
                    Start-Sleep -Milliseconds 500
                }
            }
        }
    } catch {}
    return $found
}

function Wait-ForHealth {
    param([int]$MaxSeconds = 25)
    Write-Host ("  Waiting for backend /health (up to " + $MaxSeconds + "s)...") -ForegroundColor Gray
    for ($i = 0; $i -lt $MaxSeconds; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8001/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                $body = $resp.Content | ConvertFrom-Json
                $dbStatus = if ($body.db -eq $true) { "OK" } else { "DOWN" }
                Write-Host ("  /health OK (db=" + $dbStatus + ", v=" + $body.version + ") after " + ($i+1) + "s") -ForegroundColor Green
                return $true
            }
        } catch {}
    }
    Write-Host ("  /health did NOT respond within " + $MaxSeconds + "s") -ForegroundColor Red
    return $false
}

# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "  SIT-System v2.0 - Single Terminal Launcher"       -ForegroundColor White
Write-Host "  Press Ctrl+C to stop all services"                -ForegroundColor DarkGray
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "[REMINDER] Start XAMPP MySQL first." -ForegroundColor Yellow
Write-Host ("ROOT: " + $ROOT) -ForegroundColor DarkGray
Write-Host ""

# ── Sanity: venv python must exist ──
if (-not (Test-Path -LiteralPath $VENV_PY)) {
    Write-Host "ERROR: venv python not found at:" -ForegroundColor Red
    Write-Host ("  " + $VENV_PY) -ForegroundColor Red
    Write-Host "Fix:  cd backend && python -m venv .venv && .venv\Scripts\pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# ── Create logs directory ──
if (-not (Test-Path -LiteralPath $LOG_DIR)) {
    New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null
}

# ── [1/6] Ensure sit_db ──
$MYSQL_EXE = "C:\xampp\mysql\bin\mysql.exe"
if (Test-Path -LiteralPath $MYSQL_EXE) {
    Write-Host "[1/6] Ensuring database 'sit_db'..." -ForegroundColor Gray
    try {
        & $MYSQL_EXE -u root -e "CREATE DATABASE IF NOT EXISTS sit_db;" 2>$null
        Write-Host "  sit_db ready" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not create sit_db (MySQL may not be running)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[1/6] MySQL client not found - create sit_db manually" -ForegroundColor Yellow
}

# ── [2/6] Port conflicts ──
Write-Host "[2/6] Checking ports..." -ForegroundColor Gray
$null = Test-PortConflict -Port 8001
$null = Test-PortConflict -Port 5500
Start-Sleep -Milliseconds 500

# ── [3/6] Kill old bot processes ──
Write-Host "[3/6] Killing old bot processes..." -ForegroundColor Gray
try {
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and ($_.CommandLine -like "*bot.py*") } |
        ForEach-Object {
            Write-Host ("  Killing PID " + $_.ProcessId) -ForegroundColor DarkYellow
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
} catch {}
if (Test-Path -LiteralPath $BOT_LOCK) {
    Remove-Item -LiteralPath $BOT_LOCK -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 1

# ── [4/6] Start Backend (background) ──
Write-Host "[4/6] Starting Backend on :8001 (background)..." -ForegroundColor White
$beLog    = Join-Path $LOG_DIR "backend.log"
$beErrLog = Join-Path $LOG_DIR "backend-err.log"
$beProc = Start-Process -NoNewWindow -PassThru -FilePath $VENV_PY `
    -ArgumentList "-u","-m","uvicorn","app.main:app","--host","127.0.0.1","--port","8001","--reload","--log-level","info" `
    -WorkingDirectory $BACKEND_DIR `
    -RedirectStandardOutput $beLog `
    -RedirectStandardError $beErrLog
$script:bgPids += $beProc.Id
Write-Host ("  Backend PID: " + $beProc.Id + "  (log: logs\backend.log)") -ForegroundColor DarkGray

# ── [5/6] Wait for backend health ──
Write-Host "[5/6] Waiting for backend..." -ForegroundColor White
$healthOk = Wait-ForHealth -MaxSeconds 25

if (-not $healthOk) {
    Write-Host "  Backend may still be starting. Check logs\backend-err.log" -ForegroundColor Yellow
}

# ── Start Frontend (background) ──
Write-Host "  Starting Frontend on :5500 (background)..." -ForegroundColor White
$feLog    = Join-Path $LOG_DIR "frontend.log"
$feErrLog = Join-Path $LOG_DIR "frontend-err.log"
$feProc = Start-Process -NoNewWindow -PassThru -FilePath $VENV_PY `
    -ArgumentList "-u","-m","http.server","5500","--bind","127.0.0.1" `
    -WorkingDirectory $FRONTEND_DIR `
    -RedirectStandardOutput $feLog `
    -RedirectStandardError $feErrLog
$script:bgPids += $feProc.Id
Write-Host ("  Frontend PID: " + $feProc.Id + "  (log: logs\frontend.log)") -ForegroundColor DarkGray

Start-Sleep -Seconds 1

# ── [6/6] Final status ──
$beOk = Test-Port -HostName "127.0.0.1" -Port 8001
$feOk = Test-Port -HostName "127.0.0.1" -Port 5500

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
if ($beOk) { Write-Host "  Backend  (8001) : RUNNING" -ForegroundColor Green }
else       { Write-Host "  Backend  (8001) : STARTING... (check logs\backend-err.log)" -ForegroundColor Yellow }
if ($feOk) { Write-Host "  Frontend (5500) : RUNNING" -ForegroundColor Green }
else       { Write-Host "  Frontend (5500) : STARTING..." -ForegroundColor Yellow }
Write-Host "  Bot              : Starting below..." -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Panel  : http://127.0.0.1:5500/login.html" -ForegroundColor White
Write-Host "  Swagger: http://127.0.0.1:8001/docs"       -ForegroundColor Gray
Write-Host "  Health : http://127.0.0.1:8001/health"      -ForegroundColor Gray
Write-Host "  Bot    : @AinanScamCheckBot on Telegram"     -ForegroundColor Cyan
Write-Host ""
Write-Host "  Logs in: $LOG_DIR" -ForegroundColor DarkGray
Write-Host "  Press Ctrl+C to stop everything." -ForegroundColor DarkGray
Write-Host ""

# ── Open browser ──
Start-Process "http://127.0.0.1:5500/login.html"

# ══════════════════════════════════════════════════════════════
#  BOT runs in FOREGROUND (you see its output here)
# ══════════════════════════════════════════════════════════════
Write-Host "--- Bot output below ---" -ForegroundColor DarkGray
Write-Host ""

try {
    & $VENV_PY -u (Join-Path $BOT_DIR "bot.py")
} finally {
    Cleanup-All
}
