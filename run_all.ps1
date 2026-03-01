# ============================================================
#  SIT-System v2.0 - One-Click Launcher
#  Compatible: Windows PowerShell 5.1+
#  SPACE-SAFE: uses -EncodedCommand (Base64 Unicode) so paths
#              with spaces never break quoting.
#  Starts: Backend (8002) | Frontend (5500) | Telegram Bot
# ============================================================

$ErrorActionPreference = "Stop"

# -- Resolve project root (works even when invoked via -File) --
$ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ROOT

$BACKEND_DIR  = Join-Path $ROOT "backend"
$FRONTEND_DIR = Join-Path $ROOT "frontend\admin"
$BOT_DIR      = Join-Path $BACKEND_DIR "bot"
$VENV_PY      = Join-Path $BACKEND_DIR ".venv\Scripts\python.exe"
$BOT_LOCK     = Join-Path $BOT_DIR ".bot.lock"

# ── Helper: open a NEW PowerShell window via -EncodedCommand ──
function Start-ServiceWindow {
    param(
        [string]$Label,
        [string]$WorkDir,
        [string]$Cmd
    )
    $full  = "Set-Location -LiteralPath '" + $WorkDir + "'; " + $Cmd
    $bytes = [System.Text.Encoding]::Unicode.GetBytes($full)
    $enc   = [Convert]::ToBase64String($bytes)
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit","-EncodedCommand",$enc
    Write-Host ("  -> " + $Label) -ForegroundColor DarkGray
}

# ── Helper: TCP port probe with 2-second timeout ──
function Test-Port {
    param(
        [string]$HostName,
        [int]$Port
    )
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $ar  = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $ok  = $ar.AsyncWaitHandle.WaitOne(2000, $false)
        if ($ok) { $tcp.EndConnect($ar) }
        $tcp.Close()
        return $ok
    } catch {
        return $false
    }
}

# ── Helper: detect port conflict, show PID + process name, auto-kill project procs ──
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

                # Auto-kill if it is a python process (likely our own from a previous run)
                if ($procName -eq "python" -or $procName -eq "python3") {
                    Write-Host ("  Auto-killing PID " + $pid + " (python process from previous run)") -ForegroundColor Yellow
                    try { Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue } catch {}
                    Start-Sleep -Milliseconds 500
                } else {
                    Write-Host ("  Fix: taskkill /PID " + $pid + " /F") -ForegroundColor Yellow
                }
            }
        }
    } catch {}
    return $found
}

# ── Helper: wait for /health endpoint to respond (up to N seconds) ──
function Wait-ForHealth {
    param([int]$MaxSeconds = 20)
    Write-Host ("  Waiting for backend /health (up to " + $MaxSeconds + "s)...") -ForegroundColor Gray
    for ($i = 0; $i -lt $MaxSeconds; $i++) {
        Start-Sleep -Seconds 1
        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8002/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop
            if ($resp.StatusCode -eq 200) {
                $body = $resp.Content | ConvertFrom-Json
                $dbStatus = "DOWN"
                if ($body.db -eq $true) { $dbStatus = "OK" }
                Write-Host ("  /health OK (db=" + $dbStatus + ", version=" + $body.version + ") after " + ($i+1) + "s") -ForegroundColor Green
                return $true
            }
        } catch {}
    }
    Write-Host ("  /health did NOT respond within " + $MaxSeconds + "s") -ForegroundColor Red
    Write-Host "  Check the backend window for errors." -ForegroundColor Yellow
    return $false
}

# ── Banner ──
Write-Host ""
Write-Host "==================================================" -ForegroundColor DarkGray
Write-Host "  SIT-System v2.0 - Enterprise MVP Launcher"       -ForegroundColor White
Write-Host "==================================================" -ForegroundColor DarkGray
Write-Host "[REMINDER] Start XAMPP MySQL first. Ensure 'sit_db' exists." -ForegroundColor Yellow
Write-Host ("ROOT: " + $ROOT) -ForegroundColor DarkGray
Write-Host ""

# ── Sanity: venv python must exist ──
if (-not (Test-Path -LiteralPath $VENV_PY)) {
    Write-Host "ERROR: venv python not found:" -ForegroundColor Red
    Write-Host ("  " + $VENV_PY) -ForegroundColor Red
    Write-Host "" -ForegroundColor Yellow
    Write-Host "Fix (run these one at a time):" -ForegroundColor Yellow
    Write-Host "  cd backend"                                                  -ForegroundColor Yellow
    Write-Host "  python -m venv .venv"                                        -ForegroundColor Yellow
    Write-Host "  .venv\Scripts\python.exe -m pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

# ── [0/6] Ensure sit_db exists (avoids "Unknown database" 500) ──
$MYSQL_EXE = "C:\xampp\mysql\bin\mysql.exe"
if (Test-Path -LiteralPath $MYSQL_EXE) {
    Write-Host "[0/6] Ensuring database 'sit_db' exists..." -ForegroundColor Gray
    try {
        & $MYSQL_EXE -u root -e "CREATE DATABASE IF NOT EXISTS sit_db;" 2>$null
        Write-Host "  sit_db ready" -ForegroundColor DarkGray
    } catch {
        Write-Host "  Could not create sit_db (MySQL may not be running)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[0/6] MySQL client not found at $MYSQL_EXE - create sit_db manually in phpMyAdmin" -ForegroundColor Yellow
}

# ── [1/6] Check for port conflicts ──
Write-Host "[1/6] Checking for port conflicts..." -ForegroundColor Gray
$conflict8002 = Test-PortConflict -Port 8002
$conflict5500 = Test-PortConflict -Port 5500
if ($conflict8002 -or $conflict5500) {
    Start-Sleep -Seconds 1
}

# ── [2/6] Kill old bot.py processes (prevent Telegram 409) ──
Write-Host "[2/6] Killing old bot.py processes..." -ForegroundColor Gray
try {
    Get-CimInstance Win32_Process -Filter "Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and ($_.CommandLine -like "*bot.py*") } |
        ForEach-Object {
            Write-Host ("  Killing PID " + $_.ProcessId) -ForegroundColor DarkYellow
            Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
        }
} catch { }

if (Test-Path -LiteralPath $BOT_LOCK) {
    Remove-Item -LiteralPath $BOT_LOCK -Force -ErrorAction SilentlyContinue
    Write-Host "  Removed stale .bot.lock" -ForegroundColor DarkGray
}
Start-Sleep -Seconds 1

# ── [3/6] Backend: uvicorn on :8002 ──
Write-Host "[3/6] Starting Backend on 127.0.0.1:8002..." -ForegroundColor White
$beCmd = "& '" + $VENV_PY + "' -m uvicorn app.main:app --host 127.0.0.1 --port 8002 --reload --log-level info"
Start-ServiceWindow -Label "Backend (uvicorn :8002)" -WorkDir $BACKEND_DIR -Cmd $beCmd

# ── [4/6] Wait for backend /health before starting other services ──
Write-Host "[4/6] Waiting for backend to be ready..." -ForegroundColor White
$healthOk = Wait-ForHealth -MaxSeconds 20

if (-not $healthOk) {
    Write-Host ""
    Write-Host "  Backend failed to start. Common causes:" -ForegroundColor Red
    Write-Host "    - XAMPP MySQL not running"              -ForegroundColor Yellow
    Write-Host "    - Database 'sit_db' does not exist"     -ForegroundColor Yellow
    Write-Host "    - Python dependency missing (run pip install -r requirements.txt)" -ForegroundColor Yellow
    Write-Host "    - Port 8002 still occupied"             -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Starting frontend and bot anyway..." -ForegroundColor Yellow
}

# ── [5/6] Frontend: http.server on :5500 ──
Write-Host "[5/6] Starting Frontend on 127.0.0.1:5500..." -ForegroundColor White
$feCmd = "& '" + $VENV_PY + "' -m http.server 5500 --bind 127.0.0.1"
Start-ServiceWindow -Label "Frontend (http.server :5500)" -WorkDir $FRONTEND_DIR -Cmd $feCmd

# ── Bot: launch after backend confirmed healthy ──
Write-Host "  Starting Bot..." -ForegroundColor White
Start-Sleep -Seconds 1
$botCmd = "& '" + $VENV_PY + "' -u bot.py"
Start-ServiceWindow -Label "Telegram Bot" -WorkDir $BOT_DIR -Cmd $botCmd

# ── [6/6] Final port checks ──
Write-Host "[6/6] Final port check..." -ForegroundColor Gray
Start-Sleep -Seconds 2

$beOk = Test-Port -HostName "127.0.0.1" -Port 8002
$feOk = Test-Port -HostName "127.0.0.1" -Port 5500

Write-Host ""
Write-Host "==================================================" -ForegroundColor DarkGray
if ($beOk) { Write-Host "  Backend  (8002) : PASS" -ForegroundColor Green }
else       { Write-Host "  Backend  (8002) : FAIL - check backend window" -ForegroundColor Red }
if ($healthOk) { Write-Host "  /health  check  : PASS" -ForegroundColor Green }
else           { Write-Host "  /health  check  : FAIL - backend may still be starting" -ForegroundColor Yellow }
if ($feOk) { Write-Host "  Frontend (5500) : PASS" -ForegroundColor Green }
else       { Write-Host "  Frontend (5500) : FAIL - check frontend window" -ForegroundColor Red }
Write-Host "  Bot              : Started (check its window)" -ForegroundColor Yellow
Write-Host "==================================================" -ForegroundColor DarkGray
Write-Host ""

# ── Auto-open browser tabs ──
Start-Process "http://127.0.0.1:8002/docs"
Start-Process "http://127.0.0.1:5500/login.html"

# ── Credentials / URLs ──
Write-Host "Admin  : nalcsbaru@gmail.com / admin123 (2FA)" -ForegroundColor White
Write-Host "Bot    : Message @AinanScamCheckBot on Telegram (not SiT_bot)" -ForegroundColor Cyan
Write-Host "Swagger: http://127.0.0.1:8002/docs"   -ForegroundColor Gray
Write-Host "Health : http://127.0.0.1:8002/health"  -ForegroundColor Gray
Write-Host "Panel  : http://127.0.0.1:5500/login.html" -ForegroundColor Gray
Write-Host ""
Write-Host "NOTE: /docs may take 5-10s to render (loads OpenAPI schema)." -ForegroundColor DarkGray
Write-Host "      /health is the real readiness check."                    -ForegroundColor DarkGray
Write-Host ""
Write-Host "To stop everything, close the spawned PowerShell windows." -ForegroundColor DarkGray
Write-Host ""
