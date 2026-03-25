# Push this repo to GitHub (run once after you create an empty repo on github.com)
# Usage:
#   .\scripts\push-to-github.ps1 -RepoUrl "https://github.com/YOUR_USERNAME/YOUR_REPO.git"
#
# Or set the URL below and run this script without parameters.

param(
    [string] $RepoUrl = ""
)

if ([string]::IsNullOrWhiteSpace($RepoUrl)) {
    Write-Host "Edit scripts/push-to-github.ps1 and set `$RepoUrl, or run:" -ForegroundColor Yellow
    Write-Host '  .\scripts\push-to-github.ps1 -RepoUrl "https://github.com/YOUR_USERNAME/YOUR_REPO.git"' -ForegroundColor Cyan
    exit 1
}

$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

$existing = git remote get-url origin 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Host "Remote 'origin' already exists: $existing" -ForegroundColor Yellow
    $r = Read-Host "Replace it with $RepoUrl ? (y/N)"
    if ($r -ne "y" -and $r -ne "Y") { exit 0 }
    git remote remove origin
}

git remote add origin $RepoUrl
Write-Host "Pushing branch main to origin..." -ForegroundColor Green
git push -u origin main
if ($LASTEXITCODE -eq 0) {
    Write-Host "Done. Open your repo on GitHub to verify." -ForegroundColor Green
}
