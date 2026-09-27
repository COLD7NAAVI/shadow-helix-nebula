# Shadow : Helix Nebula (SHN) — Start Test Database
# Starts an isolated PostgreSQL 17 test database on port 54329 (Docker or local fallback)

$Port = 54329
$TestDbDir = Join-Path $PSScriptRoot "..\tmp\test-db"

# Check if port is already listening
$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    Write-Host "[+] PostgreSQL test database is already listening on port $Port."
    exit 0
}

# Check if Docker is running
$dockerRunning = $false
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) { $dockerRunning = $true }
} catch {}

if ($dockerRunning) {
    Write-Host "[*] Starting PostgreSQL test container via Docker Compose..."
    docker compose -f docker-compose.test.yml up -d
    Write-Host "[+] Docker test container started."
    exit 0
}

# Fallback to local PostgreSQL binaries
$pgBin = "C:\Program Files\PostgreSQL\17\bin"
if (Test-Path $pgBin) {
    Write-Host "[*] Docker not running. Starting local PostgreSQL 17 test cluster on port $Port..."
    if (-not (Test-Path $TestDbDir)) {
        & "$pgBin\initdb.exe" -U postgres -A trust -E UTF8 $TestDbDir | Out-Null
    }
    Start-Process -FilePath "$pgBin\postgres.exe" -ArgumentList "-D `"$TestDbDir`" -p $Port" -NoNewWindow
    Start-Sleep -Seconds 2
    Write-Host "[+] Local PostgreSQL test cluster started on port $Port."
    exit 0
}

Write-Error "Neither Docker nor local PostgreSQL 17 installation found. Cannot start test database."
exit 1
