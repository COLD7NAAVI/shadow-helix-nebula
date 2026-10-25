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

# Prioritize local PostgreSQL 17 cluster if binaries exist (preserves persistent records in tmp/test-db)
$pgBin = "C:\Program Files\PostgreSQL\17\bin"
if (Test-Path $pgBin) {
    Write-Host "[*] Starting local PostgreSQL 17 test cluster on port $Port..."
    if (-not (Test-Path $TestDbDir)) {
        & "$pgBin\initdb.exe" -U postgres -A trust -E UTF8 $TestDbDir | Out-Null
    }

    # Clean up stale postmaster.pid if process is not actually running
    $pidFile = Join-Path $TestDbDir "postmaster.pid"
    if (Test-Path $pidFile) {
        $firstLine = (Get-Content $pidFile -TotalCount 1)
        if ($firstLine -match "^\d+$") {
            $pidNum = [int]$firstLine
            $proc = Get-Process -Id $pidNum -ErrorAction SilentlyContinue
            if (-not $proc) {
                Write-Host "[*] Removing stale postmaster.pid (PID $pidNum is not running)..."
                Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
            }
        }
    }

    $logFile = Join-Path $PSScriptRoot "..\tmp\test-db.log"
    if (Test-Path "$pgBin\pg_ctl.exe") {
        & "$pgBin\pg_ctl.exe" start -D "$TestDbDir" -o "-p $Port" -l "$logFile"
    } else {
        Start-Process -FilePath "$pgBin\postgres.exe" -ArgumentList "-D `"$TestDbDir`" -p $Port" -NoNewWindow
    }

    Start-Sleep -Seconds 2
    $started = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    if ($started) {
        Write-Host "[+] Local PostgreSQL test cluster started on port $Port."
        exit 0
    }
}

# Fallback to Docker if local PostgreSQL binary is not found
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

Write-Error "Neither local PostgreSQL 17 installation nor Docker found. Cannot start test database."
exit 1
