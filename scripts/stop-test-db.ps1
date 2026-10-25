# Shadow : Helix Nebula (SHN) — Stop Test Database
$Port = 54329
$TestDbDir = Join-Path $PSScriptRoot "..\tmp\test-db"

# Check Docker container
try {
    $dockerInfo = docker info 2>&1
    if ($LASTEXITCODE -eq 0) {
        docker compose -f docker-compose.test.yml down 2>$null
    }
} catch {}

# Gracefully stop local PostgreSQL test cluster using pg_ctl if available
$pgBin = "C:\Program Files\PostgreSQL\17\bin"
if ((Test-Path "$pgBin\pg_ctl.exe") -and (Test-Path $TestDbDir)) {
    Write-Host "[*] Gracefully stopping local PostgreSQL cluster via pg_ctl..."
    & "$pgBin\pg_ctl.exe" stop -D "$TestDbDir" -m fast 2>$null
    Start-Sleep -Seconds 1
}

# Stop any remaining processes listening on the test port
$connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like "*postgres*") {
        Write-Host "[*] Terminating remaining PostgreSQL process $($proc.Id)..."
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[+] Test database stopped."
