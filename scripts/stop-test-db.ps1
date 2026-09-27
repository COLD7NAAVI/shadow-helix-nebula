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

# Stop local postgres on test port
$connections = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $connections) {
    $proc = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
    if ($proc -and $proc.ProcessName -like "*postgres*") {
        Write-Host "[*] Stopping local PostgreSQL test process $($proc.Id)..."
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "[+] Test database stopped."
