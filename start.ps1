# Start script for Bespin Security Suite (Windows)
# This starts the AgentOS backend, streamer, and optionally the frontend

Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  AI Security Analyst - Startup" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check for API key
if (-not $env:OPENROUTER_API_KEY) {
    # Try loading from .env file
    if (Test-Path ".env") {
        Get-Content ".env" | ForEach-Object {
            if ($_ -match "^\s*([^#][^=]+)=(.*)$") {
                [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), "Process")
            }
        }
    }
}

if (-not $env:OPENROUTER_API_KEY) {
    Write-Host "Warning: OPENROUTER_API_KEY not set!" -ForegroundColor Yellow
    Write-Host "Add it to your .env file or set it as an environment variable." -ForegroundColor Yellow
    Write-Host ""
}

# Activate venv if it exists
if (Test-Path ".venv\Scripts\Activate.ps1") {
    Write-Host "Activating Python virtual environment..." -ForegroundColor Gray
    & .\.venv\Scripts\Activate.ps1
}

Write-Host ""
Write-Host "Starting services..." -ForegroundColor Green
Write-Host ""

# Start streamer in background
Write-Host "[1/3] Starting Streamer (DuckDB writer)..." -ForegroundColor Cyan
$streamer = Start-Process -FilePath "python" -ArgumentList "-m", "security_analyst.streamer" -PassThru -WindowStyle Minimized
Write-Host "      Streamer started (PID: $($streamer.Id))" -ForegroundColor Gray

Start-Sleep -Seconds 2

# Start AgentOS backend in background
Write-Host "[2/3] Starting AgentOS backend on http://localhost:7777..." -ForegroundColor Cyan
$backend = Start-Process -FilePath "python" -ArgumentList "agentos.py" -PassThru -WindowStyle Minimized
Write-Host "      Backend started (PID: $($backend.Id))" -ForegroundColor Gray

Start-Sleep -Seconds 3

# Check if agent-ui exists, install if not
if (-not (Test-Path "agent-ui\package.json")) {
    Write-Host "[3/3] Installing AgentUI frontend..." -ForegroundColor Cyan
    npx -y create-agent-ui@latest agent-ui
    Start-Sleep -Seconds 2
}

if (Test-Path "agent-ui\package.json") {
    Write-Host "[3/3] Starting AgentUI frontend on http://localhost:3000..." -ForegroundColor Cyan
    $frontend = Start-Process -FilePath "cmd.exe" -ArgumentList "/c", "cd agent-ui && npm run dev" -PassThru -WindowStyle Minimized
    Write-Host "      Frontend started (PID: $($frontend.Id))" -ForegroundColor Gray
} else {
    Write-Host "[3/3] AgentUI installation failed. Try manually: npx create-agent-ui@latest agent-ui" -ForegroundColor Yellow
    $frontend = $null
}

Start-Sleep -Seconds 2

Write-Host ""
Write-Host "============================================" -ForegroundColor Green
Write-Host "  Services Started!" -ForegroundColor White
Write-Host "============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Cyan
Write-Host "  AgentUI:  http://localhost:3000" -ForegroundColor White
Write-Host "  Backend:  http://localhost:7777" -ForegroundColor White
Write-Host ""
Write-Host "How to connect:" -ForegroundColor Cyan
Write-Host "  1. Open http://localhost:3000 in your browser" -ForegroundColor Gray
Write-Host "  2. Click 'Add new OS' -> 'Local'" -ForegroundColor Gray
Write-Host "  3. Enter endpoint: http://localhost:7777" -ForegroundColor Gray
Write-Host "  4. Start chatting with Security Analyst!" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop services, close the minimized windows or run:" -ForegroundColor Yellow
Write-Host "  Stop-Process -Id $($streamer.Id), $($backend.Id)" -NoNewline -ForegroundColor Gray
if ($frontend) {
    Write-Host ", $($frontend.Id)" -ForegroundColor Gray
} else {
    Write-Host "" 
}
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
