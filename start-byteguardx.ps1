# ByteGuardX Enterprise Security Platform Startup Script
# PowerShell version for better process management

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "   ByteGuardX Enterprise Security Platform" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Set environment variables for development
$env:FLASK_ENV = "development"
$env:NODE_ENV = "development"
$env:BYTEGUARDX_ENV = "development"

# Function to check if port is available
function Test-Port {
    param([int]$Port)
    try {
        $connection = New-Object System.Net.Sockets.TcpClient
        $connection.Connect("localhost", $Port)
        $connection.Close()
        return $true
    } catch {
        return $false
    }
}

# Function to wait for service to be ready
function Wait-ForService {
    param([string]$Url, [string]$ServiceName, [int]$MaxAttempts = 30)
    
    Write-Host "Waiting for $ServiceName to be ready..." -ForegroundColor Yellow
    
    for ($i = 1; $i -le $MaxAttempts; $i++) {
        try {
            $response = Invoke-WebRequest -Uri $Url -TimeoutSec 2 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Host "✅ $ServiceName is ready!" -ForegroundColor Green
                return $true
            }
        } catch {
            # Service not ready yet
        }
        
        Write-Host "." -NoNewline -ForegroundColor Yellow
        Start-Sleep -Seconds 2
    }
    
    Write-Host ""
    Write-Host "❌ $ServiceName failed to start within expected time" -ForegroundColor Red
    return $false
}

# Check if ports are available
Write-Host "[0/3] Checking port availability..." -ForegroundColor Blue

if (Test-Port 5000) {
    Write-Host "⚠️  Port 5000 is already in use. Attempting to stop existing process..." -ForegroundColor Yellow
    Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowTitle -like "*ByteGuardX*"} | Stop-Process -Force
    Start-Sleep -Seconds 2
}

if (Test-Port 3000) {
    Write-Host "⚠️  Port 3000 is already in use. Attempting to stop existing process..." -ForegroundColor Yellow
    Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {$_.MainWindowTitle -like "*ByteGuardX*"} | Stop-Process -Force
    Start-Sleep -Seconds 2
}

# Create logs directory if it doesn't exist
if (!(Test-Path "logs")) {
    New-Item -ItemType Directory -Path "logs" | Out-Null
}

Write-Host ""
Write-Host "[1/3] Starting Backend API Server..." -ForegroundColor Blue

# Start backend server
$backendProcess = Start-Process -FilePath "python" -ArgumentList "-m", "byteguardx.api.app" -WindowStyle Normal -PassThru
Start-Sleep -Seconds 3

# Wait for backend to be ready
if (!(Wait-ForService "http://localhost:5000/health" "Backend API")) {
    Write-Host "Failed to start backend. Exiting..." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "[2/3] Starting Frontend Development Server..." -ForegroundColor Blue

# Start frontend server
$frontendProcess = Start-Process -FilePath "npm" -ArgumentList "run", "dev" -WindowStyle Normal -PassThru
Start-Sleep -Seconds 5

# Wait for frontend to be ready
if (!(Wait-ForService "http://localhost:3000" "Frontend Server")) {
    Write-Host "Failed to start frontend. Exiting..." -ForegroundColor Red
    $backendProcess | Stop-Process -Force
    exit 1
}

Write-Host ""
Write-Host "[3/3] Opening ByteGuardX Application..." -ForegroundColor Blue
Start-Sleep -Seconds 2

# Open the application in default browser
Start-Process "http://localhost:3000"

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "   ByteGuardX is now running locally!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "🌐 Frontend:  http://localhost:3000" -ForegroundColor Cyan
Write-Host "🔧 Backend:   http://localhost:5000" -ForegroundColor Cyan
Write-Host "📊 Health:    http://localhost:5000/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "🧪 Test Pages:" -ForegroundColor Yellow
Write-Host "   • Connection Test: http://localhost:3000/test-connection.html"
Write-Host "   • Signup Test:     http://localhost:3000/test-signup.html"
Write-Host "   • CSRF Test:       http://localhost:3000/test-csrf.html"
Write-Host ""
Write-Host "Press Ctrl+C to stop all servers..." -ForegroundColor Yellow

# Wait for user to stop
try {
    while ($true) {
        Start-Sleep -Seconds 1
    }
} finally {
    Write-Host ""
    Write-Host "Stopping ByteGuardX servers..." -ForegroundColor Yellow
    
    # Stop processes gracefully
    if ($frontendProcess -and !$frontendProcess.HasExited) {
        $frontendProcess | Stop-Process -Force
        Write-Host "✅ Frontend server stopped" -ForegroundColor Green
    }
    
    if ($backendProcess -and !$backendProcess.HasExited) {
        $backendProcess | Stop-Process -Force
        Write-Host "✅ Backend server stopped" -ForegroundColor Green
    }
    
    # Clean up any remaining processes
    Get-Process -Name python -ErrorAction SilentlyContinue | Where-Object {$_.ProcessName -eq "python" -and $_.CommandLine -like "*byteguardx*"} | Stop-Process -Force
    Get-Process -Name node -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -like "*vite*"} | Stop-Process -Force
    
    Write-Host ""
    Write-Host "ByteGuardX stopped successfully!" -ForegroundColor Green
}
