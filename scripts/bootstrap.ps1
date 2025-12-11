# ByteGuardX One-Click Setup Script for Windows
# This script sets up ByteGuardX with all dependencies and runs the first scan

param(
    [switch]$SkipNodeJS = $false,
    [switch]$Verbose = $false
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Function to write colored output
function Write-Status {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Blue
}

function Write-Success {
    param([string]$Message)
    Write-Host "[SUCCESS] $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "[WARNING] $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "[ERROR] $Message" -ForegroundColor Red
}

# Function to check if command exists
function Test-Command {
    param([string]$Command)
    try {
        Get-Command $Command -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

# Function to create necessary directories
function New-Directories {
    Write-Status "Creating necessary directories..."
    
    $directories = @(
        "data\logs",
        "data\audit_logs", 
        "data\secure",
        "data\rate_limits",
        "data\plugins",
        "data\backups",
        "reports\output",
        "temp"
    )
    
    foreach ($dir in $directories) {
        if (!(Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "Directories created successfully"
}

# Function to install Python dependencies
function Install-PythonDependencies {
    Write-Status "Installing Python dependencies..."
    
    if (Test-Command "pip") {
        & pip install --upgrade pip
        & pip install -r requirements.txt
    }
    elseif (Test-Command "pip3") {
        & pip3 install --upgrade pip
        & pip3 install -r requirements.txt
    }
    else {
        Write-Error "pip not found. Please install Python and pip first."
        exit 1
    }
    
    Write-Success "Python dependencies installed"
}

# Function to install Node.js dependencies
function Install-NodeDependencies {
    if ($SkipNodeJS) {
        Write-Warning "Skipping Node.js dependencies as requested"
        return
    }
    
    Write-Status "Installing Node.js dependencies..."
    
    if (Test-Command "npm") {
        & npm install
        Write-Success "Node.js dependencies installed"
    }
    elseif (Test-Command "yarn") {
        & yarn install
        Write-Success "Node.js dependencies installed with Yarn"
    }
    else {
        Write-Warning "npm/yarn not found. Skipping frontend dependencies."
        Write-Warning "You can install Node.js later to use the web interface."
    }
}

# Function to setup configuration
function Set-Configuration {
    Write-Status "Setting up configuration..."
    
    # Copy environment file if it doesn't exist
    if (!(Test-Path ".env")) {
        if (Test-Path ".env.backend.example") {
            Copy-Item ".env.backend.example" ".env"
            Write-Success "Environment configuration created from template"
        }
        else {
            Write-Warning "No environment template found. You may need to configure manually."
        }
    }
    
    # Generate secret keys if needed
    if (Test-Command "python") {
        $pythonScript = @"
import secrets
import os

# Generate secret keys
secret_key = secrets.token_urlsafe(32)
jwt_key = secrets.token_urlsafe(32)
master_key = secrets.token_urlsafe(32)

# Update .env file
if os.path.exists('.env'):
    with open('.env', 'r') as f:
        content = f.read()
    
    # Replace placeholder keys
    content = content.replace('your-super-secret-key-change-this-in-production', secret_key)
    content = content.replace('your-jwt-secret-key-change-this', jwt_key)
    content = content.replace('your-base64-encoded-master-key-32-bytes', master_key)
    
    with open('.env', 'w') as f:
        f.write(content)
    
    print('✅ Secret keys generated and configured')
else:
    print('⚠️  No .env file found to update')
"@
        
        & python -c $pythonScript
    }
}

# Function to setup database
function Initialize-Database {
    Write-Status "Setting up database..."
    
    if (Test-Command "python") {
        $pythonScript = @"
try:
    from byteguardx.database.connection_pool import init_db
    init_db('sqlite:///data/byteguardx.db')
    print('✅ Database initialized successfully')
except Exception as e:
    print(f'⚠️  Database setup warning: {e}')
"@
        
        & python -c $pythonScript
    }
}

# Function to run test scan
function Test-Installation {
    Write-Status "Running test scan to verify installation..."
    
    # Create test project directory
    if (!(Test-Path "test_project")) {
        New-Item -ItemType Directory -Path "test_project" | Out-Null
    }
    
    # Create test file with secrets
    $testContent = @"
# Test file for ByteGuardX
api_key = "sk_test_1234567890abcdef"
password = "my_secret_password"

def main():
    print("Hello, World!")

if __name__ == "__main__":
    main()
"@
    
    Set-Content -Path "test_project\test_file.py" -Value $testContent
    
    # Run the scan
    if (Test-Command "python") {
        try {
            & python -m byteguardx.cli.cli scan test_project --output test_results.json
            
            if (Test-Path "test_results.json") {
                Write-Success "Test scan completed successfully!"
                Write-Status "Results saved to test_results.json"
                
                # Show summary
                $summaryScript = @"
import json
try:
    with open('test_results.json', 'r') as f:
        results = json.load(f)
    
    total_findings = len(results.get('findings', []))
    print(f'📊 Found {total_findings} test findings (expected: 2)')
    
    if total_findings >= 2:
        print('✅ ByteGuardX is working correctly!')
    else:
        print('⚠️  Fewer findings than expected. Check configuration.')
        
except Exception as e:
    print(f'⚠️  Could not parse results: {e}')
"@
                
                & python -c $summaryScript
            }
            else {
                Write-Warning "Test scan completed but no results file found"
            }
        }
        catch {
            Write-Warning "Test scan encountered an issue: $($_.Exception.Message)"
        }
    }
    
    # Cleanup test files
    if (Test-Path "test_project") {
        Remove-Item -Path "test_project" -Recurse -Force
    }
    if (Test-Path "test_results.json") {
        Remove-Item -Path "test_results.json" -Force
    }
}

# Main function
function Main {
    Write-Host "🔐 ByteGuardX One-Click Setup" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    
    # Check if we're in the right directory
    if (!(Test-Path "setup.py") -or !(Test-Path "requirements.txt")) {
        Write-Error "Please run this script from the ByteGuardX root directory"
        exit 1
    }
    
    # Check Python
    if (Test-Command "python") {
        $pythonVersion = & python --version 2>&1
        Write-Status "Python version: $pythonVersion"
    }
    else {
        Write-Error "Python not found. Please install Python 3.8+ first."
        exit 1
    }
    
    Write-Host ""
    Write-Status "Starting ByteGuardX setup..."
    Write-Host ""
    
    try {
        # Step 1: Create directories
        New-Directories
        
        # Step 2: Install Python dependencies
        Install-PythonDependencies
        
        # Step 3: Install Node.js dependencies (optional)
        Install-NodeDependencies
        
        # Step 4: Setup configuration
        Set-Configuration
        
        # Step 5: Setup database
        Initialize-Database
        
        # Step 6: Install ByteGuardX package
        Write-Status "Installing ByteGuardX package..."
        & pip install -e .
        Write-Success "ByteGuardX package installed"
        
        # Step 7: Run test scan
        Test-Installation
        
        Write-Host ""
        Write-Host "🎉 ByteGuardX Setup Complete!" -ForegroundColor Green
        Write-Host "==============================" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "1. Run 'byteguardx init' for guided setup" -ForegroundColor White
        Write-Host "2. Scan your first project: 'byteguardx scan C:\path\to\project'" -ForegroundColor White
        Write-Host "3. Start the web interface: 'python run.py'" -ForegroundColor White
        Write-Host "4. View API docs: 'byteguardx --help'" -ForegroundColor White
        Write-Host ""
        Write-Host "For more information, visit: https://docs.byteguardx.com" -ForegroundColor Cyan
        Write-Host ""
    }
    catch {
        Write-Error "Setup failed: $($_.Exception.Message)"
        if ($Verbose) {
            Write-Host $_.Exception.StackTrace -ForegroundColor Red
        }
        exit 1
    }
}

# Run main function
Main
