@echo off
REM ByteGuardX Unified Startup Script for Windows
REM Validates environment and starts the complete stack

echo 🚀 ByteGuardX Unified Startup
echo ==============================

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python is required but not installed
    pause
    exit /b 1
)

REM Check if we're in the right directory
if not exist "launch_stack.py" (
    echo ❌ Please run this script from the ByteGuardX root directory
    pause
    exit /b 1
)

echo 🔍 Validating environment...
python validate_environment.py

if errorlevel 1 (
    echo ❌ Environment validation failed
    echo Please fix the issues above and try again
    pause
    exit /b 1
)

echo ✅ Environment validation passed
echo.
echo 🚀 Starting ByteGuardX stack...
echo Press Ctrl+C to stop all services
echo.

REM Start the unified stack
python launch_stack.py

pause
