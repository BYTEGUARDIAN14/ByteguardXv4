@echo off
echo.
echo ========================================
echo    ByteGuardX Enterprise Security Platform
echo ========================================
echo.
echo Starting ByteGuardX locally...
echo.

REM Set environment variables for development
set FLASK_ENV=development
set NODE_ENV=development
set BYTEGUARDX_ENV=development

REM Create logs directory if it doesn't exist
if not exist "logs" mkdir logs

echo [1/3] Starting Backend API Server...
start "ByteGuardX Backend" cmd /k "python -m byteguardx.api.app"

REM Wait for backend to start
timeout /t 5 /nobreak > nul

echo [2/3] Starting Frontend Development Server...
start "ByteGuardX Frontend" cmd /k "npm run dev"

REM Wait for frontend to start
timeout /t 10 /nobreak > nul

echo [3/3] Opening ByteGuardX Application...
timeout /t 3 /nobreak > nul

REM Open the application in default browser
start http://localhost:3000

echo.
echo ========================================
echo    ByteGuardX is now running locally!
echo ========================================
echo.
echo Frontend:  http://localhost:3000
echo Backend:   http://localhost:5000
echo.
echo Press any key to stop all servers...
pause > nul

echo.
echo Stopping ByteGuardX servers...
taskkill /f /im python.exe /fi "WINDOWTITLE eq ByteGuardX Backend*" 2>nul
taskkill /f /im node.exe /fi "WINDOWTITLE eq ByteGuardX Frontend*" 2>nul

echo ByteGuardX stopped.
pause
