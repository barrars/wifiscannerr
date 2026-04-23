@echo off
cd /d "%~dp0"

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: Node.js is not installed.
    echo  Download and install it from: https://nodejs.org
    echo  Then run this file again.
    echo.
    pause
    exit /b 1
)

if not exist node_modules (
    echo Installing dependencies...
    call npm install --silent
    echo Done.
    echo.
) else (
    call npm install --silent 2>nul
)

echo  Freeing port 3456 if in use...
for /f "tokens=5" %%p in ('netstat -aon ^| findstr ":3456 " ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1
)

echo  Starting WiFi Surveyor...
echo  Your browser will open automatically.
echo  Press Ctrl+C to stop the server.
echo.

node server.js
pause
