@echo off
cd /d "%~dp0"

echo ============================================
echo  WiFi Surveyor -- Build Portable EXE
echo ============================================
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo  ERROR: Node.js must be installed on THIS machine to build the exe.
    echo  Download and install it from: https://nodejs.org
    echo  After installing, run this file again.
    echo.
    pause
    exit /b 1
)

echo [1/3] Installing all dependencies...
call npm install
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: npm install failed. Check your internet connection and try again.
    pause
    exit /b 1
)

echo.
echo [2/3] Building portable exe...
echo       (First run downloads Node 18 binaries -- may take a minute)
echo.
if not exist dist mkdir dist
call npx @yao-pkg/pkg . --compress GZip --output dist\WiFiSurveyor.exe
if %errorlevel% neq 0 (
    echo.
    echo  ERROR: Build failed. See output above for details.
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo.
echo  =====================================================
echo   dist\WiFiSurveyor.exe  is ready.
echo.
echo   To use on any Windows machine (no install needed):
echo     1. Copy WiFiSurveyor.exe to a USB drive
echo     2. Double-click it on the target machine
echo     3. A browser will open automatically
echo     4. Scans are saved in a "scans" folder next
echo        to wherever the exe is located
echo  =====================================================
echo.
pause
