@echo off
setlocal EnableDelayedExpansion

:: ==============================================================
:: InsiEDR Enterprise Native Sensor - Silent Service Installer
:: SASTRA University Lab & Campus Production Deployment
:: ==============================================================

echo ==========================================================
echo    InsiEDR Enterprise Windows Native Sensor Installer
echo ==========================================================
echo.

:: 1. Verify Administrative Privileges
echo [*] Checking Administrator Privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] ERROR: Administrator privileges required!
    echo [!] Right-click install.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)
echo [✓] Administrator privileges confirmed.

:: 2. Set Destination Directories
set "INSTALL_DIR=C:\Program Files\InsiEDR"
set "DATA_DIR=C:\ProgramData\InsiEDR"

echo [*] Target Installation Directory: %INSTALL_DIR%
echo [*] Local Spool and Cache Directory:  %DATA_DIR%

:: 3. Gracefully Stop and Clean Existing Instances (if already installed)
echo [*] Cleaning up any previous running instances...
sc stop InsiEDR >nul 2>&1
sc delete InsiEDR >nul 2>&1
schtasks /delete /tn "InsiEDR" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "InsiEDR" /f >nul 2>&1
taskkill /F /IM insiedr-service.exe >nul 2>&1
taskkill /F /IM insiedr-broker.exe >nul 2>&1
taskkill /F /IM insiedr-watchdog.exe >nul 2>&1

:: 4. Create Directories
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

:: 5. Copy Production Executables and Configuration
echo [*] Deploying native sensor binaries and configuration...
copy /Y "%~dp0insiedr-service.exe" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0insiedr-broker.exe" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0insiedr-watchdog.exe" "%INSTALL_DIR%\" >nul
copy /Y "%~dp0agent_config.json" "%INSTALL_DIR%\" >nul

if not exist "%INSTALL_DIR%\insiedr-service.exe" (
    echo [-] ERROR: Failed to copy insiedr-service.exe to %INSTALL_DIR%.
    pause
    exit /b 1
)

:: 6. Apply Anti-Tamper DACL Permissions
echo [*] Hardening directory permissions...
icacls "%INSTALL_DIR%" /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)RX" >nul 2>&1
icacls "%DATA_DIR%" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)M" >nul 2>&1

:: 7. Register Auto-Start Task (Automatic Startup on every Windows Boot & Logon)
echo [*] Registering InsiEDR automatic startup task...
schtasks /create /tn "InsiEDR" /tr "\"%INSTALL_DIR%\insiedr-service.exe\"" /sc onlogon /rl HIGHEST /f >nul 2>&1
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "InsiEDR" /t REG_SZ /d "\"%INSTALL_DIR%\insiedr-service.exe\"" /f >nul 2>&1

:: 8. Launch InsiEDR Sensor in Background (Hidden Window)
echo [*] Starting InsiEDR Sensor in background...
powershell -Command "Start-Process -FilePath '%INSTALL_DIR%\insiedr-service.exe' -WindowStyle Hidden"
timeout /t 3 /nobreak >nul

:: 9. Verify Running State
tasklist /FI "IMAGENAME eq insiedr-service.exe" | findstr /i "insiedr-service.exe" >nul
if %errorlevel% equ 0 (
    echo.
    echo ==========================================================
    echo  [✓] SUCCESS: InsiEDR Sensor is ACTIVE and RUNNING!
    echo ==========================================================
    echo  • Mode:              Silent Background Process (Hidden Window)
    echo  • Startup:           Automatic on every boot / login
    echo  • CPU Limit:         Hardware-capped at 3.00%%
    echo  • Local Spool:       %DATA_DIR%\spool.db
    echo  • Configuration:     %INSTALL_DIR%\agent_config.json
    echo.
    echo Telemetry and Keystroke Biometrics are now streaming to the server.
    echo You can manage and monitor this endpoint from the Web Dashboard (http://172.16.22.198).
    echo.
) else (
    echo.
    echo [!] Process check:
    tasklist /FI "IMAGENAME eq insiedr*"
)

pause
