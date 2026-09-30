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
echo [*] Local Spool & Cache Directory:  %DATA_DIR%

:: 3. Gracefully Stop and Remove Existing Service (if already installed)
sc query InsiEDR >nul 2>&1
if %errorlevel% equ 0 (
    echo [*] Found existing InsiEDR service. Stopping and cleaning up...
    net stop InsiEDR >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete InsiEDR >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: Kill any stray running instances
taskkill /F /IM insiedr-service.exe >nul 2>&1
taskkill /F /IM insiedr-broker.exe >nul 2>&1
taskkill /F /IM insiedr-watchdog.exe >nul 2>&1

:: 4. Create Directories
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%DATA_DIR%" mkdir "%DATA_DIR%"

:: 5. Copy Production Executables & Configuration
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
echo [*] Hardening directory permissions (Prevent standard user tampering)...
icacls "%INSTALL_DIR%" /inheritance:r /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)RX" >nul 2>&1
icacls "%DATA_DIR%" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" /grant "Users:(OI)(CI)M" >nul 2>&1

:: 7. Register Windows Service (Automatic Startup on Boot)
echo [*] Registering InsiEDR as an automatic Windows Service...
sc create InsiEDR binPath= "\"%INSTALL_DIR%\insiedr-service.exe\"" start= auto DisplayName= "InsiEDR Endpoint Sensor" depend= Tcpip/EventLog >nul
if %errorlevel% neq 0 (
    echo [-] ERROR: Failed to register Windows Service.
    pause
    exit /b 1
)

:: 8. Configure Automatic Recovery (Restart on crash/kill)
echo [*] Configuring self-healing auto-restart recovery actions...
sc failure InsiEDR reset= 0 actions= restart/3000/restart/3000/restart/5000 >nul

:: 9. Start the Service
echo [*] Starting InsiEDR Sensor Service...
sc start InsiEDR >nul
timeout /t 3 /nobreak >nul

:: 10. Verify Running State
sc query InsiEDR | findstr /i "STATE" | findstr /i "RUNNING" >nul
if %errorlevel% equ 0 (
    echo.
    echo ==========================================================
    echo  [✓] SUCCESS: InsiEDR Sensor is ACTIVE and RUNNING!
    echo ==========================================================
    echo  • Mode:              Silent Windows Service (NT AUTHORITY\SYSTEM)
    echo  • Startup:           Automatic (Runs before Windows login)
    echo  • CPU Limit:         Hardware-capped at 3.00%%
    echo  • Local Spool:       %DATA_DIR%\spool.db
    echo  • Configuration:     %INSTALL_DIR%\agent_config.json
    echo.
    echo Telemetry and Keystroke Biometrics are now streaming to the server.
    echo You can manage and monitor this endpoint from the Web Dashboard.
    echo.
) else (
    echo.
    echo [!] Service registered. Checking status:
    sc query InsiEDR
)

pause
