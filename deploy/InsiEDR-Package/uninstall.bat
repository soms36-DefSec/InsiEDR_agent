@echo off
setlocal

echo ==========================================================
echo    InsiEDR Enterprise Windows Native Sensor Uninstaller
echo ==========================================================
echo.

:: 1. Verify Administrative Privileges
echo [*] Checking Administrator Privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [-] ERROR: Administrator privileges required!
    echo [!] Right-click uninstall.bat and select "Run as administrator".
    echo.
    pause
    exit /b 1
)

echo [*] Stopping running sensor processes...
taskkill /F /IM insiedr-service.exe >nul 2>&1
taskkill /F /IM insiedr-broker.exe >nul 2>&1
taskkill /F /IM insiedr-watchdog.exe >nul 2>&1

echo [*] Removing auto-start entries...
schtasks /delete /tn "InsiEDR" /f >nul 2>&1
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v "InsiEDR" /f >nul 2>&1
sc delete InsiEDR >nul 2>&1

echo [*] Cleaning installation binaries...
if exist "C:\Program Files\InsiEDR" (
    rmdir /S /Q "C:\Program Files\InsiEDR"
)

echo [?] Do you also want to remove local offline spooled logs (C:\ProgramData\InsiEDR)?
set /p REMOVE_DATA="Remove spooled data? (Y/N, default Y): "
if /i "%REMOVE_DATA%" neq "N" (
    if exist "C:\ProgramData\InsiEDR" rmdir /S /Q "C:\ProgramData\InsiEDR"
    echo [*] Removed local spool data directory.
)

echo.
echo [✓] SUCCESS: InsiEDR Agent has been completely uninstalled.
echo.
pause
