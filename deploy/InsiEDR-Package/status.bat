@echo off
echo ==========================================================
echo    InsiEDR Endpoint Sensor Status Check
echo ==========================================================
echo.
tasklist /FI "IMAGENAME eq insiedr-service.exe" | findstr /i "insiedr-service.exe" >nul
if %errorlevel% equ 0 (
    echo [✓] InsiEDR Sensor is RUNNING and ACTIVELY COLLECTING!
    echo.
    echo Active Sensor Process:
    tasklist /FI "IMAGENAME eq insiedr*"
) else (
    echo [-] InsiEDR Sensor is NOT running.
    echo [!] Run start.bat or install.bat as administrator to start it.
)
echo.
pause
