@echo off
echo [*] Starting InsiEDR Sensor in background...
tasklist /FI "IMAGENAME eq insiedr-service.exe" | findstr /i "insiedr-service.exe" >nul
if %errorlevel% equ 0 (
    echo [!] InsiEDR Sensor is ALREADY running!
) else (
    powershell -Command "Start-Process -FilePath 'C:\Program Files\InsiEDR\insiedr-service.exe' -WindowStyle Hidden"
    timeout /t 2 /nobreak >nul
    echo [✓] InsiEDR Sensor started successfully in background.
)
pause
