@echo off
echo [*] Stopping InsiEDR Sensor...
taskkill /F /IM insiedr-service.exe >nul 2>&1
taskkill /F /IM insiedr-broker.exe >nul 2>&1
taskkill /F /IM insiedr-watchdog.exe >nul 2>&1
echo [✓] InsiEDR Sensor stopped.
pause
