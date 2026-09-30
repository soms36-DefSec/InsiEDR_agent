@echo off
echo ==========================================================
echo    InsiEDR Endpoint Sensor Status Check
echo ==========================================================
echo.
sc query InsiEDR
echo.
echo Process Details:
tasklist /FI "IMAGENAME eq insiedr*"
echo.
pause
