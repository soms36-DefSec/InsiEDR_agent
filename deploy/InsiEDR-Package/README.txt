========================================================================
InsiEDR Enterprise Windows Native Sensor - Deployment Package v2.0
========================================================================

This package contains everything needed to deploy the InsiEDR Endpoint
Sensor across Windows 10 / Windows 11 machines in the SASTRA University Lab.

FILES IN THIS PACKAGE:
  1. insiedr-service.exe   - Primary Session 0 Windows Service (Rust Native PE)
  2. insiedr-broker.exe    - Session 1 Desktop Helper (User Keystroke Biometrics)
  3. insiedr-watchdog.exe  - Anti-Tamper Supervisor Daemon
  4. agent_config.json     - Configuration file (Server URL, Crypto, Intervals)
  5. install.bat           - One-Click Silent Administrator Installer
  6. uninstall.bat         - Complete Cleanup & Uninstaller
  7. status.bat            - Check Service and Process State
  8. start.bat             - Quick Start Service
  9. stop.bat              - Quick Stop Service

------------------------------------------------------------------------
HOW TO DEPLOY ON A LAB PC:
------------------------------------------------------------------------
Step 1: 'agent_config.json' is ALREADY PRE-CONFIGURED for SASTRA Server:
        "server_url": "http://172.16.22.198"

Step 2: Right-click 'install.bat' and select "Run as administrator".

Step 3: That's it!
        - The service is installed to 'C:\Program Files\InsiEDR\'
        - It starts immediately and runs automatically on every Windows boot.
        - Students / End-users will NOT see any popups or UAC prompts.
        - The PC will immediately appear as ONLINE in the Web Dashboard.

------------------------------------------------------------------------
HOW TO MANAGE FROM THE WEB DASHBOARD:
------------------------------------------------------------------------
Open your browser to: http://172.16.22.198

1. Live Fleet Monitoring:
   - View connected PCs, CPU/RAM utilization, active usernames, and health.

2. Export Keystroke Biometrics & Sensor Logs:
   - Download Excel (.xlsx) or CSV files directly:
     * Keystroke Biometrics:  /api/v1/export/keystrokes.xlsx
     * All Sensor Features:   /api/v1/export/features.xlsx
     * Raw Telemetry Logs:    /api/v1/export/logs.csv

3. Remote Response Actions:
   - Isolate Host:          Cuts off PC network except to SASTRA server.
   - Unisolate Host:        Restores full network connectivity.
   - Kill Process:          Remotely terminates malicious PIDs.
   - Lock Workstation:      Locks student screen to Windows login prompt.
========================================================================
