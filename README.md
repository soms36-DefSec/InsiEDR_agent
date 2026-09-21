# InsiEDR Agent: Endpoint Telemetry & Threat Sensor

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python)](https://www.python.org)
[![Platform](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20%2F%20Server-0078D6.svg?style=flat&logo=windows)](https://microsoft.com)
[![Cryptography](https://img.shields.io/badge/Encryption-AES--256--GCM%20%2F%20HPKE-critical.svg)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![Packaging](https://img.shields.io/badge/Binary-PyInstaller%20Bundle-orange.svg)](https://pyinstaller.org)
[![Server](https://img.shields.io/badge/Server-InsiEDR%20Central-green.svg)](https://github.com/soms36-DefSec/InsiEDR)

**InsiEDR Agent** is a lightweight, tamper-resistant endpoint telemetry sensor designed for Windows machines. It serves as the front-line collection layer for the [InsiEDR Ecosystem](https://github.com/soms36-DefSec/InsiEDR).

While conventional antivirus agents focus solely on static file signatures and known exploits, the InsiEDR Agent continuously tracks **user behavioral telemetry, authentication anomalies, file-system staging, hardware peripheral insertions, and exfiltration attempts**—encrypting all data at the endpoint before transmission to the central analysis server.

---

## 🏛️ System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Windows Endpoint Host                           │
│                                                                        │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │                 30+ Telemetry Collectors                     │     │
│   │  • Logon & Lateral Movement    • Decoy / Honeytokens         │     │
│   │  • File Staging & USN Journal  • USB & Peripheral Devices    │     │
│   │  • HTTP & Network Outbound     • Process Tree & LSASS Monitor│     │
│   │  • Keystroke Dynamics          • Clipboard & Persistence     │     │
│   └──────────────────────────────┬───────────────────────────────┘     │
│                                  │ Normalized Event Vector             │
│                                  ▼                                     │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │             Local Encrypted Queue (Spooler)                  │     │
│   │   • Resilient SQLite/File Buffering during Network Outages   │     │
│   │   • Automatic Exponential Backoff & Retry Logic              │     │
│   └──────────────────────────────┬───────────────────────────────┘     │
│                                  │                                     │
│                                  ▼                                     │
│   ┌──────────────────────────────────────────────────────────────┐     │
│   │               Cryptographic Envelope Engine                  │     │
│   │   • Client-side AES-256-GCM / HPKE Zero-Trust Encryption     │     │
│   │   • Tamper-proof Payload Integrity & Agent Authentication    │     │
│   └──────────────────────────────┬───────────────────────────────┘     │
└──────────────────────────────────┼─────────────────────────────────────┘
                                   │ HTTPS / Encrypted JSON
                                   ▼
          ┌──────────────────────────────────────────────────┐
          │      InsiEDR Central Server (FastAPI / ASGI)     │
          │   Decryption ──> Multi-Stage ML ──> Dashboard    │
          └──────────────────────────────────────────────────┘
```

---

## 🔍 Telemetry Collectors

The agent includes 30+ specialized collectors grouped into core domains:

| Domain | Collector Module | Description |
| :--- | :--- | :--- |
| **Authentication & Access** | `logon.py` | Monitors Windows Security Event Logs (Events 4624, 4625, 4634, 4672), tracks unique machines accessed, logon spikes, and off-hour activity. |
| **File System & Honeytokens** | `file_feature.py`, `decoy_monitor.py` | Tracks mass file reads/modifications, USN journal changes, and triggers instant alerts upon access to planted honeytoken decoy files. |
| **Hardware & Peripherals** | `devices_feature.py`, `usb_monitor.py` | Inspects USB plug/unplug events, device class IDs, and unauthorized external storage connections. |
| **Network & Exfiltration** | `http_feature.py`, `dns_monitor.py` | Evaluates HTTP upload bursts, connections to known cloud/file-sharing domains, and suspicious DNS requests. |
| **Process & Memory Internals** | `process_watcher.py`, `lsass_monitor.py` | Detects unauthorized process memory access targeting LSASS, anomalous child process trees, and credential harvesting tools. |
| **Behavioral Dynamics** | `keystroke_collector.py`, `clipboard_monitor.py` | Extracts privacy-preserving behavioral cadences (flight/dwell times) and tracks sensitive clipboard copy-paste bursts. |
| **Persistence & System State** | `persistence_monitor.py`, `wmi_activity.py` | Audits Run keys, startup folders, scheduled tasks, and anomalous WMI subscriptions. |

---

## 🛡️ Zero-Trust Security & Resilience

* **End-to-End Encryption**: Every telemetry payload is encrypted on the endpoint using **AES-256-GCM** (or **HPKE**) before leaving memory. The transmission channel operates under zero-trust assumptions.
* **Offline Spooling & Resilient Delivery**: If network connectivity to the central server is interrupted, telemetry is automatically stored in a local encrypted buffer (`LocalEncryptedQueue`). When connectivity is restored, queued payloads are flushed in chronological order with rate limiting and exponential backoff.
* **Privilege Elevation (UAC Aware)**: The agent operates seamlessly in standard user environments and automatically requests administrative privileges (via UAC prompt) only when accessing protected low-level Windows Security Event Logs.

---

## 🚀 Installation & Quick Start

### 1. Prerequisites
* **Operating System**: Windows 10, Windows 11, or Windows Server 2016+
* **Python**: 3.11 or later
* Network connectivity to the InsiEDR Central Server

### 2. Clone & Install Dependencies
```powershell
git clone https://github.com/soms36-DefSec/InsiEDR_agent.git
cd InsiEDR_agent

# Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install required dependencies
pip install -r requirements.txt
```

### 3. Configure the Agent
Copy the example environment configuration:
```powershell
cp .env.example .env
```
Edit `.env` to match your deployment settings:
```ini
# Server endpoint
INSIEDR_AGENT_SERVER=http://192.168.1.100:5000/api/logs

# Shared 32-byte AES-256-GCM encryption key (must match server's INSIEDR_AES_KEY)
INSIEDR_AES_KEY=YOUR_BASE64_OR_HEX_AES_KEY

# Unique Agent Identifier
INSIEDR_AGENT_ID=ENDPOINT-WIN11-SOC01

# Operational Mode
INSIEDR_AGENT_MODE=production
INSIEDR_COLLECTION_INTERVAL_SECONDS=10
```

### 4. Run the Agent

#### Interactive Execution:
```powershell
# Run continuously in the foreground
python main.py

# Run a single collection cycle and exit (useful for health checks)
python main.py --once
```

---

## 📦 Building a Standalone Executable (PyInstaller)

To deploy the agent on machines without Python installed, package it into a self-contained single-file executable:

```powershell
pyinstaller insidedr_agent.spec
```

The resulting standalone executable will be located in the `dist/` directory:
```powershell
.\dist\insidedr_agent.exe
```

---

## ⚙️ Configuration Reference

| Environment Variable | Default | Description |
| :--- | :--- | :--- |
| `INSIEDR_AGENT_SERVER` | `http://127.0.0.1:5000/api/logs` | Target server URL for ingesting telemetry. |
| `INSIEDR_AES_KEY` | *(Required)* | 32-byte encryption key for AES-256-GCM payload encryption. |
| `INSIEDR_AGENT_ID` | `SASTRA-<hostname>` | Unique hostname or hardware identifier for the endpoint. |
| `INSIEDR_AGENT_MODE` | `production` | Operational mode (`production`, `evaluation`, `debug`). |
| `INSIEDR_COLLECTION_INTERVAL_SECONDS` | `10` | Sleep interval between collection cycles. |
| `INSIEDR_ENABLED_COLLECTORS` | *(All standard)* | Comma-delimited list of active collector plugins. |
| `INSIEDR_ALLOW_INSECURE_HTTP` | `false` | Set to `true` if testing against non-HTTPS server endpoints. |
| `INSIEDR_MAX_QUEUE_ITEMS` | `1000` | Maximum number of buffered items in local offline queue. |
| `INSIEDR_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`). |

---

## 🧪 Testing

Run automated unit and integration tests:
```powershell
pytest tests/ -v
```

---

## 🔗 Related Repositories

* **[InsiEDR Central Server](https://github.com/soms36-DefSec/InsiEDR)** — The central FastAPI backend, multi-tier ML engine (Isolation Forest, XGBoost, RedRVFL), and React SOC analyst dashboard.
