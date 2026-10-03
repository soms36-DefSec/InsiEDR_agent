# InsiEDR Agent: Current Collector Architecture Documentation

> **Status:** Analyzed & Verified against Agent Source Code  
> **Target Version:** InsiEDR Enterprise Agent v2.0.0 (Windows Native Sensor)  
> **Source Directory:** [`d:\Projects\AISH\InsiEDR-agent\src\collectors`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors)  

---

## 1. Architectural Overview

The InsiEDR Agent (`insiedr-agent` v2.0.0) is a native Windows endpoint security sensor implemented in Rust. The agent's collection architecture is designed around strict operational principles:

1. **Non-Invasive Observation & Passive Telemetry:** The main collection loop solely observes, normalizes, and transmits telemetry. It never initiates autonomous system modifications or host isolation without explicit server-downlink commands received via heartbeat tasks.
2. **Resource Governance:** A Windows Job Object CPU rate cap enforces a strict **3.00% maximum CPU utilization** ([`src/core/governor.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/core/governor.rs)).
3. **Dual Acquisition Model (Real-Time ETW + Snapshot Baselines):** High-frequency event streams (Process lifecycles and DNS queries) are captured in real-time using Event Tracing for Windows (ETW) kernel sessions ([`src/etw/`](file:///d:/Projects/AISH/InsiEDR-agent/src/etw/)), with automatic, graceful degradation to Win32 snapshot APIs if ETW is unavailable or unprivileged.
4. **Offline Resilience:** All collected events are processed through an embedded SQLite WAL spooler ([`src/spool/sqlite_spool.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/spool/sqlite_spool.rs)) before cryptographic envelope sealing (AES-256-GCM / HPKE) and transport to `/api/logs`.
5. **Unified Collector Contract:** Every telemetry provider implements the common [`Collector`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/mod.rs) trait:
   ```rust
   pub trait Collector: Send + Sync {
       fn name(&self) -> &'static str;
       fn collect(&self) -> CollectorResult;
   }
   ```

---

## 2. Collector → Features → Data Type (Master Mapping)

| Collector | Feature | Data Type |
|---|---|---|
| `logon` | `logon_count` | Float |
| `logon` | `logoff_count` | Float |
| `logon` | `unique_pc_count` | Float |
| `logon` | `daily_unique_pc_count` | Float |
| `logon` | `after_hours_logon` | Float |
| `logon` | `daily_after_hours_logon_ratio` | Float |
| `logon` | `first_logon_time` | Float |
| `logon` | `last_logoff_time` | Float |
| `logon` | `weekend_logon` | Float |
| `logon` | `daily_pc_access_entropy` | Float |
| `logon` | `successful_logons` | Integer |
| `logon` | `failed_logons` | Integer |
| `logon` | `logon_entropy` | Float |
| `logon` | `session_duration_avg` | Float |
| `logon` | `concurrent_sessions` | Integer |
| `network` | `active_connections_count` | Integer |
| `network` | `connections_sample` | Array of Objects |
| `devices` | `usb_devices_count` | Integer |
| `devices` | `usb_connect_count` | Float |
| `devices` | `usb_disconnect_count` | Float |
| `devices` | `after_hours_usb_usage` | Float |
| `devices` | `daily_device_connect_count` | Float |
| `devices` | `daily_device_usage_flag` | Float |
| `devices` | `first_usb_usage_time` | Float |
| `devices` | `usb_device_names` | Array of Strings |
| `devices` | `unauthorized_usb_detected` | Boolean |
| `http` | `http_count` | Float |
| `http` | `daily_http_request_count` | Float |
| `http` | `unique_url_count` | Float |
| `http` | `suspicious_url_count` | Float |
| `http` | `file_sharing_site_visits` | Float |
| `http` | `job_search_site_visits` | Float |
| `http` | `http_after_hours` | Float |
| `http` | `daily_unique_domain_count` | Float |
| `http` | `daily_new_domain_count` | Float |
| `http` | `daily_domain_access_entropy` | Float |
| `http` | `daily_external_domain_ratio` | Float |
| `http` | `url_access_count` | Integer |
| `http` | `domain_entropy` | Float |
| `http` | `cloud_storage_uploads` | Integer |
| `http` | `watchlisted_domain_hits` | Integer |
| `http` | `external_url_ratio` | Float |
| `http` | `browser_db_found` | Boolean |
| `keystroke-collector` | `keystroke_timings` | Array of Arrays (Float pairs) |
| `keystroke-collector` | `mean_dwell_time_ms` | Float |
| `keystroke-collector` | `std_dwell_time_ms` | Float |
| `keystroke-collector` | `mean_flight_time_ms` | Float |
| `keystroke-collector` | `std_flight_time_ms` | Float |
| `keystroke-collector` | `typing_speed_cpm` | Float |
| `keystroke-collector` | `backspace_ratio` | Float |
| `keystroke-collector` | `total_keys_sampled` | Integer |
| `keystroke-collector` | `dwell_sample_count` | Integer |
| `keystroke-collector` | `flight_sample_count` | Integer |
| `activity-monitor` | `user_idle_seconds` | Float |
| `activity-monitor` | `is_user_active` | Boolean |
| `activity-monitor` | `last_input_tick` | Integer |
| `clipboard-monitor` | `clipboard_sequence` | Integer |
| `clipboard-monitor` | `clipboard_copy_count` | Integer |
| `clipboard-monitor` | `monitor_active` | Boolean |
| `named-pipe-monitor` | `pipe_count` | Integer |
| `named-pipe-monitor` | `named_pipes_sample` | Array of Strings |
| `driver-monitor` | `driver_count` | Integer |
| `driver-monitor` | `running_drivers` | Integer |
| `driver-monitor` | `drivers_sample` | Array of Strings |
| `persistence-monitor` | `total_monitored_keys` | Integer |
| `persistence-monitor` | `entry_count` | Integer |
| `persistence-monitor` | `persistence_entries` | Array of Objects |
| `persistence-monitor` | `modifications_detected` | Boolean |
| `decoy-monitor` | `monitored_decoys` | Array of Strings |
| `decoy-monitor` | `threat_triggered` | Boolean |
| `decoy-monitor` | `events_recorded` | Boolean |
| `decoy-monitor` | `current_size` | Integer |
| `usn-monitor` | `journal_id` | Integer |
| `usn-monitor` | `first_usn` | Integer |
| `usn-monitor` | `next_usn` | Integer |
| `usn-monitor` | `usn_records_captured` | Integer |
| `process-watcher` | `daily_unique_process_count` | Integer |
| `process-watcher` | `executables_from_temp_folder` | Integer |
| `process-watcher` | `admin_process_count` | Integer |
| `process-watcher` | `tunneling_process_count` | Integer |
| `process-watcher` | `process_count` | Integer |
| `process-watcher` | `etw_realtime_active` | Boolean |
| `process-watcher` | `etw_lifecycle_events` | Object |
| `file-integrity-monitor` | `file_access_count` | Float |
| `file-integrity-monitor` | `daily_unique_filename_count` | Float |
| `file-integrity-monitor` | `daily_new_filename_count` | Float |
| `file-integrity-monitor` | `daily_file_access_entropy` | Float |
| `file-integrity-monitor` | `integrity_events` | Array of Objects |
| `file-integrity-monitor` | `event_count` | Integer |
| `file-integrity-monitor` | `monitor_active` | Boolean |
| `short-Term_EDR_Feature` | `edr_auth_event_count_window` | Integer |
| `short-Term_EDR_Feature` | `edr_failed_auth_ratio_window` | Float |
| `short-Term_EDR_Feature` | `edr_auth_events_per_minute_window` | Float |
| `short-Term_EDR_Feature` | `edr_failed_auth_events_per_minute_window` | Float |
| `short-Term_EDR_Feature` | `edr_unique_logon_type_count_window` | Integer |
| `short-Term_EDR_Feature` | `auth_rate_300s` | Float |
| `short-Term_EDR_Feature` | `auth_fail_rate_300s` | Float |
| `short-Term_EDR_Feature` | `auth_rate_3600s` | Float |
| `short-Term_EDR_Feature` | `unique_workstations_300s` | Integer |
| `short-Term_EDR_Feature` | `off_hours_auth_count` | Integer |
| `short-Term_EDR_Feature` | `logon_velocity_zscore` | Float |
| `email-monitor` | `email_clients_installed` | Array of Strings |
| `email-monitor` | `outbound_attachment_count` | Integer |
| `email-monitor` | `external_recipient_ratio` | Float |
| `email-monitor` | `monitor_active` | Boolean |
| `dns-monitor` | `total_queries_captured` | Integer |
| `dns-monitor` | `suspicious_queries_count` | Integer |
| `dns-monitor` | `channel` | String |
| `dns-monitor` | `tunneling_detected` | Boolean |
| `dns-monitor` | `etw_realtime_active` | Boolean |
| `dns-monitor` | `recent_queries` | Array of Objects |
| `lsass-monitor` | `target_process` | String |
| `lsass-monitor` | `event_count` | Integer |
| `lsass-monitor` | `credential_dumping_suspected` | Boolean |
| `wmi-activity` | `channel` | String |
| `wmi-activity` | `total_queries_captured` | Integer |
| `wmi-activity` | `lateral_movement_suspected` | Boolean |
| `memory-scanner` | `target_processes_scanned` | Integer |
| `memory-scanner` | `threats_detected` | Boolean |
| `memory-scanner` | `unbacked_executable_regions` | Integer |
| `memory-scanner` | `reflective_pe_injections` | Integer |
| `memory-scanner` | `phantom_hollowed_mappings` | Integer |
| `memory-scanner` | `sample_threats` | Array of Objects |

---

## 3. Detailed Explanation of Collectors & Features

---

### 1. Collector: `logon`
* **Implementation File:** [`src/collectors/logon.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/logon.rs)
* **Role:** Monitors the Windows Security Event Log (`OpenEventLogW` / `ReadEventLogW`) for Event ID 4624 (Logon Success) and Event ID 4625 (Logon Failure) across a rolling 24-hour lookback. It constructs behavioral baselines of user access hours, weekend operations, unique machine connections, and access dispersion.

#### Example Payload:
```json
{
  "logon_count": 5.0,
  "logoff_count": 5.0,
  "unique_pc_count": 1.0,
  "daily_unique_pc_count": 1.0,
  "after_hours_logon": 0.0,
  "daily_after_hours_logon_ratio": 0.0,
  "first_logon_time": 9.0,
  "last_logoff_time": 17.0,
  "weekend_logon": 0.0,
  "daily_pc_access_entropy": 0.0,
  "successful_logons": 5,
  "failed_logons": 0,
  "logon_entropy": 0.0,
  "session_duration_avg": 3600.0,
  "concurrent_sessions": 1
}
```

#### Feature Details:
* **`logon_count` — Float:** Total successful logon events (EID 4624) observed in the last 24h.
* **`logoff_count` — Float:** Calculated proxy for user logoffs derived from session tracking.
* **`unique_pc_count` — Float:** Count of distinct workstation names parsed from event string inserts. `1.0` indicates local host access; `>1.0` indicates lateral remote access.
* **`daily_unique_pc_count` — Float:** Daily normalized count of distinct machines accessed.
* **`after_hours_logon` — Float:** Total logons occurring outside 07:00–19:00 local time.
* **`daily_after_hours_logon_ratio` — Float:** Ratio of after-hours logons to total logons (`after_hours / logon_count`).
* **`first_logon_time` — Float:** Earliest logon hour of the day (0–23).
* **`last_logoff_time` — Float:** Latest session activity hour of the day (0–23).
* **`weekend_logon` — Float:** Number of successful logons occurring on Saturday or Sunday.
* **`daily_pc_access_entropy` — Float:** Shannon entropy representing how spread out user logins are across multiple host workstations. `0.0` represents a single machine.
* **`successful_logons` — Integer:** Raw count of EID 4624 events in the current scan.
* **`failed_logons` — Integer:** Raw count of EID 4625 events. High counts indicate brute-force or spraying.
* **`logon_entropy` — Float:** Shannon entropy of authentication distribution.
* **`session_duration_avg` — Float:** Average session duration estimate in seconds.
* **`concurrent_sessions` — Integer:** Number of simultaneous active interactive sessions.

---

### 2. Collector: `network`
* **Implementation File:** [`src/collectors/network.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/network.rs)
* **Role:** Queries active IPv4 TCP sockets directly via Windows IP Helper API (`GetExtendedTcpTable`), correlating endpoints to the owning Process ID (PID) without injecting or hooking network packets.

#### Example Payload:
```json
{
  "active_connections_count": 2,
  "connections_sample": [
    {
      "local_addr": "192.168.1.50:49712",
      "remote_addr": "172.16.22.198:80",
      "pid": 4120,
      "state": 5
    }
  ]
}
```

#### Feature Details:
* **`active_connections_count` — Integer:** Total number of active TCP sockets in the system table.
* **`connections_sample` — Array of Objects:** Up to 100 sample TCP connection descriptors:
  * `local_addr` (String): Source IP and port.
  * `remote_addr` (String): Destination peer IP and port.
  * `pid` (Integer): Process ID of the owning process.
  * `state` (Integer): TCP state code (`2` = SYN_SENT, `5` = ESTABLISHED, `12` = TIME_WAIT).

---

### 3. Collector: `devices`
* **Implementation File:** [`src/collectors/usb_devices.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/usb_devices.rs)
* **Role:** Enumerates external hardware and USB Mass Storage devices from `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` via the Windows Registry API to catch physical exfiltration and unapproved removable drives.

#### Example Payload:
```json
{
  "usb_devices_count": 1,
  "usb_connect_count": 1.0,
  "usb_disconnect_count": 0.0,
  "after_hours_usb_usage": 0.0,
  "daily_device_connect_count": 1.0,
  "daily_device_usage_flag": 1.0,
  "first_usb_usage_time": 0.0,
  "usb_device_names": ["Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00"],
  "unauthorized_usb_detected": false
}
```

#### Feature Details:
* **`usb_devices_count` — Integer:** Number of distinct USB storage devices registered in the registry.
* **`usb_connect_count` — Float:** Connection events count (reflecting discovered devices).
* **`usb_disconnect_count` — Float:** Disconnection events count.
* **`after_hours_usb_usage` — Float:** Off-hours USB connection indicator.
* **`daily_device_connect_count` — Float:** Aggregated daily count of USB device mounts.
* **`daily_device_usage_flag` — Float:** `1.0` if any USB storage device is active, `0.0` otherwise.
* **`first_usb_usage_time` — Float:** Timestamp or hour of the earliest USB connection.
* **`usb_device_names` — Array of Strings:** Full hardware ID strings of enumerated drives.
* **`unauthorized_usb_detected` — Boolean:** Heuristic alert flag for non-allowlisted devices.

---

### 4. Collector: `http`
* **Implementation File:** [`src/collectors/browser_history.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/browser_history.rs)
* **Role:** Queries local SQLite history databases of Chrome, Edge, and Brave browsers via read-only temp snapshots. Analyzes web traffic over the past 24 hours for file-sharing uploads, job portals, high-risk TLDs, and domain entropy.

#### Example Payload:
```json
{
  "http_count": 12.0,
  "daily_http_request_count": 12.0,
  "unique_url_count": 8.0,
  "suspicious_url_count": 0.0,
  "file_sharing_site_visits": 0.0,
  "job_search_site_visits": 0.0,
  "http_after_hours": 0.0,
  "daily_unique_domain_count": 4.0,
  "daily_new_domain_count": 0.0,
  "daily_domain_access_entropy": 1.352,
  "daily_external_domain_ratio": 1.0,
  "url_access_count": 12,
  "domain_entropy": 1.352,
  "cloud_storage_uploads": 0,
  "watchlisted_domain_hits": 0,
  "external_url_ratio": 1.0,
  "browser_db_found": true
}
```

#### Feature Details:
* **`http_count` — Float:** Total URL visits in the last 24h.
* **`daily_http_request_count` — Float:** 24h total request volume.
* **`unique_url_count` — Float:** Distinct URL count visited.
* **`suspicious_url_count` — Float:** Visits matching high-risk TLDs (`.ru`, `.cn`, `.tk`, `.xyz`, `.top`, `.pw`).
* **`file_sharing_site_visits` — Float:** Visits to file-sharing/cloud sites (`drive.google`, `dropbox`, `mega.nz`, etc.).
* **`job_search_site_visits` — Float:** Visits to employment sites (`linkedin`, `indeed`, `glassdoor`, etc.).
* **`http_after_hours` — Float:** Web requests during non-business hours.
* **`daily_unique_domain_count` — Float:** Distinct root domains contacted.
* **`daily_new_domain_count` — Float:** First-time observed domains.
* **`daily_domain_access_entropy` — Float:** Shannon entropy over visited domains.
* **`daily_external_domain_ratio` — Float:** Ratio of non-RFC1918 / external internet domains.
* **`url_access_count` — Integer:** Raw integer count of URLs visited.
* **`domain_entropy` — Float:** Domain diversity score.
* **`cloud_storage_uploads` — Integer:** Detected cloud storage uploads.
* **`watchlisted_domain_hits` — Integer:** Matches against watchlisted indicators.
* **`external_url_ratio` — Float:** External domain fraction.
* **`browser_db_found` — Boolean:** `true` if a browser history SQLite DB was found and read.

---

### 5. Collector: `keystroke-collector`
* **Implementation File:** [`src/collectors/keystroke_biometrics.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/keystroke_biometrics.rs)
* **Role:** Captures privacy-preserving keystroke dynamic intervals using a global hook (`WH_KEYBOARD_LL`). **Only timing intervals (dwell and flight times) are measured; no characters or text are ever logged**. Used to detect account sharing or unauthorized physical workstation access.

#### Example Payload:
```json
{
  "keystroke_timings": [[92.45, 120.32], [85.12, 115.80]],
  "mean_dwell_time_ms": 88.79,
  "std_dwell_time_ms": 12.34,
  "mean_flight_time_ms": 118.06,
  "std_flight_time_ms": 18.45,
  "typing_speed_cpm": 320.5,
  "backspace_ratio": 0.045,
  "total_keys_sampled": 150,
  "dwell_sample_count": 150,
  "flight_sample_count": 149
}
```

#### Feature Details:
* **`keystroke_timings` — Array of Arrays (Float pairs):** Up to 20 recent pairs of `[dwell_time_ms, flight_time_ms]`.
* **`mean_dwell_time_ms` — Float:** Average duration keys are held down before release.
* **`std_dwell_time_ms` — Float:** Standard deviation of key press duration.
* **`mean_flight_time_ms` — Float:** Average time gap between releasing one key and pressing the next.
* **`std_flight_time_ms` — Float:** Standard deviation of inter-key latency.
* **`typing_speed_cpm` — Float:** Estimated typing speed in characters per minute (`60,000 / mean_flight_time_ms`).
* **`backspace_ratio` — Float:** Backspace events divided by total keystrokes (`backspaces / total_keys`).
* **`total_keys_sampled` — Integer:** Total raw keystroke events intercepted.
* **`dwell_sample_count` — Integer:** Valid key-down to key-up hold intervals.
* **`flight_sample_count` — Integer:** Valid key-release to key-press gap intervals.

---

### 6. Collector: `activity-monitor`
* **Implementation File:** [`src/collectors/activity.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/activity.rs)
* **Role:** Uses `GetLastInputInfo` and `GetTickCount64` to calculate human physical presence vs. unattended system idle periods.

#### Example Payload:
```json
{
  "user_idle_seconds": 12.45,
  "is_user_active": true,
  "last_input_tick": 4582910
}
```

#### Feature Details:
* **`user_idle_seconds` — Float:** Seconds elapsed since the last mouse or keyboard input.
* **`is_user_active` — Boolean:** `true` if input occurred within the last 300 seconds; `false` if idle.
* **`last_input_tick` — Integer:** Windows tick count in milliseconds of the last registered input.

---

### 7. Collector: `clipboard-monitor`
* **Implementation File:** [`src/collectors/clipboard.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/clipboard.rs)
* **Role:** Observes changes in `GetClipboardSequenceNumber` to measure copy/cut operation velocity without reading or exposing copied data.

#### Example Payload:
```json
{
  "clipboard_sequence": 142,
  "clipboard_copy_count": 1,
  "monitor_active": true
}
```

#### Feature Details:
* **`clipboard_sequence` — Integer:** Monotonically increasing OS sequence number incremented on every clipboard write.
* **`clipboard_copy_count` — Integer:** Number of clipboard copy/cut operations executed since the prior cycle.
* **`monitor_active` — Boolean:** `true` when clipboard monitoring is active.

---

### 8. Collector: `named-pipe-monitor`
* **Implementation File:** [`src/collectors/named_pipe.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/named_pipe.rs)
* **Role:** Enumerates `\\.\pipe\*` using `FindFirstFileW` / `FindNextFileW`. Tracks active IPC channels commonly used by post-exploitation frameworks (Cobalt Strike, PsExec) for lateral execution.

#### Example Payload:
```json
{
  "pipe_count": 35,
  "named_pipes_sample": [
    "InsiEDR-Telemetry-IPC",
    "crashpad_1234_ABCDE",
    "spoolss",
    "epmapper"
  ]
}
```

#### Feature Details:
* **`pipe_count` — Integer:** Total named pipes discovered.
* **`named_pipes_sample` — Array of Strings:** Sample list of up to 50 active pipe names.

---

### 9. Collector: `driver-monitor`
* **Implementation File:** [`src/collectors/driver_monitor.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/driver_monitor.rs)
* **Role:** Enumerates all loaded kernel modules via `EnumDeviceDrivers` and `GetDeviceDriverBaseNameW` to spot Bring Your Own Vulnerable Driver (BYOVD) exploits and rootkits.

#### Example Payload:
```json
{
  "driver_count": 182,
  "running_drivers": 182,
  "drivers_sample": [
    "ntoskrnl.exe",
    "hal.dll",
    "fltmgr.sys",
    "tcpip.sys"
  ]
}
```

#### Feature Details:
* **`driver_count` — Integer:** Total number of drivers loaded in kernel memory.
* **`running_drivers` — Integer:** Number of active device drivers verified.
* **`drivers_sample` — Array of Strings:** Sample list of up to 50 driver base filenames.

---

### 10. Collector: `persistence-monitor`
* **Implementation File:** [`src/collectors/persistence.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/persistence.rs)
* **Role:** Audits Windows startup registry Run and RunOnce keys (`HKLM` and `HKCU`) using `RegEnumValueW` for newly installed persistence entries.

#### Example Payload:
```json
{
  "total_monitored_keys": 4,
  "entry_count": 4,
  "persistence_entries": [
    {
      "path": "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "name": "SecurityHealth",
      "command": "%windir%\\system32\\SecurityHealthSystray.exe"
    }
  ],
  "modifications_detected": false
}
```

#### Feature Details:
* **`total_monitored_keys` — Integer:** Total count of persistence entries found.
* **`entry_count` — Integer:** Current count of startup items.
* **`persistence_entries` — Array of Objects:** Objects detailing:
  * `path` (String): Registry hive path.
  * `name` (String): Registry value name.
  * `command` (String): Target executable or command-line string.
* **`modifications_detected` — Boolean:** `true` if unauthorized alterations were detected.

---

### 11. Collector: `decoy-monitor`
* **Implementation File:** [`src/collectors/decoy.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/decoy.rs)
* **Role:** Deploys and monitors a canary honeypot file at `C:\Users\Public\Admin_Passwords.xlsx`. Verifies byte integrity to detect unauthorized access, tampering, or ransomware encryption.

#### Example Payload:
```json
{
  "monitored_decoys": [
    "C:\\Users\\Public\\Admin_Passwords.xlsx"
  ],
  "threat_triggered": false,
  "events_recorded": false,
  "current_size": 36
}
```

#### Feature Details:
* **`monitored_decoys` — Array of Strings:** List of decoy file paths monitored.
* **`threat_triggered` — Boolean:** `true` if the canary file bytes are modified, truncated, or locked by an active encryptor.
* **`events_recorded` — Boolean:** Canary breach recorded flag.
* **`current_size` — Integer:** File size in bytes.

---

### 12. Collector: `usn-monitor`
* **Implementation File:** [`src/collectors/usn.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/usn.rs)
* **Role:** Queries the NTFS Change Journal (`FSCTL_QUERY_USN_JOURNAL`) on the system volume to detect high-rate file modification activities typical of wipers and ransomware.

#### Example Payload:
```json
{
  "journal_id": 576460752303423488,
  "first_usn": 1048576,
  "next_usn": 52428800,
  "usn_records_captured": 0
}
```

#### Feature Details:
* **`journal_id` — Integer:** 64-bit unique identifier for the NTFS USN Journal.
* **`first_usn` — Integer:** First valid 64-bit USN offset.
* **`next_usn` — Integer:** Next 64-bit USN record write pointer.
* **`usn_records_captured` — Integer:** Detailed change entries captured.

---

### 13. Collector: `process-watcher`
* **Implementation File:** [`src/collectors/process_watcher.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/process_watcher.rs)
* **Role:** Uses real-time kernel ETW (`Microsoft-Windows-Kernel-Process`) with fallback to `CreateToolhelp32Snapshot` to track process executions, specifically flagging binaries run from temporary folders, tunneling utilities, and elevated sessions.

#### Example Payload:
```json
{
  "daily_unique_process_count": 142,
  "executables_from_temp_folder": 0,
  "admin_process_count": 28,
  "tunneling_process_count": 0,
  "process_count": 142,
  "etw_realtime_active": true,
  "etw_lifecycle_events": {
    "started_count": 4,
    "stopped_count": 2,
    "image_loads_count": 35
  }
}
```

#### Feature Details:
* **`daily_unique_process_count` — Integer:** Number of distinct process image names active.
* **`executables_from_temp_folder` — Integer:** Binaries launched from `\temp\` or `\tmp\`.
* **`admin_process_count` — Integer:** Processes running under Administrator or LocalSystem SIDs.
* **`tunneling_process_count` — Integer:** Reverse proxy / tunneling processes (`ngrok`, `chisel`, `ssh`, etc.).
* **`process_count` — Integer:** Total running processes enumerated.
* **`etw_realtime_active` — Boolean:** `true` if ETW kernel feed is actively streaming events.
* **`etw_lifecycle_events` — Object:** Contains `started_count`, `stopped_count`, and `image_loads_count`.

---

### 14. Collector: `file-integrity-monitor`
* **Implementation File:** [`src/collectors/file_integrity.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/file_integrity.rs)
* **Role:** Computes SHA-256 hashes of critical operating system files (`hosts` file) and user document directories to detect unauthorized alterations.

#### Example Payload:
```json
{
  "file_access_count": 6.0,
  "daily_unique_filename_count": 6.0,
  "daily_new_filename_count": 0.0,
  "daily_file_access_entropy": 0.0,
  "integrity_events": [
    {
      "path": "C:\\Windows\\System32\\drivers\\etc\\hosts",
      "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "target_type": "critical_system_file",
      "op": "AUDIT"
    }
  ],
  "event_count": 6,
  "monitor_active": true
}
```

#### Feature Details:
* **`file_access_count` — Float:** Total audited files.
* **`daily_unique_filename_count` — Float:** Distinct filenames audited.
* **`daily_new_filename_count` — Float:** New filenames detected.
* **`daily_file_access_entropy` — Float:** Access distribution entropy.
* **`integrity_events` — Array of Objects:** Objects containing `path`, `sha256`, `target_type`, and `op`.
* **`event_count` — Integer:** Total integrity events.
* **`monitor_active` — Boolean:** `true` when file integrity audits are operational.

---

### 15. Collector: `short-Term_EDR_Feature`
* **Implementation File:** [`src/collectors/short_term_edr.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/short_term_edr.rs)
* **Role:** Evaluates sliding-window authentication velocity across 300s (5-minute) and 3600s (1-hour) windows to detect rapid brute-force attacks and password-spraying bursts.

#### Example Payload:
```json
{
  "edr_auth_event_count_window": 1,
  "edr_failed_auth_ratio_window": 0.0,
  "edr_auth_events_per_minute_window": 0.2,
  "edr_failed_auth_events_per_minute_window": 0.0,
  "edr_unique_logon_type_count_window": 1,
  "auth_rate_300s": 0.2,
  "auth_fail_rate_300s": 0.0,
  "auth_rate_3600s": 0.05,
  "unique_workstations_300s": 1,
  "off_hours_auth_count": 0,
  "logon_velocity_zscore": 1.5
}
```

#### Feature Details:
* **`edr_auth_event_count_window` — Integer:** Successful logons in the last 300 seconds.
* **`edr_failed_auth_ratio_window` — Float:** Ratio of failed authentications over 300s.
* **`edr_auth_events_per_minute_window` — Float:** Logon rate per minute (300s window).
* **`edr_failed_auth_events_per_minute_window` — Float:** Failed logon rate per minute (300s window).
* **`edr_unique_logon_type_count_window` — Integer:** Unique workstation/logon IDs in 300s window.
* **`auth_rate_300s` — Float:** 5-minute authentication rate.
* **`auth_fail_rate_300s` — Float:** 5-minute failure rate.
* **`auth_rate_3600s` — Float:** 1-hour authentication baseline rate.
* **`unique_workstations_300s` — Integer:** Distinct workstations in 300s window.
* **`off_hours_auth_count` — Integer:** Off-hours logons in window.
* **`logon_velocity_zscore` — Float:** Statistical Z-score deviation above baseline authentication velocity.

---

### 16. Collector: `email-monitor`
* **Implementation File:** [`src/collectors/email.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/email.rs)
* **Role:** Audits installed email clients (Outlook, Thunderbird) and monitors for outbound attachment exfiltration vectors.

#### Example Payload:
```json
{
  "email_clients_installed": ["Outlook"],
  "outbound_attachment_count": 0,
  "external_recipient_ratio": 0.0,
  "monitor_active": true
}
```

#### Feature Details:
* **`email_clients_installed` — Array of Strings:** Discovered email client software.
* **`outbound_attachment_count` — Integer:** Number of outbound email attachments.
* **`external_recipient_ratio` — Float:** Proportion of external recipients vs. internal recipients.
* **`monitor_active` — Boolean:** `true` indicating the email sensor is active.

---

### 17. Collector: `dns-monitor`
* **Implementation File:** [`src/collectors/dns.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/dns.rs)
* **Role:** Captures live DNS queries via the `Microsoft-Windows-DNS-Client` ETW provider to identify reverse-tunneling services, suspicious TLDs, and C2 beacons.

#### Example Payload:
```json
{
  "total_queries_captured": 14,
  "suspicious_queries_count": 0,
  "channel": "Microsoft-Windows-DNS-Client (Real-Time ETW)",
  "tunneling_detected": false,
  "etw_realtime_active": true,
  "recent_queries": [
    {
      "name": "api.github.com",
      "type": 1,
      "results": "140.82.121.4",
      "status": 0,
      "pid": 3216,
      "suspicious": false
    }
  ]
}
```

#### Feature Details:
* **`total_queries_captured` — Integer:** Total DNS queries captured in the interval.
* **`suspicious_queries_count` — Integer:** Queries matching suspicious TLDs or tunneling keywords.
* **`channel` — String:** Event channel name description.
* **`tunneling_detected` — Boolean:** `true` if any domain matches reverse-proxy tunneling domains (`ngrok.io`, `localtunnel.me`, `duckdns.org`, etc.).
* **`etw_realtime_active` — Boolean:** `true` when the real-time ETW stream is connected.
* **`recent_queries` — Array of Objects:** Sample list of up to 50 queries (`name`, `type`, `results`, `status`, `pid`, `suspicious`).

---

### 18. Collector: `lsass-monitor`
* **Implementation File:** [`src/collectors/lsass.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/lsass.rs)
* **Role:** Audits process handles opened to `lsass.exe` to intercept credential dumping attacks (Mimikatz, procdump, Comsvcs.dll).

#### Example Payload:
```json
{
  "target_process": "lsass.exe",
  "event_count": 0,
  "credential_dumping_suspected": false
}
```

#### Feature Details:
* **`target_process` — String:** Target executable monitored (`"lsass.exe"`).
* **`event_count` — Integer:** Count of suspicious handle access events opened against LSASS.
* **`credential_dumping_suspected` — Boolean:** `true` if unauthorized read/query handles were opened against LSASS memory.

---

### 19. Collector: `wmi-activity`
* **Implementation File:** [`src/collectors/wmi_activity.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/wmi_activity.rs)
* **Role:** Audits Windows Management Instrumentation activity via `Microsoft-Windows-WMI-Activity/Operational` to identify stealthy WMI persistence and lateral execution.

#### Example Payload:
```json
{
  "channel": "Microsoft-Windows-WMI-Activity/Operational",
  "total_queries_captured": 0,
  "lateral_movement_suspected": false
}
```

#### Feature Details:
* **`channel` — String:** Operational log channel audited.
* **`total_queries_captured` — Integer:** Count of WMI queries captured in this cycle.
* **`lateral_movement_suspected` — Boolean:** `true` if remote WMI execution patterns are detected.

---

### 20. Collector: `memory-scanner`
* **Implementation File:** [`src/collectors/memory_scanner.rs`](file:///d:/Projects/AISH/InsiEDR-agent/src/collectors/memory_scanner.rs)
* **Role:** Conducts deep virtual memory inspections across high-risk processes (`powershell`, `cmd`, `rundll32`, `svchost`, etc.) via `VirtualQueryEx` and `ReadProcessMemory`. Detects reflective DLL injection (unbacked MZ headers), RWX shellcode allocations, and hollowed process mappings.

#### Example Payload:
```json
{
  "target_processes_scanned": 15,
  "threats_detected": false,
  "unbacked_executable_regions": 0,
  "reflective_pe_injections": 0,
  "phantom_hollowed_mappings": 0,
  "sample_threats": []
}
```

#### Feature Details:
* **`target_processes_scanned` — Integer:** Count of high-risk processes scanned during this cycle (capped at 25).
* **`threats_detected` — Boolean:** `true` if any in-memory threat was discovered; `false` when clean.
* **`unbacked_executable_regions` — Integer:** Count of executable private memory regions without backing files on disk.
* **`reflective_pe_injections` — Integer:** Count of unbacked executable memory regions containing an MZ DOS header.
* **`phantom_hollowed_mappings` — Integer:** Count of hollowed `MEM_IMAGE` sections missing valid mapped files.
* **`sample_threats` — Array of Objects:** Array of up to 10 detected threat objects (`pid`, `process_name`, `base_address`, `region_size`, `threat_type`, `details`).
