from __future__ import annotations

import json
import logging
import os
import platform
import socket
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any

from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("devices_feature")


IS_WINDOWS = platform.system() == "Windows"
if IS_WINDOWS:
    try:
        import win32evtlog
        import winreg
    except ImportError:
        IS_WINDOWS = False


BUSINESS_HOURS = (time(9, 0), time(18, 0))
LARGE_USB_THRESHOLD_MB = 100
USB_CONNECT_EVENT_IDS = {2003, 2004}
USB_DISCONNECT_EVENT_IDS = {2100, 2102}
USB_MODERN_CHANNELS = (
    "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
)


@dataclass
class UsbEvent:
    event_id: int
    timestamp: datetime
    device_id: str
    lifetime_id: str | None = None
    bytes_written: int = 0


def _allow_synthetic_data() -> bool:
    return os.getenv("INSIEDR_ALLOW_SYNTHETIC_COLLECTOR_DATA") == "1"


def _is_access_denied(exc: BaseException) -> bool:
    code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
    if code in {5, 1314}:
        return True
    text = str(exc).lower()
    return "access is denied" in text or "privilege" in text


def _pywintypes_to_local_naive(pywints_dt: Any) -> datetime:
    return pywints_dt.astimezone().replace(tzinfo=None)


def _query_event_log(channel: str, event_ids: set[int], hours_back: int = 24) -> list[UsbEvent]:
    events: list[UsbEvent] = []
    if not IS_WINDOWS:
        return events

    handle = None
    try:
        handle = win32evtlog.OpenEventLog(None, channel)
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        cutoff = datetime.now() - timedelta(hours=hours_back)
        while True:
            batch = win32evtlog.ReadEventLog(handle, flags, 0)
            if not batch:
                break
            for event in batch:
                event_id = event.EventID & 0xFFFF
                if event_id not in event_ids:
                    continue
                timestamp = _pywintypes_to_local_naive(event.TimeGenerated)
                if timestamp < cutoff:
                    return events
                inserts = event.StringInserts or []
                events.append(
                    UsbEvent(
                        event_id=event_id,
                        timestamp=timestamp,
                        device_id=inserts[0] if inserts else "unknown",
                        lifetime_id=inserts[1] if len(inserts) > 1 else None,
                    )
                )
    except Exception as exc:
        if _is_access_denied(exc):
            log.warning("USB event log channel is not readable by this account: %s", channel)
        else:
            log.info("USB event log channel unavailable: %s", channel)
    finally:
        if handle is not None:
            try:
                win32evtlog.CloseEventLog(handle)
            except Exception:
                pass
    return events


def _parse_usb_event_xml(xml_text: str, event_ids: set[int]) -> UsbEvent | None:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    event_id_text = root.findtext("./e:System/e:EventID", namespaces=namespace)
    if not event_id_text:
        return None
    event_id = int(event_id_text)
    if event_id not in event_ids:
        return None

    time_node = root.find("./e:System/e:TimeCreated", namespaces=namespace)
    timestamp_text = time_node.attrib.get("SystemTime", "") if time_node is not None else ""
    try:
        timestamp = datetime.fromisoformat(timestamp_text.replace("Z", "+00:00")).astimezone().replace(tzinfo=None)
    except ValueError:
        timestamp = datetime.now()

    values = [
        str(node.text or "")
        for node in root.findall("./e:EventData/e:Data", namespaces=namespace)
        if str(node.text or "")
    ]
    device_id = next(
        (value for value in values if "USB" in value.upper() or "VID_" in value.upper()),
        values[0] if values else "unknown",
    )
    lifetime_id = next((value for value in values if value != device_id), None)
    return UsbEvent(event_id=event_id, timestamp=timestamp, device_id=device_id, lifetime_id=lifetime_id)


def _query_modern_event_channel(channel: str, event_ids: set[int], hours_back: int = 24) -> list[UsbEvent]:
    events: list[UsbEvent] = []
    if not IS_WINDOWS or not hasattr(win32evtlog, "EvtQuery"):
        return events

    cutoff = datetime.now() - timedelta(hours=hours_back)
    query = "*[System[{}]]".format(" or ".join(f"EventID={event_id}" for event_id in sorted(event_ids)))
    handle = None
    try:
        handle = win32evtlog.EvtQuery(channel, win32evtlog.EvtQueryReverseDirection, query)
        while True:
            batch = win32evtlog.EvtNext(handle, 32)
            if not batch:
                break
            for event_handle in batch:
                try:
                    event = _parse_usb_event_xml(
                        win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml),
                        event_ids,
                    )
                    if event is None:
                        continue
                    if event.timestamp < cutoff:
                        return events
                    events.append(event)
                finally:
                    if hasattr(win32evtlog, "EvtClose"):
                        win32evtlog.EvtClose(event_handle)
    except Exception as exc:
        if _is_access_denied(exc):
            log.warning("USB event channel is not readable by this account: %s", channel)
        else:
            log.info("USB event channel unavailable: %s", channel)
    finally:
        if handle is not None and hasattr(win32evtlog, "EvtClose"):
            win32evtlog.EvtClose(handle)
    return events


def _dedupe_usb_events(events: list[UsbEvent]) -> list[UsbEvent]:
    unique: dict[tuple[int, str, str, str | None], UsbEvent] = {}
    for event in events:
        key = (event.event_id, event.timestamp.isoformat(), event.device_id, event.lifetime_id)
        unique[key] = event
    return list(unique.values())


def _enumerate_usbstor_registry() -> list[str]:
    devices: list[str] = []
    if not IS_WINDOWS:
        return devices
    try:
        key_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as root:
            class_idx = 0
            while True:
                try:
                    class_name = winreg.EnumKey(root, class_idx)
                    class_idx += 1
                except OSError:
                    break
                try:
                    class_key_path = key_path + "\\" + class_name
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, class_key_path) as class_key:
                        serial_idx = 0
                        while True:
                            try:
                                devices.append(winreg.EnumKey(class_key, serial_idx))
                                serial_idx += 1
                            except OSError:
                                break
                except Exception as exc:
                    log.info("USBSTOR sub-key unavailable: %s", exc)
    except FileNotFoundError:
        pass
    except Exception as exc:
        log.info("USBSTOR enumeration failed: %s", exc)
    return devices


def _get_removable_bytes_written() -> dict[str, int]:
    if not IS_WINDOWS:
        return {}
    
    try:
        import win32com.client
        wmi = win32com.client.Dispatch("WbemScripting.SWbemLocator").ConnectServer(".", "root\\cimv2")
        
        # DriveType=2 means Removable Disk
        disks = wmi.ExecQuery("SELECT DeviceID FROM Win32_LogicalDisk WHERE DriveType=2")
        removable_ids = {d.DeviceID for d in disks}
        
        if not removable_ids:
            return {}
            
        perf = wmi.ExecQuery("SELECT Name, DiskWriteBytesPersec FROM Win32_PerfRawData_PerfDisk_LogicalDisk")
        return {p.Name: int(p.DiskWriteBytesPersec) for p in perf if p.Name in removable_ids}
    except Exception as exc:
        log.debug("Failed to query removable bytes written: %s", exc)
        return {}


def _update_exfiltration_state(current_bytes: dict[str, int]) -> int:
    state_file = default_state_dir() / "usb_exfiltration_state.json"
    today = datetime.now(timezone.utc).date().isoformat()
    
    state = {}
    try:
        if state_file.exists():
            state = read_json_file(state_file)
    except Exception:
        pass

    if state.get("date") != today:
        state["date"] = today
        state["daily_total"] = 0
        state["last_counters"] = {}

    last_counters = state.setdefault("last_counters", {})
    daily_total = state.get("daily_total", 0)

    for drive, bytes_written in current_bytes.items():
        if drive in last_counters:
            delta = bytes_written - last_counters[drive]
            if delta > 0:
                daily_total += delta
            elif delta < 0:
                daily_total += bytes_written
        last_counters[drive] = bytes_written

    state["daily_total"] = daily_total

    try:
        write_json_file(state_file, state)
    except Exception as exc:
        log.warning("Failed to save USB exfiltration state: %s", exc)

    return daily_total


def _synthetic_raw_telemetry() -> dict[str, Any]:
    now = datetime.now()
    return {
        "connects": [
            UsbEvent(2003, now.replace(hour=10, minute=15), "USB\\VID_0781&PID_5567", "LT1"),
            UsbEvent(2003, now.replace(hour=20, minute=42), "USB\\VID_0951&PID_1666", "LT2"),
        ],
        "disconnects": [
            UsbEvent(2102, now.replace(hour=10, minute=55), "USB\\VID_0781&PID_5567", "LT1"),
            UsbEvent(2102, now.replace(hour=21, minute=10), "USB\\VID_0951&PID_1666", "LT2"),
        ],
        "registry_devices": ["08011B501A1CA932", "001EABE4A1B2C3D4"],
        "daily_removable_bytes_written": 150000000,
        "synthetic_data": True,
    }


def collect_raw_usb_telemetry() -> dict[str, Any]:
    connects = _query_event_log("System", USB_CONNECT_EVENT_IDS)
    disconnects = _query_event_log("System", USB_DISCONNECT_EVENT_IDS)
    for channel in USB_MODERN_CHANNELS:
        modern_events = _query_modern_event_channel(channel, USB_CONNECT_EVENT_IDS | USB_DISCONNECT_EVENT_IDS)
        connects.extend(event for event in modern_events if event.event_id in USB_CONNECT_EVENT_IDS)
        disconnects.extend(event for event in modern_events if event.event_id in USB_DISCONNECT_EVENT_IDS)
    connects += _query_event_log("Security", {6416})

    connects = _dedupe_usb_events(connects)
    disconnects = _dedupe_usb_events(disconnects)
    registry_devices = _enumerate_usbstor_registry()
    
    current_bytes = _get_removable_bytes_written()
    daily_bytes = _update_exfiltration_state(current_bytes)

    if not IS_WINDOWS and not connects and not _allow_synthetic_data():
        return {
            "connects": [],
            "disconnects": [],
            "registry_devices": [],
            "daily_removable_bytes_written": 0,
            "synthetic_disabled": True,
            "unsupported_reason": "synthetic USB collector data is disabled",
        }
    if not IS_WINDOWS and not connects and _allow_synthetic_data():
        return _synthetic_raw_telemetry()

    return {
        "connects": connects,
        "disconnects": disconnects,
        "registry_devices": registry_devices,
        "daily_removable_bytes_written": daily_bytes,
        "synthetic_data": False,
    }


def _is_after_hours(timestamp: datetime) -> bool:
    local_ts = timestamp.astimezone().replace(tzinfo=None) if timestamp.tzinfo is not None else timestamp
    return not (BUSINESS_HOURS[0] <= local_ts.time() <= BUSINESS_HOURS[1])


def _empty_features() -> dict[str, Any]:
    return {
        "collected_at": datetime.now().astimezone(),
        "hostname": socket.gethostname(),
        "usb_connect_count": 0,
        "usb_disconnect_count": 0,
        "usb_usage_duration": 0,
        "usb_file_transfer_count": 0,
        "large_usb_transfer": False,
        "first_usb_usage_time": None,
        "after_hours_usb_usage": 0,
        "unique_usb_devices": 0,
        "daily_device_connect_count": 0,
        "daily_device_usage_flag": 0,
        "last_usb_usage_time": None,
        "daily_removable_bytes_written": 0,
    }


def derive_features(raw: dict[str, Any]) -> dict[str, Any]:
    connects: list[UsbEvent] = raw["connects"]
    disconnects: list[UsbEvent] = raw["disconnects"]

    pair_by_lifetime = {event.lifetime_id: event for event in disconnects if event.lifetime_id}
    total_seconds = 0
    for connect in connects:
        disconnect = pair_by_lifetime.get(connect.lifetime_id)
        if disconnect and disconnect.timestamp > connect.timestamp:
            total_seconds += int((disconnect.timestamp - connect.timestamp).total_seconds())

    transfer_bytes = raw.get("daily_removable_bytes_written", 0)
    transfer_count = sum(1 for event in connects if event.bytes_written > 0) or (1 if transfer_bytes > 0 else 0)

    features = _empty_features()
    features.update(
        {
            "usb_connect_count": len(connects),
            "usb_disconnect_count": len(disconnects),
            "usb_usage_duration": total_seconds,
            "usb_file_transfer_count": transfer_count,
            "large_usb_transfer": bool(transfer_bytes > LARGE_USB_THRESHOLD_MB * 1024 * 1024),
            "first_usb_usage_time": min((event.timestamp for event in connects), default=None),
            "last_usb_usage_time": max((event.timestamp for event in connects + disconnects), default=None),
            "after_hours_usb_usage": sum(1 for event in connects + disconnects if _is_after_hours(event.timestamp)),
            "unique_usb_devices": len({event.device_id for event in connects} | set(raw["registry_devices"])),
            "daily_device_connect_count": len(connects),
            "daily_device_usage_flag": 1 if connects or disconnects else 0,
            "daily_removable_bytes_written": transfer_bytes,
        }
    )

    feature_quality = {key: "exact" for key in features}
    for key in ("usb_usage_duration", "after_hours_usb_usage", "unique_usb_devices"):
        feature_quality[key] = "heuristic"
    if raw.get("synthetic_data"):
        features["synthetic_data"] = True
        feature_quality["synthetic_data"] = "local_only"
        features["_collector_quality"] = "local_only"
    else:
        features["_collector_quality"] = "heuristic"
    features["_feature_quality"] = feature_quality
    return features


def collect() -> dict[str, Any]:
    raw = collect_raw_usb_telemetry()
    if raw.get("synthetic_disabled"):
        features = _empty_features()
        features.update(
            {
                "_collector_status": "unsupported",
                "_collector_quality": "unsupported",
                "_collector_message": str(raw.get("unsupported_reason") or "USB collector unsupported"),
                "_feature_quality": {key: "unsupported" for key in features},
            }
        )
        return features
    return derive_features(raw)


def collect_features() -> dict[str, Any]:
    return collect()


EXPECTED_FIELDS = {
    "collected_at": datetime,
    "hostname": str,
    "usb_connect_count": int,
    "usb_disconnect_count": int,
    "usb_usage_duration": int,
    "usb_file_transfer_count": int,
    "large_usb_transfer": bool,
    "first_usb_usage_time": (datetime, type(None)),
    "after_hours_usb_usage": int,
    "unique_usb_devices": int,
    "daily_device_connect_count": int,
    "daily_device_usage_flag": int,
    "daily_removable_bytes_written": int,
}


def validate_data(features: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not features:
        return ["dataset is empty"]
    for field, expected_type in EXPECTED_FIELDS.items():
        if field not in features:
            errors.append(f"missing field: {field}")
        elif not isinstance(features[field], expected_type):
            errors.append(f"field {field} has wrong type: {type(features[field]).__name__}")
    return errors


def main() -> None:
    print(json.dumps(collect(), indent=2, default=str))


if __name__ == "__main__":
    main()
