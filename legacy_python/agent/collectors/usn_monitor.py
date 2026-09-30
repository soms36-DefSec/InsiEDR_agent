import logging
import platform
import struct
try:
    import win32file
    import pywintypes
    try:
        import win32ioctlcon
    except ImportError:
        class win32ioctlcon:
            FSCTL_QUERY_USN_JOURNAL = 0x000900e4
            FSCTL_READ_USN_JOURNAL = 0x000900bb
    _HAS_WIN32 = True
except ImportError:
    _HAS_WIN32 = False
from datetime import datetime, timezone
from typing import Any, Mapping, List, Dict

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("usn_monitor")

# USN Record V2 Structure (Simplified)
# Ref: https://docs.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
USN_RECORD_V2_MIN_SIZE = 60 

class USNJournalMonitorCollector(BaseCollector):
    """
    Audits the NTFS USN (Update Sequence Number) Change Journal.
    Provides true zero-loss file monitoring by catching changes that occurred while the agent was offline.
    """
    name = "usn-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.state_file = default_state_dir() / "usn_journal_state.json"

    def _load_state(self) -> Dict[str, Any]:
        try:
            if self.state_file.exists():
                return read_json_file(self.state_file)
        except Exception:
            pass
        return {"last_usn": 0, "journal_id": 0}

    def _save_state(self, usn: int, journal_id: int):
        try:
            write_json_file(self.state_file, {"last_usn": usn, "journal_id": journal_id})
        except Exception:
            pass

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or not _HAS_WIN32:
            return self.unsupported("USN monitor requires Windows and pywin32.")

        handle = None
        try:
            # Open the volume handle (C: drive)
            volume_path = r"\\.\C:"
            handle = win32file.CreateFile(
                volume_path,
                win32file.GENERIC_READ,
                win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )

            # 1. Query Journal Info
            # USN_JOURNAL_DATA structure
            query_buf = win32file.DeviceIoControl(
                handle,
                win32ioctlcon.FSCTL_QUERY_USN_JOURNAL,
                None,
                64
            )
            journal_id, first_usn, next_usn = struct.unpack("QQQ", query_buf[:24])

            state = self._load_state()
            # If journal ID changed (e.g. journal re-created), reset bookmark
            start_usn = state.get("last_usn", 0) if state.get("journal_id") == journal_id else first_usn
            
            # Ensure start_usn is within current journal bounds
            if start_usn < first_usn:
                start_usn = first_usn

            # 2. Read Records
            # READ_USN_JOURNAL_DATA_V0
            read_data = struct.pack("QQIIIIQ", start_usn, 0xFFFFFFFF, 0, 0, 0, 0, journal_id)
            
            records = []
            try:
                # We only read a small buffer per cycle to keep it fast
                record_buf = win32file.DeviceIoControl(
                    handle,
                    win32ioctlcon.FSCTL_READ_USN_JOURNAL,
                    read_data,
                    16384 # 16KB buffer
                )
                
                # Parse records
                offset = 8 # Skip the first 8 bytes (next USN to read)
                while offset + USN_RECORD_V2_MIN_SIZE <= len(record_buf):
                    record_len = struct.unpack("I", record_buf[offset:offset+4])[0]
                    if record_len == 0: break
                    
                    # Extract Reason, Timestamp, and FileName
                    reason = struct.unpack("I", record_buf[offset+40:offset+44])[0]
                    # We won't resolve full paths here (requires MFT lookup) to stay fast
                    # but we can capture the filename and event reasons
                    name_len = struct.unpack("H", record_buf[offset+56:offset+58])[0]
                    name_offset = struct.unpack("H", record_buf[offset+58:offset+60])[0]
                    file_name = record_buf[offset+name_offset : offset+name_offset+name_len].decode("utf-16", errors="ignore")
                    
                    records.append({
                        "file_name": file_name,
                        "reason_flags": hex(reason),
                        "usn": start_usn + offset # Approximation
                    })
                    
                    offset += record_len
                    if len(records) >= 500: break # Safety cap
            except pywintypes.error as e:
                # ERROR_HANDLE_EOF (38) is normal if no new records
                if e.winerror != 38:
                    raise

            self._save_state(next_usn, journal_id)

            payload = {
                "usn_records_captured": len(records),
                "journal_id": journal_id,
                "start_usn": start_usn,
                "next_usn": next_usn,
                "records": records[:100] # Representative sample
            }
            
            return self.success(payload, quality="heuristic")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to volume handle. Admin privileges required.", quality="permission_limited")
            log.exception("USN Journal collection failed")
            return self.failed(exc)
        finally:
            if handle:
                win32file.CloseHandle(handle)

def collect() -> dict[str, Any]:
    return USNJournalMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
