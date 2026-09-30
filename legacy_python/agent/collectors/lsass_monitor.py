import logging
import platform
from datetime import datetime, timezone, timedelta
from typing import Any, Mapping, List, Dict

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from agent.collectors.base import BaseCollector, CollectorResult
from agent.privilege import is_admin
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("lsass_monitor")

class LSASSMonitorCollector(BaseCollector):
    """
    Audits process handles opened to lsass.exe via the Windows Security Event Log.
    Detects potential credential dumping (e.g., Mimikatz, procdump).
    """
    name = "lsass-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.bookmark_file = default_state_dir() / "lsass_bookmark.json"
        self.event_ids = {4656, 4663} # Handle requested / accessed
        self.target_process = "lsass.exe"

    def _load_bookmark(self) -> int:
        try:
            if self.bookmark_file.exists():
                return int(read_json_file(self.bookmark_file).get("last_record_number", 0))
        except Exception:
            pass
        return 0

    def _save_bookmark(self, record_number: int):
        try:
            write_json_file(self.bookmark_file, {
                "last_record_number": record_number, 
                "updated_at": datetime.now(timezone.utc).isoformat()
            })
        except Exception:
            pass

    def _parse_event_data(self, strings: tuple) -> Dict[str, Any]:
        """Extracts fields from 4656/4663 string inserts."""
        # Note: Microsoft's schema varies slightly between versions, 
        # but 4656 (Handle requested) usually has:
        # 6: Process Name (Source)
        # 14: Object Name (Target Process Path)
        # 15: Handle ID
        # 16: Access Mask
        try:
            if len(strings) < 15: return {}
            
            # Look for lsass.exe in the Object Name (usually index 14 or search)
            obj_name = next((s for s in strings if self.target_process in s.lower()), "")
            if not obj_name:
                return {}

            return {
                "source_process": strings[6] if len(strings) > 6 else "unknown",
                "target_object": obj_name,
                "access_mask": strings[15] if len(strings) > 15 else "unknown",
                "handle_id": strings[14] if len(strings) > 14 else "unknown",
                "subject_user": strings[1] if len(strings) > 1 else "unknown"
            }
        except Exception:
            return {}

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32evtlog is None:
            return self.unsupported("LSASS monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "LSASS monitor requires administrator privileges to read the Security event log.",
                quality="permission_limited"
            )

        try:
            server = "localhost"
            log_type = "Security"
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            
            bookmark = self._load_bookmark()
            max_record = bookmark
            access_events = []

            handle = win32evtlog.OpenEventLog(server, log_type)
            
            while True:
                records = win32evtlog.ReadEventLog(handle, flags, 0)
                if not records:
                    break
                
                for record in records:
                    if record.RecordNumber > max_record:
                        max_record = record.RecordNumber
                    
                    # Stop if we hit the bookmark
                    if record.RecordNumber <= bookmark:
                        break
                    
                    eid = record.EventID & 0xFFFF
                    if eid in self.event_ids:
                        strings = record.StringInserts or ()
                        parsed = self._parse_event_data(strings)
                        if parsed:
                            parsed["event_id"] = eid
                            parsed["timestamp"] = record.TimeGenerated.astimezone(timezone.utc).isoformat()
                            access_events.append(parsed)
                
                # If we broke the inner loop because of bookmark, break outer too
                if records and records[-1].RecordNumber <= bookmark:
                    break

            self._save_bookmark(max_record)
            
            payload = {
                "lsass_access_events": access_events[:100], # Cap payload
                "event_count": len(access_events),
                "target_process": self.target_process
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to Security logs. Admin privileges required.", quality="permission_limited")
            log.exception("LSASS monitor collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return LSASSMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
