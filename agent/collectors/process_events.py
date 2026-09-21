import logging
import threading
import time
import queue
try:
    import pythoncom
    import win32com.client
    _HAS_WIN32COM = True
except ImportError:
    _HAS_WIN32COM = False
from datetime import datetime, timezone
from typing import Any, Mapping, List

from agent.collectors.base import BaseCollector, CollectorResult
from agent.privilege import is_admin

log = logging.getLogger("process_events")

class ProcessEventMonitor(BaseCollector):
    """
    Captures real-time process creation events using WMI Win32_ProcessStartTrace.
    Provides visibility into command-line arguments and parent-child relationships.
    """
    name = "process-events"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._event_queue: queue.Queue = queue.Queue(maxsize=10000)
        self._stop_event = threading.Event()
        self._monitor_thread: threading.Thread | None = None
        self._permission_error = False
        if _HAS_WIN32COM and is_admin():
            self._start_monitor()

    def _monitor_loop(self):
        """Background thread to listen for WMI process start events."""
        pythoncom.CoInitialize()
        try:
            # Connect to WMI
            wmi = win32com.client.GetObject("winmgmts:")
            # Subscribe to process start events
            try:
                watcher = wmi.ExecNotificationQuery(
                    "SELECT * FROM Win32_ProcessStartTrace"
                )
            except Exception as e:
                if "Access denied" in str(e):
                    log.warning("Process event monitor: WMI subscription access denied. Elevated privileges required.")
                    self._permission_error = True
                    return
                raise e
            
            log.info("Process event monitor started subscription.")
            while not self._stop_event.is_set():
                try:
                    # Wait for next event (1 second timeout to check stop_event)
                    evt = watcher.NextEvent(1000)
                    event_data = {
                        "process_name": str(evt.ProcessName),
                        "pid": int(evt.ProcessID),
                        "parent_pid": int(evt.ParentProcessID),
                        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "command_line": self._get_command_line(wmi, evt.ProcessID)
                    }
                    if not self._event_queue.full():
                        self._event_queue.put(event_data)
                except Exception as e:
                    # Timeout is normal (error code -2147209215 usually)
                    if hasattr(e, "hresult") and e.hresult == -2147209215:
                        continue
                    # Other errors might need a break or log
                    log.debug("WMI NextEvent check: %s", e)
                    time.sleep(0.5)
        finally:
            pythoncom.CoUninitialize()

    def _get_command_line(self, wmi_conn: Any, pid: int) -> str:
        """Attempts to fetch the command line for a PID. (Best effort)"""
        try:
            procs = wmi_conn.ExecQuery(f"SELECT CommandLine FROM Win32_Process WHERE ProcessID = {pid}")
            for p in procs:
                return str(p.CommandLine or "")
        except Exception:
            pass
        return ""

    def _start_monitor(self):
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, 
            name="insiedr-process-events", 
            daemon=True
        )
        self._monitor_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=2)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Flushes the event queue and returns the list of process events."""
        if not _HAS_WIN32COM:
            return self.unsupported("Process event monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "Process event monitor requires administrator privileges for WMI ProcessStartTrace subscription.",
                quality="permission_limited"
            )
        if self._permission_error:
            return self.unsupported(
                "Access denied for WMI ProcessStartTrace. Administrative privileges required for real-time process monitoring.",
                quality="permission_limited"
            )

        events = []
        while not self._event_queue.empty():
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
            if len(events) >= 1000: # Limit per-cycle batch size
                break
        
        payload = {
            "process_start_events": events,
            "event_count": len(events),
            "monitor_active": self._monitor_thread.is_alive() if self._monitor_thread else False
        }
        
        # Determine quality based on whether we might have missed events
        quality = "exact" if len(events) < 1000 else "heuristic"
        
        return self.success(payload, quality=quality)

def collect() -> dict[str, Any]:
    # Singleton-like management for the module adapter
    if not hasattr(collect, "_monitor"):
        collect._monitor = ProcessEventMonitor()
    return collect._monitor.collect().as_dict()

def stop_sampler():
    if hasattr(collect, "_monitor"):
        collect._monitor.stop()

if __name__ == "__main__":
    import json
    print("Capturing events for 5 seconds...")
    mon = ProcessEventMonitor()
    time.sleep(5)
    print(json.dumps(mon.collect().as_dict(), indent=2))
    mon.stop()
