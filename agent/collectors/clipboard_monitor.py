import logging
import threading
import time
from typing import Any, Mapping

try:
    import win32clipboard
except ImportError:
    win32clipboard = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("clipboard_monitor")

class ClipboardMonitorCollector(BaseCollector):
    """
    Monitors clipboard activity frequency and formats (Metadata only).
    Detects data harvesting behavior without storing sensitive content.
    """
    name = "clipboard-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._copy_count = 0
        self._last_sequence = 0
        self._formats_seen = set()
        self._stop_event = threading.Event()
        self._monitor_thread = None
        self._start_monitor()

    def _monitor_loop(self):
        """Background thread to poll clipboard sequence changes."""
        while not self._stop_event.is_set():
            try:
                # GetClipboardSequenceNumber is very efficient
                current_seq = win32clipboard.GetClipboardSequenceNumber()
                
                if self._last_sequence == 0:
                    self._last_sequence = current_seq
                    continue

                if current_seq != self._last_sequence:
                    self._copy_count += 1
                    self._last_sequence = current_seq
                    
                    # Optional: Identify the format being copied
                    try:
                        win32clipboard.OpenClipboard()
                        fmt = win32clipboard.EnumClipboardFormats(0)
                        while fmt:
                            self._formats_seen.add(fmt)
                            fmt = win32clipboard.EnumClipboardFormats(fmt)
                        win32clipboard.CloseClipboard()
                    except Exception:
                        pass # Avoid crashing if clipboard is locked

            except Exception as e:
                log.debug("Clipboard polling error: %s", e)
            
            # Poll every 500ms (balanced for performance/capture)
            time.sleep(0.5)

    def _start_monitor(self):
        if win32clipboard is None:
            return
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, 
            name="insiedr-clipboard-monitor", 
            daemon=True
        )
        self._monitor_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._monitor_thread:
            self._monitor_thread.join(timeout=1)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if win32clipboard is None:
            return self.unsupported("Clipboard monitor requires Windows with pywin32.")

        # Snapshot current counts and reset
        current_count = self._copy_count
        current_formats = list(self._formats_seen)
        
        # Reset per-cycle counts to capture 'delta' frequency
        self._copy_count = 0
        self._formats_seen = set()

        payload = {
            "clipboard_copy_count": current_count,
            "formats_involved": current_formats,
            "monitor_active": self._monitor_thread.is_alive() if self._monitor_thread else False
        }
        
        return self.success(payload, quality="exact")

def collect() -> dict[str, Any]:
    # Singleton management for the module adapter
    if not hasattr(collect, "_monitor"):
        collect._monitor = ClipboardMonitorCollector()
    return collect._monitor.collect().as_dict()

def stop_sampler():
    if hasattr(collect, "_monitor"):
        collect._monitor.stop()

if __name__ == "__main__":
    import json
    print("Monitoring clipboard for 5 seconds (try copying something!)...")
    mon = ClipboardMonitorCollector()
    time.sleep(5)
    print(json.dumps(mon.collect().as_dict(), indent=2))
    mon.stop()
