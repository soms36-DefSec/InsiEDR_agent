import logging
import threading
import time
import os
import hashlib
import queue
from pathlib import Path
from typing import Any, Mapping, List, Dict
from datetime import datetime, timezone

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except ImportError:
    Observer = None
    FileSystemEventHandler = object

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("file_integrity")

class FileIntegrityHandler(FileSystemEventHandler):
    def __init__(self, event_queue: queue.Queue):
        self.event_queue = event_queue

    def on_modified(self, event):
        if not event.is_directory:
            self._process(event.src_path, "MODIFY")

    def on_created(self, event):
        if not event.is_directory:
            self._process(event.src_path, "CREATE")

    def _process(self, path, op):
        try:
            # Generate SHA-256 hash
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                # Read only first 1MB to keep it fast
                hasher.update(f.read(1024 * 1024))
            file_hash = hasher.hexdigest()
            
            self.event_queue.put({
                "path": path,
                "op": op,
                "sha256": file_hash,
                "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
            })
        except Exception:
            pass # File might be locked or deleted already

class FileIntegrityMonitorCollector(BaseCollector):
    """
    Monitors sensitive directories and hashes files upon modification.
    Detects unauthorized content changes in sensitive user data.
    """
    name = "file-integrity-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._event_queue = queue.Queue(maxsize=1000)
        self._observer = None
        self._start_monitor()

    def _get_watch_paths(self) -> List[Path]:
        home = Path.home()
        candidates = [home / "Documents", home / "Desktop"]
        return [p for p in candidates if p.exists()]

    def _start_monitor(self):
        if Observer is None:
            return
        
        paths = self._get_watch_paths()
        if not paths:
            return

        self._observer = Observer()
        handler = FileIntegrityHandler(self._event_queue)
        
        for p in paths:
            self._observer.schedule(handler, str(p), recursive=False)
        
        self._observer.start()
        log.info("File integrity monitor started watching %d paths.", len(paths))

    def stop(self):
        if self._observer:
            self._observer.stop()
            self._observer.join(timeout=1)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if Observer is None:
            return self.unsupported("watchdog library is not installed.")

        events = []
        while not self._event_queue.empty():
            try:
                events.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
            if len(events) >= 100: break

        payload = {
            "integrity_events": events,
            "event_count": len(events),
            "monitor_active": self._observer.is_alive() if self._observer else False
        }
        
        return self.success(payload, quality="exact")

def collect() -> dict[str, Any]:
    if not hasattr(collect, "_monitor"):
        collect._monitor = FileIntegrityMonitorCollector()
    return collect._monitor.collect().as_dict()

def stop_sampler():
    if hasattr(collect, "_monitor"):
        collect._monitor.stop()

if __name__ == "__main__":
    import json
    from datetime import datetime, timezone
    print("Monitoring file integrity for 5 seconds...")
    mon = FileIntegrityMonitorCollector()
    time.sleep(5)
    print(json.dumps(mon.collect().as_dict(), indent=2))
    mon.stop()
