import logging
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, List, Dict

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("file_resilience")

class FileResilienceCollector(BaseCollector):
    """
    Ensures zero-loss file monitoring by tracking timestamps of sensitive files.
    Detects changes that occurred while the agent was offline.
    """
    name = "file-resilience"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.state_file = default_state_dir() / "file_resilience_state.json"
        self.watch_paths = self._get_watch_paths()

    def _get_watch_paths(self) -> List[Path]:
        # Focus on highly sensitive directories for offline tracking
        paths = []
        home = Path.home()
        candidates = [
            home / "Documents",
            home / "Downloads",
            home / "Desktop"
        ]
        for p in candidates:
            if p.exists():
                paths.append(p)
        return paths

    def _load_state(self) -> Dict[str, float]:
        """Loads filename -> mtime mapping."""
        try:
            if self.state_file.exists():
                data = read_json_file(self.state_file)
                return data.get("file_mtimes", {})
        except Exception as e:
            log.warning("File resilience state load failed: %s", e)
        return {}

    def _save_state(self, mtimes: Dict[str, float]):
        try:
            write_json_file(self.state_file, {"file_mtimes": mtimes})
        except Exception as e:
            log.warning("File resilience state save failed: %s", e)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Scans watch paths and compares mtimes with last known state."""
        current_mtimes = {}
        offline_modifications = []
        last_mtimes = self._load_state()

        try:
            for root_path in self.watch_paths:
                # Scan top-level files (to keep it fast)
                for entry in root_path.iterdir():
                    if entry.is_file():
                        try:
                            stat = entry.stat()
                            mtime = stat.st_mtime
                            path_str = str(entry)
                            current_mtimes[path_str] = mtime
                            
                            # Check if modified since last agent run
                            if path_str in last_mtimes:
                                if mtime > last_mtimes[path_str]:
                                    offline_modifications.append({
                                        "path": path_str,
                                        "modified_at": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                                        "size": stat.st_size
                                    })
                            else:
                                # New file detected while offline
                                offline_modifications.append({
                                    "path": path_str,
                                    "event": "new_file_offline",
                                    "size": stat.st_size
                                })
                        except (OSError, PermissionError):
                            continue

            # Limit output to prevent massive payloads
            payload = {
                "offline_modifications": offline_modifications[:50],
                "modification_count": len(offline_modifications),
                "total_files_scanned": len(current_mtimes)
            }
            
            # Persist state for next run
            self._save_state(current_mtimes)
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            log.exception("File resilience collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return FileResilienceCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
