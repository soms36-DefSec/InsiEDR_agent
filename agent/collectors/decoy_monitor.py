import logging
import os
from pathlib import Path
from typing import Any, Mapping, Dict

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("decoy_monitor")

class DecoyMonitorCollector(BaseCollector):
    """
    Monitors highly enticing 'fake' files (e.g., Admin_Passwords.xlsx).
    Detects if the file has been opened, modified, or deleted by comparing
    filesystem timestamps and sizes.
    """
    name = "decoy-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.state_file = default_state_dir() / "decoy_monitor_state.json"
        
        # Read from environment or use default
        env_files = os.getenv("INSIEDR_DECOY_FILES")
        if env_files:
            self.decoy_paths = [Path(p.strip()).resolve() for p in env_files.split(",") if p.strip()]
        else:
            # Default decoy file
            self.decoy_paths = [Path("C:/Users/Public/Admin_Passwords.xlsx").resolve()]

    def _ensure_decoy_exists(self, path: Path) -> None:
        """Creates the decoy file with dummy content if it doesn't exist."""
        if not path.exists():
            try:
                # Ensure parent directory exists
                path.parent.mkdir(parents=True, exist_ok=True)
                # Write some dummy bytes so it's not 0-size, which might look suspicious
                # or not trigger some file modification heuristics as easily.
                with open(path, "wb") as f:
                    # Write dummy "encrypted" looking header
                    f.write(b"PK\x03\x04DummyExcelFileContentDoNotDelete")
                log.info("Created missing decoy file at %s", path)
            except Exception as e:
                log.warning("Failed to create decoy file at %s: %s", path, e)

    def _get_file_stats(self, path: Path) -> Dict[str, Any] | None:
        """Returns the file's current size and modified time."""
        try:
            if not path.exists():
                return None
            stat = path.stat()
            return {
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "ctime": stat.st_ctime
            }
        except Exception as e:
            log.warning("Failed to stat decoy file %s: %s", path, e)
            return None

    def _load_state(self) -> Dict[str, Dict[str, Any]]:
        if self.state_file.exists():
            try:
                state = read_json_file(self.state_file)
                if isinstance(state, dict) and "files" in state:
                    return state["files"]
            except Exception as e:
                log.warning("Failed to load decoy state: %s", e)
        return {}

    def _save_state(self, state: Dict[str, Dict[str, Any]]) -> None:
        try:
            write_json_file(self.state_file, {"files": state})
        except Exception as e:
            log.warning("Failed to save decoy state: %s", e)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        previous_state = self._load_state()
        current_state: Dict[str, Dict[str, Any]] = {}
        
        events = []

        for path in self.decoy_paths:
            path_str = str(path)
            
            # Detect deletion before recreating
            was_deleted = path_str in previous_state and not path.exists()
            
            if not path.exists():
                self._ensure_decoy_exists(path)

            stats = self._get_file_stats(path)
            if not stats:
                continue # Could not stat or create it
                
            current_state[path_str] = stats

            # Compare with previous state
            if path_str in previous_state:
                prev_stats = previous_state[path_str]
                
                if was_deleted:
                    events.append({"path": path_str, "event": "deleted_and_recreated"})
                elif stats["size"] != prev_stats.get("size") or stats["mtime"] != prev_stats.get("mtime"):
                    events.append({
                        "path": path_str, 
                        "event": "modified_or_accessed",
                        "old_mtime": prev_stats.get("mtime"),
                        "new_mtime": stats["mtime"],
                        "old_size": prev_stats.get("size"),
                        "new_size": stats["size"]
                    })

        self._save_state(current_state)

        payload = {
            "monitored_decoys": [str(p) for p in self.decoy_paths],
            "events": events,
            "events_recorded": len(events) > 0,
            # Tamper detection contract keys (no scoring terminology)
            "threat_triggered": len(events) > 0,
            "threat_events": events,
        }
        
        # Use exact quality
        quality = "exact"
        return self.success(payload, quality=quality)

def collect() -> dict[str, Any]:
    return DecoyMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
