import logging
import platform
from typing import Any, Mapping, List, Dict

try:
    import winreg
except ImportError:
    winreg = None

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("persistence_monitor")

class PersistenceMonitorCollector(BaseCollector):
    """
    Monitors common Windows Registry persistence points.
    Statefully tracks modifications to detect additions, changes, or deletions 
    of persistence mechanisms.
    """
    name = "persistence-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.state_file = default_state_dir() / "persistence_monitor_state.json"
        
        self.points = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services"),
        ] if winreg else []

        self.hkey_map = {
            winreg.HKEY_LOCAL_MACHINE: "HKLM",
            winreg.HKEY_CURRENT_USER: "HKCU"
        } if winreg else {}

    def _get_values(self, hkey: int, path: str) -> Dict[str, str]:
        results = {}
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | getattr(winreg, 'KEY_WOW64_64KEY', 0)) as key:
                if path.endswith("Services"):
                    count = 0
                    while True:
                        try:
                            svc_name = winreg.EnumKey(key, count)
                            # We just track that the service exists
                            results[f"Service:{svc_name}"] = "Installed"
                            count += 1
                        except OSError:
                            break
                else:
                    count = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, count)
                            results[name] = str(value)
                            count += 1
                        except OSError:
                            break
        except Exception as e:
            log.debug("Registry access error on %s: %s", path, e)
        return results

    def _load_state(self) -> Dict[str, str]:
        if self.state_file.exists():
            try:
                state = read_json_file(self.state_file)
                if isinstance(state, dict) and "keys" in state:
                    return state["keys"]
            except Exception as e:
                log.warning("Failed to load persistence state: %s", e)
        return {}

    def _save_state(self, state: Dict[str, str]) -> None:
        try:
            write_json_file(self.state_file, {"keys": state})
        except Exception as e:
            log.warning("Failed to save persistence state: %s", e)

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or winreg is None:
            return self.unsupported("Persistence monitor requires Windows registry access.")

        current_state: Dict[str, str] = {}
        
        for hkey, path in self.points:
            values = self._get_values(hkey, path)
            hkey_name = self.hkey_map.get(hkey, str(hkey))
            for name, cmd in values.items():
                key_id = f"{hkey_name}\\{path}\\{name}"
                current_state[key_id] = cmd

        previous_state = self._load_state()
        
        added_keys = []
        modified_keys = []
        deleted_keys = []

        for key_id, cmd in current_state.items():
            if key_id not in previous_state:
                added_keys.append({"key": key_id, "command": cmd})
            elif previous_state[key_id] != cmd:
                modified_keys.append({"key": key_id, "old_command": previous_state[key_id], "new_command": cmd})

        for key_id, cmd in previous_state.items():
            if key_id not in current_state:
                deleted_keys.append({"key": key_id, "last_command": cmd})

        self._save_state(current_state)

        payload = {
            "added_keys": added_keys,
            "modified_keys": modified_keys,
            "deleted_keys": deleted_keys,
            "total_monitored_keys": len(current_state),
            "entry_count": len(current_state),
            "modifications_detected": len(added_keys) + len(modified_keys) + len(deleted_keys) > 0
        }
        
        return self.success(payload, quality="exact")

def collect() -> dict[str, Any]:
    return PersistenceMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
