from __future__ import annotations

import hashlib
import logging
import os
import platform
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Set

try:
    import psutil
except ImportError:
    psutil = None

from agent.collectors.base import BaseCollector, CollectorResult
from agent.state import default_state_dir, read_json_file, write_json_file

log = logging.getLogger("process_watcher")


class ProcessWatcher(BaseCollector):
    """
    A lightweight process collector that snapshots running processes to extract 
    security-relevant features without continuous monitoring overhead.
    """
    name = "process-watcher"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.state_file = default_state_dir() / "process_watcher_state.json"
        self._temp_paths = self._get_temp_paths()

    def _get_temp_paths(self) -> Set[Path]:
        """Identifies common temporary and user-download directories."""
        paths: Set[Path] = set()
        if platform.system() == "Windows":
            # Environment variables
            for env in ("TEMP", "TMP", "USERPROFILE"):
                val = os.getenv(env)
                if val:
                    p = Path(val).resolve()
                    paths.add(p)
                    if env == "USERPROFILE":
                        paths.add(p / "Downloads")
                        paths.add(p / "AppData" / "Local" / "Temp")
            
            # Known system paths
            paths.add(Path("C:/Windows/Temp").resolve())
            
            # Iterate actual user profiles since agent runs as SYSTEM
            users_dir = Path("C:/Users")
            if users_dir.exists():
                for user_dir in users_dir.iterdir():
                    if user_dir.is_dir():
                        paths.add((user_dir / "Downloads").resolve())
                        paths.add((user_dir / "AppData" / "Local" / "Temp").resolve())
        else:
            paths.add(Path("/tmp").resolve())
            paths.add(Path("/var/tmp").resolve())
            paths.add(Path("/dev/shm").resolve())
        
        return {p for p in paths if p.exists()}

    def _is_in_temp(self, exe_path: str) -> bool:
        """Checks if an executable resides within a temporary or user-controlled directory."""
        if not exe_path:
            return False
        try:
            p = Path(exe_path).resolve()
            for temp_path in self._temp_paths:
                try:
                    if p.is_relative_to(temp_path):
                        return True
                except (ValueError, AttributeError):
                    # Handle cases where path is on different drive or older Python
                    if str(p).startswith(str(temp_path)):
                        return True
        except (OSError, ValueError):
            pass
        return False

    def _load_state(self) -> tuple[str, set[str]]:
        """Loads the daily seen process hashes from a protected state file."""
        today = datetime.now(timezone.utc).date().isoformat()
        try:
            if self.state_file.exists():
                data = read_json_file(self.state_file)
                if data.get("date") == today:
                    hashes = data.get("hashes", [])
                    return today, set(hashes) if isinstance(hashes, list) else set()
        except Exception as exc:
            log.warning("Process watcher state load failed; starting fresh: %s", exc)
        return today, set()

    def _save_state(self, date: str, hashes: set[str]) -> None:
        """Saves the daily seen process hashes to the protected state file."""
        try:
            write_json_file(self.state_file, {
                "date": date,
                "hashes": sorted(list(hashes))
            })
        except Exception as exc:
            log.warning("Process watcher state save failed: %s", exc)

    def _hash_process_name(self, name: str) -> str:
        """Hashes a process name to avoid persisting plaintext paths/names in state."""
        return hashlib.sha256(name.lower().encode("utf-8", errors="ignore")).hexdigest()[:16]

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """
        Snapshots running processes and computes features.
        """
        if psutil is None:
            return self.unsupported("psutil library is not installed")

        daily_date, daily_hashes = self._load_state()
        
        temp_exe_count = 0
        admin_count = 0
        tunneling_process_count = 0
        permission_limited = False
        
        tunneling_tools = {"ngrok", "ssh", "plink", "localtunnel"}
        
        # We iterate over processes once to minimize performance impact
        try:
            for proc in psutil.process_iter(attrs=['name', 'exe', 'username']):
                try:
                    info = proc.info
                    name = info.get('name')
                    exe = info.get('exe')
                    username = info.get('username')
                    
                    if name:
                        # Update daily unique count state
                        h = self._hash_process_name(name)
                        daily_hashes.add(h)
                        
                        base_name = name.lower().split('.')[0]
                        if base_name in tunneling_tools:
                            tunneling_process_count += 1
                    
                    if exe and self._is_in_temp(exe):
                        temp_exe_count += 1
                    
                    # Detect administrative/elevated processes
                    if platform.system() == "Windows":
                        # System-level or known admin accounts
                        if username:
                            uname_up = username.upper()
                            if "SYSTEM" in uname_up or "ADMINISTRATOR" in uname_up:
                                admin_count += 1
                    else:
                        # On Unix-like systems, check for UID 0 (root)
                        try:
                            if proc.uids().effective == 0:
                                admin_count += 1
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass

                except psutil.AccessDenied:
                    # Expected for some system processes depending on agent privileges
                    permission_limited = True
                    continue
                except (psutil.NoSuchProcess, psutil.ZombieProcess):
                    # Process ended or became zombie during iteration
                    continue
                except Exception as exc:
                    log.debug("Error reading process info (redacted): %s", type(exc).__name__)
                    continue
        except Exception as exc:
            log.error("Process snapshot failed: %s", exc)
            return self.failed(exc)
        
        # Persist updated daily unique hashes
        self._save_state(daily_date, daily_hashes)
        
        payload = {
            "daily_unique_process_count": len(daily_hashes),
            "executables_from_temp_folder": temp_exe_count,
            "admin_process_count": admin_count,
            "tunneling_process_count": tunneling_process_count,
        }
        
        quality = "permission_limited" if permission_limited else "exact"
        
        # Feature-only telemetry: no alerts or scoring here.
        log.info("Process collection successful (quality=%s)", quality)
        
        return self.success(payload, quality=quality)


def collect() -> dict[str, Any]:
    """Entry point for the PythonModuleCollector adapter."""
    return ProcessWatcher().collect().as_dict()


if __name__ == "__main__":
    # Local execution for debugging
    import json
    print(json.dumps(collect(), indent=2))
