import logging
import platform
from typing import Any, Mapping, List, Dict

try:
    import win32com.client
except ImportError:
    class _DummyWin32Com:
        client = None
    win32com = _DummyWin32Com()

from agent.collectors.base import BaseCollector, CollectorResult
from agent.privilege import is_admin

log = logging.getLogger("driver_monitor")

class DriverMonitorCollector(BaseCollector):
    """
    Audits installed and running system drivers.
    Detects unauthorized kernel modules or 'BYOVD' (Bring Your Own Vulnerable Driver) attacks.
    """
    name = "driver-monitor"

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32com.client is None:
            return self.unsupported("Driver monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "Driver monitor requires administrator privileges to query Win32_SystemDriver via WMI.",
                quality="permission_limited"
            )

        try:
            wmi = win32com.client.GetObject("winmgmts:")
            
            # Query all system drivers
            drivers = []
            # Focusing on key properties for security auditing
            query = "SELECT Name, DisplayName, State, StartMode, PathName, ServiceType FROM Win32_SystemDriver"
            results = wmi.ExecQuery(query)
            
            for drv in results:
                drivers.append({
                    "name": str(drv.Name),
                    "display_name": str(drv.DisplayName),
                    "state": str(drv.State),
                    "start_mode": str(drv.StartMode),
                    "path": str(drv.PathName or ""),
                    "type": str(drv.ServiceType)
                })

            payload = {
                "drivers": drivers,
                "driver_count": len(drivers),
                "summary": {
                    "running_drivers": sum(1 for d in drivers if d["state"] == "Running"),
                    "kernel_drivers": sum(1 for d in drivers if "Kernel" in d["type"]),
                    "file_system_drivers": sum(1 for d in drivers if "File System" in d["type"])
                }
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to Driver WMI class. Admin privileges required.", quality="permission_limited")
            log.exception("Driver collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return DriverMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
