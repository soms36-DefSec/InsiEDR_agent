import logging
import platform
import time
from typing import Any, Mapping

try:
    import win32api
except ImportError:
    win32api = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("activity_monitor")

class ActivityMonitorCollector(BaseCollector):
    """
    Monitors user activity/idle state using win32api.
    Helps contextualize telemetry: large file transfers while idle are more suspicious.
    """
    name = "activity-monitor"

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32api is None:
            return self.unsupported("Activity monitor requires Windows with pywin32.")

        try:
            # Get idle time in milliseconds
            last_input = win32api.GetLastInputInfo()
            current_time = win32api.GetTickCount()
            idle_ms = current_time - last_input
            idle_seconds = idle_ms / 1000.0

            payload = {
                "user_idle_seconds": round(idle_seconds, 2),
                "is_user_active": idle_seconds < 300, # 5 minute threshold for "active"
                "last_input_tick": last_input
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            log.exception("Activity collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return ActivityMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
