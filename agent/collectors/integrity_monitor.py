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

log = logging.getLogger("integrity_monitor")

class IntegrityMonitorCollector(BaseCollector):
    """
    Audits Windows Services and Scheduled Tasks.
    Detects unauthorized persistence or sabotage (disabling tools).
    """
    name = "integrity-monitor"

    def _get_services(self, wmi) -> List[Dict[str, Any]]:
        services = []
        try:
            # Query services. Focus on non-Microsoft or unusual states
            procs = wmi.ExecQuery("SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service")
            for p in procs:
                services.append({
                    "name": str(p.Name),
                    "display_name": str(p.DisplayName),
                    "state": str(p.State),
                    "start_mode": str(p.StartMode),
                    "path": str(p.PathName or "")
                })
        except Exception as e:
            log.debug("Service query error: %s", e)
        return services

    def _get_scheduled_tasks(self) -> List[Dict[str, Any]]:
        """
        Queries scheduled tasks using the Task Scheduler 2.0 COM API.
        This is more robust than WMI's Win32_ScheduledJob.
        """
        tasks = []
        try:
            scheduler = win32com.client.Dispatch("Schedule.Service")
            scheduler.Connect()
            root_folder = scheduler.GetFolder("\\")
            
            # Recursive task fetcher
            def scan_folder(folder):
                for task in folder.GetTasks(0):
                    tasks.append({
                        "name": str(task.Name),
                        "path": str(task.Path),
                        "enabled": bool(task.Enabled),
                        "last_run": str(task.LastRunTime)
                    })
                for subfolder in folder.GetFolders(0):
                    scan_folder(subfolder)
            
            scan_folder(root_folder)
        except Exception as e:
            log.debug("Task Scheduler query error: %s", e)
        return tasks

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32com.client is None:
            return self.unsupported("Integrity monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "Integrity monitor requires administrator privileges to query Win32_Service and Task Scheduler.",
                quality="permission_limited"
            )

        try:
            wmi = win32com.client.GetObject("winmgmts:")
            
            services = self._get_services(wmi)
            tasks = self._get_scheduled_tasks()

            payload = {
                "services": services,
                "service_count": len(services),
                "scheduled_tasks": tasks[:200], # Sample first 200 tasks
                "task_count": len(tasks),
                "summary": {
                    "running_services": sum(1 for s in services if s["state"] == "Running"),
                    "disabled_tasks": sum(1 for t in tasks if not t["enabled"])
                }
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to Service/Task APIs. Administrative privileges required.", quality="permission_limited")
            log.exception("Integrity collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return IntegrityMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
