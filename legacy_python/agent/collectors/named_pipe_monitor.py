import logging
import platform
from typing import Any, Mapping, List

try:
    import win32file
except ImportError:
    win32file = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("named_pipe_monitor")

class NamedPipeMonitorCollector(BaseCollector):
    """
    Audits active Named Pipes on the system.
    Detects lateral movement tools (e.g., Cobalt Strike, custom C2s) that use pipes for IPC.
    """
    name = "named-pipe-monitor"

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32file is None:
            return self.unsupported("Named Pipe monitor requires Windows with pywin32.")

        try:
            pipes = []
            # Windows exposes named pipes as a special file system under \\.\pipe\
            search_path = r"\\.\pipe\*"
            
            # FindFilesW returns a list of tuples for the pattern
            # For named pipes, we can iterate all of them at once
            results = win32file.FindFilesW(search_path)
            
            for data in results:
                pipe_name = data[8] # Index 8 is the filename
                if pipe_name:
                    pipes.append({
                        "name": pipe_name,
                        "full_path": rf"\\.\pipe\{pipe_name}"
                    })

            payload = {
                "named_pipes": pipes,
                "pipe_count": len(pipes),
            }
            
            # This is exact as it's a direct filesystem enumeration
            return self.success(payload, quality="exact")

        except Exception as exc:
            log.exception("Named Pipe collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return NamedPipeMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
