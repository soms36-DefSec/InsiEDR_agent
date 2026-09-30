import logging
import platform
import socket
from typing import Any, Mapping, List, Dict, Set

try:
    import psutil
except ImportError:
    psutil = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("port_monitor")

# Standard ports that are usually "safe" or expected
STANDARD_PORTS = {
    80,   # HTTP
    443,  # HTTPS
    53,   # DNS
    123,  # NTP
    22,   # SSH
    21,   # FTP
    25,   # SMTP
    110,  # POP3
    143,  # IMAP
    3389, # RDP (Standard Windows)
    445,  # SMB
    135,  # RPC
    3306, # MySQL
    5432, # Postgres
    27017,# MongoDB
    6379, # Redis
}

class PortMonitorCollector(BaseCollector):
    """
    Monitors established network connections to identify "Unusual Ports".
    Detects reverse shells or data exfiltration to non-standard listener ports.
    """
    name = "port-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.standard_ports: Set[int] = STANDARD_PORTS

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if psutil is None:
            return self.unsupported("psutil library is not installed")

        try:
            unusual_connections = []
            all_connections = psutil.net_connections(kind="inet")
            
            for conn in all_connections:
                # We only care about established external connections
                if conn.status == "ESTABLISHED" and conn.raddr:
                    remote_port = conn.raddr.port
                    if remote_port not in self.standard_ports:
                        unusual_connections.append({
                            "local_addr": f"{conn.laddr.ip}:{conn.laddr.port}",
                            "remote_addr": f"{conn.raddr.ip}:{conn.raddr.port}",
                            "remote_port": remote_port,
                            "pid": conn.pid,
                            "process_name": self._get_proc_name(conn.pid)
                        })

            payload = {
                "unusual_established_connections": unusual_connections,
                "unusual_connection_count": len(unusual_connections),
                "total_established_connections": sum(1 for c in all_connections if c.status == "ESTABLISHED")
            }
            
            # This is heuristic because "standard" is a baseline assumption
            return self.success(payload, quality="heuristic")

        except Exception as exc:
            log.exception("Port monitor collection failed")
            return self.failed(exc)

    def _get_proc_name(self, pid: int | None) -> str:
        if pid is None:
            return "unknown"
        try:
            return psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return "unknown"

def collect() -> dict[str, Any]:
    return PortMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
