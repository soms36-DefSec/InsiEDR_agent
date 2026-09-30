import logging
import platform
import socket
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, List, Dict

try:
    import win32evtlog
except ImportError:
    win32evtlog = None

from agent.collectors.base import BaseCollector, CollectorResult
from agent.privilege import is_admin

log = logging.getLogger("dns_monitor")

class DNSMonitorCollector(BaseCollector):
    """
    Audits DNS queries from the Windows DNS Client Operational log.
    Captures network intent even if browser history or network connections are obfuscated.
    """
    name = "dns-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.channel = "Microsoft-Windows-DNS-Client/Operational"
        self.event_ids = {3008} # DNS Query events

    def _parse_dns_event(self, xml_text: str) -> Dict[str, Any] | None:
        try:
            root = ET.fromstring(xml_text)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
            
            # Extract data fields
            data_nodes = root.findall(".//e:Data", namespaces=ns)
            data = {node.get("Name"): node.text for node in data_nodes if node.get("Name")}
            
            # Extract system fields
            system = root.find("e:System", namespaces=ns)
            time_node = system.find("e:TimeCreated", namespaces=ns) if system is not None else None
            ts_str = time_node.get("SystemTime") if time_node is not None else None
            
            execution = system.find("e:Execution", namespaces=ns) if system is not None else None
            pid = execution.get("ProcessID") if execution is not None else None

            return {
                "query": data.get("QueryName"),
                "query_type": data.get("QueryType"),
                "status": data.get("QueryStatus"),
                "pid": int(pid) if pid else None,
                "timestamp": ts_str
            }
        except Exception:
            return None

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32evtlog is None:
            return self.unsupported("DNS monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "DNS monitor requires administrator privileges to read the DNS-Client/Operational event log.",
                quality="permission_limited"
            )

        try:
            # Query last 1 hour of DNS activity
            query = "*[System[EventID=3008]]"
            handle = win32evtlog.EvtQuery(self.channel, win32evtlog.EvtQueryReverseDirection, query)
            
            queries = []
            seen_queries = set()
            
            # We limit the number of events to prevent payload bloat
            count = 0
            while count < 500:
                events = win32evtlog.EvtNext(handle, 10)
                if not events:
                    break
                
                for event in events:
                    xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
                    parsed = self._parse_dns_event(xml)
                    if parsed and parsed["query"]:
                        queries.append(parsed)
                        seen_queries.add(parsed["query"].lower())
                    count += 1
            
            payload = {
                "dns_queries": queries[:100], # Detailed sample
                "total_queries_captured": len(queries),
                "unique_domains_queried": len(seen_queries),
                "channel": self.channel
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to DNS Client logs. Elevated privileges required.", quality="permission_limited")
            log.exception("DNS collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return DNSMonitorCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
