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

log = logging.getLogger("wmi_integrity")

class WMIIntegrityCollector(BaseCollector):
    """
    Audits WMI Permanent Event Subscriptions (Filters, Consumers, Bindings).
    Detects advanced "fileless" persistence often used for sabotage or exfiltration.
    """
    name = "wmi-integrity"

    def _query_namespace(self, wmi, query: str) -> List[Dict[str, Any]]:
        results = []
        try:
            items = wmi.ExecQuery(query)
            for item in items:
                # Extract all properties as a dictionary
                prop_dict = {}
                for prop in item.Properties_:
                    prop_dict[prop.Name] = str(prop.Value) if prop.Value is not None else ""
                results.append(prop_dict)
        except Exception as e:
            log.debug("WMI Query error [%s]: %s", query, e)
        return results

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if platform.system() != "Windows" or win32com.client is None:
            return self.unsupported("WMI integrity monitor requires Windows with pywin32.")
        if not is_admin():
            return self.unsupported(
                "WMI integrity monitor requires administrator privileges to query WMI subscription namespaces.",
                quality="permission_limited"
            )

        try:
            # Note: Permanent subscriptions usually live in ROOT\subscription
            # but some legacy ones might be in ROOT\default or ROOT\cimv2
            namespaces = ["ROOT\\subscription", "ROOT\\default", "ROOT\\cimv2"]
            
            all_filters = []
            all_consumers = []
            all_bindings = []

            for ns in namespaces:
                try:
                    wmi = win32com.client.GetObject(f"winmgmts:{ns}")
                    
                    # 1. Event Filters (The "When")
                    filters = self._query_namespace(wmi, "SELECT * FROM __EventFilter")
                    for f in filters:
                        f["_namespace"] = ns
                        all_filters.append(f)

                    # 2. Event Consumers (The "What")
                    consumers = self._query_namespace(wmi, "SELECT * FROM __EventConsumer")
                    for c in consumers:
                        c["_namespace"] = ns
                        all_consumers.append(c)

                    # 3. Bindings (The Link)
                    bindings = self._query_namespace(wmi, "SELECT * FROM __FilterToConsumerBinding")
                    for b in bindings:
                        b["_namespace"] = ns
                        all_bindings.append(b)
                except Exception:
                    continue # Skip namespaces that don't support these classes

            payload = {
                "wmi_event_filters": all_filters,
                "wmi_event_consumers": all_consumers,
                "wmi_filter_to_consumer_bindings": all_bindings,
                "summary": {
                    "filter_count": len(all_filters),
                    "consumer_count": len(all_consumers),
                    "binding_count": len(all_bindings)
                }
            }
            
            return self.success(payload, quality="exact")

        except Exception as exc:
            if "Access is denied" in str(exc):
                return self.unsupported("Access denied to WMI Subscription namespaces. Elevated privileges required.", quality="permission_limited")
            log.exception("WMI Integrity collection failed")
            return self.failed(exc)

def collect() -> dict[str, Any]:
    return WMIIntegrityCollector().collect().as_dict()

if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
