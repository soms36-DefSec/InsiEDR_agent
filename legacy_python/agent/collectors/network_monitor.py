from __future__ import annotations

import ipaddress
import logging
import socket
from datetime import datetime, timezone
from typing import Any, Mapping

try:
    import psutil
except ImportError:
    psutil = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("network_monitor")

_PROCESS_NAME_CACHE: dict[int, str] = {}


def is_external_ip(ip_str: str) -> bool:
    """Classifies an IP address as external (public Internet) vs local/private/reserved."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_multicast
            or addr.is_reserved
        )
    except ValueError:
        return False


def get_process_name(pid: int | None) -> str | None:
    """Resolves PID to process name with in-memory caching to minimize system overhead."""
    if not pid or pid <= 0:
        return None
    if pid in _PROCESS_NAME_CACHE:
        return _PROCESS_NAME_CACHE[pid]
    if psutil is None:
        return None
    try:
        proc = psutil.Process(pid)
        name = proc.name()
        if len(_PROCESS_NAME_CACHE) > 1000:
            _PROCESS_NAME_CACHE.clear()
        _PROCESS_NAME_CACHE[pid] = name
        return name
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return None


def is_after_hours(dt: datetime | None = None) -> bool:
    """Determines whether current timestamp is outside standard business hours (Mon-Fri 08:00-18:00)."""
    target = dt or datetime.now()
    if target.weekday() >= 5:  # Saturday or Sunday
        return True
    return target.hour < 8 or target.hour >= 18


class NetworkMonitor(BaseCollector):
    """
    Level 1 Endpoint Network Telemetry Collector.
    Captures connection-level 5-tuples, process attribution, and behavioral features.
    """
    name = "network-monitor"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)

    def _utc_now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    def _safe_net_connections(self) -> list[Any]:
        try:
            return list(psutil.net_connections(kind="inet"))
        except (psutil.AccessDenied, PermissionError, OSError):
            return []

    def _safe_net_if_addrs(self) -> dict[str, list[Any]]:
        try:
            return psutil.net_if_addrs()
        except (psutil.AccessDenied, PermissionError, OSError, AttributeError):
            return {}

    def _address_family_name(self, family: Any) -> str:
        family_value = getattr(family, "name", str(family))
        if family_value in {"AF_INET", str(socket.AF_INET)}:
            return "ipv4"
        if family_value in {"AF_INET6", str(socket.AF_INET6)}:
            return "ipv6"
        if "PACKET" in family_value or "LINK" in family_value:
            return "link"
        return family_value.lower()

    def _interface_addresses(self, addrs: dict[str, list[Any]], name: str) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for addr in addrs.get(name, []):
            summaries.append(
                {
                    "family": self._address_family_name(getattr(addr, "family", "")),
                    "address": str(getattr(addr, "address", "") or ""),
                    "netmask": str(getattr(addr, "netmask", "") or ""),
                    "broadcast": str(getattr(addr, "broadcast", "") or ""),
                    "ptp": str(getattr(addr, "ptp", "") or ""),
                }
            )
        return summaries

    def _connection_counts(self, connections: list[Any]) -> dict[str, int]:
        established = listening = loopback = 0
        remote_addresses: set[str] = set()
        for conn in connections:
            status = str(getattr(conn, "status", "") or "").upper()
            local = getattr(conn, "laddr", None)
            remote = getattr(conn, "raddr", None)
            if status == "ESTABLISHED":
                established += 1
            if status == "LISTEN":
                listening += 1
            if (
                local
                and getattr(local, "ip", "") in {"127.0.0.1", "::1"}
                or remote
                and getattr(remote, "ip", "") in {"127.0.0.1", "::1"}
            ):
                loopback += 1
            if remote and getattr(remote, "ip", ""):
                remote_addresses.add(str(remote.ip))

        return {
            "network_active_connection_count": len(connections),
            "network_established_connection_count": established,
            "network_listening_connection_count": listening,
            "network_loopback_connection_count": loopback,
            "network_unique_remote_address_count": len(remote_addresses),
            "active_connection_count": len(connections),
            "listening_connection_count": listening,
        }

    def _extract_connections_and_features(
        self, connections: list[Any], timestamp: str
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        events: list[dict[str, Any]] = []
        destination_ips: set[str] = set()
        external_ips: set[str] = set()
        destination_ports: set[int] = set()
        tcp_count = 0
        udp_count = 0
        external_count = 0

        for conn in connections:
            raddr = getattr(conn, "raddr", None)
            laddr = getattr(conn, "laddr", None)
            conn_type = getattr(conn, "type", None)
            status = str(getattr(conn, "status", "") or "").upper()
            pid = getattr(conn, "pid", None)

            protocol = (
                "TCP" if conn_type == socket.SOCK_STREAM
                else "UDP" if conn_type == socket.SOCK_DGRAM
                else "OTHER"
            )
            if protocol == "TCP":
                tcp_count += 1
            elif protocol == "UDP":
                udp_count += 1

            if not raddr:
                continue

            r_ip = str(getattr(raddr, "ip", "") or "")
            r_port = int(getattr(raddr, "port", 0) or 0)
            l_ip = str(getattr(laddr, "ip", "") or "") if laddr else ""
            l_port = int(getattr(laddr, "port", 0) or 0) if laddr else 0

            is_ext = is_external_ip(r_ip) if r_ip else False
            proc_name = get_process_name(pid)

            if r_ip:
                destination_ips.add(r_ip)
            if r_port:
                destination_ports.add(r_port)
            if is_ext:
                external_count += 1
                if r_ip:
                    external_ips.add(r_ip)

            events.append(
                {
                    "timestamp": timestamp,
                    "src_ip": l_ip,
                    "src_port": l_port,
                    "dst_ip": r_ip,
                    "dst_port": r_port,
                    "protocol": protocol,
                    "state": status,
                    "pid": pid,
                    "process": proc_name,
                    "external": is_ext,
                }
            )

        features: dict[str, Any] = {
            "network_connection_count": len(events),
            "unique_destination_ips": len(destination_ips),
            "external_connection_count": external_count,
            "unique_external_ips": len(external_ips),
            "unique_destination_ports": len(destination_ports),
            "tcp_connection_count": tcp_count,
            "udp_connection_count": udp_count,
            "after_hours_network_activity": is_after_hours(),
        }
        return events, features

    def _interface_summaries(self) -> list[dict[str, Any]]:
        stats = psutil.net_if_stats()
        counters = psutil.net_io_counters(pernic=True)
        addresses = self._safe_net_if_addrs()
        summaries: list[dict[str, Any]] = []
        for name, stat in sorted(stats.items()):
            io = counters.get(name)
            summaries.append(
                {
                    "name": name,
                    "is_up": bool(stat.isup),
                    "speed_mbps": int(stat.speed or 0),
                    "mtu": int(stat.mtu or 0),
                    "bytes_sent": int(getattr(io, "bytes_sent", 0) if io else 0),
                    "bytes_recv": int(getattr(io, "bytes_recv", 0) if io else 0),
                    "packets_sent": int(getattr(io, "packets_sent", 0) if io else 0),
                    "packets_recv": int(getattr(io, "packets_recv", 0) if io else 0),
                    "errors_in": int(getattr(io, "errin", 0) if io else 0),
                    "errors_out": int(getattr(io, "errout", 0) if io else 0),
                    "dropin": int(getattr(io, "dropin", 0) if io else 0),
                    "dropout": int(getattr(io, "dropout", 0) if io else 0),
                    "duplex": str(getattr(stat, "duplex", "")),
                    "flags": str(getattr(stat, "flags", "") or ""),
                    "addresses": self._interface_addresses(addresses, name),
                }
            )
        return summaries

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Collect Level 1 network connections and behavioral statistics."""
        if psutil is None:
            return self.unsupported("psutil library is not installed")

        try:
            total = psutil.net_io_counters()
            interfaces = self._interface_summaries()
            connections = self._safe_net_connections()
            now_iso = self._utc_now_iso()

            events, net_features = self._extract_connections_and_features(connections, now_iso)

            features: dict[str, Any] = {
                "collected_at": now_iso,
                "hostname": socket.gethostname(),
                "network_interface_count": len(interfaces),
                "network_interfaces_up_count": sum(1 for item in interfaces if item["is_up"]),
                "network_bytes_sent": int(total.bytes_sent),
                "network_bytes_recv": int(total.bytes_recv),
                "network_packets_sent": int(total.packets_sent),
                "network_packets_recv": int(total.packets_recv),
                "network_errors_in": int(total.errin),
                "network_errors_out": int(total.errout),
                "network_dropin": int(total.dropin),
                "network_dropout": int(total.dropout),
                "network_interfaces": interfaces,
            }
            # Add legacy count aggregations
            features.update(self._connection_counts(connections))
            # Add new behavioral features
            features.update(net_features)
            # Add raw connection list (capped at 200 to prevent unbounded payload size)
            features["network_connections"] = events[:200]

            log.info(
                "Network collection successful: %d connections (%d external)",
                len(events),
                net_features["external_connection_count"],
            )
            return self.success(features)
        except Exception as exc:
            log.error("Network collection failed: %s", exc)
            return self.failed(exc)


def collect_features() -> dict[str, Any]:
    """Legacy backward-compatible entry point expected by tests and PythonModuleCollector."""
    result = NetworkMonitor().collect()
    return result.payload if result.status == "success" else result.as_dict()


def collect() -> dict[str, Any]:
    """Entry point for the PythonModuleCollector adapter."""
    return NetworkMonitor().collect().as_dict()


if __name__ == "__main__":
    import json
    print(json.dumps(collect(), indent=2))
