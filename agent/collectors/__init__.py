from __future__ import annotations

import logging
import os
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .base import BaseCollector, CollectorResult, ComputedMetaFeatureCollector, PythonModuleCollector


log = logging.getLogger(__name__)

_override = os.environ.get("INSIEDR_COLLECTORS_DIR")
COLLECTOR_DIR = Path(_override) if _override else Path(__file__).resolve().parent
DEFAULT_DISCOVERY_COLLECTORS = (
    "short-term-edr",
    "computed-meta-features",
    "devices-feature",
    "file-feature",
    "http-feature",
    "logon",
    "network-monitor",
    "process-events",
    "dns-monitor",
    "persistence-monitor",
    "activity-monitor",
    "integrity-monitor",
    "port-monitor",
    "file-resilience",
    "clipboard-monitor",
    "wmi-integrity",
    "lsass-monitor",
    "wmi-activity",
    "driver-monitor",
    "named-pipe-monitor",
    "usn-monitor",
    "file-integrity-monitor",
    "decoy-monitor",
    "email-monitor",
    "process-watcher",
    "keystroke-collector",
)


def _short_term_fallback(module) -> Mapping[str, Any]:
    raw_events = module.collect_auth_events(module.CONFIG["LOOKBACK_SECONDS"])
    return module.compute_features(raw_events)


def _device_fallback(module) -> Mapping[str, Any]:
    if hasattr(module, "collect"):
        return module.collect()
    return module.derive_features(module.collect_raw_usb_telemetry())


def _file_fallback(module) -> Mapping[str, Any]:
    return module.collect_file_features()


def _http_fallback(module) -> Mapping[str, Any]:
    return module.collect_http_features()


def _logon_fallback(module) -> Mapping[str, Any]:
    target = datetime.now(timezone.utc)
    day_start, day_end = module._build_time_filter(target)
    events = module.query_security_events([4624, 4634, 4647, 4625], day_start, day_end)
    return module.derive_features(events, target)


COLLECTOR_SPECS = {
    "short-term-edr": {
        "filename": "short-Term_EDR_Feature.py",
        "fallback": _short_term_fallback,
        "aliases": {"short-term-edr", "short_term_edr", "short_term_edr_feature", "short-Term_EDR_Feature.py"},
    },
    "computed-meta-features": {
        "filename": "computed_Meta-Features",
        "aliases": {"computed-meta-features", "computed_meta_features", "computed_Meta-Features"},
    },
    "devices-feature": {
        "filename": "devices_feature.py",
        "fallback": _device_fallback,
        "aliases": {"devices-feature", "devices_feature", "devices_feature.py", "device"},
    },
    "file-feature": {
        "filename": "file_feature.py",
        "fallback": _file_fallback,
        "aliases": {"file-feature", "file_feature", "file_feature.py", "file"},
    },
    "http-feature": {
        "filename": "http_feature.py",
        "fallback": _http_fallback,
        "aliases": {"http-feature", "http_feature", "browser-history", "browser_history", "http_feature.py", "http"},
    },
    "logon": {
        "filename": "logon.py",
        "fallback": _logon_fallback,
        "aliases": {"logon", "session-monitor", "session_monitor", "logon.py"},
    },
    "keystroke-collector": {
        "filename": "keystroke_collector.py",
        "aliases": {"keystroke-collector", "keystroke_collector", "keystroke_collector.py"},
    },
    "network-monitor": {
        "filename": "network_monitor.py",
        "aliases": {"network-monitor", "network_monitor", "network_monitor.py"},
    },
    "process-events": {
        "filename": "process_events.py",
        "aliases": {"process-events", "process_events", "process_events.py", "process"},
    },
    "dns-monitor": {
        "filename": "dns_monitor.py",
        "aliases": {"dns-monitor", "dns_monitor", "dns_monitor.py"},
    },
    "persistence-monitor": {
        "filename": "persistence_monitor.py",
        "aliases": {"persistence-monitor", "persistence_monitor", "persistence_monitor.py"},
    },
    "activity-monitor": {
        "filename": "activity_monitor.py",
        "aliases": {"activity-monitor", "activity_monitor", "activity_monitor.py"},
    },
    "integrity-monitor": {
        "filename": "integrity_monitor.py",
        "aliases": {"integrity-monitor", "integrity_monitor", "integrity_monitor.py"},
    },
    "port-monitor": {
        "filename": "port_monitor.py",
        "aliases": {"port-monitor", "port_monitor", "port_monitor.py"},
    },
    "file-resilience": {
        "filename": "file_resilience.py",
        "aliases": {"file-resilience", "file_resilience", "file_resilience.py"},
    },
    "clipboard-monitor": {
        "filename": "clipboard_monitor.py",
        "aliases": {"clipboard-monitor", "clipboard_monitor", "clipboard_monitor.py"},
    },
    "wmi-integrity": {
        "filename": "wmi_integrity.py",
        "aliases": {"wmi-integrity", "wmi_integrity", "wmi_integrity.py"},
    },
    "lsass-monitor": {
        "filename": "lsass_monitor.py",
        "aliases": {"lsass-monitor", "lsass_monitor", "lsass_monitor.py"},
    },
    "wmi-activity": {
        "filename": "wmi_activity.py",
        "aliases": {"wmi-activity", "wmi_activity", "wmi_activity.py"},
    },
    "driver-monitor": {
        "filename": "driver_monitor.py",
        "aliases": {"driver-monitor", "driver_monitor", "driver_monitor.py"},
    },
    "named-pipe-monitor": {
        "filename": "named_pipe_monitor.py",
        "aliases": {"named-pipe-monitor", "named_pipe_monitor", "named_pipe_monitor.py"},
    },
    "usn-monitor": {
        "filename": "usn_monitor.py",
        "aliases": {"usn-monitor", "usn_monitor", "usn_monitor.py"},
    },
    "file-integrity-monitor": {
        "filename": "file_integrity_monitor.py",
        "aliases": {"file-integrity-monitor", "file_integrity_monitor", "file_integrity_monitor.py"},
    },
    "decoy-monitor": {
        "filename": "decoy_monitor.py",
        "aliases": {"decoy-monitor", "decoy_monitor", "decoy_monitor.py"},
    },
    "email-monitor": {
        "filename": "email_monitor.py",
        "aliases": {"email-monitor", "email_monitor", "email_monitor.py"},
    },
    "process-watcher": {
        "filename": "process_watcher.py",
        "aliases": {"process-watcher", "process_watcher", "process_watcher.py"},
    },
}


def _normalize_name(name: str) -> str:
    stem = Path(name.strip()).stem
    return re.sub(r"[^a-z0-9]+", "_", stem.lower()).strip("_")


def _canonical_name(name: str) -> str:
    normalized = _normalize_name(name)
    for canonical, spec in COLLECTOR_SPECS.items():
        names = {canonical, *spec["aliases"]}
        if normalized in {_normalize_name(item) for item in names}:
            return canonical
    return name.strip()


def discover_collectors(
    enabled: Iterable[str] | None = None,
    *,
    collectors_dir: Path | None = None,
    hostname: str | None = None,
    timeout_seconds: int = 30,
) -> list[BaseCollector]:
    base_dir = collectors_dir or COLLECTOR_DIR
    requested = [_canonical_name(item) for item in (enabled or DEFAULT_DISCOVERY_COLLECTORS)]
    collectors: list[BaseCollector] = []

    for name in requested:
        spec = COLLECTOR_SPECS.get(name)
        if spec is None:
            log.warning("unknown collector configured: %s", name)
            continue
        path = base_dir / spec["filename"]
        if name == "computed-meta-features":
            collectors.append(
                ComputedMetaFeatureCollector(path=path, hostname=hostname, timeout_seconds=timeout_seconds)
            )
        else:
            collectors.append(
                PythonModuleCollector(
                    name=name,
                    path=path,
                    hostname=hostname,
                    timeout_seconds=timeout_seconds,
                    fallback=spec.get("fallback"),
                )
            )
    return collectors


def run_collectors(collectors: Iterable[BaseCollector]) -> list[CollectorResult]:
    collector_list = list(collectors)
    results: list[CollectorResult | None] = [None] * len(collector_list)
    is_active: list[bool] = [True] * len(collector_list)
    lock = threading.Lock()
    context: dict[str, Any] = {"results": results}

    def collect_one(index: int, collector: BaseCollector) -> None:
        try:
            result = collector.collect(context)
        except BaseException as exc:
            log.exception("collector wrapper raised unexpectedly: %s", collector.name)
            result = collector.failed(exc)
        with lock:
            if is_active[index] and results[index] is None:
                results[index] = result

    threads: list[threading.Thread] = []
    deadlines: list[float] = []
    started = time.monotonic()
    for index, collector in enumerate(collector_list):
        thread = threading.Thread(
            target=collect_one,
            args=(index, collector),
            name=f"insiedr-collector-{collector.name}",
            daemon=True,
        )
        threads.append(thread)
        deadlines.append(started + max(1, int(getattr(collector, "timeout_seconds", 30))))
        thread.start()

    for index, (collector, thread, deadline) in enumerate(zip(collector_list, threads, deadlines)):
        remaining = max(0.0, deadline - time.monotonic())
        thread.join(remaining)
        if thread.is_alive():
            with lock:
                is_active[index] = False
                if results[index] is None:
                    timeout_seconds = max(1, int(getattr(collector, "timeout_seconds", 30)))
                    results[index] = collector.failed(
                        f"collector exceeded timeout of {timeout_seconds} seconds",
                        error_type="CollectorTimeout",
                        quality="unsupported",
                    )

    return [result if result is not None else collector.failed("collector did not return") for result, collector in zip(results, collector_list)]


__all__ = [
    "BaseCollector",
    "CollectorResult",
    "discover_collectors",
    "run_collectors",
]
