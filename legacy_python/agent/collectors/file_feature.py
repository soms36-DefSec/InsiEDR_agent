from __future__ import annotations

import atexit
import hashlib
import json
import logging
import math
import os
import threading
from collections import Counter, defaultdict
from datetime import datetime, time as dtime, timezone
from pathlib import Path
from typing import Any

from agent.state import default_state_dir, read_json_file, write_json_file


try:
    import psutil
except ImportError:
    psutil = None

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
except ImportError:
    FileSystemEventHandler = object
    Observer = None


log = logging.getLogger("file_feature")


def _watch_paths() -> list[str]:
    configured = os.getenv("INSIEDR_FILE_WATCH_PATHS")
    if configured:
        return [item.strip() for item in configured.split(os.pathsep) if item.strip()]
    return [str(Path.home())]


CONFIG = {
    "watch_paths": _watch_paths(),
    "business_hours": (dtime(9, 0), dtime(18, 0)),
    "large_file_bytes": int(os.getenv("INSIEDR_LARGE_FILE_BYTES", str(50 * 1024 * 1024))),
    "sensitive_patterns": ["confidential", "secret", "payroll", "salary", "passport", ".pem", ".key"],
    "state_file": default_state_dir() / "file_feature_state.json",
}


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _load_state() -> dict[str, Any]:
    today = datetime.now(timezone.utc).date().isoformat()
    try:
        if CONFIG["state_file"].exists():
            data = read_json_file(CONFIG["state_file"])
            if data.get("date") != today:
                data = {} # Reset for new day
            else:
                hashes = data.get("known_file_hashes", [])
                return {
                    "date": today,
                    "known_file_hashes": [str(item) for item in hashes if isinstance(item, str)],
                    "previous_access_count": int(data.get("previous_access_count", 0) or 0),
                    "daily_counts": data.get("daily_counts", {})
                }
    except Exception as exc:
        log.warning("file collector state load failed; starting with empty state: %s", exc)
    return {"date": today, "known_file_hashes": [], "previous_access_count": 0, "daily_counts": {}}


def _save_state(state: dict[str, Any]) -> None:
    try:
        write_json_file(CONFIG["state_file"], state)
    except Exception as exc:
        log.warning("file collector state save failed: %s", exc)


class FileEventCollector(FileSystemEventHandler):
    def __init__(self) -> None:
        super().__init__()
        self._lock = threading.Lock()
        self.events: list[dict[str, Any]] = []

    def _record(self, op: str, path: str, is_dir: bool = False) -> None:
        if is_dir:
            return
        try:
            size = os.path.getsize(path) if os.path.exists(path) else 0
        except OSError:
            size = 0
        with self._lock:
            self.events.append(
                {
                    "op": op,
                    "path": path,
                    "size": size,
                    "ts": datetime.now(timezone.utc),
                }
            )

    def on_created(self, event) -> None:
        self._record("CREATE", event.src_path, event.is_directory)

    def on_modified(self, event) -> None:
        self._record("WRITE", event.src_path, event.is_directory)

    def on_deleted(self, event) -> None:
        self._record("DELETE", event.src_path, event.is_directory)

    def on_moved(self, event) -> None:
        self._record("MOVE", event.dest_path, event.is_directory)

    def snapshot(self, *, clear: bool = True) -> list[dict[str, Any]]:
        with self._lock:
            events = list(self.events)
            if clear:
                self.events.clear()
            return events


class FileFeatureSampler:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._handler: FileEventCollector | None = None
        self._observer = None
        self._started = False
        self._start_error = ""

    @property
    def started(self) -> bool:
        return self._started

    @property
    def start_error(self) -> str:
        return self._start_error

    def start(self) -> bool:
        with self._lock:
            if self._started:
                return True
            if Observer is None:
                self._start_error = "watchdog is not installed"
                return False

            handler = FileEventCollector()
            observer = Observer()
            watch_paths = list(CONFIG["watch_paths"])
            if psutil is not None:
                try:
                    for partition in psutil.disk_partitions(all=False):
                        if partition.fstype:
                            rb = os.path.join(partition.mountpoint, "$Recycle.Bin")
                            if os.path.isdir(rb) and rb not in watch_paths:
                                watch_paths.append(rb)
                except Exception as exc:
                    log.warning("failed to enumerate recycle bins: %s", exc)

            for path in watch_paths:
                if os.path.isdir(path):
                    try:
                        observer.schedule(handler, path, recursive=True)
                        scheduled = True
                    except (PermissionError, OSError) as exc:
                        log.debug("skipping restricted path %s: %s", path, exc)
                else:
                    log.info("file watch path is unavailable: %s", path)

            if not scheduled:
                self._start_error = "no valid file watch paths"
                return False

            try:
                observer.start()
            except Exception as exc:
                self._start_error = f"observer start failed: {exc}"
                return False

            self._handler = handler
            self._observer = observer
            self._started = True
            self._start_error = ""
            return True

    def stop(self) -> None:
        with self._lock:
            observer = self._observer
            self._observer = None
            self._handler = None
            self._started = False
        if observer is not None:
            try:
                observer.stop()
                observer.join(timeout=5)
            except Exception:
                log.debug("file observer stop failed", exc_info=True)

    def flush_features(self) -> dict[str, Any]:
        if not self.start():
            data = _empty_features()
            data.update(
                {
                    "_collector_status": "unsupported",
                    "_collector_quality": "unsupported",
                    "_collector_message": f"file background sampler unavailable: {self._start_error}",
                    "_feature_quality": {key: "unsupported" for key in data},
                }
            )
            return data
        handler = self._handler
        events = handler.snapshot(clear=True) if handler is not None else []
        return _aggregate_events(events)


def _get_removable_mounts() -> set[str]:
    mounts: set[str] = set()
    if psutil is None:
        return mounts
    try:
        for partition in psutil.disk_partitions(all=False):
            if "removable" in partition.opts.lower() or "cdrom" in (partition.fstype or "").lower():
                mounts.add(partition.mountpoint.lower())
    except Exception as exc:
        log.warning("removable-drive enumeration failed: %s", exc)
    return mounts


def _empty_features() -> dict[str, Any]:
    return {
        "collected_at": datetime.now(timezone.utc),
        "host": os.environ.get("COMPUTERNAME", os.uname().nodename if hasattr(os, "uname") else "unknown"),
        "file_access_count": 0,
        "file_open_count": 0,
        "file_copy_count": 0,
        "file_write_count": 0,
        "file_delete_count": 0,
        "sensitive_file_access": 0,
        "external_drive_file_copy": 0,
        "file_access_after_hours": 0,
        "weekend_file_access": 0,
        "large_file_transfer_count": 0,
        "unusual_file_access_ratio": 0.0,
        "daily_files_to_removable_count": 0,
        "daily_removable_media_flag": 0,
        "daily_file_access_entropy": 0.0,
        "daily_unique_filename_count": 0,
        "daily_new_filename_count": 0,
        "daily_file_open_count": 0,
        "daily_file_write_count": 0,
        "daily_file_delete_count": 0,
        "first_file_access_time": None,
        "last_file_access_time": None,
        "recycle_bin_additions_count": 0,
        "recycle_bin_emptied_flag": 0,
        "mass_deletion_burst_count": 0,
        "staging_archive_count": 0,
        "total_staged_bytes": 0,
        "large_staging_burst_flag": 0,
    }


def _aggregate_events(events: list[dict[str, Any]]) -> dict[str, Any]:
    removable = _get_removable_mounts()
    state = _load_state()
    known_hashes_list = state.get("known_file_hashes", [])
    known_hashes = set(known_hashes_list)
    bh_start, bh_end = CONFIG["business_hours"]

    features = _empty_features()
    path_access: Counter[str] = Counter()
    filenames_today: list[str] = []
    seen_writes_by_name: defaultdict[str, int] = defaultdict(int)
    recycle_bin_deletes = 0
    archive_sizes: dict[str, int] = {}
    archive_exts = {".zip", ".rar", ".7z", ".tar", ".gz", ".iso"}

    for event in events:
        op = str(event.get("op", ""))
        path = str(event.get("path", ""))
        size = int(event.get("size", 0) or 0)
        ts = event.get("ts")
        if not isinstance(ts, datetime):
            ts = datetime.now(timezone.utc)

        lowered = path.lower()
        path_access[path] += 1
        filenames_today.append(path)

        is_recycle_bin = "$recycle.bin" in lowered
        ext = os.path.splitext(lowered)[1]
        is_archive = ext in archive_exts

        if is_archive and op in {"CREATE", "WRITE", "MOVE"}:
            archive_sizes[path] = max(archive_sizes.get(path, 0), size)

        if op in {"CREATE", "MOVE"}:
            if is_recycle_bin:
                features["recycle_bin_additions_count"] += 1
            features["file_open_count"] += 1
            base = os.path.basename(lowered)
            seen_writes_by_name[base] += 1
            if seen_writes_by_name[base] > 1:
                features["file_copy_count"] += 1
        elif op == "WRITE":
            features["file_write_count"] += 1
        elif op == "DELETE":
            features["file_delete_count"] += 1
            if is_recycle_bin:
                recycle_bin_deletes += 1

        if any(pattern in lowered for pattern in CONFIG["sensitive_patterns"]):
            features["sensitive_file_access"] += 1
        if size >= CONFIG["large_file_bytes"]:
            features["large_file_transfer_count"] += 1
        if any(lowered.startswith(mount) for mount in removable):
            features["external_drive_file_copy"] += 1
            features["daily_files_to_removable_count"] += 1

        local_dt = ts.astimezone() if ts.tzinfo is not None else ts
        local_time = local_dt.time()
        if not (bh_start <= local_time <= bh_end):
            features["file_access_after_hours"] += 1
        if local_dt.weekday() >= 5:  # Saturday=5, Sunday=6
            features["weekend_file_access"] += 1

        hashed_path = _hash_value(path)
        if hashed_path not in known_hashes:
            features["daily_new_filename_count"] += 1
            known_hashes.add(hashed_path)
            known_hashes_list.append(hashed_path)

    total = sum(path_access.values())
    entropy = 0.0
    if total > 0:
        entropy = -sum((count / total) * math.log2(count / total) for count in path_access.values())

    previous_access_count = int(state.get("previous_access_count", 0) or 1)
    features["file_access_count"] = len(events)
    features["unusual_file_access_ratio"] = round(len(events) / previous_access_count, 4)

    # Accumulate daily counts
    daily = state.get("daily_counts", {})
    daily["daily_files_to_removable_count"] = daily.get("daily_files_to_removable_count", 0) + features["daily_files_to_removable_count"]
    features["daily_files_to_removable_count"] = daily["daily_files_to_removable_count"]
    features["daily_removable_media_flag"] = 1 if features["daily_files_to_removable_count"] > 0 else 0
    
    features["daily_file_access_entropy"] = round(entropy, 4) # Entropy remains on the 5-min snapshot as it's a rate indicator
    
    daily["daily_unique_filename_count"] = len(known_hashes)
    features["daily_unique_filename_count"] = daily["daily_unique_filename_count"]
    
    daily["daily_file_open_count"] = daily.get("daily_file_open_count", 0) + features["file_open_count"]
    features["daily_file_open_count"] = daily["daily_file_open_count"]
    
    daily["daily_file_write_count"] = daily.get("daily_file_write_count", 0) + features["file_write_count"]
    features["daily_file_write_count"] = daily["daily_file_write_count"]
    
    daily["daily_file_delete_count"] = daily.get("daily_file_delete_count", 0) + features["file_delete_count"]
    features["daily_file_delete_count"] = daily["daily_file_delete_count"]

    # Temporal spread of file activity
    timestamps = [event["ts"] for event in events if isinstance(event.get("ts"), datetime)]
    if timestamps:
        features["first_file_access_time"] = min(timestamps).isoformat()
        features["last_file_access_time"] = max(timestamps).isoformat()

    if recycle_bin_deletes >= 10:
        features["recycle_bin_emptied_flag"] = 1
        
    mass_delete_baseline = 50
    if features["file_delete_count"] > mass_delete_baseline:
        features["mass_deletion_burst_count"] = features["file_delete_count"]

    features["staging_archive_count"] += len(archive_sizes)
    features["total_staged_bytes"] += sum(archive_sizes.values())
    if any(s > 100 * 1024 * 1024 for s in archive_sizes.values()):
        features["large_staging_burst_flag"] = 1

    _save_state(
        {
            "date": state.get("date"),
            "known_file_hashes": known_hashes_list[-10000:],
            "previous_access_count": max(previous_access_count, len(events)),
            "daily_counts": daily,
        }
    )

    feature_quality = {key: "exact" for key in features}
    for key in (
        "file_copy_count",
        "sensitive_file_access",
        "external_drive_file_copy",
        "file_access_after_hours",
        "unusual_file_access_ratio",
        "daily_files_to_removable_count",
        "daily_removable_media_flag",
        "daily_file_access_entropy",
        "daily_new_filename_count",
        "recycle_bin_emptied_flag",
        "mass_deletion_burst_count",
        "staging_archive_count",
        "total_staged_bytes",
        "large_staging_burst_flag",
    ):
        feature_quality[key] = "heuristic"
    features["_collector_quality"] = "heuristic"
    features["_feature_quality"] = feature_quality
    return features


_SAMPLER = FileFeatureSampler()
atexit.register(_SAMPLER.stop)


def start_sampler() -> bool:
    return _SAMPLER.start()


def stop_sampler() -> None:
    _SAMPLER.stop()


def collect_file_features() -> dict[str, Any]:
    return _SAMPLER.flush_features()


def validate_data(features: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key, value in _empty_features().items():
        if key not in features:
            errors.append(f"missing field: {key}")
        elif key != "collected_at" and not isinstance(features[key], type(value)):
            errors.append(f"{key} has wrong type: {type(features[key]).__name__}")
    return errors


def collect() -> dict[str, Any]:
    return collect_file_features()


def collect_features() -> dict[str, Any]:
    return collect()


def main() -> None:
    print(json.dumps(collect_file_features(), indent=2, default=str))


if __name__ == "__main__":
    main()
