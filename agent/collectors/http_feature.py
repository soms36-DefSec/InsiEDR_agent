from __future__ import annotations

import getpass
import hashlib
import json
import logging
import math
import os
import shutil
import sqlite3
import sys
import tempfile
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse

from agent.state import default_state_dir, read_json_file, write_json_file


log = logging.getLogger("http_features")

WORK_HOUR_START = 9
WORK_HOUR_END = 18
INTERNAL_SUFFIXES = (".corp", ".local", ".internal", ".lan")

WATCHLISTED_DOMAINS = {
    "pastebin.com",
    "anonfiles.com",
    "mega.nz",
    "tor2web.org",
    "onion.ws",
    "transfer.sh",
    "ghostbin.com",
    "rentry.co",
}
FILE_SHARING_DOMAINS = {
    "drive.google.com",
    "dropbox.com",
    "onedrive.live.com",
    "wetransfer.com",
    "box.com",
    "mega.nz",
    "mediafire.com",
    "sendspace.com",
    "icloud.com",
}
JOB_SEARCH_DOMAINS = {
    "indeed.com",
    "linkedin.com",
    "glassdoor.com",
    "monster.com",
    "naukri.com",
    "ziprecruiter.com",
    "dice.com",
    "careerbuilder.com",
}

HISTORICAL_DOMAIN_STATE = str(default_state_dir() / "http_known_domain_hashes.json")


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()


def _matches_domain(host: str, domain_set: set[str]) -> bool:
    return any(host == domain or host.endswith("." + domain) for domain in domain_set)


def _browser_history_paths() -> list[str]:
    """Discover browser history database paths specifically on Windows."""
    if sys.platform != "win32":
        return []

    local_app_data = os.environ.get("LOCALAPPDATA")
    app_data = os.environ.get("APPDATA")
    
    paths = []

    if local_app_data:
        chromium_local_paths = [
            os.path.join(local_app_data, "Google", "Chrome", "User Data", "Default", "History"),
            os.path.join(local_app_data, "Microsoft", "Edge", "User Data", "Default", "History"),
            os.path.join(local_app_data, "BraveSoftware", "Brave-Browser", "User Data", "Default", "History"),
            os.path.join(local_app_data, "Vivaldi", "User Data", "Default", "History"),
        ]
        for path in chromium_local_paths:
            if os.path.isfile(path):
                paths.append(path)

    if app_data:
        opera_path = os.path.join(app_data, "Opera Software", "Opera Stable", "History")
        if os.path.isfile(opera_path):
            paths.append(opera_path)
            
        mozilla_bases = [
            os.path.join(app_data, "Mozilla", "Firefox", "Profiles"),
            os.path.join(app_data, "Waterfox", "Profiles"),
            os.path.join(app_data, "Moonchild Productions", "Pale Moon", "Profiles"),
        ]
        
        for base in mozilla_bases:
            if os.path.isdir(base):
                for profile in os.listdir(base):
                    candidate = os.path.join(base, profile, "places.sqlite")
                    if os.path.isfile(candidate):
                        paths.append(candidate)

    return paths


def _safe_copy(src: str) -> str | None:
    import time
    for attempt in range(3):
        try:
            tmp_f = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
            tmp = tmp_f.name
            tmp_f.close()
            shutil.copy2(src, tmp)
            return tmp
        except PermissionError as exc:
            if attempt < 2:
                time.sleep(0.5)
                continue
            log.warning("could not copy browser history database (locked): %s", exc)
            return None
        except Exception as exc:
            log.warning("could not copy browser history database: %s", exc)
            return None
    return None


def _chrome_time_to_local(timestamp: int) -> datetime:
    value = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=timestamp)
    return value.astimezone()


def _firefox_time_to_local(timestamp: int) -> datetime:
    return datetime.fromtimestamp(timestamp / 1_000_000, tz=timezone.utc).astimezone()


def _read_browser_db(path: str) -> tuple[list[tuple[str, datetime]], int]:
    visits: list[tuple[str, datetime]] = []
    downloads = 0
    tmp = _safe_copy(path)
    if not tmp:
        return visits, downloads

    try:
        conn = sqlite3.connect(f"file:{tmp}?mode=ro", uri=True, timeout=5)
        try:
            cur = conn.cursor()
            if path.endswith("History"):
                cur.execute(
                    """
                    SELECT urls.url, visits.visit_time
                    FROM visits JOIN urls ON visits.url = urls.id
                    """
                )
                for url, timestamp in cur.fetchall():
                    try:
                        visits.append((url, _chrome_time_to_local(timestamp)))
                    except Exception as exc:
                        log.debug("skipped Chrome visit with invalid timestamp %s: %s", timestamp, exc)
                try:
                    cur.execute("SELECT COUNT(*) FROM downloads")
                    downloads = int(cur.fetchone()[0])
                except sqlite3.Error:
                    pass
            else:
                cur.execute(
                    """
                    SELECT p.url, h.visit_date
                    FROM moz_historyvisits h JOIN moz_places p ON h.place_id = p.id
                    """
                )
                for url, timestamp in cur.fetchall():
                    try:
                        visits.append((url, _firefox_time_to_local(timestamp)))
                    except Exception as exc:
                        log.debug("skipped Firefox visit with invalid timestamp %s: %s", timestamp, exc)
                try:
                    cur.execute(
                        "SELECT COUNT(*) FROM moz_annos "
                        "WHERE anno_attribute_id IN "
                        "(SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI')"
                    )
                    downloads = int(cur.fetchone()[0])
                except sqlite3.Error:
                    pass
        finally:
            conn.close()
    except Exception as exc:
        log.warning("failed reading browser history database: %s", exc)
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass
    return visits, downloads


def _load_known_domain_hashes() -> set[str]:
    try:
        path = Path(HISTORICAL_DOMAIN_STATE)
        if path.exists():
            data = read_json_file(path)
            return {str(item) for item in data.get("known_domain_hashes", []) if isinstance(item, str)}
    except Exception:
        return set()
    return set()


def _save_known_domain_hashes(domain_hashes: set[str]) -> None:
    try:
        write_json_file(Path(HISTORICAL_DOMAIN_STATE), {"known_domain_hashes": sorted(domain_hashes)[-50000:]})
    except Exception as exc:
        log.warning("could not persist known domain state: %s", exc)


def _domain_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def collect_http_features() -> dict[str, object]:
    all_visits: list[tuple[str, datetime]] = []
    total_downloads = 0

    for db_path in _browser_history_paths():
        visits, downloads = _read_browser_db(db_path)
        all_visits.extend(visits)
        total_downloads += downloads

    today = datetime.now().astimezone().date()
    todays_visits = [(url, ts) for url, ts in all_visits if ts.date() == today]

    all_domains = [_domain_of(url) for url, _ in all_visits if _domain_of(url)]
    today_domains = [_domain_of(url) for url, _ in todays_visits if _domain_of(url)]

    entropy = 0.0
    if today_domains:
        counts = Counter(today_domains)
        total = sum(counts.values())
        entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())

    external = sum(1 for domain in today_domains if not any(domain.endswith(suffix) for suffix in INTERNAL_SUFFIXES))
    external_ratio = (external / len(today_domains)) if today_domains else 0.0

    known_hashes = _load_known_domain_hashes()
    current_hashes = {_hash_value(domain) for domain in today_domains}
    all_hashes = {_hash_value(domain) for domain in all_domains}
    new_domain_hashes = current_hashes - known_hashes
    _save_known_domain_hashes(known_hashes | all_hashes)

    after_hours = sum(
        1
        for _, timestamp in todays_visits
        if timestamp.hour < WORK_HOUR_START or timestamp.hour >= WORK_HOUR_END
    )

    unique_domains = sorted(list(set(all_domains)))
    
    # Format the extracted data as a detailed log for the current collection window (today's visits)
    detailed_activity = []
    for url, ts in todays_visits:
        domain = _domain_of(url)
        if domain:
            detailed_activity.append({
                "site_name": domain,
                "accessed_at": ts.isoformat()
            })

    data: dict[str, object] = {
        "collected_at": datetime.now(timezone.utc),
        "hostname": os.getenv("COMPUTERNAME", "unknown"),
        "username": getpass.getuser(),
        "http_count": len(all_visits),
        "unique_url_count": len({url for url, _ in all_visits}),
        "watchlisted_url_count": sum(1 for domain in all_domains if _matches_domain(domain, WATCHLISTED_DOMAINS)),
        "file_sharing_site_visits": sum(1 for domain in all_domains if _matches_domain(domain, FILE_SHARING_DOMAINS)),
        "job_search_site_visits": sum(1 for domain in all_domains if _matches_domain(domain, JOB_SEARCH_DOMAINS)),
        "download_count": int(total_downloads),
        "upload_count": None,
        "http_after_hours": after_hours,
        "daily_external_domain_ratio": round(external_ratio, 4),
        "daily_domain_access_entropy": round(entropy, 4),
        "daily_http_request_count": len(todays_visits),
        "daily_unique_domain_count": len(set(today_domains)),
        "daily_new_domain_count": len(new_domain_hashes),
        "visited_domains": unique_domains,
        "detailed_browser_activity": detailed_activity,
    }

    feature_quality = {key: "exact" for key in data}
    for key in (
        "watchlisted_url_count",
        "file_sharing_site_visits",
        "job_search_site_visits",
        "upload_count",
        "http_after_hours",
        "daily_external_domain_ratio",
        "daily_domain_access_entropy",
        "daily_new_domain_count",
    ):
        feature_quality[key] = "heuristic" if key != "upload_count" else "unsupported"
    data["_collector_quality"] = "heuristic"
    data["_feature_quality"] = feature_quality
    return data


EXPECTED_TYPES = {
    "collected_at": datetime,
    "hostname": str,
    "username": str,
    "http_count": int,
    "unique_url_count": int,
    "watchlisted_url_count": int,
    "file_sharing_site_visits": int,
    "job_search_site_visits": int,
    "download_count": int,
    "upload_count": type(None),
    "http_after_hours": int,
    "daily_external_domain_ratio": float,
    "daily_domain_access_entropy": float,
    "daily_http_request_count": int,
    "daily_unique_domain_count": int,
    "daily_new_domain_count": int,
    "visited_domains": list,
    "detailed_browser_activity": list,
}


def validate_data(data: dict[str, object]) -> list[str]:
    errors: list[str] = []
    if not data:
        return ["collected data is empty"]
    for field, expected_type in EXPECTED_TYPES.items():
        if field not in data:
            errors.append(f"missing field: {field}")
            continue
        if not isinstance(data[field], expected_type):
            errors.append(f"{field} has wrong type: {type(data[field]).__name__}")
    return errors


def collect() -> dict[str, object]:
    return collect_http_features()


def collect_features() -> dict[str, object]:
    return collect()


def main() -> None:
    print(json.dumps(collect_http_features(), indent=2, default=str))


if __name__ == "__main__":
    main()
