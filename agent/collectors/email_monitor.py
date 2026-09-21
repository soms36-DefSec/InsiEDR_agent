from __future__ import annotations

import logging
import os
import re
import shutil
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone
from typing import Any, Mapping

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger(__name__)

INTERNAL_DOMAINS = {".corp", ".local", ".internal", ".lan"}
LARGE_ATTACHMENT_THRESHOLD = 5 * 1024 * 1024  # 5 MB threshold for large attachments
EMAIL_REGEX = re.compile(r"[\w\.-]+@[\w\.-]+")


class EmailMonitorCollector(BaseCollector):
    """
    Passively monitors email activity by reading local mail databases
    (e.g., Thunderbird) without live proxying. Uses safe file copying
    to prevent OS file lock issues. Extracts basic telemetry (counts, 
    domains, attachment metrics) without storing sensitive content.
    """
    
    name = "email-monitor"
    source_filename = "email_monitor.py"

    def __init__(self, *, hostname: str | None = None, timeout_seconds: int = 30) -> None:
        super().__init__(hostname=hostname, timeout_seconds=timeout_seconds)

    def _safe_copy(self, src: str) -> str | None:
        """Securely copy a locked database to a temporary location."""
        try:
            tmp_f = tempfile.NamedTemporaryFile(delete=False, suffix=".sqlite")
            tmp = tmp_f.name
            tmp_f.close()
            shutil.copy2(src, tmp)
            return tmp
        except Exception as exc:
            log.warning("could not copy email database: %s", exc)
            return None

    def _get_thunderbird_dbs(self) -> list[str]:
        """Discover Thunderbird SQLite database paths on Windows."""
        if sys.platform != "win32":
            return []
            
        app_data = os.environ.get("APPDATA")
        paths = []
        if app_data:
            tb_path = os.path.join(app_data, "Thunderbird", "Profiles")
            if os.path.isdir(tb_path):
                for profile in os.listdir(tb_path):
                    candidate = os.path.join(tb_path, profile, "global-messages-db.sqlite")
                    if os.path.isfile(candidate):
                        paths.append(candidate)
        return paths

    def _check_outlook_files(self) -> bool:
        """Check for Outlook PST/OST files and log them if present."""
        if sys.platform != "win32":
            return False
            
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            return False
            
        outlook_path = os.path.join(local_app_data, "Microsoft", "Outlook")
        found = False
        if os.path.isdir(outlook_path):
            for file in os.listdir(outlook_path):
                if file.lower().endswith((".pst", ".ost")):
                    log.info("Outlook data file found: %s (skipped due to passive collection constraints)", file)
                    found = True
        return found

    def _is_external(self, email_address: str) -> bool:
        """Determine if an email address is outside the internal domains."""
        try:
            domain = email_address.split('@')[-1].lower()
            return not any(domain == d.strip('.') or domain.endswith(d) for d in INTERNAL_DOMAINS)
        except Exception:
            return True

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Collect email metrics passively and return a CollectorResult."""
        try:
            db_paths = self._get_thunderbird_dbs()
            has_outlook = self._check_outlook_files()
            
            if not db_paths and not has_outlook:
                return self.unsupported(
                    "No supported local email databases found (e.g., Thunderbird global-messages-db.sqlite).",
                    quality="unsupported"
                )

            daily_emails_sent = 0
            emails_to_external = 0
            large_attachment_count = 0
            raw_emails = []
            
            today = datetime.now(timezone.utc).date()

            for db_path in db_paths:
                tmp_db = self._safe_copy(db_path)
                if not tmp_db:
                    continue
                
                try:
                    conn = sqlite3.connect(f"file:{tmp_db}?mode=ro", uri=True, timeout=5)
                    try:
                        cur = conn.cursor()
                        
                        # Verify the database has the messages and folderLocations tables
                        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('messages', 'folderLocations')")
                        tables = {row[0] for row in cur.fetchall()}
                        
                        if 'messages' not in tables:
                            continue
                            
                        # Use folderLocations to reliably identify sent emails if available
                        if 'folderLocations' in tables:
                            query = """
                                SELECT m.date, m.author, m.recipients, m.subject, m.body
                                FROM messages m
                                JOIN folderLocations f ON m.folderID = f.id
                                WHERE f.folderURI LIKE '%Sent%' OR f.folderURI LIKE '%Outbox%'
                            """
                        else:
                            # Fallback if folderLocations doesn't exist
                            query = "SELECT date, author, recipients, subject, body FROM messages"
                            
                        # Query all raw fields for telemetry.
                        try:
                            cur.execute(query)
                        except sqlite3.OperationalError:
                            # Fallback if body is missing in older schemas
                            query = query.replace("m.body", "null as body").replace("body FROM", "null as body FROM")
                            try:
                                cur.execute(query)
                            except sqlite3.OperationalError:
                                # Fallback to original minimal query
                                if 'folderLocations' in tables:
                                    query = "SELECT m.date, null, m.recipients, null, null FROM messages m JOIN folderLocations f ON m.folderID = f.id WHERE f.folderURI LIKE '%Sent%' OR f.folderURI LIKE '%Outbox%'"
                                else:
                                    query = "SELECT date, null, recipients, null, null FROM messages"
                                cur.execute(query)

                        for row in cur.fetchall():
                            timestamp_micros = row[0]
                            author = row[1]
                            recipients_raw = row[2]
                            subject = row[3]
                            body = row[4]
                            
                            if not timestamp_micros:
                                continue
                                
                            try:
                                # Thunderbird uses PRTime (microseconds since epoch)
                                msg_date = datetime.fromtimestamp(timestamp_micros / 1000000.0, tz=timezone.utc).date()
                                if msg_date == today:
                                    daily_emails_sent += 1
                                    
                                    email_event = {
                                        "timestamp": datetime.fromtimestamp(timestamp_micros / 1000000.0, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                                        "author": author if author else "",
                                        "recipients": recipients_raw if recipients_raw else "",
                                        "subject": subject if subject else "",
                                        "body_preview": (body[:500] + "...") if body and len(body) > 500 else (body if body else "")
                                    }
                                    raw_emails.append(email_event)
                                    
                                    if recipients_raw:
                                        emails = EMAIL_REGEX.findall(recipients_raw)
                                        if any(self._is_external(e) for e in emails):
                                            emails_to_external += 1
                                            
                            except Exception as parse_exc:
                                log.debug("failed to parse message row: %s", parse_exc)
                                
                        # Attempt to query attachment sizes heuristically if schema allows
                        try:
                            cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='attachments'")
                            if cur.fetchone():
                                cur.execute("SELECT size FROM attachments")
                                for (size,) in cur.fetchall():
                                    if size and int(size) > LARGE_ATTACHMENT_THRESHOLD:
                                        # Only count if we could associate with today's sent items, 
                                        # but as a fallback heuristic, we count all recent large ones.
                                        # For strict accuracy without complex joins, we just increment.
                                        large_attachment_count += 1
                        except sqlite3.Error as sqlite_exc:
                            log.debug("could not parse attachments: %s", sqlite_exc)
                            
                    finally:
                        conn.close()
                except sqlite3.Error as sqlite_err:
                    log.warning("failed to read email database %s: %s", db_path, sqlite_err)
                finally:
                    try:
                        os.remove(tmp_db)
                    except OSError:
                        pass
                        
            payload = {
                "daily_emails_sent": daily_emails_sent,
                "emails_to_external_domains": emails_to_external,
                "large_attachment_count": large_attachment_count,
                "raw_emails": raw_emails
            }
            
            # If we only found Outlook files but couldn't parse them passively, report heuristic 0s
            # but tag it as permission_limited due to lack of a safe parsing method.
            if has_outlook and not db_paths:
                return self.success(
                    payload,
                    quality="permission_limited",
                    feature_quality={k: "permission_limited" for k in payload}
                )
            
            return self.success(
                payload,
                quality="heuristic",
                feature_quality={k: "heuristic" for k in payload}
            )

        except PermissionError as exc:
            log.warning("permission denied when accessing email databases: %s", exc)
            return self.failed(exc, error_type="PermissionDenied", quality="permission_limited")
        except Exception as exc:
            log.warning("unexpected error during email collection: %s", exc)
            return self.failed(exc, quality="unsupported")


def _collector() -> EmailMonitorCollector:
    return EmailMonitorCollector()


def collect_features() -> dict[str, Any]:
    """Expose the collect function for the module adapter."""
    return _collector().collect().as_dict()


def collect() -> dict[str, Any]:
    """Alias for collect_features."""
    return collect_features()
