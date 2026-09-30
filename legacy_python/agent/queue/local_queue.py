from __future__ import annotations

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Mapping

from agent.fs_utils import safe_replace
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class QueueItem:
    path: Path
    body: dict[str, Any]

    @property
    def payload_id(self) -> str:
        envelope = self.body.get("envelope") if isinstance(self.body, dict) else {}
        return str(self.body.get("payload_id") or (envelope or {}).get("payload_id") or self.path.stem)


class LocalEncryptedQueue:
    """File-backed queue for already encrypted payload envelopes."""

    suffix = ".json"

    def __init__(
        self,
        queue_dir: str | Path,
        *,
        max_items: int = 1000,
        max_bytes: int = 100 * 1024 * 1024,
        max_age_days: int = 30,
    ) -> None:
        self.queue_dir = Path(queue_dir).expanduser()
        self.dead_letter_dir = self.queue_dir / "dead_letter"
        self.max_items = max_items
        self.max_bytes = max_bytes
        self.max_age_days = max_age_days
        self.queue_dir.mkdir(parents=True, exist_ok=True)
        self.dead_letter_dir.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.queue_dir, 0o700)
            os.chmod(self.dead_letter_dir, 0o700)
        except OSError:
            pass

    def enqueue(self, envelope: Mapping[str, Any], headers: Mapping[str, str] | None = None) -> Path:
        self._validate_envelope(envelope)
        if headers is not None and not isinstance(headers, Mapping):
            raise ValueError("queue headers must be an object")
        created = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        payload_id = str(envelope.get("payload_id") or uuid.uuid4())
        filename = f"{created}-{payload_id}-{uuid.uuid4().hex}{self.suffix}"
        final_path = self.queue_dir / filename
        tmp_path = final_path.with_suffix(".tmp")
        body = {
            "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "payload_id": payload_id,
            "headers": dict(headers or {}),
            "envelope": dict(envelope),
        }
        with tmp_path.open("w", encoding="utf-8") as fh:
            json.dump(body, fh, sort_keys=True, separators=(",", ":"))
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        safe_replace(tmp_path, final_path)
        try:
            os.chmod(final_path, 0o600)
        except OSError:
            pass
        self._enforce_bounds()
        return final_path

    def iter_items(self, *, limit: int | None = None) -> Iterator[QueueItem]:
        self._expire_old_items()
        yielded = 0
        for path in sorted(self.queue_dir.glob(f"*{self.suffix}")):
            if limit is not None and yielded >= limit:
                return
            try:
                with path.open("r", encoding="utf-8") as fh:
                    body = json.load(fh)
                if not isinstance(body, dict) or not isinstance(body.get("envelope"), dict):
                    raise ValueError("queue file does not contain an encrypted envelope")
                if not isinstance(body.get("headers", {}), dict):
                    raise ValueError("queue file headers must be an object")
                self._validate_envelope(body["envelope"])
            except Exception as exc:
                log.warning("ignoring corrupt queue file %s: %s", path.name, exc)
                try:
                    import uuid as _uuid
                    dead_path = self.dead_letter_dir / f"{path.name}.invalid-{_uuid.uuid4().hex}"
                    safe_replace(path, dead_path)
                except OSError:
                    try:
                        path.unlink()
                    except OSError:
                        pass
                continue
            yielded += 1
            yield QueueItem(path=path, body=body)

    def delete(self, item: QueueItem | Path) -> None:
        path = item.path if isinstance(item, QueueItem) else Path(item)
        try:
            path.unlink()
        except FileNotFoundError:
            pass

    def count(self) -> int:
        return sum(1 for _ in self.queue_dir.glob(f"*{self.suffix}"))

    def dead_letter_count(self) -> int:
        return sum(1 for path in self.dead_letter_dir.iterdir() if path.is_file())

    def disk_usage_bytes(self) -> int:
        return sum(path.stat().st_size for path in self.queue_dir.glob(f"*{self.suffix}") if path.is_file())

    def enqueue_dead_letter(
        self,
        envelope: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
        *,
        reason: str,
    ) -> Path:
        path = self.enqueue(envelope, headers)
        return self._move_to_dead_letter(path, reason=reason)

    def dead_letter(self, item: QueueItem | Path, *, reason: str) -> Path:
        path = item.path if isinstance(item, QueueItem) else Path(item)
        return self._move_to_dead_letter(path, reason=reason)

    @staticmethod
    def _validate_envelope(envelope: Mapping[str, Any]) -> None:
        if not isinstance(envelope, Mapping):
            raise ValueError("encrypted envelope must be an object")
        scheme = envelope.get("scheme")
        if scheme not in ("aes-256-gcm", "hpke"):
            raise ValueError(f"queue only accepts AES-GCM or HPKE encrypted envelopes, got {scheme}")
        if not envelope.get("nonce") or not envelope.get("ciphertext"):
            raise ValueError("encrypted envelope is missing nonce or ciphertext")
        if scheme == "hpke" and not envelope.get("encapped_key"):
            raise ValueError("HPKE encrypted envelope is missing encapped_key")

    def _expire_old_items(self) -> None:
        cutoff = datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        # 1. Expire active queue items
        for path in sorted(self.queue_dir.glob(f"*{self.suffix}")):
            try:
                ts_str = path.name.split("-")[0]
                created_at = datetime.strptime(ts_str, "%Y%m%dT%H%M%S%fZ").replace(tzinfo=timezone.utc)
                if created_at < cutoff:
                    self._move_to_dead_letter(path, reason="expired")
            except (ValueError, IndexError):
                try:
                    with path.open("r", encoding="utf-8") as fh:
                        body = json.load(fh)
                    created_at = datetime.fromisoformat(str(body["created_at"]).replace("Z", "+00:00"))
                    if created_at.tzinfo is None:
                        created_at = created_at.replace(tzinfo=timezone.utc)
                    if created_at < cutoff:
                        self._move_to_dead_letter(path, reason="expired")
                except Exception:
                    continue
                
        # 2. Prune dead letter directory to prevent infinite disk exhaustion
        cutoff_timestamp = cutoff.timestamp()
        for path in self.dead_letter_dir.iterdir():
            if not path.is_file():
                continue
            try:
                if path.stat().st_mtime < cutoff_timestamp:
                    path.unlink()
            except OSError:
                pass

    def _enforce_bounds(self) -> None:
        self._expire_old_items()
        
        paths_with_sizes = []
        current_bytes = 0
        for path in self.queue_dir.glob(f"*{self.suffix}"):
            if not path.is_file():
                continue
            try:
                size = path.stat().st_size
                paths_with_sizes.append((path, size))
                current_bytes += size
            except OSError:
                pass
                
        paths_with_sizes.sort(key=lambda x: x[0].name)
        paths_count = len(paths_with_sizes)
        
        pop_idx = 0
        while paths_count > self.max_items or current_bytes > self.max_bytes:
            if pop_idx >= len(paths_with_sizes):
                break
            oldest_path, oldest_size = paths_with_sizes[pop_idx]
            self._move_to_dead_letter(oldest_path, reason="queue_limit")
            current_bytes -= oldest_size
            paths_count -= 1
            pop_idx += 1

    def _move_to_dead_letter(self, path: Path, *, reason: str) -> Path:
        safe_reason = "".join(char if char.isalnum() or char in "-_" else "_" for char in reason)
        dead_path = self.dead_letter_dir / f"{path.name}.{safe_reason}-{uuid.uuid4().hex}"
        try:
            safe_replace(path, dead_path)
            try:
                os.chmod(dead_path, 0o600)
            except OSError:
                pass
            return dead_path
        except OSError:
            try:
                path.unlink()
            except OSError:
                pass
            return dead_path
