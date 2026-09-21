from __future__ import annotations

import importlib.util
import logging
import re
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType
from typing import Any, Callable, Mapping

from agent.quality import default_feature_quality, validate_feature_quality, validate_quality_value


log = logging.getLogger(__name__)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (set, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    
    # Robustness against Mock objects in tests
    if hasattr(value, "__dict__") and "_mock_return_value" in getattr(value, "__dict__", {}):
        return str(value)
    if hasattr(value, "adapted") and not hasattr(value, "_mock_return_value"):
        return json_safe(getattr(value, "adapted"))
    
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"unsupported collector payload value type: {type(value).__name__}")


@dataclass
class CollectorResult:
    collector: str
    collected_at: str
    hostname: str
    status: str
    quality: str = "exact"
    payload: dict[str, Any] | None = None
    error: dict[str, str] | None = None
    feature_quality: dict[str, str] | None = None

    def as_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "collector": self.collector,
            "collected_at": self.collected_at,
            "hostname": self.hostname,
            "status": self.status,
            "quality": validate_quality_value(self.quality),
        }
        if self.payload is not None:
            data["payload"] = json_safe(self.payload)
        if self.feature_quality is not None:
            data["feature_quality"] = validate_feature_quality(self.feature_quality)
        if self.error is not None:
            data["error"] = self.error
        return data


class BaseCollector(ABC):
    name = "base"
    source_filename = ""

    def __init__(self, *, hostname: str | None = None, timeout_seconds: int = 30) -> None:
        self.hostname = hostname or socket.gethostname()
        self.timeout_seconds = timeout_seconds

    @abstractmethod
    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        """Collect features and return a wrapped result."""

    def _result(
        self,
        *,
        status: str,
        payload: Mapping[str, Any] | None = None,
        error: dict[str, str] | None = None,
        quality: str = "exact",
        feature_quality: Mapping[str, str] | None = None,
    ) -> CollectorResult:
        cleaned_payload = dict(json_safe(payload or {})) if payload is not None else None
        validate_quality_value(quality)
        validated_feature_quality = (
            validate_feature_quality(feature_quality)
            if feature_quality is not None
            else default_feature_quality(cleaned_payload or {}, quality)
            if cleaned_payload is not None
            else {}
        )
        return CollectorResult(
            collector=self.name,
            collected_at=utc_now_iso(),
            hostname=self.hostname,
            status=status,
            quality=quality,
            payload=cleaned_payload,
            error=error,
            feature_quality=validated_feature_quality,
        )

    def success(
        self,
        payload: Mapping[str, Any],
        *,
        quality: str = "exact",
        feature_quality: Mapping[str, str] | None = None,
    ) -> CollectorResult:
        return self._result(
            status="success",
            payload=payload,
            quality=quality,
            feature_quality=feature_quality,
        )

    def unsupported(
        self,
        message: str,
        *,
        quality: str = "unsupported",
        payload: Mapping[str, Any] | None = None,
        error_type: str = "CollectorUnsupported",
    ) -> CollectorResult:
        return self._result(
            status="unsupported",
            payload=payload,
            quality=quality,
            error={"type": error_type, "message": message},
        )

    def failed(
        self,
        exc: BaseException | str,
        *,
        error_type: str | None = None,
        quality: str = "unsupported",
    ) -> CollectorResult:
        if isinstance(exc, BaseException):
            error = {"type": error_type or exc.__class__.__name__, "message": str(exc)}
        else:
            error = {"type": error_type or "CollectorError", "message": exc}
        return self._result(
            status="failed",
            error=error,
            quality=quality,
        )


def _module_name_from_path(path: Path) -> str:
    safe = re.sub(r"\W+", "_", path.stem).strip("_").lower()
    return f"insiedr_collector_{safe}"


class PythonModuleCollector(BaseCollector):
    """Adapter for existing collector scripts, including hyphenated filenames."""

    def __init__(
        self,
        *,
        name: str,
        path: Path,
        hostname: str | None = None,
        timeout_seconds: int = 30,
        function_names: tuple[str, ...] = ("collect_features", "collect"),
        fallback: Callable[[ModuleType], Mapping[str, Any]] | None = None,
    ) -> None:
        super().__init__(hostname=hostname, timeout_seconds=timeout_seconds)
        self.name = name
        self.source_filename = path.name
        self.path = path
        self.function_names = function_names
        self.fallback = fallback
        self._module: ModuleType | None = None

    def _load_module(self) -> ModuleType:
        # Return the cached module on subsequent collection cycles to avoid
        # polluting sys.modules with a fresh duplicate entry every 5 minutes.
        if self._module is not None:
            return self._module
        if not self.path.is_file():
            raise FileNotFoundError(str(self.path))
        spec = importlib.util.spec_from_file_location(_module_name_from_path(self.path), self.path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot build import spec for {self.path.name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
        except BaseException:
            sys.modules.pop(spec.name, None)
            raise
        self._module = module
        return module

    def _call_module(self, module: ModuleType) -> Mapping[str, Any]:
        for function_name in self.function_names:
            candidate = getattr(module, function_name, None)
            if callable(candidate):
                result = candidate()
                if isinstance(result, Mapping):
                    return result
                if isinstance(result, list):
                    return {"items": result}
                raise TypeError(
                    f"collector {self.source_filename} returned unsupported payload type: "
                    f"{type(result).__name__}"
                )
        if self.fallback is not None:
            return self.fallback(module)
        raise AttributeError(f"collector {self.source_filename} has no callable collection entry point")

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        del context
        try:
            module = self._load_module()
            payload = self._call_module(module)
            payload_data = dict(payload)
            
            if "status" in payload_data and "payload" in payload_data and "collector" in payload_data:
                status = str(payload_data.pop("status", "success"))
                quality = str(payload_data.pop("quality", "exact"))
                feature_quality = payload_data.pop("feature_quality", None)
                payload_data = payload_data.get("payload") or {}
            else:
                status = str(payload_data.pop("_collector_status", "success"))
                quality = str(payload_data.pop("_collector_quality", "exact"))
                feature_quality = payload_data.pop("_feature_quality", None)
                
            if status == "unsupported":
                return self.unsupported(
                    str(payload_data.pop("_collector_message", "collector is unsupported")),
                    quality=quality,
                    payload=payload_data,
                )
            if status == "failed":
                return self.failed(
                    str(payload_data.pop("_collector_message", "collector failed")),
                    quality=quality,
                )
            return self.success(payload_data, quality=quality, feature_quality=feature_quality)
        except BaseException as exc:
            log.warning("collector %s failed: %s", self.name, exc)
            return self.failed(exc)

    def stop(self) -> None:
        if self._module is None:
            return
        stop = getattr(self._module, "stop_sampler", None)
        if callable(stop):
            stop()


class ComputedMetaFeatureCollector(BaseCollector):
    name = "computed-meta-features"
    source_filename = "computed_Meta-Features"

    def __init__(self, *, path: Path, hostname: str | None = None, timeout_seconds: int = 30) -> None:
        super().__init__(hostname=hostname, timeout_seconds=timeout_seconds)
        self.path = path

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        del context
        if not self.path.exists():
            return self.failed(f"spec file missing: {self.path.name}")
        payload = {
            "spec_file": self.path.name,
            "status": "server_deferred",
            "server_deferred_features": [
                "daily_files_to_removable_7d_sum",
            ],
            "reason": "The endpoint emits collection features only; long-window derivations are computed from received telemetry outside the agent.",
        }
        return self.success(
            payload,
            quality="server_deferred",
            feature_quality={key: "server_deferred" for key in payload},
        )
