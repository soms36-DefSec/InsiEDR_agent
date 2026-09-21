from __future__ import annotations

from pathlib import Path

from . import _http_fallback
from .base import PythonModuleCollector


name = "browser-history"
source_filename = "http_feature.py"


def _collector() -> PythonModuleCollector:
    return PythonModuleCollector(
        name=name,
        path=Path(__file__).resolve().parent / source_filename,
        fallback=_http_fallback,
    )


def collect_features():
    return _collector().collect().as_dict()


def collect():
    return collect_features()
