from __future__ import annotations

from pathlib import Path

from . import _logon_fallback
from .base import PythonModuleCollector


name = "session-monitor"
source_filename = "logon.py"


def _collector() -> PythonModuleCollector:
    return PythonModuleCollector(
        name=name,
        path=Path(__file__).resolve().parent / source_filename,
        fallback=_logon_fallback,
    )


def collect_features():
    return _collector().collect().as_dict()


def collect():
    return collect_features()
