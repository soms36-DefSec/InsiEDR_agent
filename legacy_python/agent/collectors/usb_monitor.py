from __future__ import annotations

from pathlib import Path

from . import _device_fallback
from .base import PythonModuleCollector


name = "usb-monitor"
source_filename = "devices_feature.py"


def _collector() -> PythonModuleCollector:
    return PythonModuleCollector(
        name=name,
        path=Path(__file__).resolve().parent / source_filename,
        fallback=_device_fallback,
    )


def collect_features():
    return _collector().collect().as_dict()


def collect():
    return collect_features()
