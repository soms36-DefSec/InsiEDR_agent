from __future__ import annotations

from . import _file_fallback
from .base import PythonModuleCollector
from pathlib import Path


name = "file-scanner"
source_filename = "file_feature.py"


def _collector() -> PythonModuleCollector:
    return PythonModuleCollector(
        name=name,
        path=Path(__file__).resolve().parent / source_filename,
        fallback=_file_fallback,
    )


def collect_features():
    return _collector().collect().as_dict()


def collect():
    return collect_features()
