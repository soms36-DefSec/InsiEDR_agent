import logging
import threading
import time
from typing import Any, Mapping

try:
    from pynput import keyboard
except ImportError:
    keyboard = None

from agent.collectors.base import BaseCollector, CollectorResult

log = logging.getLogger("keystroke_collector")

class KeystrokeCollector(BaseCollector):
    """
    Captures keystroke timings (Hold-Time, Flight-Time) without capturing characters.
    Used for Continuous Biometric Authentication.
    """
    name = "keystroke-collector"

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._key_timings = []
        self._current_keys = {}
        self._last_keyup_time = None
        self._listener = None
        self._lock = threading.Lock()
        self._start_listener()

    def _on_press(self, key):
        t = time.time()
        key_str = str(key)
        if key_str not in self._current_keys:
            self._current_keys[key_str] = t

    def _on_release(self, key):
        t = time.time()
        key_str = str(key)
        if key_str in self._current_keys:
            press_time = self._current_keys.pop(key_str)
            hold_time = t - press_time
            flight_time = 0.0
            if self._last_keyup_time is not None:
                flight_time = press_time - self._last_keyup_time
            
            self._last_keyup_time = t
            
            with self._lock:
                # We store as (Hold-Time, Flight-Time)
                self._key_timings.append((hold_time, flight_time))
                # Keep batch size manageable to avoid memory leaks if not collected
                if len(self._key_timings) > 2000:
                    self._key_timings = self._key_timings[-2000:]

    def _start_listener(self):
        if keyboard is None:
            log.warning("pynput not installed. Keystroke collection disabled.")
            return
        
        self._listener = keyboard.Listener(
            on_press=self._on_press,
            on_release=self._on_release)
        self._listener.daemon = True
        self._listener.start()

    def stop(self):
        if self._listener:
            self._listener.stop()

    def collect(self, context: Mapping[str, Any] | None = None) -> CollectorResult:
        if keyboard is None:
            return self.unsupported("Keystroke collector requires pynput.")

        with self._lock:
            timings = list(self._key_timings)
            self._key_timings.clear()

        payload = {
            "keystroke_timings": timings,
            "count": len(timings)
        }
        
        return self.success(payload, quality="exact")

_instance = None

def collect(context: Mapping[str, Any] | None = None) -> Any:
    global _instance
    if _instance is None:
        _instance = KeystrokeCollector()
    res = _instance.collect(context)
    if res.status == "success":
        return res.payload
    return {
        "_collector_status": res.status,
        "_collector_message": res.error.get("message", "") if res.error else "failed"
    }

def stop() -> None:
    global _instance
    if _instance is not None:
        _instance.stop()
