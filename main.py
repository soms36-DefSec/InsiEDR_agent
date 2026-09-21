import sys
import os

# --- PyInstaller Hidden Imports ---
# The collectors are loaded dynamically via importlib, so PyInstaller doesn't see their dependencies.
# We explicitly import them here so PyInstaller bundles them into the executable.
try:
    import agent.state
    import agent.privilege
    import agent.quality
    import win32evtlog
    import win32con
    import win32api
    import win32security
    import pywintypes
except ImportError:
    pass
# --------------------------------

from agent.agent import main

if __name__ == '__main__':
    sys.exit(main())
