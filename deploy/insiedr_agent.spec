# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ["../main.py"],
    pathex=[".."],
    binaries=[],
    datas=[
        ("../agent/collectors/*.py", "agent/collectors"),
        ("../agent/collectors/computed_Meta-Features", "agent/collectors"),
        ("../agent/watchdog.py", "agent"),
    ],
    hiddenimports=[
        "win32api", "win32con", "win32event", "win32security",
        "win32evtlog", "win32evtlogutil", "win32service",
        "win32serviceutil", "servicemanager", "pywintypes",
        "win32com", "win32com.client", "win32com.shell", "win32com.shell.shell",
        "pythoncom",
        "psutil", "psutil._pswindows",
        "watchdog.observers", "watchdog.observers.winapi",
        "watchdog.events",
        "cryptography.hazmat.primitives.ciphers.aead",
        "cryptography.hazmat.backends.openssl",
        "requests", "urllib3", "certifi",
        "dotenv",
        "sqlite3", "xml.etree", "xml.etree.ElementTree", "pynput",
        "pynput.keyboard._win32", "pynput.mouse._win32",
    ],
    hookspath=["deploy/hooks"],
    runtime_hooks=["deploy/hooks/rthook_collectors.py"],
    excludes=[
        "flask", "werkzeug", "sqlalchemy", "alembic",
        "torch", "numpy", "pandas", "scipy",
        "sklearn", "xgboost", "joblib",
        "matplotlib", "seaborn", "notebook", "jupyter",
    ],
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="insidedr_agent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
