# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('agent/collectors/*.py', 'agent/collectors')],
    hiddenimports=[
        # Standard library modules loaded dynamically by collectors
        'sqlite3',
        'xml',
        'xml.etree',
        'xml.etree.ElementTree',
        'xml.etree.cElementTree',
        # Windows-specific modules for event log and security collectors
        'win32evtlog',
        'win32evtlogutil',
        'win32api',
        'win32con',
        'win32security',
        'pywintypes',
        # python-dotenv for .env loading inside the frozen exe
        'dotenv',
        # Cryptography
        'cryptography',
        'cryptography.hazmat.primitives.ciphers.aead',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='insidedr_agent',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
