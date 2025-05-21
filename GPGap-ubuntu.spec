# -*- mode: python ; coding: utf-8 -*-
import sysconfig


a = Analysis(
    ['gpgap.py'],
    pathex=[],
    binaries=[],
    datas=[
        # include current Poetry venv site-packages
        (sysconfig.get_paths()['purelib'], '.'),
        ('assets/*', 'assets'),
        ("pyproject.toml", "."),
    ],
    hiddenimports=[],
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
    name='GPGap',
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
