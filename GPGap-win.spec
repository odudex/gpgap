# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['gpgap.py'],
    pathex=['C:\\Users\\Odudex\\AppData\\Local\\pypoetry\\Cache\\virtualenvs\\gpgap-v-HHYl7C-py3.13\\Lib\\site-packages'],
    binaries=[('dlls/libiconv.dll', '.'), ('dlls/libzbar-64.dll', '.')],
    datas=[('assets', 'assets')],
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
    name='GPGap-win',
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
