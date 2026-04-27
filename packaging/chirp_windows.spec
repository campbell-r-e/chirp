# -*- mode: python ; coding: utf-8 -*-
# Windows PyInstaller spec — run this ON Windows with:
#   pip install pyinstaller wxPython pyserial requests yattag suds lark
#   pyinstaller packaging/chirp_windows.spec
import os
from PyInstaller.utils.hooks import collect_all

chirp_root = os.path.abspath('.')

datas = [
    (os.path.join(chirp_root, 'chirp', 'share'), 'chirp/share'),
    (os.path.join(chirp_root, 'chirp', 'stock_configs'), 'chirp/stock_configs'),
    (os.path.join(chirp_root, 'chirp', 'locale'), 'chirp/locale'),
]

wx_datas, wx_binaries, wx_hiddenimports = collect_all('wx')
chirp_datas, chirp_binaries, chirp_hiddenimports = collect_all('chirp')

a = Analysis(
    [os.path.join(chirp_root, 'chirpwx.py')],
    pathex=[chirp_root],
    binaries=wx_binaries + chirp_binaries,
    datas=datas + wx_datas + chirp_datas,
    hiddenimports=wx_hiddenimports + chirp_hiddenimports + [
        'chirp.drivers',
        'chirp.wxui',
        'chirp.sources',
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name='CHIRP',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=os.path.join(chirp_root, 'chirp', 'share', 'chirp.ico'),
)
