# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec for the Sentinel SIEM single-executable bundle.

Build with:
    pyinstaller installer/sentinel.spec

Outputs:
    dist/sentinel/           (one-dir mode)
    dist/sentinel/sentinel   (or sentinel.exe on Windows)

The build.py script in this directory handles:
  - building the React UI before PyInstaller runs
  - downloading embedded PostgreSQL and Redis binaries
  - copying them into the correct locations inside dist/sentinel/
"""

import sys
import platform
from pathlib import Path

ROOT = Path(SPECPATH).parent  # repo root

# ── Hidden imports ────────────────────────────────────────────────────────────
# These are modules that PyInstaller cannot detect via static analysis.

HIDDEN_IMPORTS = [
    # asyncio / uvicorn internals
    "asyncio",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    # SQLAlchemy dialects
    "sqlalchemy.dialects.postgresql",
    "sqlalchemy.dialects.postgresql.asyncpg",
    "asyncpg",
    "asyncpg.pgproto",
    # Alembic
    "alembic",
    "alembic.config",
    "alembic.runtime.migration",
    # FastAPI / Starlette internals
    "fastapi",
    "starlette.routing",
    "starlette.staticfiles",
    "starlette.responses",
    # Pydantic v2
    "pydantic",
    "pydantic_core",
    # APScheduler
    "apscheduler",
    "apscheduler.schedulers.asyncio",
    "apscheduler.triggers.interval",
    # structlog
    "structlog",
    # python-dotenv
    "dotenv",
    # httpx
    "httpx",
    "httpx._transports.asgi",
    # Redis / aioredis
    "redis",
    "redis.asyncio",
    # MaxMind
    "maxminddb",
    # Azure SDK
    "azure.storage.blob",
    "azure.identity",
    # JWT
    "jwt",
    "cryptography",
    # Pillow (for tray icon)
    "PIL",
    "PIL.Image",
    "PIL.ImageDraw",
    # pystray
    "pystray",
    # tkinter (setup wizard)
    "tkinter",
    "tkinter.ttk",
    "tkinter.messagebox",
    # tenacity
    "tenacity",
    # GeoIP2
    "geoip2",
    # pgvector
    "pgvector",
]

# ── Data files ────────────────────────────────────────────────────────────────
# (src_path, dest_dir_inside_bundle)

DATAS = [
    # Alembic migrations
    (str(ROOT / "db"), "db"),
    # .env template
    (str(ROOT / ".env.example"), "."),
    # Alembic ini
    (str(ROOT / "db" / "alembic.ini"), "db"),
]

# Pre-built React UI (built by build.py before pyinstaller runs)
UI_DIST = ROOT / "ui" / "dist"
if UI_DIST.exists():
    DATAS.append((str(UI_DIST), "ui"))

# Embedded PostgreSQL binaries (downloaded by build.py)
EMBEDDED_PG = ROOT / "installer" / "embedded" / "postgresql"
if EMBEDDED_PG.exists():
    DATAS.append((str(EMBEDDED_PG), "embedded/postgresql"))

# Embedded Redis binary (downloaded by build.py)
EMBEDDED_REDIS = ROOT / "installer" / "embedded" / "redis"
if EMBEDDED_REDIS.exists():
    DATAS.append((str(EMBEDDED_REDIS), "embedded/redis"))

# ── Analysis ──────────────────────────────────────────────────────────────────

# Only include the custom hooks directory if it actually exists
_HOOKS_DIR = ROOT / "installer" / "hooks"
_HOOKS_PATH = [str(_HOOKS_DIR)] if _HOOKS_DIR.is_dir() else []

a = Analysis(
    [str(ROOT / "installer" / "launcher" / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=_HOOKS_PATH,
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "pytest", "pytest_asyncio",
        "ipython", "jupyter",
        "sphinx",
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=None)

# ── Icon — only set if the file actually exists (missing icon = hard error) ──

def _resolve_icon() -> str | None:
    if platform.system() == "Windows":
        p = ROOT / "installer" / "assets" / "icon.ico"
        return str(p) if p.exists() else None
    if platform.system() == "Darwin":
        p = ROOT / "installer" / "assets" / "icon.icns"
        return str(p) if p.exists() else None
    return None

_icon_path = _resolve_icon()

# ── Executable ────────────────────────────────────────────────────────────────

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sentinel",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,           # No console window (tray app); use True for headless debug
    disable_windowed_traceback=False,
    argv_emulation=False,    # macOS: set True if you need argv from Finder
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=_icon_path,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="sentinel",
)

# macOS .app bundle
if platform.system() == "Darwin":
    app = BUNDLE(
        coll,
        name="Sentinel.app",
        icon=_icon_path,
        bundle_identifier="com.nebula.sentinel",
        info_plist={
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleName": "Sentinel SIEM",
            "LSBackgroundOnly": False,
            "NSHighResolutionCapable": True,
        },
    )
