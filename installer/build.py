"""
Sentinel SIEM — Build Orchestrator
====================================
Prepares all dependencies and then runs PyInstaller.

Usage (run from repo root):
    python installer/build.py [--platform windows|macos|linux] [--skip-ui] [--skip-deps]

Steps:
  1. Build the React UI  (npm run build  →  ui/dist/)
  2. Download embedded PostgreSQL binaries  →  installer/embedded/postgresql/
  3. Download embedded Redis binary         →  installer/embedded/redis/
  4. Run PyInstaller with installer/sentinel.spec
  5. (Optional) Run platform-specific packaging script
"""

from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
import zipfile
import tarfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EMBEDDED_DIR = ROOT / "installer" / "embedded"
SYSTEM = platform.system()

# ── PostgreSQL portable download URLs ────────────────────────────────────────
# We use the EnterpriseDB binaries (the same ones used by the official installer).
PG_VERSION = "16.3-1"
PG_URLS = {
    "Windows": (
        "https://get.enterprisedb.com/postgresql/"
        f"postgresql-{PG_VERSION}-windows-x64-binaries.zip"
    ),
    "Darwin": (
        "https://get.enterprisedb.com/postgresql/"
        f"postgresql-{PG_VERSION}-osx-binaries.zip"
    ),
    "Linux": None,   # Linux: use system PostgreSQL (listed as .deb/.rpm dependency)
}

# ── Redis download URLs ───────────────────────────────────────────────────────
REDIS_VERSION = "7.2.4"
REDIS_URLS = {
    "Windows": (
        f"https://github.com/tporadowski/redis/releases/download/"
        f"v{REDIS_VERSION}/Redis-x64-{REDIS_VERSION}.zip"
    ),
    "Darwin": None,   # macOS: compiled from source or Homebrew during CI
    "Linux": None,    # Linux: system package
}


def _run(cmd: list[str], **kwargs) -> None:
    print(f"\n▶ {' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        sys.exit(result.returncode)


def build_ui() -> None:
    print("\n═══ Building React UI ═══")
    ui_dir = ROOT / "ui"
    _run(["npm", "install"], cwd=ui_dir, shell=(SYSTEM == "Windows"))
    _run(["npm", "run", "build"], cwd=ui_dir, shell=(SYSTEM == "Windows"))
    print(f"✓ UI built → {ui_dir / 'dist'}")


def download_pg() -> None:
    print("\n═══ Downloading embedded PostgreSQL ═══")
    url = PG_URLS.get(SYSTEM)
    if not url:
        print(f"  Skipping: using system PostgreSQL on {SYSTEM}")
        return

    dest_dir = EMBEDDED_DIR / "postgresql"
    if dest_dir.exists():
        print(f"  Already exists: {dest_dir}")
        return

    archive = EMBEDDED_DIR / "pg.zip"
    EMBEDDED_DIR.mkdir(parents=True, exist_ok=True)

    print(f"  Downloading from {url} …")
    urllib.request.urlretrieve(url, archive)

    print("  Extracting …")
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(EMBEDDED_DIR / "_pg_tmp")

    # EnterpriseDB zip has a top-level 'pgsql/' directory
    extracted = EMBEDDED_DIR / "_pg_tmp" / "pgsql"
    shutil.move(str(extracted), str(dest_dir))
    shutil.rmtree(EMBEDDED_DIR / "_pg_tmp", ignore_errors=True)
    archive.unlink()

    print(f"✓ PostgreSQL → {dest_dir}")


def download_redis() -> None:
    print("\n═══ Downloading embedded Redis ═══")
    url = REDIS_URLS.get(SYSTEM)

    if not url:
        if SYSTEM == "Darwin":
            # Build from source using Homebrew's formula in CI or use system Redis
            _compile_redis_macos()
        else:
            print(f"  Skipping: using system Redis on {SYSTEM}")
        return

    dest_dir = EMBEDDED_DIR / "redis"
    if dest_dir.exists():
        print(f"  Already exists: {dest_dir}")
        return

    archive = EMBEDDED_DIR / "redis.zip"
    EMBEDDED_DIR.mkdir(parents=True, exist_ok=True)

    print(f"  Downloading from {url} …")
    urllib.request.urlretrieve(url, archive)

    print("  Extracting …")
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as zf:
        for member in zf.namelist():
            if "redis-server" in member.lower():
                zf.extract(member, dest_dir)
    archive.unlink()

    print(f"✓ Redis → {dest_dir}")


def _compile_redis_macos() -> None:
    """Download and compile Redis on macOS (used in CI)."""
    import tarfile

    dest_dir = EMBEDDED_DIR / "redis"
    if dest_dir.exists():
        return

    url = f"https://download.redis.io/releases/redis-{REDIS_VERSION}.tar.gz"
    archive = EMBEDDED_DIR / "redis.tar.gz"
    EMBEDDED_DIR.mkdir(parents=True, exist_ok=True)

    print(f"  Downloading Redis source from {url} …")
    urllib.request.urlretrieve(url, archive)

    src_dir = EMBEDDED_DIR / f"redis-{REDIS_VERSION}"
    with tarfile.open(archive) as tf:
        tf.extractall(EMBEDDED_DIR)
    archive.unlink()

    print("  Compiling Redis …")
    _run(["make", "-C", str(src_dir), "-j4"])

    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src_dir / "src" / "redis-server", dest_dir / "redis-server")
    shutil.rmtree(src_dir, ignore_errors=True)
    print(f"✓ Redis → {dest_dir / 'redis-server'}")


def create_placeholder_icon() -> None:
    """Generate a minimal placeholder icon if none exists."""
    assets_dir = ROOT / "installer" / "assets"
    assets_dir.mkdir(exist_ok=True)

    png = assets_dir / "icon.png"
    if png.exists():
        return

    try:
        from PIL import Image, ImageDraw, ImageFont
        img = Image.new("RGBA", (256, 256), (37, 99, 235, 255))
        d = ImageDraw.Draw(img)
        d.ellipse([20, 20, 236, 236], fill=(59, 130, 246, 255))
        d.text((80, 90), "S", fill="white")
        img.save(png)

        # Windows .ico
        ico = assets_dir / "icon.ico"
        img.save(ico, format="ICO", sizes=[(16,16),(32,32),(48,48),(256,256)])

        # macOS .icns — requires iconutil; save png as placeholder
        icns = assets_dir / "icon.icns"
        img.save(icns, format="ICNS")

        print(f"✓ Placeholder icons generated in {assets_dir}")
    except Exception as e:
        print(f"  Warning: could not generate icons ({e}). "
              "Place icon.ico / icon.icns / icon.png in installer/assets/ manually.")


def run_pyinstaller() -> None:
    print("\n═══ Running PyInstaller ═══")
    _run(
        [sys.executable, "-m", "PyInstaller",
         "--clean",
         str(ROOT / "installer" / "sentinel.spec")],
        cwd=ROOT,
    )
    print(f"✓ Bundle → {ROOT / 'dist' / 'sentinel'}")


def package_windows() -> None:
    print("\n═══ Building Windows installer (Inno Setup) ═══")
    iss = ROOT / "installer" / "windows" / "sentinel.iss"
    iscc = shutil.which("iscc") or shutil.which("ISCC")
    if not iscc:
        print("  WARNING: Inno Setup (iscc) not found. Skipping .exe packaging.")
        print("  Install from https://jrsoftware.org/isdl.php then re-run.")
        return
    _run([iscc, str(iss)])
    print("✓ Windows installer → dist/SentinelSetup.exe")


def package_macos() -> None:
    print("\n═══ Building macOS installer (.pkg) ═══")
    script = ROOT / "installer" / "macos" / "build-pkg.sh"
    _run(["bash", str(script)])
    print("✓ macOS installer → dist/SentinelSetup.pkg")


def package_linux() -> None:
    print("\n═══ Building Linux packages (.deb / .rpm) ═══")
    script = ROOT / "installer" / "linux" / "build-packages.sh"
    _run(["bash", str(script)])
    print("✓ Linux packages → dist/sentinel_*.deb  dist/sentinel-*.rpm")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build Sentinel SIEM installers")
    parser.add_argument("--skip-ui", action="store_true", help="Skip React UI build")
    parser.add_argument("--skip-deps", action="store_true", help="Skip PG/Redis download")
    parser.add_argument("--skip-package", action="store_true",
                        help="Skip platform packaging (only run PyInstaller)")
    parser.add_argument("--platform", choices=["windows", "macos", "linux"],
                        default=SYSTEM.lower(), help="Target platform")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  Sentinel SIEM Build  —  platform: {args.platform}")
    print(f"{'═'*60}")

    create_placeholder_icon()

    if not args.skip_ui:
        build_ui()

    if not args.skip_deps:
        download_pg()
        download_redis()

    run_pyinstaller()

    if not args.skip_package:
        if args.platform == "windows":
            package_windows()
        elif args.platform == "macos":
            package_macos()
        elif args.platform == "linux":
            package_linux()

    print("\n✅ Build complete.\n")


if __name__ == "__main__":
    main()
