"""Generate placeholder icons for the Sentinel installer bundle.

Run before PyInstaller on each platform:
    python installer/generate_icons.py

Produces:
    installer/assets/icon.png   (source)
    installer/assets/icon.ico   (Windows)
    installer/assets/icon.icns  (macOS — requires sips + iconutil)
"""

import platform
import subprocess
import sys
from pathlib import Path

try:
    from PIL import Image, ImageDraw
except ImportError:
    print("Pillow not installed — skipping icon generation.")
    sys.exit(0)

ASSETS = Path(__file__).parent / "assets"
ASSETS.mkdir(parents=True, exist_ok=True)

# Draw a simple blue shield icon
img = Image.new("RGBA", (512, 512), (0, 0, 0, 0))
d = ImageDraw.Draw(img)
d.ellipse([40, 40, 472, 472], fill=(37, 99, 235, 255))
d.ellipse([60, 60, 452, 452], fill=(59, 130, 246, 255))
d.rectangle([196, 180, 316, 340], fill="white")
d.rectangle([236, 140, 276, 380], fill="white")

png_path = ASSETS / "icon.png"
img.save(png_path)
print(f"Generated: {png_path}")

# Windows .ico
ico_path = ASSETS / "icon.ico"
img.save(str(ico_path), format="ICO",
         sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
print(f"Generated: {ico_path}")

# macOS .icns — requires sips and iconutil (available on all macOS systems)
if platform.system() == "Darwin":
    iconset = ASSETS / "icon.iconset"
    iconset.mkdir(exist_ok=True)
    for size in [16, 32, 64, 128, 256, 512]:
        out = iconset / f"icon_{size}x{size}.png"
        subprocess.run(
            ["sips", "-z", str(size), str(size), str(png_path), "--out", str(out)],
            check=True, capture_output=True,
        )
        # @2x variant
        if size <= 256:
            out2x = iconset / f"icon_{size}x{size}@2x.png"
            subprocess.run(
                ["sips", "-z", str(size * 2), str(size * 2), str(png_path), "--out", str(out2x)],
                check=True, capture_output=True,
            )
    icns_path = ASSETS / "icon.icns"
    subprocess.run(
        ["iconutil", "-c", "icns", str(iconset), "-o", str(icns_path)],
        check=True,
    )
    print(f"Generated: {icns_path}")

print("Icon generation complete.")
