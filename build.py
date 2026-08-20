#!/usr/bin/env python3
"""
ExposedGuard build script.

Generates one ready-to-load folder per browser in dist/, plus an upload zip
for each:

    dist/firefox/    MV2 build (Firefox desktop + Android)
    dist/chrome/     MV3 build (Chrome)
    dist/brave/      MV3 build (Brave)
    dist/opera/      MV3 build (Opera)
    dist/edge/       MV3 build (Edge)
    dist/exposed-guard-<version>-<browser>.zip

Usage:
    python build.py
"""

import json
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
DIST = ROOT / "dist"

# Files/folders shared by every browser build
SHARED = [
    "background.js",
    "content.js",
    "browser-polyfill.min.js",
    "icons",
    "popup",
]

# browser target -> manifest template
TARGETS = {
    "firefox": "manifest.firefox.json",
    "chrome": "manifest.chromium.json",
    "brave": "manifest.chromium.json",
    "opera": "manifest.chromium.json",
    "edge": "manifest.chromium.json",
}


def copy_shared(dest: Path):
    for rel in SHARED:
        src = SRC / rel
        dst = dest / rel
        if src.is_dir():
            shutil.copytree(src, dst)
        else:
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)


def zip_folder(folder: Path, zip_path: Path):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(folder.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(folder))


def main():
    versions = set()
    for name, manifest_file in TARGETS.items():
        manifest_src = SRC / manifest_file
        manifest = json.loads(manifest_src.read_text(encoding="utf-8"))
        versions.add(manifest["version"])

        dest = DIST / name
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)

        copy_shared(dest)
        # each build gets a plain "manifest.json"
        shutil.copy2(manifest_src, dest / "manifest.json")

        zip_path = DIST / f"exposed-guard-{manifest['version']}-{name}.zip"
        zip_folder(dest, zip_path)
        print(f"[{name:7s}] MV{manifest['manifest_version']}  "
              f"-> {dest.relative_to(ROOT)}  +  {zip_path.name} "
              f"({zip_path.stat().st_size} bytes)")

    if len(versions) != 1:
        raise SystemExit(f"ERROR: manifest versions differ: {versions}")
    print(f"\nAll builds at version {versions.pop()}.")


if __name__ == "__main__":
    main()
