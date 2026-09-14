#!/usr/bin/env python3
"""Rebuild and check the pinned RAM-only ARM helper using an explicit toolchain."""

from __future__ import annotations

import argparse
import hashlib
import subprocess
import tempfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cc", required=True, type=Path)
    parser.add_argument("--objcopy", required=True, type=Path)
    args = parser.parse_args()
    assets = Path(__file__).resolve().parents[1] / "src/pluto_plus/recovery/assets"
    with tempfile.TemporaryDirectory(prefix="ppu-ram-digest-") as directory:
        elf = Path(directory) / "helper.elf"
        binary = Path(directory) / "helper.bin"
        subprocess.run(
            [
                str(args.cc),
                "-Os",
                "-mcpu=cortex-a9",
                "-marm",
                "-ffixed-r9",
                "-ffreestanding",
                "-fno-builtin",
                "-fno-stack-protector",
                "-nostdlib",
                "-static",
                "-Wl,--build-id=none",
                "-Wl,-T," + str(assets / "sha256_ram.ld"),
                str(assets / "sha256_ram.c"),
                "-o",
                str(elf),
            ],
            check=True,
        )
        subprocess.run([str(args.objcopy), "-O", "binary", str(elf), str(binary)], check=True)
        actual = binary.read_bytes()
        if actual != (assets / "sha256_ram.bin").read_bytes():
            raise SystemExit(
                "Rebuilt helper differs from the committed bytes; review before repinning"
            )
        print("Reproducible RAM helper SHA256:", hashlib.sha256(actual).hexdigest())


if __name__ == "__main__":
    main()
