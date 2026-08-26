"""Installed entry point for the immutable metadata libiio builder."""

from __future__ import annotations

import subprocess
import sys
from importlib.resources import files
from pathlib import Path


def main() -> None:
    """Run the package-owned installer with its arguments unchanged."""

    resource = files("pluto_plus").joinpath("_native/install_native_libiio.sh")
    script = Path(str(resource))
    if not script.is_file():
        raise SystemExit("packaged metadata-runtime installer is missing")
    arguments = list(sys.argv[1:])
    if "--python" not in arguments:
        arguments[:0] = ["--python", sys.executable]
    if "--prefix" not in arguments:
        arguments[:0] = ["--prefix", sys.prefix]
    result = subprocess.run(
        ("/bin/bash", str(script), *arguments),
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
        check=False,
    )
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
