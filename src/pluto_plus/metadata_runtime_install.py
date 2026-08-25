"""Installed entry point for the immutable metadata libiio builder."""

from __future__ import annotations

import subprocess
import sys
from importlib.metadata import distribution
from importlib.resources import files
from pathlib import Path


def _installer_script() -> Path:
    """Locate the bundled installer in both wheel and editable installs."""

    resource = Path(str(files("pluto_plus").joinpath("_native/install_native_libiio.sh")))
    if resource.is_file():
        return resource

    # Hatch editable installs import ``pluto_plus`` from ``src/`` while
    # force-included wheel resources live in site-packages. Distribution
    # metadata resolves the latter without assuming a venv layout.
    installed = Path(
        str(
            distribution("pluto-plus-utils").locate_file(
                "pluto_plus/_native/install_native_libiio.sh"
            )
        )
    )
    if installed.is_file():
        return installed
    raise SystemExit("packaged metadata-runtime installer is missing")


def main() -> None:
    """Run the package-owned installer with its arguments unchanged."""

    script = _installer_script()
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
