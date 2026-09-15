"""Exact reviewed conservative writer footprint; never an address-range grant."""

from __future__ import annotations

import json
from importlib.resources import files

_MANIFEST = json.loads(files("pluto_plus").joinpath("flash_writer_issue99.json").read_text())
ISSUE99_FILES: dict[str, str] = _MANIFEST["files"]
ISSUE99_COMMANDS: dict[str, str] = _MANIFEST["commands"]
ISSUE99_UPDATER_SHA256: str = ISSUE99_FILES["/sbin/update_frm.sh"]
ISSUE99_TOOLS_SHA256: str = _MANIFEST["tools_sha256"]


def tools_observation_script() -> bytes:
    """Hash dependencies at their reviewed paths and check PATH resolution."""
    lines = [f'if [ "$updater" = {ISSUE99_UPDATER_SHA256} ]; then']
    # The writer sets this same PATH. Shell builtins execute in the pinned /bin/sh.
    lines += [f'  test "$(command -v {name})" = {path}' for name, path in ISSUE99_COMMANDS.items()]
    lines += [
        "  test ! -e /etc/ld.so.preload",
        '  test -z "${LD_PRELOAD-}${LD_LIBRARY_PATH-}"',
        "  tools=$(sha256sum " + " ".join(ISSUE99_FILES) + ")",
        "else",
        "  tools=$(sha256sum /bin/busybox /usr/sbin/fw_setenv /etc/device_config)",
        "fi",
    ]
    return ("\n".join(lines) + "\n").encode()
