"""Exact reviewed conservative writer footprint; never an address-range grant."""

from __future__ import annotations

import hashlib
import json
from importlib.resources import files

_MANIFEST_RESOURCE = files("pluto_plus").joinpath("flash_writer_issue99.json")
_MANIFEST_BYTES = _MANIFEST_RESOURCE.read_bytes()
_MANIFEST = json.loads(_MANIFEST_BYTES)
_RELEASE = json.loads(
    files("pluto_plus").joinpath("flash_writer_issue99_release.json").read_text()
)
if hashlib.sha256(_MANIFEST_BYTES).hexdigest() != _RELEASE["base_manifest_sha256"]:
    raise RuntimeError("issue 99 release writer base manifest does not match its reviewed digest")
ISSUE99_FILES: dict[str, str] = _MANIFEST["files"]
ISSUE99_COMMANDS: dict[str, str] = _MANIFEST["commands"]
ISSUE99_UPDATER_SHA256: str = ISSUE99_FILES["/sbin/update_frm.sh"]
ISSUE99_TOOLS_SHA256: str = _MANIFEST["tools_sha256"]
ISSUE99_RELEASE_FILES: dict[str, str] = {
    path: _RELEASE["digest_replacements"].get(digest, digest)
    for path, digest in ISSUE99_FILES.items()
}
ISSUE99_RELEASE_TOOLS_SHA256: str = _RELEASE["tools_sha256"]
ISSUE99_TOOLS_SHA256S = frozenset((ISSUE99_TOOLS_SHA256, ISSUE99_RELEASE_TOOLS_SHA256))


def _aggregate(files_by_path: dict[str, str]) -> str:
    listing = "".join(f"{digest}  {path}\n" for path, digest in files_by_path.items())
    return hashlib.sha256(listing.encode()).hexdigest()


if (
    ISSUE99_RELEASE_FILES["/sbin/update_frm.sh"] != ISSUE99_UPDATER_SHA256
    or set(ISSUE99_RELEASE_FILES) != set(ISSUE99_FILES)
    or _aggregate(ISSUE99_RELEASE_FILES) != ISSUE99_RELEASE_TOOLS_SHA256
):
    raise RuntimeError("issue 99 release writer manifest is internally inconsistent")


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
