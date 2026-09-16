"""Verified filesystem bundles; never formats a disk or chooses media implicitly."""

from __future__ import annotations

import io
import json
import os
import shutil
import zipfile
from collections.abc import Callable
from pathlib import Path

from .contracts import Blob, Plan, Profile, RecoveryError, canonical, digest
from .store import publish, read_regular

# This verifier is deliberately self-contained for an SD reader on another host.
VERIFIER = '''#!/usr/bin/env python3
"""Verify recovery bundle files. Does not write, format, or access a radio."""
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
manifest = json.loads((root / "manifest.json").read_text())
expected = set(manifest["files"]) | {"manifest.json", "verify.py"}
actual = {p.name for p in root.iterdir()}
if actual != expected:
    raise SystemExit("FAIL: missing or unexpected files; use the dedicated recovery filesystem")
for name, claim in manifest["files"].items():
    if pathlib.PurePath(name).name != name or name in {".", ".."}:
        raise SystemExit("FAIL: unsafe filename")
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit("FAIL: expected regular file")
    data = path.read_bytes()
    if len(data) != claim["size"] or hashlib.sha256(data).hexdigest() != claim["sha256"]:
        raise SystemExit("FAIL: file length/digest differs")
print("File verification passed; compare the manifest SHA-256 with the PPU receipt:")
print(hashlib.sha256((root / "manifest.json").read_bytes()).hexdigest())
print("This does not qualify the board or prove the running bootstrap.")
'''

# A distinct subdirectory keeps planned payloads separate from startup files.
REPAIR_VERIFIER = VERIFIER.replace('"manifest.json"', '"repair-manifest.json"').replace(
    '"verify.py"', '"verify-repair.py"'
)


def export_repair(plan: Plan, get: Callable[[Blob], bytes], output: Path) -> str:
    """Export or finish an interrupted export, checking every existing byte."""
    payloads = {s.after.sha256: s.after for s in plan.sectors}
    payloads.update({p.payload.sha256: p.payload for p in plan.patches if p.kind == "fit"})
    manifest = canonical(
        {
            "plan_sha256": plan.sha256,
            "files": {f"ppu-{b.sha256}.bin": b.model_dump() for b in payloads.values()},
        }
    )
    files = {f"ppu-{b.sha256}.bin": get(b) for b in payloads.values()}
    files.update({"repair-manifest.json": manifest, "verify-repair.py": REPAIR_VERIFIER.encode()})
    _publish_files(files, output)
    return digest(manifest)


def export_repair_archive(source: Path, output: Path) -> str:
    """Create a deterministic Mac-transfer ZIP containing one ppu-repair directory."""
    names = sorted(path.name for path in source.iterdir())
    if not names or any(name in {".", ".."} for name in names):
        raise RecoveryError("sd_manifest_invalid", "repair bundle is empty or unsafe")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in names:
            data = read_regular(source / name)
            entry = zipfile.ZipInfo(f"ppu-repair/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            entry.create_system = 3
            entry.external_attr = 0o600 << 16
            archive.writestr(entry, data)
    data = buffer.getvalue()
    if output.exists() or output.is_symlink():
        if read_regular(output) != data:
            raise RecoveryError("artifact_corrupt", "existing repair archive differs")
    else:
        publish(output, data)
    return digest(data)


def _publish_files(files: dict[str, bytes], output: Path) -> None:
    if output.parent.resolve() != output.parent.absolute():
        raise RecoveryError("media_invalid", "bundle parent must be a real directory")
    output.mkdir(mode=0o700, exist_ok=True)
    if output.is_symlink() or output.resolve() != output.absolute():
        raise RecoveryError("media_invalid", "bundle output must be a real directory")
    if {p.name for p in output.iterdir()} - files.keys():
        raise RecoveryError("sd_files_conflict", "unexpected files in bundle output")
    for name, data in files.items():
        path = output / name
        if path.exists() or path.is_symlink():
            if read_regular(path) != data:
                raise RecoveryError("artifact_corrupt", "existing bundle output differs")
        else:
            publish(path, data)


def prepare_bundle(profile: Profile, source: Path, output: Path) -> str:
    if not profile.sd_files or {"manifest.json", "verify.py"} & set(profile.sd_files):
        raise RecoveryError("sd_manifest_invalid", "missing boot file set or reserved names")
    files: dict[str, bytes] = {}
    for name, claim in profile.sd_files.items():
        if name in {".", ".."}:
            raise RecoveryError("sd_manifest_invalid", "unsafe filename")
        data = read_regular(source / name, claim.size)
        if len(data) != claim.size or digest(data) != claim.sha256:
            raise RecoveryError("artifact_corrupt", "SD asset differs from qualified manifest")
        files[name] = data
    required = sum(len(data) for data in files.values()) + 1024 * 1024
    if shutil.disk_usage(output.parent).free < required:
        raise RecoveryError("insufficient_space", "not enough space for diagnostic bundle")
    manifest = canonical(
        {
            "schema_version": 1,
            "profile_id": profile.profile_id,
            "profile_sha256": profile.sha256,
            "files": {name: blob.model_dump() for name, blob in profile.sd_files.items()},
        }
    )
    files.update({"manifest.json": manifest, "verify.py": VERIFIER.encode()})
    _publish_files(files, output)
    verify_bundle(profile, output)
    return digest(manifest)


def verify_bundle(profile: Profile, root: Path) -> None:
    if root.is_symlink() or not root.is_dir():
        raise RecoveryError("media_invalid", "bundle must be a real directory")
    expected = set(profile.sd_files) | {"manifest.json", "verify.py"}
    if {p.name for p in root.iterdir()} != expected:
        raise RecoveryError(
            "sd_files_conflict", "missing or unexpected files in recovery filesystem"
        )
    manifest = json.loads(read_regular(root / "manifest.json", 1024 * 1024))
    if manifest != {
        "schema_version": 1,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.sha256,
        "files": {name: blob.model_dump() for name, blob in profile.sd_files.items()},
    }:
        raise RecoveryError("sd_manifest_invalid", "manifest differs from shipped profile")
    for name, claim in profile.sd_files.items():
        data = read_regular(root / name, claim.size)
        if len(data) != claim.size or digest(data) != claim.sha256:
            raise RecoveryError("artifact_corrupt", "SD file failed readback")
    if read_regular(root / "verify.py") != VERIFIER.encode():
        raise RecoveryError("artifact_corrupt", "portable verifier changed")


def media_identity(root: Path) -> str:
    selected = root.absolute()
    if selected.resolve() != selected or not os.path.ismount(selected):
        raise RecoveryError("media_invalid", "select an explicit mounted filesystem root")
    state = selected.stat()
    return digest(canonical({"path": str(selected), "device": state.st_dev, "inode": state.st_ino}))


def copy_to_media(profile: Profile, bundle: Path, media: Path, expected_identity: str) -> None:
    verify_bundle(profile, bundle)
    if media_identity(media) != expected_identity or any(media.iterdir()):
        raise RecoveryError("media_changed", "media identity changed or filesystem is not empty")
    required = sum(p.stat().st_size for p in bundle.iterdir()) + 1024 * 1024
    if shutil.disk_usage(media).free < required:
        raise RecoveryError("insufficient_space", "SD filesystem is full")
    for path in bundle.iterdir():
        if media_identity(media) != expected_identity:
            raise RecoveryError("media_changed", "media changed during copy")
        # FAT need not support hard links. O_EXCL never replaces an existing file;
        # a partial copy stays visibly incomplete and cannot pass verification.
        fd = os.open(media / path.name, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(read_regular(path))
            stream.flush()
            os.fsync(stream.fileno())
    verify_bundle(profile, media)
    if media_identity(media) != expected_identity:
        raise RecoveryError("media_changed", "media changed after copy")
