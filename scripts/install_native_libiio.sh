#!/usr/bin/env bash
# Install the immutable SPF libiio into this project's venv without root.

set -euo pipefail
umask 0022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${repo_root}/.venv/bin/python"
prefix="${repo_root}/.venv"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
uv_bin=""
metadata_abi=1
firmware_version=""
source_ref=""
source_commit=""

usage() {
    cat <<EOF
Usage: scripts/install_native_libiio.sh --uv-bin ABSOLUTE_PATH
       [--python PATH] [--prefix PATH] [--jobs N] [--metadata-abi 1|2]
       [--firmware-version VERSION]

Builds the exact host libiio matched to the selected firmware profile with USB
support. Metadata ABI 2 requires the exact reviewed firmware version; ABI 2 by
itself is not a runtime profile. The default ABI is 1 for the production-radio
profile. The source-checkout script defaults to that checkout's .venv; the
installed entry point defaults to its own Python environment.
EOF
}

while (($#)); do
    case "$1" in
    --python) python_bin="${2:?missing value for --python}"; shift 2 ;;
    --prefix) prefix="${2:?missing value for --prefix}"; shift 2 ;;
    --jobs) jobs="${2:?missing value for --jobs}"; shift 2 ;;
    --uv-bin) uv_bin="${2:?missing value for --uv-bin}"; shift 2 ;;
    --metadata-abi) metadata_abi="${2:?missing value for --metadata-abi}"; shift 2 ;;
    --firmware-version) firmware_version="${2:?missing value for --firmware-version}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; printf 'ERROR: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

case "$metadata_abi" in
1)
    [[ -z "$firmware_version" ]] || {
        printf 'ERROR: the ABI 1 production profile does not take --firmware-version\n' >&2
        exit 2
    }
    source_ref="spf-frame-metadata-source/v0.25-final-v3"
    source_commit="c26258bfa33098c2b215e19cf85d448e89499b1a"
    ;;
2)
    [[ "$firmware_version" == "v0.40-plutoplus-spf-tandem-agc-v7" ]] || {
        printf '%s\n' \
            'ERROR: ABI 2 requires --firmware-version v0.40-plutoplus-spf-tandem-agc-v7' >&2
        exit 2
    }
    source_ref="tandem-agc-v2-source/libiio-v9"
    source_commit="015e4924113d4996667f80b880c34cbf7d1147de"
    ;;
*)
    printf 'ERROR: --metadata-abi must be 1 or 2\n' >&2
    exit 2
    ;;
esac

[[ "$python_bin" == /* && "$prefix" == /* && "$uv_bin" == /* ]] || {
    printf 'ERROR: --python, --prefix, and --uv-bin must be absolute paths\n' >&2
    exit 2
}
[[ -x "$python_bin" ]] || {
    printf 'ERROR: Python environment is missing: %s (run uv sync --extra hardware)\n' \
        "$python_bin" >&2
    exit 1
}
[[ -f "$uv_bin" && -x "$uv_bin" && ! -L "$uv_bin" ]] || {
    printf 'ERROR: --uv-bin must be a regular non-symlink executable: %s\n' "$uv_bin" >&2
    exit 1
}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || {
    printf 'ERROR: --jobs must be a positive integer\n' >&2
    exit 2
}
for command in git cmake; do
    command -v "$command" >/dev/null || {
        printf 'ERROR: %s is required\n' "$command" >&2
        exit 1
    }
done

worktree="$(mktemp -d "${TMPDIR:-/tmp}/pluto-plus-libiio.XXXXXX")"
cleanup() {
    rm -rf -- "$worktree"
}
trap cleanup EXIT

git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$source_ref" \
    https://github.com/misko/libiio.git "$worktree/src"
actual_commit="$(git -C "$worktree/src" rev-parse HEAD)"
[[ "$actual_commit" == "$source_commit" ]] || {
    printf 'ERROR: immutable libiio tag resolved to %s, expected %s\n' \
        "$actual_commit" "$source_commit" >&2
    exit 1
}

cmake -S "$worktree/src" -B "$worktree/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$prefix" \
    -DINSTALL_UDEV_RULE=OFF \
    -DPYTHON_BINDINGS=ON \
    -DPYTHON_EXECUTABLE="$python_bin" \
    -DHAVE_DNS_SD=OFF \
    -DWITH_AIO=OFF \
    -DWITH_DOC=OFF \
    -DWITH_EXAMPLES=OFF \
    -DWITH_IIOD=OFF \
    -DWITH_LOCAL_BACKEND=ON \
    -DWITH_NETWORK_BACKEND=ON \
    -DWITH_SERIAL_BACKEND=OFF \
    -DWITH_TESTS=ON \
    -DWITH_USB_BACKEND=ON
cmake --build "$worktree/build" --parallel "$jobs"
cmake --install "$worktree/build"
"$uv_bin" pip install --python "$python_bin" --quiet --force-reinstall --no-deps \
    --no-build-isolation "$worktree/build/bindings/python"

PLUTO_LIBIIO_LIBRARY="$prefix/lib/libiio.so.0" \
    PLUTO_METADATA_ABI="$metadata_abi" \
    PLUTO_METADATA_FIRMWARE_VERSION="$firmware_version" \
    PLUTO_METADATA_PREFIX="$prefix" \
    PLUTO_METADATA_SOURCE_REF="$source_ref" \
    PLUTO_METADATA_SOURCE_COMMIT="$source_commit" \
    "$python_bin" - <<'PY'
import hashlib
import inspect
import json
import os
import sys
from pathlib import Path

from pluto_plus.hardware.preflight import inspect_iio_environment, verify_metadata_runtime

report = inspect_iio_environment()
assert report.healthy, report.actionable_message
assert "usb" in report.backends, report.backends
import iio
assert hasattr(iio, "MetadataBuffer"), "patched binding lacks MetadataBuffer"
abi = int(os.environ["PLUTO_METADATA_ABI"])
parameters = tuple(inspect.signature(iio.MetadataBuffer.__init__).parameters)
expected = (
    ("self", "device", "samples_count", "metadata_capacity")
    if abi == 1
    else ("self", "device", "samples_count", "request", "metadata_capacity")
)
assert parameters == expected, (parameters, expected)
prefix = Path(os.environ["PLUTO_METADATA_PREFIX"]).resolve(strict=True)
if Path(sys.prefix).resolve(strict=True) != prefix:
    raise RuntimeError((sys.prefix, prefix))
native_path = (prefix / "lib/libiio.so.0").resolve(strict=True)
binding_path = Path(iio.__file__).resolve(strict=True)
if not native_path.is_relative_to(prefix) or not binding_path.is_relative_to(prefix):
    raise RuntimeError((native_path, binding_path, prefix))

def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()

receipt = {
    "schema_version": 1,
    "metadata_abi": abi,
    "firmware_version": os.environ["PLUTO_METADATA_FIRMWARE_VERSION"] or None,
    "source_ref": os.environ["PLUTO_METADATA_SOURCE_REF"],
    "source_commit": os.environ["PLUTO_METADATA_SOURCE_COMMIT"],
    "native_libiio_path": str(native_path),
    "native_libiio_sha256": sha256(native_path),
    "pylibiio_path": str(binding_path),
    "pylibiio_sha256": sha256(binding_path),
    "metadata_buffer_parameters": list(parameters),
    "libiio_version": report.libiio_version,
    "backends": list(report.backends),
}
receipt_path = prefix / "share/pluto-plus-utils/metadata-runtime.json"
receipt_path.parent.mkdir(parents=True, exist_ok=True)
temporary = receipt_path.with_suffix(".json.tmp")
temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
temporary.replace(receipt_path)
verification = verify_metadata_runtime(
    expected_abi=abi,
    expected_firmware_version=os.environ["PLUTO_METADATA_FIRMWARE_VERSION"] or None,
)
assert Path(verification.native_libiio_path) == native_path
print(
    f"PASS: metadata_abi={abi} firmware={verification.firmware_version} "
    f"{report.libiio_version} "
    f"{report.native_libiio_path} backends={report.backends} receipt={receipt_path}"
)
PY

printf '\nInstalled immutable metadata profile ABI=%s firmware=%s into %s.\n' \
    "$metadata_abi" "${firmware_version:-production}" "$prefix"
printf 'Run: uv run pluto environment\n'
