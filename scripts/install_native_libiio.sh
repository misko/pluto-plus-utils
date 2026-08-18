#!/usr/bin/env bash
# Install the immutable SPF libiio into this project's venv without root.

set -euo pipefail
umask 0022

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python_bin="${repo_root}/.venv/bin/python"
prefix="${repo_root}/.venv"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '1')"
source_ref="spf-frame-metadata-source/v0.25-final-v3"
source_commit="c26258bfa33098c2b215e19cf85d448e89499b1a"

usage() {
    cat <<EOF
Usage: scripts/install_native_libiio.sh [--python PATH] [--prefix PATH] [--jobs N]

Builds exact tag ${source_ref} (${source_commit}) with USB support. The default
prefix is this checkout's .venv, which Pluto+ Utils discovers automatically.
EOF
}

while (($#)); do
    case "$1" in
    --python) python_bin="${2:?missing value for --python}"; shift 2 ;;
    --prefix) prefix="${2:?missing value for --prefix}"; shift 2 ;;
    --jobs) jobs="${2:?missing value for --jobs}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; printf 'ERROR: unknown argument: %s\n' "$1" >&2; exit 2 ;;
    esac
done

[[ "$python_bin" == /* && "$prefix" == /* ]] || {
    printf 'ERROR: --python and --prefix must be absolute paths\n' >&2
    exit 2
}
[[ -x "$python_bin" ]] || {
    printf 'ERROR: Python environment is missing: %s (run uv sync --extra hardware)\n' \
        "$python_bin" >&2
    exit 1
}
[[ "$jobs" =~ ^[1-9][0-9]*$ ]] || {
    printf 'ERROR: --jobs must be a positive integer\n' >&2
    exit 2
}
for command in git cmake uv; do
    command -v "$command" >/dev/null || {
        printf 'ERROR: %s is required\n' "$command" >&2
        exit 1
    }
done

uv pip install --python "$python_bin" pip setuptools

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
"$python_bin" -m pip install --quiet --force-reinstall --no-deps \
    "$worktree/build/bindings/python"

PLUTO_LIBIIO_LIBRARY="$prefix/lib/libiio.so.0" "$python_bin" - <<'PY'
from pluto_plus.hardware.preflight import inspect_iio_environment

report = inspect_iio_environment()
assert report.healthy, report.actionable_message
assert report.libiio_version == "0.25 (c26258b)", report.libiio_version
assert "usb" in report.backends, report.backends
import iio
assert hasattr(iio, "MetadataBuffer"), "patched binding lacks MetadataBuffer"
print(f"PASS: {report.libiio_version} {report.native_libiio_path} backends={report.backends}")
PY

printf '\nInstalled the immutable SPF libiio into %s.\n' "$prefix"
printf 'Run: uv run pluto environment\n'
