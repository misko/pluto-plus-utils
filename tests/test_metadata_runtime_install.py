from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import pluto_plus.metadata_runtime_install as installer


def test_installed_entrypoint_uses_its_own_python_prefix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    package = tmp_path / "pluto_plus"
    script = package / "_native/install_native_libiio.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/bash\n")
    observed: list[tuple[str, ...]] = []

    def run(command: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        observed.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer, "files", lambda _name: package)
    monkeypatch.setattr(installer.subprocess, "run", run)
    monkeypatch.setattr(installer.sys, "argv", ["installer", "--uv-bin", "/sealed/uv"])
    monkeypatch.setattr(installer.sys, "prefix", "/release/.venv")
    monkeypatch.setattr(installer.sys, "executable", "/release/.venv/bin/python")

    with pytest.raises(SystemExit) as exit_info:
        installer.main()

    assert exit_info.value.code == 0
    assert observed == [
        (
            "/bin/bash",
            str(script),
            "--prefix",
            "/release/.venv",
            "--python",
            "/release/.venv/bin/python",
            "--uv-bin",
            "/sealed/uv",
        )
    ]


def test_source_installer_requires_explicit_sealed_uv() -> None:
    script = Path(__file__).parents[1] / "scripts/install_native_libiio.sh"
    result = subprocess.run(
        (str(script), "--metadata-abi", "1"),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 2
    assert "--uv-bin must be absolute" in result.stderr
    text = script.read_text()
    assert "import setuptools" in text
    assert '"$uv_bin" pip install' in text
    assert "--no-build-isolation" in text
    assert "iq-direct-async-minimal-rc1-source/libiio-v1" in text
    assert "393cd218f5a8953dd4f1574ae3f80d088d93d793" in text
    assert "iio-gain-timeline-v8-rc1-source/libiio-v4" in text
    assert "98a5e6139459a01a5a42ca7cd3e98d807156b6b0" in text


def test_source_installer_fails_fast_when_setuptools_is_missing(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "scripts/install_native_libiio.sh"
    python = tmp_path / "python"
    uv = tmp_path / "uv"
    python.write_text("#!/bin/sh\nexit 1\n")
    uv.write_text("#!/bin/sh\nexit 0\n")
    python.chmod(0o755)
    uv.chmod(0o755)

    result = subprocess.run(
        (
            str(script),
            "--metadata-abi",
            "3",
            "--python",
            str(python),
            "--prefix",
            str(tmp_path / "prefix"),
            "--uv-bin",
            str(uv),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 1
    assert "build dependency setuptools is missing" in result.stderr
    assert "uv sync --extra hardware" in result.stderr
