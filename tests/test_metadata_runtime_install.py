from __future__ import annotations

import subprocess
import sys
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


def test_editable_console_entrypoint_can_find_packaged_installer() -> None:
    entrypoint = Path(sys.executable).with_name("pluto-install-metadata-runtime")

    result = subprocess.run(
        (str(entrypoint), "--help"),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert result.returncode == 0, result.stderr
    assert "Usage: scripts/install_native_libiio.sh" in result.stdout


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
    assert "pip setuptools" not in text
    assert '"$uv_bin" pip install' in text
    assert "--no-build-isolation" in text


def test_source_installer_binds_abi2_to_the_exact_v7_profile(tmp_path: Path) -> None:
    script = Path(__file__).parents[1] / "scripts/install_native_libiio.sh"
    executable = tmp_path / "uv"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)

    missing_version = subprocess.run(
        (str(script), "--metadata-abi", "2", "--uv-bin", str(executable)),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )
    wrong_version = subprocess.run(
        (
            str(script),
            "--metadata-abi",
            "2",
            "--firmware-version",
            "v0.40-plutoplus-spf-tandem-agc-v8",
            "--uv-bin",
            str(executable),
        ),
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        check=False,
        timeout=10,
    )

    assert missing_version.returncode == 2
    assert "requires --firmware-version v0.40-plutoplus-spf-tandem-agc-v7" in (
        missing_version.stderr
    )
    assert wrong_version.returncode == 2
    text = script.read_text()
    assert 'source_ref="tandem-agc-v2-source/libiio-v9"' in text
    assert 'source_commit="015e4924113d4996667f80b880c34cbf7d1147de"' in text
    assert "tandem-agc-v8-rc2-source/libiio-v1" not in text
    assert "6305ea1d43436ff8bdd83aa6c9e5abf7244aa5f7" not in text
