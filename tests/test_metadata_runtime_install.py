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
    assert "pip setuptools" not in text
    assert '"$uv_bin" pip install' in text
    assert "--no-build-isolation" in text
    assert "ddr-burst-v1-source/libiio-v2" in text
    assert "6591aa335ee124c32d9ef500f728068d299af71a" in text
