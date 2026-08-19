from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus

SERIAL = "104000b29905000e17000800065934759d"
runner = CliRunner()


@pytest.fixture(autouse=True)
def _healthy_environment(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment",
        lambda **_kwargs: IioEnvironmentReport(
            healthy=True,
            status=IioEnvironmentStatus.READY,
            message="ready",
            python_executable="/venv/python",
            pyadi_path="/venv/adi/__init__.py",
            pylibiio_path="/venv/iio.py",
            native_libiio_candidate="libiio.so.0",
            native_libiio_path="/usr/lib/libiio.so.0",
            libiio_version="0.25",
            backends=("ip",),
        ),
    )


def test_metadata_soak_dry_run_is_non_mutating_and_exact() -> None:
    result = runner.invoke(
        app,
        [
            "radio",
            "soak-metadata",
            "192.168.1.15",
            "--expect-serial",
            SERIAL,
            "--slots",
            "9",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["execute"] is False
    assert document["plan"]["serial"] == SERIAL
    assert document["plan"]["expected_metadata_abi"] == 2
    assert document["confirmation_phrase"] == f"SOAK METADATA {SERIAL} 9"


def test_metadata_soak_execute_forwards_safety_inputs(
    tmp_path: Path, monkeypatch: Any
) -> None:
    known_hosts = tmp_path / "known_hosts"
    password = tmp_path / "password"
    known_hosts.write_text("192.168.1.15 ssh-ed25519 AAAATEST\n")
    password.write_text("analog\n")
    known_hosts.chmod(0o600)
    password.chmod(0o600)
    report = tmp_path / "report.json"
    calls: list[dict[str, Any]] = []

    class Transport:
        def __init__(self, **kwargs: Any) -> None:
            calls.append({"transport": kwargs})

    class Probe:
        def __init__(self, transport: object, *, serial: str) -> None:
            calls.append({"probe": {"transport": transport, "serial": serial}})

    def execute(plan: object, **kwargs: Any) -> object:
        calls.append({"execute": {"plan": plan, **kwargs}})
        return SimpleNamespace(model_dump=lambda **_kwargs: {"outcome": "pass"})

    monkeypatch.setattr("pluto_plus.cli.BoundSshTransport", Transport)
    monkeypatch.setattr("pluto_plus.cli.SshMetadataHealthProbe", Probe)
    monkeypatch.setattr("pluto_plus.cli.execute_metadata_soak", execute)

    result = runner.invoke(
        app,
        [
            "radio",
            "soak-metadata",
            "192.168.1.15",
            "--expect-serial",
            SERIAL,
            "--slots",
            "2",
            "--ssh-known-hosts-file",
            str(known_hosts),
            "--ssh-password-file",
            str(password),
            "--report",
            str(report),
            "--execute",
            "--confirm",
            f"SOAK METADATA {SERIAL} 2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["transport"]["host"] == "192.168.1.15"
    assert calls[0]["transport"]["known_hosts_file"] == known_hosts.resolve()
    assert calls[1]["probe"]["serial"] == SERIAL
    execution = calls[2]["execute"]
    assert execution["report_path"] == report.resolve()
    assert execution["slot_runner"].__name__ == "run_live_metadata_slot"


def test_metadata_soak_execute_requires_exact_confirmation_and_credentials() -> None:
    base = [
        "radio",
        "soak-metadata",
        "192.168.1.15",
        "--expect-serial",
        SERIAL,
        "--slots",
        "1",
        "--execute",
    ]
    result = runner.invoke(app, [*base, "--confirm", "wrong"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "metadata_soak_confirmation_required"
