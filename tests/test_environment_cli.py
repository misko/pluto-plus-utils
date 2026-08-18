from __future__ import annotations

import json
from typing import Any

from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus

runner = CliRunner()


def _report(*, healthy: bool) -> IioEnvironmentReport:
    return IioEnvironmentReport(
        healthy=healthy,
        status=(
            IioEnvironmentStatus.READY
            if healthy
            else IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE
        ),
        message="ready" if healthy else "native library and binding are incompatible",
        remediation=None if healthy else "install a matched pair",
        python_executable="/venv/python",
        pyadi_path="/venv/adi/__init__.py",
        pylibiio_path="/venv/iio.py",
        native_libiio_candidate="libiio.so.0",
        native_libiio_path="/usr/lib/libiio.so.0",
        libiio_version="0.25" if healthy else None,
        backends=("local", "ip", "usb") if healthy else (),
        underlying_error=None if healthy else "AttributeError: undefined symbol: example",
    )


def test_environment_json_reports_healthy_native_details(monkeypatch: Any) -> None:
    monkeypatch.setattr("pluto_plus.cli.inspect_iio_environment", lambda: _report(healthy=True))

    result = runner.invoke(app, ["environment", "--format", "json"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["status"] == "ready"
    assert payload["native_libiio_path"] == "/usr/lib/libiio.so.0"
    assert payload["backends"] == ["local", "ip", "usb"]


def test_environment_failure_is_json_safe_and_nonzero(monkeypatch: Any) -> None:
    monkeypatch.setattr("pluto_plus.cli.inspect_iio_environment", lambda: _report(healthy=False))

    result = runner.invoke(app, ["environment", "--format", "json"])

    assert result.exit_code == 5
    payload = json.loads(result.stdout)
    assert payload["status"] == "libiio_abi_incompatible"
    assert payload["underlying_error"] == "AttributeError: undefined symbol: example"
    assert payload["remediation"] == "install a matched pair"


def test_ladder_preflight_returns_precise_error_before_radio_open(monkeypatch: Any) -> None:
    called = False

    def run(**_kwargs: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment", lambda **_kwargs: _report(healthy=False)
    )
    monkeypatch.setattr("pluto_plus.cli.run_iio_ladder", run)

    result = runner.invoke(app, ["radio", "ladder", "SERIAL_A", "--transport", "usb"])

    assert result.exit_code == 5
    assert called is False
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "libiio_abi_incompatible"
    assert "undefined symbol: example" in error["message"]
    assert "install a matched pair" in error["message"]
