from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus
from pluto_plus.tandem_qualification import TandemQualificationPlan

runner = CliRunner()


def _plan() -> TandemQualificationPlan:
    return TandemQualificationPlan(
        profile_id="candidate-profile",
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        physical_attenuation_db=20,
        strong_tx_gain_db=-10,
        weak_tx_gain_db=-60,
        effective_attenuation_db=30,
        expected_firmware="candidate-v6",
        expected_metadata_abi=2,
        frequencies_hz=(915_000_000, 2_450_000_000, 5_800_000_000),
        confirmation_phrase="QUALIFY TANDEM SERIAL_A 20DB",
    )


def _arguments() -> list[str]:
    return [
        "radio",
        "qualify-tandem",
        "SERIAL_A",
        "--usb-sysfs-path",
        "/sys/bus/usb/devices/3-8",
        "--attenuation-db",
        "20",
    ]


def _unhealthy_environment() -> IioEnvironmentReport:
    return IioEnvironmentReport(
        healthy=False,
        status=IioEnvironmentStatus.LIBIIO_ABI_INCOMPATIBLE,
        message="The native libiio library is incompatible with pylibiio.",
        remediation="Install a matched native libiio and pylibiio pair.",
        python_executable="/venv/python",
        pyadi_path="/venv/adi/__init__.py",
        pylibiio_path="/venv/iio.py",
        native_libiio_candidate="libiio.so.0",
        underlying_error="AttributeError: undefined symbol: iio_get_backends_count",
    )


def test_qualify_tandem_dry_run_does_not_require_host_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pluto_plus.tandem_qualification.prepare_tandem_qualification",
        lambda *args, **kwargs: _plan(),
    )
    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment",
        lambda **kwargs: pytest.fail("dry run must not inspect the host IIO environment"),
    )

    result = runner.invoke(app, _arguments())

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["mode"] == "dry_run"
    assert document["will_enable_tx2"] is False
    assert document["plan"]["confirmation_phrase"] == "QUALIFY TANDEM SERIAL_A 20DB"


def test_qualify_tandem_forwards_exact_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected: list[str] = []

    def prepare(*args: object, **kwargs: object) -> TandemQualificationPlan:
        del args
        selected.append(str(kwargs["profile_id"]))
        return _plan()

    monkeypatch.setattr(
        "pluto_plus.tandem_qualification.prepare_tandem_qualification",
        prepare,
    )

    result = runner.invoke(
        app,
        [*_arguments(), "--profile", "exact-candidate-profile"],
    )

    assert result.exit_code == 0, result.output
    assert selected == ["exact-candidate-profile"]


def test_qualify_tandem_execute_preflights_usb_before_confirmation_or_hardware(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[bool] = []
    executed = False

    monkeypatch.setattr(
        "pluto_plus.tandem_qualification.prepare_tandem_qualification",
        lambda *args, **kwargs: _plan(),
    )

    def inspect(*, require_usb: bool) -> IioEnvironmentReport:
        calls.append(require_usb)
        return _unhealthy_environment()

    def execute(*args: object, **kwargs: object) -> None:
        nonlocal executed
        executed = True

    monkeypatch.setattr("pluto_plus.cli.inspect_iio_environment", inspect)
    monkeypatch.setattr(
        "pluto_plus.tandem_qualification.execute_tandem_qualification", execute
    )

    result = runner.invoke(app, [*_arguments(), "--execute"])

    assert result.exit_code == 5
    assert calls == [True]
    assert executed is False
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "libiio_abi_incompatible"
    assert "undefined symbol: iio_get_backends_count" in error["message"]
    assert "Install a matched native libiio and pylibiio pair" in error["message"]
    assert "Traceback" not in result.output
