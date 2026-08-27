from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.fastlock import FastLockProbePlan
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus

runner = CliRunner()


def _plan() -> FastLockProbePlan:
    return FastLockProbePlan(
        serial="SERIAL_A",
        uri="usb:3.49.5",
        usb_path="/sys/bus/usb/devices/3-8",
        lower_frequency_hz=959_687_500,
        upper_frequency_hz=1_190_312_500,
        lower_profile=6,
        upper_profile=7,
        hops_per_mode=4,
        dwell_us=1_000,
        profile_settle_ms=20,
        max_seconds=60,
        expected_confirmation="FASTLOCK USB SERIAL_A",
    )


def _healthy_environment() -> IioEnvironmentReport:
    return IioEnvironmentReport(
        healthy=True,
        status=IioEnvironmentStatus.READY,
        message="ready",
        python_executable="/venv/python",
        pyadi_path="/venv/adi/__init__.py",
        pylibiio_path="/venv/iio.py",
        native_libiio_candidate="libiio.so.0",
        native_libiio_path="/venv/lib/libiio.so.0",
        libiio_version="0.25",
        backends=("usb",),
    )


def test_fastlock_dry_run_prints_exact_usb_plan_without_opening_radio(
    monkeypatch: Any,
) -> None:
    monkeypatch.setattr("pluto_plus.cli.prepare_usb_fastlock_probe", lambda *_a, **_k: _plan())
    monkeypatch.setattr(
        "pluto_plus.cli.run_usb_fastlock_probe",
        lambda _plan: (_ for _ in ()).throw(AssertionError("radio must not open")),
    )

    result = runner.invoke(app, ["radio", "fastlock-probe", "SERIAL_A"])

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["execute"] is False
    assert payload["plan"]["uri"] == "usb:3.49.5"
    assert payload["confirmation_phrase"] == "FASTLOCK USB SERIAL_A"


def test_fastlock_execution_requires_confirmation_and_writes_report(
    monkeypatch: Any, tmp_path: Path
) -> None:
    plan = _plan()
    monkeypatch.setattr("pluto_plus.cli.prepare_usb_fastlock_probe", lambda *_a, **_k: plan)
    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment", lambda **_k: _healthy_environment()
    )
    report = SimpleNamespace(model_dump=lambda **_kwargs: {"serial": "SERIAL_A", "ok": True})
    calls: list[tuple[Path, object]] = []
    monkeypatch.setattr("pluto_plus.cli.run_usb_fastlock_probe", lambda _plan: report)
    monkeypatch.setattr(
        "pluto_plus.cli.write_fastlock_report", lambda path, value: calls.append((path, value))
    )
    path = tmp_path / "fastlock.json"

    refused = runner.invoke(
        app,
        ["radio", "fastlock-probe", "SERIAL_A", "--execute", "--confirm", "wrong"],
    )
    assert refused.exit_code == 2
    assert json.loads(refused.stderr)["error"]["code"] == "fastlock_confirmation_required"

    result = runner.invoke(
        app,
        [
            "radio",
            "fastlock-probe",
            "SERIAL_A",
            "--execute",
            "--confirm",
            plan.expected_confirmation,
            "--format",
            "json",
            "--report",
            str(path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [(path.resolve(), report)]
    assert json.loads(result.stdout)["report"]["ok"] is True
