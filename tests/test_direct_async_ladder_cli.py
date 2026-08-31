from __future__ import annotations

import json
from typing import Any

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.direct_async_ladder import (
    DirectAsyncLadderCell,
    DirectAsyncLadderReport,
)
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus

runner = CliRunner()


@pytest.fixture(autouse=True)
def _healthy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
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
            native_libiio_path="/venv/lib/libiio.so.0",
            libiio_version="0.25 (b7303fd)",
            backends=("ip", "usb"),
        ),
    )


def _report(**kwargs: Any) -> DirectAsyncLadderReport:
    cells = tuple(
        DirectAsyncLadderCell(
            sample_rate_hz=rate,
            requested_duration_seconds=duration,
            nominal_capture_seconds=1_048_576 / rate,
            samples_per_frame=1_048_576,
            requested_frames=1,
            observed_frames=1,
            capture_segments=1,
            iq_bytes=4_194_304,
            elapsed_seconds=0.1,
            offered_payload_mbps=rate * 4 / 1_000_000,
            achieved_payload_mbps=41.94304,
            achieved_payload_mibps=40.0,
            gap_frames=0,
            missing_sample_count=0,
            overflow_frames=0,
            inter_segment_skipped_samples=0,
            ram_spilled_frames=0,
            ram_drained_frames=0,
            ram_high_water_frames=0,
            passed=True,
        )
        for rate in kwargs["rates_hz"]
        for duration in kwargs["durations_seconds"]
    )
    return DirectAsyncLadderReport(
        serial=kwargs["serial"],
        uri=kwargs["uri"],
        transport="iio_ip",
        model="Pluto+ Test",
        firmware_version="direct-v1",
        mode="direct",
        channels=kwargs["channels"],
        rates_hz=kwargs["rates_hz"],
        durations_seconds=kwargs["durations_seconds"],
        samples_per_frame=1_048_576,
        kernel_buffers=kwargs["kernel_buffers"],
        ram_ring_slots=0,
        tandem_mode=kwargs["tandem_mode"],
        iq_decoder=kwargs["iq_decoder"],
        cells=cells,
        failures=(),
        original_settings_restored=True,
    )


def test_direct_ladder_one_command_forwards_exact_requested_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(**kwargs: Any) -> DirectAsyncLadderReport:
        calls.append(kwargs)
        return _report(**kwargs)

    monkeypatch.setattr("pluto_plus.cli.run_direct_async_ladder", run)
    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.1.15",
            "--transport",
            "ip",
            "--ip-port",
            "30432",
            "--expect-serial",
            "SERIAL_A",
            "--rates",
            "5M,10M,15M,25M",
            "--durations",
            "3,10",
            "--channels",
            "rx0",
            "--samples",
            "1048576",
            "--kernel-buffers",
            "15",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls == [
        {
            "uri": "ip:192.168.1.15:30432",
            "serial": "SERIAL_A",
            "rates_hz": (5_000_000, 10_000_000, 15_000_000, 25_000_000),
            "durations_seconds": (3.0, 10.0),
            "channels": (0,),
            "samples_per_frame": 1_048_576,
            "kernel_buffers": 15,
            "ram_ring_slots": 0,
            "tandem_mode": "hold",
            "iq_decoder": "pyadi",
        }
    ]
    document = json.loads(result.stdout)
    assert document["rates_hz"] == [5_000_000, 10_000_000, 15_000_000, 25_000_000]
    assert document["durations_seconds"] == [3.0, 10.0]
    assert len(document["cells"]) == 8


def test_direct_ladder_defaults_are_the_requested_release_matrix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(**kwargs: Any) -> DirectAsyncLadderReport:
        calls.append(kwargs)
        return _report(**kwargs)

    monkeypatch.setattr("pluto_plus.cli.run_direct_async_ladder", run)
    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.1.15",
            "--expect-serial",
            "SERIAL_A",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["rates_hz"] == (5_000_000, 10_000_000, 15_000_000, 25_000_000)
    assert calls[0]["durations_seconds"] == (3.0, 10.0)


def test_direct_ladder_table_names_segment_and_rearm_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("pluto_plus.cli.run_direct_async_ladder", _report)
    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.1.15",
            "--expect-serial",
            "SERIAL_A",
            "--rates",
            "5M",
            "--durations",
            "3",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "REARM SKIP" in result.stdout
    assert "segments gapless" in result.stdout


def test_direct_ram_ladder_forwards_extension_slots(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_with_slots(**kwargs: Any) -> DirectAsyncLadderReport:
        raise RuntimeError(f"slots={kwargs['ram_ring_slots']}")

    monkeypatch.setattr("pluto_plus.cli.run_direct_async_ladder", fail_with_slots)
    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.1.15",
            "--expect-serial",
            "SERIAL_A",
            "--ram-ring-slots",
            "13",
        ],
    )

    assert result.exit_code == 5
    assert "slots=13" in result.output


def test_direct_ladder_requires_exact_ip_identity() -> None:
    result = runner.invoke(
        app,
        ["radio", "direct-async-ladder", "192.168.1.15"],
    )

    assert result.exit_code == 2
    assert "requires --expect-serial" in result.output
