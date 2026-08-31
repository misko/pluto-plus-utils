from __future__ import annotations

import json
from types import SimpleNamespace
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
            ram_dropped_frames=0,
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
            "drop_backlog_on_overrun": True,
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


def test_direct_ladder_can_select_preserve_backlog(monkeypatch: pytest.MonkeyPatch) -> None:
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
            "--rates",
            "5M",
            "--durations",
            "3",
            "--preserve-backlog-on-overrun",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["drop_backlog_on_overrun"] is False


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


def test_direct_ladder_route_isolation_requires_exact_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_radio = SimpleNamespace(
        serial="SERIAL_A",
        usb_path="/sys/bus/usb/devices/3-8",
        host_network_interfaces=(SimpleNamespace(name="enx001"),),
    )
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (local_radio,))
    monkeypatch.setattr(
        "pluto_plus.host_isolation.prepare_usb_ssh_isolation",
        lambda *_args, **_kwargs: SimpleNamespace(
            confirmation_phrase="ISOLATE USB SSH enx001"
        ),
    )

    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.2.1",
            "--expect-serial",
            "SERIAL_A",
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--isolate-usb-route",
        ],
    )

    assert result.exit_code == 2, result.output
    assert "host_isolation_confirmation_required" in result.output
    assert "ISOLATE USB SSH enx001" in result.output


def test_direct_ladder_runs_inside_exact_usb_route_isolation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local_radio = SimpleNamespace(
        serial="SERIAL_A",
        usb_path="/sys/bus/usb/devices/3-8",
        host_network_interfaces=(SimpleNamespace(name="enx001"),),
    )
    plan = SimpleNamespace(confirmation_phrase="ISOLATE USB SSH enx001")
    receipt = SimpleNamespace(receipt_path="/private/isolation.json")
    prepared: list[tuple[tuple[object, ...], dict[str, object]]] = []
    executed: list[dict[str, object]] = []

    def prepare(*args: object, **kwargs: object) -> object:
        prepared.append((args, kwargs))
        return plan

    def execute(_plan: object, **kwargs: object) -> tuple[DirectAsyncLadderReport, object]:
        executed.append(kwargs)
        action = kwargs["action"]
        assert callable(action)
        return action(), receipt

    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (local_radio,))
    monkeypatch.setattr("pluto_plus.host_isolation.prepare_usb_ssh_isolation", prepare)
    monkeypatch.setattr("pluto_plus.host_isolation.execute_usb_ssh_isolated", execute)
    monkeypatch.setattr("pluto_plus.cli.run_direct_async_ladder", _report)

    result = runner.invoke(
        app,
        [
            "radio",
            "direct-async-ladder",
            "192.168.2.1",
            "--ip-port",
            "30431",
            "--expect-serial",
            "SERIAL_A",
            "--rates",
            "5M",
            "--durations",
            "3",
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--isolate-usb-route",
            "--isolation-confirm",
            "ISOLATE USB SSH enx001",
        ],
    )

    assert result.exit_code == 0, result.output
    assert prepared == [
        (
            ("enx001", "192.168.2.1"),
            {"pluto_interfaces": ("enx001",)},
        )
    ]
    assert executed[0]["confirmation"] == "ISOLATE USB SSH enx001"
    assert "Host isolation receipt: /private/isolation.json" in result.stdout


def test_direct_ladder_requires_exact_ip_identity() -> None:
    result = runner.invoke(
        app,
        ["radio", "direct-async-ladder", "192.168.1.15"],
    )

    assert result.exit_code == 2
    assert "requires --expect-serial" in result.output
