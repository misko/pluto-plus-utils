from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus
from pluto_plus.ladder import (
    UNSAFE_KERNEL_QUEUE_CONFIRMATION,
    LadderCell,
    LadderReport,
)

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
            backends=("ip", "usb"),
        ),
    )


def _report(uri: str, serial: str, channels: tuple[int, ...] = (0, 1)) -> LadderReport:
    return LadderReport(
        serial=serial,
        uri=uri,
        transport="iio_usb" if uri.startswith("usb:") else "iio_ip",
        model="Pluto+ Test",
        firmware_version="v6",
        channels=channels,
        kernel_buffers=8,
        kernel_buffer_configuration_basis="readback",
        kernel_queue_bytes=262_144 * len(channels) * 4 * 8,
        unsafe_kernel_queue_override=False,
        wire_bytes_per_sample_period=len(channels) * 4,
        warmup_frames=2,
        cells=(
            LadderCell(
                sample_rate_hz=1_000_000,
                actual_sample_rate_hz=1_000_000,
                samples_per_channel=262_144,
                frames=12,
                wire_bytes=25_165_824,
                elapsed_seconds=3.2,
                offered_payload_mbps=8.0,
                achieved_payload_mbps=7.86432,
                achieved_payload_mibps=7.5,
                transferred_mb_per_minute=471.8592,
                delivered_sample_rate_sps=983_040,
                delivery_fraction=0.98304,
                latency_p50_ms=260,
                latency_p95_ms=280,
                kept_pace=True,
            ),
        ),
        failures=(),
        original_settings_restored=True,
    )


def test_ip_ladder_is_standalone_and_forwards_exact_identity(
    monkeypatch: Any,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(**kwargs: Any) -> LadderReport:
        calls.append(kwargs)
        return _report(kwargs["uri"], kwargs["serial"])

    monkeypatch.setattr("pluto_plus.cli.run_iio_ladder", run)
    result = runner.invoke(
        app,
        [
            "radio",
            "ladder",
            "192.168.1.15",
            "--transport",
            "ip",
            "--expect-serial",
            "SERIAL_A",
            "--rates",
            "1M,2M",
            "--channels",
            "rx0",
            "--frames",
            "4",
            "--samples",
            "16384",
            "--format",
            "json",
            "--kernel-buffers",
            "8",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["uri"] == "ip:192.168.1.15"
    assert calls[0]["serial"] == "SERIAL_A"
    assert calls[0]["rates_hz"] == (1_000_000, 2_000_000)
    assert calls[0]["channels"] == (0,)
    assert calls[0]["frames"] == 4
    assert calls[0]["kernel_buffers"] == 8
    assert calls[0]["allow_unsafe_kernel_queue"] is False
    assert json.loads(result.stdout)["original_settings_restored"] is True


def test_ip_ladder_forwards_exact_unsafe_kernel_queue_confirmation(
    monkeypatch: Any,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(**kwargs: Any) -> LadderReport:
        calls.append(kwargs)
        return _report(kwargs["uri"], kwargs["serial"], channels=(0,))

    monkeypatch.setattr("pluto_plus.cli.run_iio_ladder", run)
    result = runner.invoke(
        app,
        [
            "radio",
            "ladder",
            "192.168.1.187",
            "--transport",
            "ip",
            "--expect-serial",
            "SERIAL_A",
            "--channels",
            "rx0",
            "--unsafe-kernel-queue-confirm",
            UNSAFE_KERNEL_QUEUE_CONFIRMATION,
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["allow_unsafe_kernel_queue"] is True


def test_ip_ladder_rejects_inexact_unsafe_kernel_queue_confirmation() -> None:
    result = runner.invoke(
        app,
        [
            "radio",
            "ladder",
            "192.168.1.187",
            "--transport",
            "ip",
            "--expect-serial",
            "SERIAL_A",
            "--unsafe-kernel-queue-confirm",
            "yes",
        ],
    )

    assert result.exit_code == 2
    assert "must be exactly" in result.output


def test_usb_ladder_table_includes_bandwidth_and_restore_status(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "pluto_plus.cli.run_iio_ladder",
        lambda **kwargs: _report("usb:3.49.5", kwargs["serial"]),
    )
    result = runner.invoke(app, ["radio", "ladder", "SERIAL_A", "--transport", "usb"])

    assert result.exit_code == 0, result.output
    assert "7.86 MB/s" in result.stdout
    assert "472 MB/min" in result.stdout
    assert "98.3%" in result.stdout
    assert "Original RX settings restored: yes" in result.stdout
    assert "does not prove a gapless FPGA timeline" in result.stdout


def test_ladder_rejects_invalid_transport_target_and_identity(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "pluto_plus.cli.run_iio_ladder",
        lambda **_kwargs: _report("usb:1", "SERIAL_A"),
    )
    cases = (
        ["radio", "ladder", "host.local", "--transport", "ip"],
        ["radio", "ladder", "SERIAL_A", "--transport", "direct-usb"],
        [
            "radio",
            "ladder",
            "SERIAL_A",
            "--transport",
            "usb",
            "--expect-serial",
            "SERIAL_B",
        ],
    )
    for arguments in cases:
        result = runner.invoke(app, arguments)
        assert result.exit_code == 2
        assert "error" in json.loads(result.stderr)


def test_ladder_ip_isolation_requires_exact_usb_identity_and_confirmation(
    monkeypatch: Any,
) -> None:
    local_radio = SimpleNamespace(
        serial="SERIAL_A",
        usb_path="/sys/bus/usb/devices/3-8",
        host_network_interfaces=(SimpleNamespace(name="enx001"),),
    )
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (local_radio,))
    monkeypatch.setattr(
        "pluto_plus.host_isolation.prepare_usb_ssh_isolation",
        lambda *_args, **_kwargs: SimpleNamespace(confirmation_phrase="ISOLATE USB SSH enx001"),
    )

    result = runner.invoke(
        app,
        [
            "radio",
            "ladder",
            "192.168.2.1",
            "--transport",
            "ip",
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


def test_ladder_writes_an_absent_only_private_report(tmp_path: Path, monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "pluto_plus.cli.run_iio_ladder",
        lambda **kwargs: _report("usb:3.49.5", kwargs["serial"], kwargs["channels"]),
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir(mode=0o700)
    destination = evidence / "rx1.json"
    arguments = [
        "radio",
        "ladder",
        "SERIAL_A",
        "--transport",
        "usb",
        "--channels",
        "rx1",
        "--format",
        "json",
        "--report",
        str(destination),
    ]

    result = runner.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    assert destination.stat().st_mode & 0o777 == 0o600
    assert json.loads(destination.read_text())["channels"] == [1]
    repeated = runner.invoke(app, arguments)
    assert repeated.exit_code == 5, repeated.output
    assert "contract destination already exists" in repeated.output
