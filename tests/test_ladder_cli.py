from __future__ import annotations

import json
from typing import Any

from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.ladder import LadderCell, LadderReport

runner = CliRunner()


def _report(uri: str, serial: str) -> LadderReport:
    return LadderReport(
        serial=serial,
        uri=uri,
        transport="iio_usb" if uri.startswith("usb:") else "iio_ip",
        model="Pluto+ Test",
        firmware_version="v6",
        channels=(0, 1),
        kernel_buffers=8,
        wire_bytes_per_sample_period=8,
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
    assert calls[0]["frames"] == 4
    assert calls[0]["kernel_buffers"] == 8
    assert json.loads(result.stdout)["original_settings_restored"] is True


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
