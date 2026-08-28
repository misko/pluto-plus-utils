from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.data_plane import (
    MAX_SAFE_IIO_BUFFER_BYTES,
    DataPlaneProbe,
    DataPlaneRecoveryError,
    iio_buffer_wire_bytes,
    inspect_data_plane_runtime,
    probe_iio_data_plane,
    require_safe_iio_buffer,
    restart_attested_iiod,
    wait_for_iio_data_plane,
)


class _ProbeDevice:
    def __init__(self, uri: str, *, serial: str = "SERIAL_A", fail: bool = False) -> None:
        self.uri = uri
        self.fail = fail
        self.timeout_calls: list[int] = []
        self.destroy_calls = 0
        self.rx_buffer_size = 1
        self.rx_enabled_channels = [0, 1]
        self.ctx = SimpleNamespace(
            attrs={"hw_serial": serial},
            set_timeout=self.timeout_calls.append,
            destroy=lambda: None,
        )

    def rx_destroy_buffer(self) -> None:
        self.destroy_calls += 1

    def rx(self) -> np.ndarray:
        if self.fail:
            raise TimeoutError(110, "synthetic iiOD wedge")
        return np.ones((2, self.rx_buffer_size), dtype=np.complex64)


class _ProbeAdi:
    def __init__(self, *, serial: str = "SERIAL_A", fail: bool = False) -> None:
        self.serial = serial
        self.fail = fail
        self.device: _ProbeDevice | None = None

    def ad9361(self, uri: str) -> _ProbeDevice:
        self.device = _ProbeDevice(uri, serial=self.serial, fail=self.fail)
        return self.device


def test_single_iio_buffer_guard_enforces_half_of_supported_cma() -> None:
    assert require_safe_iio_buffer(4_194_304, 2) == MAX_SAFE_IIO_BUFFER_BYTES

    with pytest.raises(DataPlaneRecoveryError, match="50%"):
        require_safe_iio_buffer(4_194_305, 2)

    assert iio_buffer_wire_bytes(16_000_000, 1) > MAX_SAFE_IIO_BUFFER_BYTES


def test_bounded_data_plane_probe_attests_serial_shape_and_cleanup() -> None:
    module = _ProbeAdi()

    probe = probe_iio_data_plane(
        "usb:",
        "SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
    )

    assert probe.status == "pass"
    assert probe.receiver_count == 2
    assert probe.wire_bytes == 524_288
    assert probe.uri == "usb:1.2.3"
    assert module.device is not None
    assert module.device.destroy_calls == 3


def test_bounded_data_plane_probe_reports_timeout_without_throwing() -> None:
    probe = probe_iio_data_plane(
        "usb:",
        "SERIAL_A",
        adi_module=_ProbeAdi(fail=True),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )

    assert probe.status == "fail"
    assert probe.error is not None and "TimeoutError" in probe.error


def test_bounded_data_plane_probe_preloads_exact_native_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "pluto_plus.data_plane.inspect_iio_environment",
        lambda **kwargs: SimpleNamespace(
            healthy=False,
            actionable_message="exact metadata runtime is unavailable",
        ),
    )

    probe = probe_iio_data_plane("usb:", "SERIAL_A")

    assert probe.status == "fail"
    assert probe.failure_kind == "environment"
    assert probe.error is not None and "exact metadata runtime" in probe.error


def test_bounded_data_plane_probe_rejects_wrong_context_identity() -> None:
    probe = probe_iio_data_plane(
        "usb:",
        "SERIAL_A",
        adi_module=_ProbeAdi(serial="SERIAL_B"),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )

    assert probe.status == "fail"
    assert probe.error is not None and "SERIAL_B" in probe.error


def test_data_plane_wait_retries_startup_timeouts_but_not_identity_failures() -> None:
    calls = 0

    def eventually_healthy(uri: str, serial: str) -> DataPlaneProbe:
        nonlocal calls
        calls += 1
        return DataPlaneProbe(
            status="pass" if calls == 2 else "fail",
            serial=serial,
            uri=uri,
            samples_per_channel=65_536,
            receiver_count=2,
            wire_bytes=524_288,
            elapsed_ms=1,
            failure_kind=None if calls == 2 else "timeout",
            error=None if calls == 2 else "TimeoutError",
        )

    assert (
        wait_for_iio_data_plane(
            "usb:",
            "SERIAL_A",
            timeout_s=1,
            poll_interval_s=0.001,
            probe=eventually_healthy,
        ).status
        == "pass"
    )
    assert calls == 2


class _RecoveryTransport:
    def __init__(self, output: str) -> None:
        self.output = output
        self.command = ""
        self.stdin: bytes | None = None

    def run(self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15) -> str:
        del timeout_s
        self.command = command
        self.stdin = stdin
        return self.output


def _restart_report(*, serial: str = "SERIAL_A") -> str:
    return "\n".join(
        (
            f"PPU\tserial\t{serial}",
            "PPU\tprevious_pid\t101",
            "PPU\treplacement_pid\t202",
            "PPU\tprevious_start_ticks\t1000",
            "PPU\treplacement_start_ticks\t2000",
            "PPU\tactive_rx_buffers_before\t1",
            "PPU\tcma_total_kib\t65536",
            "PPU\tcma_free_before_kib\t12000",
            "PPU\tcma_free_after_kib\t65000",
        )
    )


def _runtime_report(*, serial: str = "SERIAL_A") -> str:
    def encode(value: str) -> str:
        return value.encode().hex()

    dma_devices = encode("7c400000.dma\n")
    fpga_devices = encode("7c400000.dma\n79020000.cf-ad9361-lpc\n")
    interrupt_lines = encode("54: 9 0 dma0chan0\n")
    kernel_events = encode("axi-dmac initialized\n")
    return "\n".join(
        (
            f"PPU\tserial\t{serial}",
            "PPU\tiiod_pid\t4371",
            "PPU\tiiod_start_ticks\t352201",
            "PPU\tiiod_generation\t2",
            "PPU\tactive_rx_buffers\t0",
            "PPU\trx_buffer_length\t65536",
            "PPU\trx_data_available\t0",
            "PPU\trx_device_path\t/sys/devices/fpga-axi/iio:device1",
            "PPU\tcma_total_kib\t65536",
            "PPU\tcma_free_kib\t64620",
            "PPU\tinterrupt_total\t1234",
            f"PPU\tfpga_devices_hex\t{fpga_devices}",
            f"PPU\tdma_devices_hex\t{dma_devices}",
            f"PPU\tinterrupt_lines_hex\t{interrupt_lines}",
            f"PPU\tkernel_events_hex\t{kernel_events}",
        )
    )


def test_inspect_data_plane_runtime_uses_read_only_fixed_script() -> None:
    transport = _RecoveryTransport(_runtime_report())

    status = inspect_data_plane_runtime(transport, "SERIAL_A")

    assert transport.command == "sh -s -- SERIAL_A"
    assert transport.stdin is not None
    assert b"/proc/interrupts" in transport.stdin
    assert b"rx_bus_path" in transport.stdin
    assert b"kill " not in transport.stdin
    assert b">\"$rx_device" not in transport.stdin
    assert status.iiod_pid == 4371
    assert status.cma_free_bytes == 64_620 * 1024
    assert status.interrupt_total == 1234
    assert status.fpga_devices == ("7c400000.dma", "79020000.cf-ad9361-lpc")
    assert status.dma_devices == ("7c400000.dma",)
    assert status.interrupt_lines == ("54: 9 0 dma0chan0",)


def test_restart_attested_iiod_uses_fixed_script_and_records_generation() -> None:
    transport = _RecoveryTransport(_restart_report())

    evidence = restart_attested_iiod(transport, "SERIAL_A")

    assert transport.command == "sh -s -- SERIAL_A 30"
    assert transport.stdin is not None
    assert b'kill "$previous_pid"' in transport.stdin
    assert evidence.previous_pid == 101
    assert evidence.replacement_pid == 202
    assert evidence.active_rx_buffers_before == 1
    assert evidence.cma_total_bytes == 64 * 1024 * 1024


def test_restart_attested_iiod_rejects_wrong_radio_and_unchanged_generation() -> None:
    with pytest.raises(DataPlaneRecoveryError, match="different radio"):
        restart_attested_iiod(_RecoveryTransport(_restart_report(serial="SERIAL_B")), "SERIAL_A")

    unchanged = (
        _restart_report()
        .replace("replacement_pid\t202", "replacement_pid\t101")
        .replace("replacement_start_ticks\t2000", "replacement_start_ticks\t1000")
    )
    with pytest.raises(DataPlaneRecoveryError, match="did not change"):
        restart_attested_iiod(_RecoveryTransport(unchanged), "SERIAL_A")
