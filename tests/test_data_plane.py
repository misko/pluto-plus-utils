from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.data_plane import (
    MAX_SAFE_IIO_BUFFER_BYTES,
    DataPlaneProbe,
    DataPlaneRecoveryError,
    DataPlaneRuntimeStatus,
    IiodThreadRuntime,
    compare_iiod_thread_cpu,
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
    iiod_threads = encode(
        "4371\t352201\t120\t30\t302d31\t69696f64\n"
        "4380\t352250\t80\t20\t31\t69696f642d72772d776f726b6572\n"
    )
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
            "PPU\ttandem_state\t0",
            "PPU\ttandem_fifo_level\t0",
            "PPU\ttandem_fault_flags\t0",
            "PPU\ttandem_overflow_count\t7",
            "PPU\tcma_total_kib\t65536",
            "PPU\tcma_free_kib\t64620",
            "PPU\tmemory_total_kib\t492560",
            "PPU\tmemory_available_kib\t401234",
            "PPU\tinterrupt_total\t1234",
            "PPU\tclock_ticks_per_second\t100",
            "PPU\tuptime_centiseconds\t123456",
            f"PPU\tiiod_threads_hex\t{iiod_threads}",
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
    assert b"tandem_device" in transport.stdin
    assert b"kill " not in transport.stdin
    assert b'>"$rx_device' not in transport.stdin
    assert status.iiod_pid == 4371
    assert status.cma_free_bytes == 64_620 * 1024
    assert status.memory_total_bytes == 492_560 * 1024
    assert status.memory_available_bytes == 401_234 * 1024
    assert status.interrupt_total == 1234
    assert status.clock_ticks_per_second == 100
    assert status.uptime_centiseconds == 123_456
    assert [(thread.tid, thread.user_ticks) for thread in status.iiod_threads] == [
        (4371, 120),
        (4380, 80),
    ]
    assert status.iiod_threads[1].name == "iiod-rw-worker"
    assert status.iiod_threads[1].cpu_allowed_list == "1"
    assert status.tandem_state == 0
    assert status.tandem_fifo_level == 0
    assert status.tandem_fault_flags == 0
    assert status.tandem_overflow_count == 7
    assert status.fpga_devices == ("7c400000.dma", "79020000.cf-ad9361-lpc")
    assert status.dma_devices == ("7c400000.dma",)
    assert status.interrupt_lines == ("54: 9 0 dma0chan0",)


def _cpu_snapshot(
    *,
    uptime_centiseconds: int,
    threads: tuple[IiodThreadRuntime, ...],
    pid: int = 4371,
) -> DataPlaneRuntimeStatus:
    return DataPlaneRuntimeStatus(
        serial="SERIAL_A",
        iiod_pid=pid,
        iiod_start_ticks=352201,
        iiod_generation=2,
        active_rx_buffers=0,
        rx_buffer_length=65_536,
        rx_data_available=0,
        rx_device_path="/sys/devices/fpga-axi/iio:device1",
        tandem_state=0,
        tandem_fifo_level=0,
        tandem_fault_flags=0,
        tandem_overflow_count=0,
        cma_total_bytes=64 * 1024 * 1024,
        cma_free_bytes=63 * 1024 * 1024,
        memory_total_bytes=492_560 * 1024,
        memory_available_bytes=401_234 * 1024,
        interrupt_total=1_234,
        clock_ticks_per_second=100,
        uptime_centiseconds=uptime_centiseconds,
        iiod_threads=threads,
        fpga_devices=("7c400000.dma",),
        dma_devices=("7c400000.dma",),
        interrupt_lines=(),
        kernel_events=(),
    )


def _thread(
    tid: int,
    *,
    start_ticks: int,
    user_ticks: int,
    system_ticks: int,
) -> IiodThreadRuntime:
    return IiodThreadRuntime(
        tid=tid,
        start_ticks=start_ticks,
        user_ticks=user_ticks,
        system_ticks=system_ticks,
        cpu_allowed_list="1",
        name="iiod",
    )


def test_compare_iiod_thread_cpu_reports_stable_threads_and_churn() -> None:
    before = _cpu_snapshot(
        uptime_centiseconds=1_000,
        threads=(
            _thread(4371, start_ticks=352201, user_ticks=100, system_ticks=20),
            _thread(4380, start_ticks=352250, user_ticks=50, system_ticks=10),
            _thread(4381, start_ticks=352260, user_ticks=20, system_ticks=5),
        ),
    )
    after = _cpu_snapshot(
        uptime_centiseconds=1_200,
        threads=(
            _thread(4371, start_ticks=352201, user_ticks=120, system_ticks=30),
            _thread(4380, start_ticks=352250, user_ticks=130, system_ticks=20),
            _thread(4382, start_ticks=352400, user_ticks=1, system_ticks=0),
        ),
    )

    sample = compare_iiod_thread_cpu(before, after)

    assert sample.elapsed_ms == 2_000
    assert sample.total_cpu_seconds == pytest.approx(1.2)
    assert sample.total_cpu_percent == pytest.approx(60)
    assert [(thread.tid, thread.cpu_percent) for thread in sample.threads] == [
        (4371, pytest.approx(15)),
        (4380, pytest.approx(45)),
    ]
    assert sample.new_thread_ids == (4382,)
    assert sample.disappeared_thread_ids == (4381,)


def test_compare_iiod_thread_cpu_rejects_process_change_and_counter_regression() -> None:
    thread = _thread(4371, start_ticks=352201, user_ticks=100, system_ticks=20)
    before = _cpu_snapshot(uptime_centiseconds=1_000, threads=(thread,))
    changed = _cpu_snapshot(uptime_centiseconds=1_200, threads=(thread,), pid=5000)
    with pytest.raises(DataPlaneRecoveryError, match="identity changed"):
        compare_iiod_thread_cpu(before, changed)

    regressed = _cpu_snapshot(
        uptime_centiseconds=1_200,
        threads=(_thread(4371, start_ticks=352201, user_ticks=99, system_ticks=20),),
    )
    with pytest.raises(DataPlaneRecoveryError, match="moved backwards"):
        compare_iiod_thread_cpu(before, regressed)


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
