"""Hardware-free finite PIL1 lifecycle tests; mocks are not DMA/RF qualification."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from types import SimpleNamespace

import pytest

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware import pilot_iio
from pluto_plus.hardware.pilot_iio import (
    PILOT_CAPTURE_ABI,
    PILOT_DEVICE,
    PilotCaptureError,
    PilotIioClient,
)

SERIAL = "1040007c4a94000211000b009186843ef2"


class _Attr:
    def __init__(self, value: str, *, getter: Callable[[], str] | None = None) -> None:
        self.stored = value
        self.getter = getter
        self.on_write: Callable[[str], None] | None = None

    @property
    def value(self) -> str:
        return self.getter() if self.getter else self.stored

    @value.setter
    def value(self, value: str) -> None:
        if self.on_write:
            self.on_write(value)
        self.stored = value


class _Device:
    def __init__(self, *, rate: int = 15_000_000) -> None:
        self.name = PILOT_DEVICE
        self.rate = rate
        self.actual_rate = rate
        self.sample_size = 4
        self.samples = 0
        self.visit = 0
        self.generation = 0
        self.active = False
        self.armed = False
        self.fault = 0
        self.ddc_fault = 0
        self.clips = 0
        self.dma_error = 0
        self.recovery_failed = 0
        self.freeze_generation = False
        self.snapshot_hook: Callable[[], None] | None = None
        self.attrs = {
            "capture_abi": _Attr(PILOT_CAPTURE_ABI),
            "capture_visit_id": _Attr("77"),
            "capture_sample_limit": _Attr("100"),
            "capture_snapshot": _Attr("", getter=self.snapshot),
        }
        self.channels = [
            SimpleNamespace(
                scan_element=True, index=index, output=False, enabled=bool(index),
                modifier=SimpleNamespace(name=("IIO_MOD_I", "IIO_MOD_Q")[index]),
                data_format=SimpleNamespace(
                    length=16, bits=16, shift=0, repeat=1, is_signed=True,
                    is_be=False, is_fully_defined=True,
                ),
                attrs={"sampling_frequency": _Attr("2500000")},
            )
            for index in range(2)
        ]

    def snapshot(self) -> str:
        if self.snapshot_hook:
            self.snapshot_hook()
        if not self.freeze_generation or not self.generation:
            self.generation += 1
        words = [0] * 26
        first = 540 if self.samples else 0
        last = first + (self.samples - 1) * 6 if self.samples else 0
        unsupported = 90 if self.armed else 0
        values = (first, last, self.samples, self.samples, unsupported, 0,
                  (self.samples + unsupported) * 6, self.samples + unsupported)
        for index, value in enumerate(values):
            words[2 * index:2 * index + 2] = [value & 0xffffffff, value >> 32]
        words[16] = self.clips
        words[17] = self.ddc_fault
        words[18] = self.fault
        words[19] = (int(self.active) | (4 if self.fault else 0) |
                     (8 if self.samples else 0) | (16 if self.armed else 0))
        words[20] = self.visit
        return (
            f"PIL1 00010000 {self.rate} 2500000 {self.generation} "
            f"{self.recovery_failed} {self.actual_rate} {self.dma_error} " +
            " ".join(f"{word:08x}" for word in words)
        )


class _Context:
    def __init__(self, device: _Device) -> None:
        self.device = device
        self.attrs = {"hw_serial": SERIAL, "boot_id": "boot-a"}
        self.timeouts: list[int] = []
        self.closes = 0

    def set_timeout(self, milliseconds: int) -> None:
        self.timeouts.append(milliseconds)

    def find_device(self, name: str) -> _Device | None:
        return self.device if name == PILOT_DEVICE else None

    def close(self) -> None:
        self.closes += 1


class _Buffer:
    def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
        assert not cyclic
        assert count % 2 == 0
        assert device.attrs["capture_sample_limit"].value != "100"
        assert device.attrs["capture_visit_id"].value != "77"
        assert all(channel.enabled for channel in device.channels)
        self.device = device
        self.count = count
        self._samples_count = count
        self.byte_length = count * 4
        self.limit = int(device.attrs["capture_sample_limit"].value)
        self.step = 4
        self.refills = 0
        self.closes = 0
        self.cancels = 0
        self.read_delta = 0
        self.on_refill: Callable[[], None] | None = None
        self.on_close: Callable[[], None] | None = None
        device.samples = 0
        device.armed = device.active = True
        device.visit = int(device.attrs["capture_visit_id"].value)

    def refill(self) -> None:
        self.refills += 1
        if self.on_refill:
            self.on_refill()
        self.device.samples += self.count
        self.device.active = self.device.samples < self.limit

    def __len__(self) -> int:
        return self.byte_length

    def read(self) -> bytes:
        return bytes([self.refills & 0xff]) * (self.count * 4 + self.read_delta)

    def close(self) -> None:
        self.closes += 1
        self.device.active = False
        if self.on_close:
            self.on_close()

    def cancel(self) -> None:
        self.cancels += 1
        raise AssertionError("native cancel must not bypass acknowledged network CLOSE")


class _Module:
    def __init__(self, context: _Context) -> None:
        self.context = context
        self.context_opens: list[str] = []
        self.buffers: list[_Buffer] = []
        self.configure: Callable[[_Buffer], None] | None = None

    def Context(self, uri: str) -> _Context:
        self.context_opens.append(uri)
        return self.context

    def Buffer(self, device: _Device, count: int, cyclic: bool) -> _Buffer:
        buffer = _Buffer(device, count, cyclic)
        self.buffers.append(buffer)
        if self.configure:
            self.configure(buffer)
        return buffer


def _setup(*, rate: int = 15_000_000) -> tuple[_Device, _Context, _Module]:
    device = _Device(rate=rate)
    context = _Context(device)
    return device, context, _Module(context)


def _connect(module: _Module, **kwargs: object) -> PilotIioClient:
    args = {"expected_serial": SERIAL, "source_rate_hz": module.context.device.rate}
    args.update(kwargs)
    return PilotIioClient.connect("ip:explicit-canary", iio_module=module, **args)


def _assert_restored(device: _Device, module: _Module) -> None:
    assert device.attrs["capture_visit_id"].value == "77"
    assert device.attrs["capture_sample_limit"].value == "100"
    assert [channel.enabled for channel in device.channels] == [False, True]
    assert all(buffer.closes == 1 and not buffer.cancels for buffer in module.buffers)


@pytest.mark.parametrize("rate", (15_000_000, 30_000_000, 60_000_000))
def test_finite_120ms_binds_identity_bytes_rates_and_restoration(rate: int) -> None:
    device, context, module = _setup(rate=rate)
    with _connect(module, expected_boot_id="boot-a") as client:
        result = client.capture(visit_id=17)
    assert context.closes == 1
    assert module.context_opens == ["ip:explicit-canary"]
    assert result.serial == SERIAL and result.boot_id == "boot-a"
    assert result.source_rate_hz == rate and result.output_rate_hz == 2_500_000
    assert result.visit_id == 17 and len(result.iq) == 1_200_000
    assert result.iq == b"".join(bytes([index]) * 100_000 for index in range(1, 13))
    assert result.iq_sha256 == hashlib.sha256(result.iq).hexdigest()
    assert result.snapshot_armed.active and not result.snapshot_final.active
    assert result.snapshot_final.axis_delivered_samples == 300_000
    assert not result.upstream_health_qualified
    assert not result.live_signal_qualified and not result.disk_persisted
    assert all(0 < value <= 1000 for value in context.timeouts)
    _assert_restored(device, module)


def test_multiple_finite_visits_share_context_not_capture_generations() -> None:
    device, context, module = _setup()
    with _connect(module) as client:
        first = client.capture(visit_id=17, samples=8, refill_samples=2)
        second = client.capture(visit_id=18, samples=8, refill_samples=2)
    assert first.session_id == second.session_id
    assert first.snapshot_final.visit_id == 17 and second.snapshot_final.visit_id == 18
    assert len(module.buffers) == 2 and context.closes == 1
    _assert_restored(device, module)


@pytest.mark.parametrize("kwargs", [
    {"expected_serial": ""}, {"expected_serial": "wrong serial"},
    {"source_rate_hz": 2_500_000}, {"source_rate_hz": True},
    {"io_timeout_ms": 0}, {"io_timeout_ms": True}, {"io_timeout_ms": 60001},
    {"expected_boot_id": ""},
])
def test_bad_connection_arguments_cannot_open_context(kwargs: dict) -> None:
    _, _, module = _setup()
    with pytest.raises(ValueError):
        _connect(module, **kwargs)
    assert not module.context_opens


@pytest.mark.parametrize("attrs", [
    {}, {"hw_serial": "other-radio"}, {"serial": SERIAL, "hw_serial": "other-radio"},
    {"hw_serial": SERIAL, "usb,serial": "other-radio"},
])
def test_wrong_or_conflicting_serial_closes_context_without_buffer(attrs: dict[str, str]) -> None:
    _, context, module = _setup()
    context.attrs = attrs
    with pytest.raises(RadioConfigurationError, match="serial"):
        _connect(module)
    assert context.closes == 1 and not module.buffers


def test_boot_identity_is_optional_but_never_invented() -> None:
    _, context, module = _setup()
    del context.attrs["boot_id"]
    with _connect(module) as client:
        result = client.capture(visit_id=17, samples=8, refill_samples=2)
    assert result.boot_id is None
    with pytest.raises(RadioConfigurationError, match="boot identity"):
        _connect(module, expected_boot_id="boot-a")


@pytest.mark.parametrize("field,value", [
    ("index", 1), ("output", True), ("modifier", SimpleNamespace(name="IIO_MOD_Q")),
    ("length", 32), ("bits", 12), ("shift", 1), ("repeat", 2),
    ("is_signed", False), ("is_be", True), ("is_fully_defined", False),
])
def test_rejects_wrong_scan_layout_before_buffer(field: str, value: object) -> None:
    device, context, module = _setup()
    target = device.channels[0] if field in {"index", "output", "modifier"} else (
        device.channels[0].data_format
    )
    setattr(target, field, value)
    with pytest.raises(RadioConfigurationError):
        _connect(module)
    assert context.closes == 1 and not module.buffers


@pytest.mark.parametrize("kind", ("extra-channel", "abi", "export-rate", "timeout"))
def test_requires_exact_device_contract_and_bounded_io(kind: str) -> None:
    device, context, module = _setup()
    if kind == "extra-channel":
        device.channels.append(device.channels[0])
    elif kind == "abi":
        device.attrs["capture_abi"].value = "TAG2"
    elif kind == "export-rate":
        device.channels[0].attrs["sampling_frequency"].value = "15000000"
    else:
        context.set_timeout = None  # type: ignore[method-assign,assignment]
    with pytest.raises(RadioConfigurationError):
        _connect(module)
    assert context.closes == 1 and not module.buffers


@pytest.mark.parametrize("kwargs", [
    {"visit_id": 0}, {"visit_id": True}, {"samples": 0}, {"samples": 2_500_001},
    {"samples": True}, {"refill_samples": 131072}, {"refill_samples": 3},
    {"refill_samples": 0}, {"timeout_ms": 0}, {"timeout_ms": 60001},
])
def test_rejects_bad_finite_geometry_without_configuring_device(kwargs: dict) -> None:
    device, _, module = _setup()
    with _connect(module) as client:
        args = {"visit_id": 17}
        args.update(kwargs)
        with pytest.raises(ValueError):
            client.capture(**args)
    assert device.generation == 0 and not module.buffers
    _assert_restored(device, module)


@pytest.mark.parametrize("field,value", [
    ("actual_rate", 2_500_000), ("rate", 30_000_000), ("dma_error", -5),
    ("recovery_failed", 1), ("fault", 4), ("ddc_fault", 1), ("clips", 1),
])
def test_rejects_unhealthy_source_before_arm(field: str, value: int) -> None:
    device, _, module = _setup()
    with _connect(module) as client:
        setattr(device, field, value)
        with pytest.raises(PilotCaptureError):
            client.capture(visit_id=17)
    assert not module.buffers


@pytest.mark.parametrize("delta", (-4, -1, 4))
def test_malformed_refill_retains_bounded_partial_bytes_and_restores(delta: int) -> None:
    device, _, module = _setup()
    module.configure = lambda buffer: setattr(buffer, "read_delta", delta)
    with _connect(module) as client:
        with pytest.raises(PilotCaptureError, match="refill") as raised:
            client.capture(visit_id=17, samples=8, refill_samples=2)
        error = raised.value
        assert len(error.partial_iq) == min(8, 8 + delta)
        assert error.snapshots[-1].axis_delivered_samples == 2
        assert not error.cleanup_errors
        with pytest.raises(RadioConfigurationError, match="reconnection"):
            client.capture(visit_id=18)
    _assert_restored(device, module)


def test_timeout_retains_prior_full_refill_and_terminal_fault_diagnostics() -> None:
    device, _, module = _setup()

    def configure(buffer: _Buffer) -> None:
        def fail_second() -> None:
            if buffer.refills == 2:
                device.fault = 4
                raise TimeoutError("mid-descriptor hardware fault")
        buffer.on_refill = fail_second

    module.configure = configure
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="hardware fault") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert raised.value.partial_iq == bytes([1]) * 8
    assert raised.value.snapshots[-1].capture_faults == 4
    _assert_restored(device, module)


@pytest.mark.parametrize("field,value", [
    ("actual_rate", 2_500_000), ("dma_error", -5), ("fault", 4),
    ("ddc_fault", 1), ("clips", 1), ("visit", 99),
])
def test_final_rate_health_and_visit_changes_are_not_accepted(field: str, value: int) -> None:
    device, _, module = _setup()

    def configure(buffer: _Buffer) -> None:
        buffer.on_refill = lambda: setattr(device, field, value)

    module.configure = configure
    with _connect(module) as client, pytest.raises(PilotCaptureError):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    _assert_restored(device, module)


def test_stale_snapshot_generation_fails_even_if_counts_match() -> None:
    device, _, module = _setup()
    module.configure = lambda buffer: setattr(device, "freeze_generation", True)
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="generation"):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    _assert_restored(device, module)


def test_cooperative_cancel_preserves_normal_remote_close_and_partial_data() -> None:
    device, _, module = _setup()
    with _connect(module) as client:
        module.configure = lambda buffer: setattr(buffer, "on_refill", client.cancel)
        with pytest.raises(PilotCaptureError, match="cancelled") as raised:
            client.capture(visit_id=17, samples=8, refill_samples=2)
    assert raised.value.partial_iq == bytes([1]) * 8
    _assert_restored(device, module)


def test_overall_deadline_expires_even_if_each_refill_succeeds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device, context, module = _setup()
    now = [10.0]
    monkeypatch.setattr(pilot_iio.time, "monotonic", lambda: now[0])

    def configure(buffer: _Buffer) -> None:
        def consume_budget() -> None:
            now[0] += .060
        buffer.on_refill = consume_budget

    module.configure = configure
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="deadline") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2, timeout_ms=100)
    assert len(raised.value.partial_iq) == 16
    assert 40 in context.timeouts or 41 in context.timeouts
    _assert_restored(device, module)


def test_cleanup_failure_is_not_hidden_by_successful_reads() -> None:
    device, _, module = _setup()

    def configure(buffer: _Buffer) -> None:
        buffer.on_close = lambda: setattr(device, "recovery_failed", 1)

    module.configure = configure
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="terminal snapshot") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert len(raised.value.partial_iq) == 32
    assert raised.value.snapshots[-1].recovery_failed
    assert raised.value.cleanup_errors
    _assert_restored(device, module)


def test_terminal_identity_change_invalidates_complete_capture() -> None:
    device, context, module = _setup()

    def configure(buffer: _Buffer) -> None:
        buffer.on_close = lambda: context.attrs.update(boot_id="boot-b")

    module.configure = configure
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="terminal identity"),
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    _assert_restored(device, module)


def test_native_buffer_destroy_is_used_without_cancelling() -> None:
    calls = []
    buffer = SimpleNamespace(_buffer=123, cancel=lambda: pytest.fail("unexpected cancel"))
    module = SimpleNamespace(_buffer_destroy=calls.append)
    pilot_iio._destroy_pilot_buffer(module, buffer)
    assert calls == [123] and buffer._buffer is None


@pytest.mark.parametrize("field,value", [
    ("step", 8), ("byte_length", 9), ("_samples_count", 3), ("sample_count", 3),
])
def test_actual_buffer_geometry_must_match_finite_request(field: str, value: int) -> None:
    device, _, module = _setup()
    module.configure = lambda buffer: setattr(buffer, field, value)
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="finite"):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert not module.buffers[0].refills
    _assert_restored(device, module)


def test_close_is_idempotent_and_closed_client_cannot_capture() -> None:
    _, context, module = _setup()
    client = _connect(module)
    client.close()
    client.close()
    assert context.closes == 1
    with pytest.raises(RadioConfigurationError, match="closed"):
        client.capture(visit_id=17)


def test_identity_changes_before_capture_cannot_configure_or_arm() -> None:
    device, context, module = _setup()
    with _connect(module) as client:
        context.attrs["hw_serial"] = "not-the-owned-radio"
        with pytest.raises(PilotCaptureError, match="serial"):
            client.capture(visit_id=17)
    assert not module.buffers and not device.generation
    _assert_restored(device, module)


def test_existing_capture_is_not_stopped_by_new_client() -> None:
    device, _, module = _setup()
    device.armed = device.active = True
    device.visit = 90
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="already active"):
        client.capture(visit_id=17)
    assert device.active and not module.buffers
    _assert_restored(device, module)


def test_device_scan_stride_mismatch_never_constructs_buffer() -> None:
    device, _, module = _setup()
    device.sample_size = 8
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="scan stride"):
        client.capture(visit_id=17)
    assert not module.buffers
    _assert_restored(device, module)


def test_wrong_armed_visit_fails_before_reading_any_iq() -> None:
    device, _, module = _setup()
    module.configure = lambda buffer: setattr(device, "visit", 99)
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="requested visit"):
        client.capture(visit_id=17)
    assert not module.buffers[0].refills
    _assert_restored(device, module)


def test_config_readback_mismatch_is_not_silently_accepted() -> None:
    device, _, module = _setup()
    device.attrs["capture_sample_limit"].getter = lambda: "100"
    with _connect(module) as client, pytest.raises(PilotCaptureError, match="readback mismatch"):
        client.capture(visit_id=17)
    assert not module.buffers
    _assert_restored(device, module)


def test_refill_exception_and_destroy_exception_are_both_preserved() -> None:
    _, _, module = _setup()

    def configure(buffer: _Buffer) -> None:
        def refill_failure() -> None:
            raise OSError("primary read failure")

        def close_failure() -> None:
            raise OSError("secondary close failure")

        buffer.on_refill = refill_failure
        buffer.on_close = close_failure

    module.configure = configure
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="primary read failure") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert "secondary close failure" in raised.value.cleanup_errors[0]
    assert not raised.value.partial_iq
    assert isinstance(raised.value.__cause__, OSError)


def test_configuration_restore_failure_invalidates_successful_iq() -> None:
    device, _, module = _setup()

    def check_write(value: str) -> None:
        if value == "77":
            raise OSError("cannot restore original visit")

    device.attrs["capture_visit_id"].on_write = check_write
    with (
        _connect(module) as client,
        pytest.raises(PilotCaptureError, match="restoration") as raised,
    ):
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert len(raised.value.partial_iq) == 32
    assert device.attrs["capture_sample_limit"].value == "100"
    assert module.buffers[0].closes == 1


def test_context_close_failure_does_not_mask_capture_failure() -> None:
    _, context, module = _setup()

    def close_failure() -> None:
        raise OSError("context close failure")

    context.close = close_failure  # type: ignore[method-assign]
    with pytest.raises(PilotCaptureError, match="refill") as raised, _connect(module) as client:
        module.configure = lambda buffer: setattr(buffer, "read_delta", -1)
        client.capture(visit_id=17, samples=8, refill_samples=2)
    assert "context close failure" in raised.value.__notes__[0]


def test_direct_native_destruction_requires_a_supported_binding() -> None:
    with pytest.raises(RadioConfigurationError, match="deterministic destroy"):
        pilot_iio._destroy_pilot_buffer(SimpleNamespace(), SimpleNamespace())
