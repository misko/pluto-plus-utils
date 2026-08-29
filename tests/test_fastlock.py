from __future__ import annotations

import stat
from pathlib import Path
from typing import Any

import pytest

from pluto_plus.fastlock import (
    FastLockProbeError,
    confirmation_phrase,
    prepare_usb_fastlock_probe,
    run_usb_fastlock_probe,
    write_fastlock_report,
)
from pluto_plus.hardware.base import SettingsRestorationError
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import RadioIdentity, RadioSettings, Transport

SERIAL = "SERIAL_A"


class ManualClock:
    def __init__(self) -> None:
        self.now_ns = 1_000_000_000

    def __call__(self) -> int:
        return self.now_ns

    def advance_us(self, duration_us: float) -> None:
        self.now_ns += round(duration_us * 1_000)

    def sleep(self, duration_seconds: float) -> None:
        self.now_ns += round(duration_seconds * 1_000_000_000)


class FakeFastLockRadio:
    def __init__(
        self,
        uri: str,
        serial: str,
        clock: ManualClock,
        *,
        fail_recall: bool = False,
        metadata_abi: int | None = 2,
        stall_counter: bool = False,
        fail_restore: bool = False,
        fail_mute_at: int | None = None,
        fail_close: bool = False,
    ) -> None:
        self._identity = RadioIdentity(
            radio_id=serial,
            serial=serial,
            uri=uri,
            transport=Transport.IIO_USB,
            model="Pluto+ Test",
            firmware_version="v-test",
            usb_path="/sys/bus/usb/devices/3-8",
        )
        self.settings = RadioSettings()
        self.original = self.settings
        self.clock = clock
        self.fail_recall = fail_recall
        self.metadata_abi = metadata_abi
        self.stall_counter = stall_counter
        self.fail_restore = fail_restore
        self.fail_mute_at = fail_mute_at
        self.fail_close = fail_close
        self.profiles: dict[int, tuple[int, tuple[int, ...]]] = {}
        self.active_profile: int | None = None
        self.opened = False
        self.closed = False
        self.mute_count = 0

    @property
    def identity(self) -> RadioIdentity:
        return self._identity

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True
        if self.fail_close:
            raise OSError("injected close failure")

    def read_settings(self) -> RadioSettings:
        return self.settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        if self.fail_restore:
            raise OSError("injected restore failure")
        self.clock.advance_us(1_000)
        self.settings = settings
        self.active_profile = None
        return settings

    def reset_receive_buffer(self) -> None:
        pass

    def mute_transmit(self) -> None:
        self.mute_count += 1
        if self.mute_count == self.fail_mute_at:
            raise OSError("injected final mute failure")

    def read_device_sample_counter_low32(self) -> int:
        if self.stall_counter:
            return 123
        return (
            self.clock.now_ns * round(self.settings.sample_rate_hz) // 1_000_000_000
        ) & 0xFFFFFFFF

    def write_center_frequency(self, center_frequency_hz: float) -> None:
        self.clock.advance_us(1_000)
        self.settings = self.settings.model_copy(
            update={"center_frequency_hz": float(round(center_frequency_hz))}
        )
        self.active_profile = None

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None:
        self.write_center_frequency(center_frequency_hz)

    def read_center_frequency(self) -> float:
        return self.settings.center_frequency_hz

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        frequency = round(self.settings.center_frequency_hz)
        values = tuple((frequency // (index + 1) + profile) & 0xFF for index in range(16))
        self.profiles[profile] = (frequency, values)
        return values

    def recall_rx_fastlock_profile(self, profile: int) -> None:
        self.clock.advance_us(200)
        if self.fail_recall:
            raise OSError("injected Fast Lock failure")
        # The real AD9361 clock framework can leave this ordinary frequency
        # attribute cached at the last conventional tune during Fast Lock.
        _frequency, _values = self.profiles[profile]
        self.active_profile = profile

    def read_active_rx_fastlock_profile(self) -> int | None:
        return self.active_profile

    def diagnostic_facts(self) -> dict[str, object]:
        return {"buffer_metadata_abi": self.metadata_abi}


def _device(tmp_path: Path, *, serial: str = SERIAL) -> LocalUsbPluto:
    usb_path = tmp_path / "3-8"
    usb_path.mkdir(exist_ok=True)
    Path(f"{usb_path}:1.5").mkdir(exist_ok=True)
    return LocalUsbPluto(
        usb_path=str(usb_path),
        bus_number=3,
        device_number=49,
        product="PlutoSDR+ with timestamp support",
        serial=serial,
        speed_mbps=480,
        interface_count=6,
    )


def _plan(tmp_path: Path):
    return prepare_usb_fastlock_probe(
        SERIAL,
        hops_per_mode=4,
        dwell_us=1_000,
        usb_devices=(_device(tmp_path),),
    )


def test_plan_resolves_only_one_exact_local_usb_serial(tmp_path: Path) -> None:
    device = _device(tmp_path)
    plan = prepare_usb_fastlock_probe(SERIAL, hops_per_mode=4, usb_devices=(device,))

    assert plan.uri == "usb:3.49.5"
    assert plan.expected_confirmation == confirmation_phrase(SERIAL)
    assert plan.lower_frequency_hz == 959_687_500
    assert plan.upper_frequency_hz == 1_190_312_500

    with pytest.raises(FastLockProbeError, match="found 0"):
        prepare_usb_fastlock_probe("MISSING", usb_devices=(device,))
    with pytest.raises(FastLockProbeError, match="found 2"):
        prepare_usb_fastlock_probe(SERIAL, usb_devices=(device, device))
    with pytest.raises(ValueError, match="must be even"):
        prepare_usb_fastlock_probe(SERIAL, hops_per_mode=3, usb_devices=(device,))


def test_probe_measures_fastlock_and_restores_exact_settings(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    clock = ManualClock()
    radio = FakeFastLockRadio(plan.uri, plan.serial, clock)

    report = run_usb_fastlock_probe(
        plan,
        radio_factory=lambda _uri, _serial: radio,
        clock_ns=clock,
        sleeper=clock.sleep,
    )

    assert radio.opened and radio.closed
    assert radio.settings == radio.original
    assert radio.mute_count == 2
    assert len(report.measurements) == 8
    assert report.ordinary_timing.median_us == 1_000
    assert report.fastlock_timing.median_us == 200
    assert report.median_speedup == 5
    assert report.restoration.original == report.restoration.restored
    assert report.fastlock_inactive_before_and_after
    assert report.volatile_profiles_overwritten == (6, 7)
    assert report.restoration.requested_lo_attempts_hz == (
        round(radio.original.center_frequency_hz),
    )
    assert report.firmware_metadata_abi == 2
    assert all(item.sample_counter_bracket_delta > 0 for item in report.measurements)
    assert [item.mode for item in report.measurements] == [
        "ordinary",
        "fastlock",
        "fastlock",
        "ordinary",
        "ordinary",
        "fastlock",
        "fastlock",
        "ordinary",
    ]
    assert [item.target for item in report.measurements] == [
        "lower",
        "upper",
        "lower",
        "upper",
        "lower",
        "upper",
        "lower",
        "upper",
    ]
    assert report.counter_preflight_advance_low32 > 0
    assert report.schema_version == 2
    assert report.ownership_assumption == "operator_confirmed_idle"


def test_probe_restores_and_closes_after_fastlock_failure(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    clock = ManualClock()
    radio = FakeFastLockRadio(plan.uri, plan.serial, clock, fail_recall=True)

    with pytest.raises(OSError, match="injected Fast Lock failure"):
        run_usb_fastlock_probe(
            plan,
            radio_factory=lambda _uri, _serial: radio,
            clock_ns=clock,
            sleeper=clock.sleep,
        )

    assert radio.settings == radio.original
    assert radio.closed
    assert radio.mute_count == 2


def test_probe_rejects_missing_or_stalled_fpga_counter_capability(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    clock = ManualClock()
    missing = FakeFastLockRadio(plan.uri, plan.serial, clock, metadata_abi=None)

    with pytest.raises(FastLockProbeError, match="sample-counter metadata capability"):
        run_usb_fastlock_probe(
            plan,
            radio_factory=lambda _uri, _serial: missing,
            clock_ns=clock,
            sleeper=clock.sleep,
        )
    assert missing.closed

    clock = ManualClock()
    stalled = FakeFastLockRadio(plan.uri, plan.serial, clock, stall_counter=True)
    with pytest.raises(FastLockProbeError, match="did not advance"):
        run_usb_fastlock_probe(
            plan,
            radio_factory=lambda _uri, _serial: stalled,
            clock_ns=clock,
            sleeper=clock.sleep,
        )
    assert stalled.closed


@pytest.mark.parametrize(
    ("kwargs", "error_type", "message"),
    [
        ({"fail_restore": True}, SettingsRestorationError, "exact settings restoration failed"),
        ({"fail_mute_at": 2}, OSError, "injected final mute failure"),
        ({"fail_close": True}, OSError, "injected close failure"),
    ],
)
def test_probe_attempts_all_cleanup_steps_after_cleanup_failure(
    tmp_path: Path, kwargs: dict[str, Any], error_type: type[Exception], message: str
) -> None:
    plan = _plan(tmp_path)
    clock = ManualClock()
    radio = FakeFastLockRadio(plan.uri, plan.serial, clock, **kwargs)

    with pytest.raises(error_type, match=message):
        run_usb_fastlock_probe(
            plan,
            radio_factory=lambda _uri, _serial: radio,
            clock_ns=clock,
            sleeper=clock.sleep,
        )

    assert radio.closed
    assert radio.mute_count == 2


def test_report_write_is_atomic_private_json(tmp_path: Path) -> None:
    plan = _plan(tmp_path)
    clock = ManualClock()
    radio = FakeFastLockRadio(plan.uri, plan.serial, clock)
    report = run_usb_fastlock_probe(
        plan,
        radio_factory=lambda _uri, _serial: radio,
        clock_ns=clock,
        sleeper=clock.sleep,
    )
    path = tmp_path / "receipts" / "fastlock.json"

    write_fastlock_report(path, report)

    assert path.read_text().endswith("\n")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not tuple(path.parent.glob(".fastlock.json.*"))
