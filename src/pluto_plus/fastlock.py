"""Bounded, receive-only AD9361 Fast Lock probe for one exact local USB radio."""

from __future__ import annotations

import json
import math
import os
import re
import tempfile
import time
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from pydantic import Field, model_validator

from pluto_plus.hardware.base import SettingsRestoration, restore_settings_exact
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.models import ApiModel, RadioIdentity, RadioSettings, Transport

DEFAULT_LOWER_FREQUENCY_HZ = 959_687_500
DEFAULT_UPPER_FREQUENCY_HZ = 1_190_312_500
DEFAULT_LOWER_PROFILE = 6
DEFAULT_UPPER_PROFILE = 7
DEFAULT_HOPS_PER_MODE = 32
DEFAULT_DWELL_US = 1_000
DEFAULT_PROFILE_SETTLE_MS = 20
DEFAULT_MAX_SECONDS = 60
MAX_SECONDS = 300
MAX_HOPS_PER_MODE = 1_000
MAX_LO_ERROR_HZ = 10
USB_IIO_INTERFACE = 5
_CONCRETE_USB_URI = re.compile(r"^usb:[0-9]+[.][0-9]+[.]5$")


class FastLockProbeError(RuntimeError):
    """The guarded Fast Lock experiment could not produce a valid receipt."""


class FastLockProbePlan(ApiModel):
    schema_version: Literal[2] = 2
    serial: str = Field(min_length=1)
    uri: str = Field(pattern=r"^usb:[0-9]+[.][0-9]+[.]5$")
    usb_path: str = Field(min_length=1)
    lower_frequency_hz: int = Field(ge=70_000_000, le=6_000_000_000)
    upper_frequency_hz: int = Field(ge=70_000_000, le=6_000_000_000)
    lower_profile: int = Field(ge=0, le=7)
    upper_profile: int = Field(ge=0, le=7)
    hops_per_mode: int = Field(ge=2, le=MAX_HOPS_PER_MODE)
    dwell_us: int = Field(ge=0, le=1_000_000)
    profile_settle_ms: int = Field(ge=0, le=1_000)
    max_seconds: int = Field(ge=1, le=MAX_SECONDS)
    expected_confirmation: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_relationships(self) -> FastLockProbePlan:
        if self.lower_frequency_hz >= self.upper_frequency_hz:
            raise ValueError("lower Fast Lock frequency must be below upper frequency")
        if self.lower_profile == self.upper_profile:
            raise ValueError("lower and upper Fast Lock profiles must differ")
        if self.hops_per_mode % 2:
            raise ValueError("hops_per_mode must be even so both frequencies have equal trials")
        expected = confirmation_phrase(self.serial)
        if self.expected_confirmation != expected:
            raise ValueError("Fast Lock confirmation phrase does not match the selected serial")
        minimum_sleep_seconds = (
            (2 * self.hops_per_mode + 4) * self.dwell_us / 1_000_000
            + 2 * self.profile_settle_ms / 1_000
            + 0.001
        )
        if minimum_sleep_seconds >= self.max_seconds:
            raise ValueError("Fast Lock dwell and settle sleeps cannot fit inside max_seconds")
        return self


class FastLockProfileReceipt(ApiModel):
    label: Literal["lower", "upper"]
    profile: int = Field(ge=0, le=7)
    requested_frequency_hz: int = Field(gt=0)
    readback_frequency_hz: int = Field(gt=0)
    register_values: tuple[int, ...] = Field(min_length=16, max_length=16)


class FastLockHopMeasurement(ApiModel):
    mode: Literal["ordinary", "fastlock"]
    hop_index: int = Field(ge=0)
    target: Literal["lower", "upper"]
    target_frequency_hz: int = Field(gt=0)
    profile: int | None = Field(default=None, ge=0, le=7)
    active_profile_readback: int | None = Field(default=None, ge=0, le=7)
    frequency_attribute_readback_hz: int = Field(gt=0)
    frequency_attribute_matches_target: bool
    write_started_monotonic_ns: int = Field(ge=0)
    write_ended_monotonic_ns: int = Field(ge=0)
    write_duration_us: float = Field(ge=0)
    sample_counter_before_low32: int = Field(ge=0, le=0xFFFFFFFF)
    sample_counter_after_low32: int = Field(ge=0, le=0xFFFFFFFF)
    sample_counter_bracket_delta: int = Field(ge=0, le=0xFFFFFFFF)


class FastLockTimingSummary(ApiModel):
    count: int = Field(gt=0)
    minimum_us: float = Field(ge=0)
    median_us: float = Field(ge=0)
    p95_us: float = Field(ge=0)
    p99_us: float = Field(ge=0)
    maximum_us: float = Field(ge=0)
    mean_us: float = Field(ge=0)


class FastLockRestorationReceipt(ApiModel):
    original: RadioSettings
    restored: RadioSettings
    requested_lo_attempts_hz: tuple[int, ...]


class FastLockProbeReport(ApiModel):
    schema_version: Literal[2] = 2
    experiment: Literal["ad9361-usb-fastlock-control-plane-v2"] = (
        "ad9361-usb-fastlock-control-plane-v2"
    )
    started_at: datetime
    finished_at: datetime
    duration_seconds: float = Field(ge=0)
    plan: FastLockProbePlan
    identity: RadioIdentity
    firmware_metadata_abi: Literal[1, 2, 3]
    counter_preflight_advance_low32: int = Field(gt=0, le=0xFFFFFFFF)
    profiles: tuple[FastLockProfileReceipt, FastLockProfileReceipt]
    measurements: tuple[FastLockHopMeasurement, ...]
    ordinary_timing: FastLockTimingSummary
    fastlock_timing: FastLockTimingSummary
    median_speedup: float = Field(gt=0)
    restoration: FastLockRestorationReceipt
    tx_muted_and_verified: bool
    fastlock_inactive_before_and_after: bool
    volatile_profiles_overwritten: tuple[int, int]
    ownership_assumption: Literal["operator_confirmed_idle"] = "operator_confirmed_idle"
    rx_buffer_armed: Literal[False] = False
    continuity_claim: str = (
        "FPGA low-32 counter reads bracket each USB write, but no RX buffer was armed; "
        "the result does not identify the exact IQ sample at which the synthesizer locked"
    )
    latency_claim: str = (
        "write_duration_us is host-observed USB IIO attribute-write latency, not the "
        "AD9361 silicon RF-lock interval; ordinary and Fast Lock trials are interleaved "
        "bufferless writes after an unreported warmup cycle; during Fast Lock the frequency "
        "attribute may remain cached at the last conventionally tuned frequency"
    )
    profile_state_claim: str = (
        "the selected volatile Fast Lock profile slots are overwritten and left populated but "
        "inactive; pre-existing slot contents cannot be losslessly restored because the driver "
        "does not expose each slot's initialized flag"
    )
    ownership_limit_claim: str = (
        "the operator confirmation asserts that no other client is using this radio; the probe "
        "does not acquire a cross-transport ownership lock or exclude concurrent controllers"
    )


class FastLockRadio(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_settings(self) -> RadioSettings: ...

    def apply_settings(self, settings: RadioSettings) -> RadioSettings: ...

    def reset_receive_buffer(self) -> None: ...

    def mute_transmit(self) -> None: ...

    def read_device_sample_counter_low32(self) -> int: ...

    def write_center_frequency(self, center_frequency_hz: float) -> None: ...

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None: ...

    def read_center_frequency(self) -> float: ...

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]: ...

    def recall_rx_fastlock_profile(self, profile: int) -> None: ...

    def read_active_rx_fastlock_profile(self) -> int | None: ...

    def diagnostic_facts(self) -> Mapping[str, object]: ...


def confirmation_phrase(serial: str) -> str:
    return f"FASTLOCK USB {serial}"


def prepare_usb_fastlock_probe(
    serial: str,
    *,
    lower_frequency_hz: int = DEFAULT_LOWER_FREQUENCY_HZ,
    upper_frequency_hz: int = DEFAULT_UPPER_FREQUENCY_HZ,
    lower_profile: int = DEFAULT_LOWER_PROFILE,
    upper_profile: int = DEFAULT_UPPER_PROFILE,
    hops_per_mode: int = DEFAULT_HOPS_PER_MODE,
    dwell_us: int = DEFAULT_DWELL_US,
    profile_settle_ms: int = DEFAULT_PROFILE_SETTLE_MS,
    max_seconds: int = DEFAULT_MAX_SECONDS,
    usb_devices: Sequence[LocalUsbPluto] | None = None,
) -> FastLockProbePlan:
    """Resolve one serial to one current local USB bus address without opening IIO."""

    if not serial.strip() or serial != serial.strip():
        raise ValueError("Fast Lock target serial must be one trimmed nonempty value")
    devices = tuple(scan_local_usb_plutos() if usb_devices is None else usb_devices)
    matches = tuple(device for device in devices if device.serial == serial)
    if len(matches) != 1:
        raise FastLockProbeError(
            f"expected exactly one attached local USB Pluto with serial {serial}, "
            f"found {len(matches)}"
        )
    target = matches[0]
    if not target.confirmed_plus:
        raise FastLockProbeError("Fast Lock target is not classified as a confirmed Pluto+")
    if target.bus_number is None or target.device_number is None:
        raise FastLockProbeError("Fast Lock target lacks a current USB bus/device address")
    if target.interface_count is None or target.interface_count <= USB_IIO_INTERFACE:
        raise FastLockProbeError("Fast Lock target lacks the USB IIO interface")
    interface_path = Path(f"{target.usb_path}:1.{USB_IIO_INTERFACE}")
    if not interface_path.is_dir():
        raise FastLockProbeError(f"USB IIO interface disappeared: {interface_path}")
    uri = f"usb:{target.bus_number}.{target.device_number}.{USB_IIO_INTERFACE}"
    return FastLockProbePlan(
        serial=serial,
        uri=uri,
        usb_path=target.usb_path,
        lower_frequency_hz=lower_frequency_hz,
        upper_frequency_hz=upper_frequency_hz,
        lower_profile=lower_profile,
        upper_profile=upper_profile,
        hops_per_mode=hops_per_mode,
        dwell_us=dwell_us,
        profile_settle_ms=profile_settle_ms,
        max_seconds=max_seconds,
        expected_confirmation=confirmation_phrase(serial),
    )


def run_usb_fastlock_probe(
    plan: FastLockProbePlan,
    *,
    radio_factory: Callable[[str, str], FastLockRadio] | None = None,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
    sleeper: Callable[[float], None] = time.sleep,
) -> FastLockProbeReport:
    """Compare ordinary LO writes with Fast Lock while assuming operator-confirmed idleness."""

    if _CONCRETE_USB_URI.fullmatch(plan.uri) is None:
        raise FastLockProbeError("Fast Lock execution accepts only a concrete local USB URI")
    radio = (
        radio_factory(plan.uri, plan.serial)
        if radio_factory is not None
        else IioRadioDevice(
            plan.uri,
            serial=plan.serial,
            expected_usb_path=plan.usb_path,
            require_idle_tandem_owner=True,
            radio_id=plan.serial,
        )
    )
    opened = False
    original: RadioSettings | None = None
    restoration: SettingsRestoration | None = None
    identity: RadioIdentity | None = None
    facts: dict[str, object] = {}
    profiles: tuple[FastLockProfileReceipt, FastLockProfileReceipt] | None = None
    measurements: tuple[FastLockHopMeasurement, ...] | None = None
    counter_preflight_advance = 0
    failure: BaseException | None = None
    cleanup_errors: list[BaseException] = []
    started_at = datetime.now(UTC)
    started_ns = clock_ns()
    deadline_ns = started_ns + plan.max_seconds * 1_000_000_000
    try:
        radio.open()
        opened = True
        identity = radio.identity
        if identity.serial != plan.serial:
            raise FastLockProbeError(f"opened serial {identity.serial!r}, expected {plan.serial!r}")
        if identity.transport is not Transport.IIO_USB or identity.uri != plan.uri:
            raise FastLockProbeError(
                f"opened nonmatching USB route {identity.uri!r}, expected {plan.uri!r}"
            )
        original = radio.read_settings()
        facts = dict(radio.diagnostic_facts())
        metadata_abi = facts.get("buffer_metadata_abi")
        if metadata_abi not in {1, 2, 3}:
            raise FastLockProbeError(
                "firmware does not attest the FPGA sample-counter metadata capability"
            )
        radio.reset_receive_buffer()
        radio.mute_transmit()
        if radio.read_active_rx_fastlock_profile() is not None:
            raise FastLockProbeError("refusing to overwrite an already-active Fast Lock session")
        counter_before = radio.read_device_sample_counter_low32()
        sleeper(0.001)
        counter_after = radio.read_device_sample_counter_low32()
        counter_preflight_advance = (counter_after - counter_before) & 0xFFFFFFFF
        if counter_preflight_advance == 0:
            raise FastLockProbeError("FPGA sample counter did not advance during preflight")

        profiles = _store_profiles(
            radio,
            plan,
            deadline_ns=deadline_ns,
            clock_ns=clock_ns,
            sleeper=sleeper,
        )
        if profiles[0].register_values == profiles[1].register_values:
            raise FastLockProbeError("lower and upper Fast Lock profile readbacks are identical")
        _warmup_hops(
            radio,
            plan,
            deadline_ns=deadline_ns,
            clock_ns=clock_ns,
            sleeper=sleeper,
        )
        measurements = _measure_interleaved_hops(
            radio,
            plan,
            deadline_ns=deadline_ns,
            clock_ns=clock_ns,
            sleeper=sleeper,
        )
    except BaseException as error:
        failure = error
    finally:
        if opened:
            if original is not None:
                try:
                    restoration = restore_settings_exact(cast(Any, radio), original)
                except BaseException as error:
                    cleanup_errors.append(error)
            try:
                if (
                    restoration is not None
                    and radio.read_active_rx_fastlock_profile() is not None
                ):
                    raise FastLockProbeError("normal LO restoration did not exit RX Fast Lock mode")
            except BaseException as error:
                cleanup_errors.append(error)
            try:
                radio.mute_transmit()
            except BaseException as error:
                cleanup_errors.append(error)
            try:
                radio.close()
            except BaseException as error:
                cleanup_errors.append(error)

    if failure is not None:
        for cleanup_error in cleanup_errors:
            failure.add_note(f"cleanup also failed: {cleanup_error!r}")
        raise failure.with_traceback(failure.__traceback__)
    if cleanup_errors:
        cleanup_failure = cleanup_errors[0]
        for additional_error in cleanup_errors[1:]:
            cleanup_failure.add_note(f"additional cleanup failure: {additional_error!r}")
        raise cleanup_failure.with_traceback(cleanup_failure.__traceback__)

    if any(value is None for value in (original, restoration, identity, profiles, measurements)):
        raise FastLockProbeError("Fast Lock probe ended without a complete restoration receipt")
    assert original is not None
    assert restoration is not None
    assert identity is not None
    assert profiles is not None
    assert measurements is not None
    finished_at = datetime.now(UTC)
    ordinary_summary = summarize_timings(
        tuple(item.write_duration_us for item in measurements if item.mode == "ordinary")
    )
    fastlock_summary = summarize_timings(
        tuple(item.write_duration_us for item in measurements if item.mode == "fastlock")
    )
    speedup = ordinary_summary.median_us / fastlock_summary.median_us
    metadata_abi = facts.get("buffer_metadata_abi")
    return FastLockProbeReport(
        started_at=started_at,
        finished_at=finished_at,
        duration_seconds=max(0.0, (finished_at - started_at).total_seconds()),
        plan=plan,
        identity=identity,
        firmware_metadata_abi=cast(Literal[1, 2, 3], metadata_abi),
        counter_preflight_advance_low32=counter_preflight_advance,
        profiles=profiles,
        measurements=measurements,
        ordinary_timing=ordinary_summary,
        fastlock_timing=fastlock_summary,
        median_speedup=speedup,
        restoration=FastLockRestorationReceipt(
            original=original,
            restored=restoration.restored,
            requested_lo_attempts_hz=tuple(
                attempt.requested_center_frequency_hz for attempt in restoration.attempts
            ),
        ),
        tx_muted_and_verified=True,
        fastlock_inactive_before_and_after=True,
        volatile_profiles_overwritten=(plan.lower_profile, plan.upper_profile),
    )


def summarize_timings(values_us: Sequence[float]) -> FastLockTimingSummary:
    if not values_us:
        raise ValueError("cannot summarize an empty timing sequence")
    values = tuple(sorted(float(value) for value in values_us))
    if any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("timings must be finite and nonnegative")
    return FastLockTimingSummary(
        count=len(values),
        minimum_us=values[0],
        median_us=_percentile(values, 50),
        p95_us=_percentile(values, 95),
        p99_us=_percentile(values, 99),
        maximum_us=values[-1],
        mean_us=sum(values) / len(values),
    )


def write_fastlock_report(path: Path, report: FastLockProbeReport) -> None:
    """Atomically persist a private JSON restoration/timing receipt."""

    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True) + "\n"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
        os.chmod(destination, 0o600)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def _warmup_hops(
    radio: FastLockRadio,
    plan: FastLockProbePlan,
    *,
    deadline_ns: int,
    clock_ns: Callable[[], int],
    sleeper: Callable[[float], None],
) -> None:
    """Run one unreported O-F-F-O cycle so setup and first-use costs are excluded."""

    sequence: tuple[tuple[Literal["ordinary", "fastlock"], Literal["lower", "upper"]], ...] = (
        ("ordinary", "lower"),
        ("fastlock", "upper"),
        ("fastlock", "lower"),
        ("ordinary", "upper"),
    )
    for mode, target in sequence:
        _execute_hop(
            radio,
            plan,
            mode=mode,
            target=target,
            hop_index=0,
            deadline_ns=deadline_ns,
            clock_ns=clock_ns,
            sleeper=sleeper,
        )


def _measure_interleaved_hops(
    radio: FastLockRadio,
    plan: FastLockProbePlan,
    *,
    deadline_ns: int,
    clock_ns: Callable[[], int],
    sleeper: Callable[[float], None],
) -> tuple[FastLockHopMeasurement, ...]:
    """Measure balanced O-F-F-O cycles while making every operation a real frequency hop."""

    measurements: list[FastLockHopMeasurement] = []
    mode_indices: dict[Literal["ordinary", "fastlock"], int] = {
        "ordinary": 0,
        "fastlock": 0,
    }
    sequence: tuple[tuple[Literal["ordinary", "fastlock"], Literal["lower", "upper"]], ...] = (
        ("ordinary", "lower"),
        ("fastlock", "upper"),
        ("fastlock", "lower"),
        ("ordinary", "upper"),
    )
    for _cycle in range(plan.hops_per_mode // 2):
        for mode, target in sequence:
            hop_index = mode_indices[mode]
            measurements.append(
                _execute_hop(
                    radio,
                    plan,
                    mode=mode,
                    target=target,
                    hop_index=hop_index,
                    deadline_ns=deadline_ns,
                    clock_ns=clock_ns,
                    sleeper=sleeper,
                )
            )
            mode_indices[mode] += 1
    return tuple(measurements)


def _execute_hop(
    radio: FastLockRadio,
    plan: FastLockProbePlan,
    *,
    mode: Literal["ordinary", "fastlock"],
    target: Literal["lower", "upper"],
    hop_index: int,
    deadline_ns: int,
    clock_ns: Callable[[], int],
    sleeper: Callable[[float], None],
) -> FastLockHopMeasurement:
    _require_before_deadline(clock_ns, deadline_ns)
    lower = target == "lower"
    frequency = plan.lower_frequency_hz if lower else plan.upper_frequency_hz
    profile = (plan.lower_profile if lower else plan.upper_profile) if mode == "fastlock" else None
    before = radio.read_device_sample_counter_low32()
    write_started = clock_ns()
    if mode == "ordinary":
        radio.write_center_frequency_bufferless(frequency)
    else:
        assert profile is not None
        radio.recall_rx_fastlock_profile(profile)
    write_ended = clock_ns()
    after = radio.read_device_sample_counter_low32()
    if write_ended < write_started:
        raise FastLockProbeError("monotonic timing clock regressed")
    counter_delta = (after - before) & 0xFFFFFFFF
    if counter_delta == 0:
        raise FastLockProbeError("FPGA sample counter stalled across a measured hop")
    active = radio.read_active_rx_fastlock_profile() if mode == "fastlock" else None
    if profile is not None and active != profile:
        raise FastLockProbeError(f"RX Fast Lock active profile is {active}, expected {profile}")
    readback = round(radio.read_center_frequency())
    readback_matches = abs(readback - frequency) <= MAX_LO_ERROR_HZ
    if mode == "ordinary" and not readback_matches:
        raise FastLockProbeError(f"RX LO readback {readback} differs from target {frequency}")
    measurement = FastLockHopMeasurement(
        mode=mode,
        hop_index=hop_index,
        target=target,
        target_frequency_hz=frequency,
        profile=profile,
        active_profile_readback=active,
        frequency_attribute_readback_hz=readback,
        frequency_attribute_matches_target=readback_matches,
        write_started_monotonic_ns=write_started,
        write_ended_monotonic_ns=write_ended,
        write_duration_us=(write_ended - write_started) / 1_000,
        sample_counter_before_low32=before,
        sample_counter_after_low32=after,
        sample_counter_bracket_delta=counter_delta,
    )
    if plan.dwell_us:
        sleeper(plan.dwell_us / 1_000_000)
    _require_before_deadline(clock_ns, deadline_ns)
    return measurement


def _store_profiles(
    radio: FastLockRadio,
    plan: FastLockProbePlan,
    *,
    deadline_ns: int,
    clock_ns: Callable[[], int],
    sleeper: Callable[[float], None],
) -> tuple[FastLockProfileReceipt, FastLockProfileReceipt]:
    receipts: list[FastLockProfileReceipt] = []
    configurations: tuple[tuple[Literal["lower", "upper"], int, int], ...] = (
        ("lower", plan.lower_frequency_hz, plan.lower_profile),
        ("upper", plan.upper_frequency_hz, plan.upper_profile),
    )
    for label, frequency, profile in configurations:
        _require_before_deadline(clock_ns, deadline_ns)
        radio.write_center_frequency_bufferless(frequency)
        readback = round(radio.read_center_frequency())
        if abs(readback - frequency) > MAX_LO_ERROR_HZ:
            raise FastLockProbeError(
                f"profile setup LO readback {readback} differs from target {frequency}"
            )
        if plan.profile_settle_ms:
            sleeper(plan.profile_settle_ms / 1_000)
        _require_before_deadline(clock_ns, deadline_ns)
        values = radio.store_rx_fastlock_profile(profile)
        receipts.append(
            FastLockProfileReceipt(
                label=label,
                profile=profile,
                requested_frequency_hz=frequency,
                readback_frequency_hz=readback,
                register_values=values,
            )
        )
    return cast(tuple[FastLockProfileReceipt, FastLockProfileReceipt], tuple(receipts))


def _require_before_deadline(clock_ns: Callable[[], int], deadline_ns: int) -> None:
    if clock_ns() >= deadline_ns:
        raise FastLockProbeError("Fast Lock probe exceeded its bounded execution deadline")


def _percentile(values: Sequence[float], percentile: float) -> float:
    if len(values) == 1:
        return float(values[0])
    position = (len(values) - 1) * percentile / 100
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return float(values[lower])
    fraction = position - lower
    return float(values[lower] * (1 - fraction) + values[upper] * fraction)
