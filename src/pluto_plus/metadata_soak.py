"""Bounded, identity-attested metadata lifecycle soak orchestration."""

from __future__ import annotations

import gc
import ipaddress
import json
import multiprocessing
import os
import re
import tempfile
import time
from collections.abc import Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import Field

from pluto_plus.bootstrap_firmware import STANDALONE_FLASH_PROFILES
from pluto_plus.doctor import TANDEM_AGC_V7_RAM_POLICY
from pluto_plus.hardware.preflight import inspect_iio_environment
from pluto_plus.models import ApiModel
from pluto_plus.setup_helper import SetupTransport
from pluto_plus.tandem import RadioMetadataV4, TandemMode, TandemSessionRequestV1, TandemState

MAX_SLOTS = 936
MAX_CLOSE_SECONDS = 2.0
MAX_LO_ERROR_HZ = 100
SLOT_PROCESS_TIMEOUT_SECONDS = 30.0
SLOT_PERIOD_SECONDS = 400.0 / 13.0
MAX_SCHEDULE_OVERRUN_SECONDS = 1.0
RETUNE_FREQUENCIES_HZ = (
    959_687_500,
    1_190_312_500,
    1_209_687_500,
    1_440_312_500,
    1_459_687_500,
    1_690_312_500,
    1_709_687_500,
    1_940_312_500,
)


class MetadataSoakError(RuntimeError):
    """A soak precondition, workload, or lifecycle invariant failed."""


class MetadataMatrixCell(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    dwell_milliseconds: int = Field(gt=0)
    samples_per_refill: int = Field(gt=0)
    refills: int = Field(ge=1, le=4)


SOAK_MATRIX = tuple(
    MetadataMatrixCell(
        sample_rate_hz=rate,
        dwell_milliseconds=dwell,
        samples_per_refill=rate * 40 // 1000,
        refills=dwell // 40,
    )
    for rate in (1_250_000, 2_500_000, 5_000_000)
    for dwell in (40, 80, 160)
)


class MetadataSoakPlan(ApiModel):
    profile_id: str
    target: str
    serial: str
    slots: int = Field(ge=1, le=MAX_SLOTS)
    expected_firmware: str
    expected_metadata_abi: int
    matrix: tuple[MetadataMatrixCell, ...]
    lo_frequencies_hz: tuple[int, ...]
    maximum_close_seconds: float = Field(gt=0)
    slot_period_seconds: float = Field(gt=0)
    confirmation_phrase: str


class MetadataHealth(ApiModel):
    serial: str
    firmware_version: str
    boot_id: str
    uptime_seconds: float = Field(ge=0)
    iiod_pid: int = Field(gt=0)
    iiod_generation: int = Field(gt=0)
    iiod_start_ticks: int = Field(gt=0)
    active_rx_buffers: int = Field(ge=0)
    active_tx_buffers: int = Field(ge=0)
    tandem_state: int = Field(ge=0)
    fault_flags: int = Field(ge=0)
    overflow_count: int = Field(ge=0)
    tx1_gain_db: float
    tx2_gain_db: float
    dds_enabled: bool

    @property
    def tx_safe(self) -> bool:
        return (
            self.tx1_gain_db == -80.0
            and self.tx2_gain_db == -80.0
            and not self.dds_enabled
            and self.active_tx_buffers == 0
        )


class MetadataSlotResult(ApiModel):
    slot: int = Field(ge=0)
    context_count: int = Field(ge=1)
    retunes: int = Field(ge=1)
    metadata_frames: int = Field(ge=1)
    maximum_close_seconds: float = Field(ge=0)
    settings_restored: bool
    lo_readbacks_hz: tuple[int, ...]


class MetadataSoakCheckpoint(ApiModel):
    slot: int = Field(ge=0)
    scheduled_offset_seconds: float = Field(ge=0)
    start_lateness_seconds: float
    matrix_cell: MetadataMatrixCell
    result: MetadataSlotResult
    health: MetadataHealth


class MetadataSoakReport(ApiModel):
    schema_version: int = 1
    started_at_unix_ns: int
    finished_at_unix_ns: int
    outcome: str
    plan: MetadataSoakPlan
    initial_health: MetadataHealth | None = None
    checkpoints: tuple[MetadataSoakCheckpoint, ...] = ()
    final_health: MetadataHealth | None = None
    error: str | None = None


class MetadataHealthProbe(Protocol):
    def inspect(self) -> MetadataHealth: ...

    def ensure_tx_safe(self) -> MetadataHealth: ...


MetadataSlotRunner = Callable[
    [MetadataSoakPlan, MetadataMatrixCell, int], MetadataSlotResult
]


class SshMetadataHealthProbe:
    """Read fixed lifecycle facts and enforce TX safety through pinned SSH."""

    def __init__(self, transport: SetupTransport, *, serial: str) -> None:
        self._transport = transport
        self._serial = serial

    def inspect(self) -> MetadataHealth:
        output = self._transport.run(
            f"/bin/sh -s -- {self._serial} 0",
            stdin=_HEALTH_SCRIPT.encode(),
            timeout_s=15,
        )
        return _parse_health(output)

    def ensure_tx_safe(self) -> MetadataHealth:
        output = self._transport.run(
            f"/bin/sh -s -- {self._serial} 1",
            stdin=_HEALTH_SCRIPT.encode(),
            timeout_s=20,
        )
        return _parse_health(output)


def run_live_metadata_slot(
    plan: MetadataSoakPlan,
    cell: MetadataMatrixCell,
    slot: int,
) -> MetadataSlotResult:
    """Run one context in a killable child so every slot has a wall-clock bound."""

    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_metadata_slot_worker,
        args=(plan.model_dump(mode="json"), cell.model_dump(mode="json"), slot, child),
        daemon=True,
    )
    process.start()
    child.close()
    try:
        process.join(SLOT_PROCESS_TIMEOUT_SECONDS)
        if process.is_alive():
            process.terminate()
            process.join(5)
            if process.is_alive():
                process.kill()
                process.join(5)
            raise MetadataSoakError("metadata slot exceeded its wall-clock process deadline")
        if not parent.poll():
            raise MetadataSoakError(
                f"metadata slot worker exited without a result (exit code {process.exitcode})"
            )
        message = cast(dict[str, Any], parent.recv())
    finally:
        parent.close()
        if process.is_alive():
            process.kill()
            process.join(5)
    if message.get("outcome") != "pass":
        raise MetadataSoakError(str(message.get("error") or "metadata slot worker failed"))
    return MetadataSlotResult.model_validate(message["result"])


def _metadata_slot_worker(
    raw_plan: dict[str, Any],
    raw_cell: dict[str, Any],
    slot: int,
    connection: Any,
) -> None:
    try:
        environment = inspect_iio_environment(require_usb=False)
        if not environment.healthy:
            raise MetadataSoakError(
                f"metadata slot worker IIO environment failed: "
                f"{environment.actionable_message}"
            )
        result = _execute_live_metadata_slot(
            MetadataSoakPlan.model_validate(raw_plan),
            MetadataMatrixCell.model_validate(raw_cell),
            slot,
        )
        connection.send({"outcome": "pass", "result": result.model_dump(mode="json")})
    except BaseException as error:
        connection.send({"outcome": "fail", "error": f"{type(error).__name__}: {error}"})
    finally:
        connection.close()


def _execute_live_metadata_slot(
    plan: MetadataSoakPlan,
    cell: MetadataMatrixCell,
    slot: int,
) -> MetadataSlotResult:
    import adi
    import iio

    with _metadata_phase(slot, "context_open"):
        sdr = adi.ad9361(uri=f"ip:{plan.target}")
    buffer: Any | None = None
    maximum_close = 0.0
    frames = 0
    lo_readbacks: list[int] = []
    original: dict[str, Any] = {}
    restored = False
    try:
        with _metadata_phase(slot, "context_attestation"):
            if sdr._ctx.attrs.get("hw_serial") != plan.serial:
                raise MetadataSoakError("IIO context serial does not match the soak plan")
            if sdr._ctx.attrs.get("fw_version") != plan.expected_firmware:
                raise MetadataSoakError("IIO context firmware does not match the soak profile")
            if sdr._ctx.attrs.get("iio,buffer-metadata") != str(plan.expected_metadata_abi):
                raise MetadataSoakError("IIO context metadata ABI does not match the soak profile")
            if sdr._ctx.find_device("tandem-agc") is None:
                raise MetadataSoakError("IIO context lacks the tandem-AGC device")
            metadata_buffer = getattr(iio, "MetadataBuffer", None)
            if metadata_buffer is None:
                raise MetadataSoakError("loaded libiio Python binding lacks MetadataBuffer")
        with _metadata_phase(slot, "configure"):
            original = _read_live_rx_settings(sdr)
            _mute_live_tx(sdr)
            sdr.rx_enabled_channels = [0, 1]
            sdr.sample_rate = cell.sample_rate_hz
            sdr.rx_rf_bandwidth = min(cell.sample_rate_hz, 20_000_000)
            sdr.rx_buffer_size = cell.samples_per_refill
            sdr.gain_control_mode_chan0 = "manual"
            sdr.gain_control_mode_chan1 = "manual"
            sdr.rx_hardwaregain_chan0 = 30
            sdr.rx_hardwaregain_chan1 = 30
            sdr._rxadc.set_kernel_buffers_count(2)
        frequencies = (
            plan.lo_frequencies_hz
            if slot % 2 == 0
            else tuple(reversed(plan.lo_frequencies_hz))
        )
        for frequency in frequencies:
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="destroy_before_retune",
            ):
                sdr.rx_destroy_buffer()
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="lo_write",
            ):
                sdr.rx_lo = frequency
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="lo_readback",
            ):
                actual_frequency = int(sdr.rx_lo)
                lo_readbacks.append(actual_frequency)
                if abs(actual_frequency - frequency) > MAX_LO_ERROR_HZ:
                    raise MetadataSoakError(
                        "RX LO readback exceeded the quantization tolerance: "
                        f"requested={frequency} actual={actual_frequency}"
                    )
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="ordinary_prime_refill",
            ):
                prime = sdr.rx()
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="destroy_after_prime",
            ):
                sdr.rx_destroy_buffer()
            with _metadata_phase(
                slot,
                "retune_and_prime",
                frequency=frequency,
                operation="prime_shape_validation",
            ):
                if len(prime) != 2 or any(
                    len(channel) != cell.samples_per_refill for channel in prime
                ):
                    raise MetadataSoakError(
                        "ordinary RX prime did not establish paired scan mask"
                    )
            with _metadata_phase(slot, "metadata_buffer_open", frequency=frequency):
                request = TandemSessionRequestV1(mode=TandemMode.HOLD).pack(
                    cell.samples_per_refill
                )
                buffer = metadata_buffer(
                    sdr._rxadc,
                    cell.samples_per_refill,
                    request,
                    64 * 1024,
                )
                sdr._rxbuf = buffer
            for refill in range(cell.refills):
                with _metadata_phase(
                    slot,
                    "metadata_refill",
                    frequency=frequency,
                    refill=refill,
                ):
                    signal = sdr.rx()
                    if len(signal) != 2 or any(
                        len(channel) != cell.samples_per_refill for channel in signal
                    ):
                        raise MetadataSoakError(
                            "metadata refill did not return paired RX samples"
                        )
                    raw = buffer.metadata
                    if raw is None:
                        raise MetadataSoakError("metadata refill returned no header")
                    metadata = RadioMetadataV4.unpack(raw)
                    if metadata.tandem_state is not TandemState.ARMED_HOLD:
                        raise MetadataSoakError("metadata refill lost tandem HOLD ownership")
                    frames += 1
            with _metadata_phase(slot, "metadata_buffer_close", frequency=frequency):
                maximum_close = max(maximum_close, _close_live_buffer(sdr, buffer))
            buffer = None
        _restore_live_rx_settings(sdr, original, slot=slot)
        with _metadata_phase(slot, "settings_restore", operation="settings_readback"):
            restored = _read_live_rx_settings(sdr) == original
    finally:
        if buffer is not None:
            maximum_close = max(maximum_close, _close_live_buffer(sdr, buffer))
        try:
            if original and not restored:
                _restore_live_rx_settings(sdr, original)
                restored = _read_live_rx_settings(sdr) == original
        finally:
            _mute_live_tx(sdr)
            sdr.rx_destroy_buffer()
            sdr._ctx.close()
            del sdr
            gc.collect()
    return MetadataSlotResult(
        slot=slot,
        context_count=1,
        retunes=len(plan.lo_frequencies_hz),
        metadata_frames=frames,
        maximum_close_seconds=maximum_close,
        settings_restored=restored,
        lo_readbacks_hz=tuple(lo_readbacks),
    )


@contextmanager
def _metadata_phase(
    slot: int,
    phase: str,
    *,
    frequency: int | None = None,
    refill: int | None = None,
    operation: str | None = None,
) -> Any:
    try:
        yield
    except BaseException as error:
        details = [f"slot={slot}", f"phase={phase}"]
        if frequency is not None:
            details.append(f"frequency_hz={frequency}")
        if refill is not None:
            details.append(f"refill={refill}")
        if operation is not None:
            details.append(f"operation={operation}")
        raise MetadataSoakError(
            f"{' '.join(details)}: {type(error).__name__}: {error}"
        ) from error


def _read_live_rx_settings(sdr: Any) -> dict[str, Any]:
    return {
        "sample_rate": int(sdr.sample_rate),
        "rx_rf_bandwidth": int(sdr.rx_rf_bandwidth),
        "rx_lo": int(sdr.rx_lo),
        "rx_enabled_channels": tuple(int(item) for item in sdr.rx_enabled_channels),
        "gain_control_mode_chan0": str(sdr.gain_control_mode_chan0),
        "gain_control_mode_chan1": str(sdr.gain_control_mode_chan1),
        "rx_hardwaregain_chan0": float(sdr.rx_hardwaregain_chan0),
        "rx_hardwaregain_chan1": float(sdr.rx_hardwaregain_chan1),
        "rx_buffer_size": int(sdr.rx_buffer_size),
    }


def _restore_live_rx_settings(
    sdr: Any, settings: dict[str, Any], *, slot: int | None = None
) -> None:
    def restore(operation: str, setter: Callable[[], None]) -> None:
        if slot is None:
            setter()
            return
        with _metadata_phase(slot, "settings_restore", operation=operation):
            setter()

    restore("destroy_before_restore", sdr.rx_destroy_buffer)
    restore(
        "enabled_channels_write",
        lambda: setattr(sdr, "rx_enabled_channels", list(settings["rx_enabled_channels"])),
    )
    restore("sample_rate_write", lambda: setattr(sdr, "sample_rate", settings["sample_rate"]))
    restore(
        "rf_bandwidth_write",
        lambda: setattr(sdr, "rx_rf_bandwidth", settings["rx_rf_bandwidth"]),
    )
    restore("lo_write", lambda: setattr(sdr, "rx_lo", settings["rx_lo"]))
    restore(
        "buffer_size_write",
        lambda: setattr(sdr, "rx_buffer_size", settings["rx_buffer_size"]),
    )
    restore(
        "gain_mode_chan0_write",
        lambda: setattr(
            sdr, "gain_control_mode_chan0", settings["gain_control_mode_chan0"]
        ),
    )
    restore(
        "gain_mode_chan1_write",
        lambda: setattr(
            sdr, "gain_control_mode_chan1", settings["gain_control_mode_chan1"]
        ),
    )
    if settings["gain_control_mode_chan0"] == "manual":
        restore(
            "hardware_gain_chan0_write",
            lambda: setattr(
                sdr, "rx_hardwaregain_chan0", settings["rx_hardwaregain_chan0"]
            ),
        )
    if settings["gain_control_mode_chan1"] == "manual":
        restore(
            "hardware_gain_chan1_write",
            lambda: setattr(
                sdr, "rx_hardwaregain_chan1", settings["rx_hardwaregain_chan1"]
            ),
        )


def _close_live_buffer(sdr: Any, buffer: Any) -> float:
    if getattr(sdr, "_rxbuf", None) is buffer:
        sdr._rxbuf = None
    started = time.monotonic()
    close = getattr(buffer, "close", None)
    if callable(close):
        close()
    del buffer
    gc.collect()
    return time.monotonic() - started


def _mute_live_tx(sdr: Any) -> None:
    sdr.tx_hardwaregain_chan0 = -80
    sdr.tx_hardwaregain_chan1 = -80
    dds = sdr._ctx.find_device("cf-ad9361-dds-core-lpc")
    if dds is None:
        raise MetadataSoakError("IIO context lacks the TX DDS device")
    for channel in dds.channels:
        for name in ("raw", "scale"):
            attribute = channel.attrs.get(name)
            if attribute is not None:
                attribute.value = "0"


def _parse_health(output: str) -> MetadataHealth:
    fields: dict[str, str] = {}
    for line in output.splitlines():
        if not line.startswith("PPU\t"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or parts[1] in fields:
            raise MetadataSoakError("remote health report is malformed or duplicated")
        fields[parts[1]] = parts[2]
    expected = {
        "serial",
        "firmware_version",
        "boot_id",
        "uptime_seconds",
        "iiod_pid",
        "iiod_generation",
        "iiod_start_ticks",
        "active_rx_buffers",
        "active_tx_buffers",
        "tandem_state",
        "fault_flags",
        "overflow_count",
        "tx1_gain_db",
        "tx2_gain_db",
        "dds_enabled",
    }
    if set(fields) != expected:
        raise MetadataSoakError("remote health report omitted or added fields")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", fields["serial"]):
        raise MetadataSoakError("remote health report serial is invalid")
    try:
        return MetadataHealth(
            serial=fields["serial"],
            firmware_version=fields["firmware_version"],
            boot_id=fields["boot_id"],
            uptime_seconds=float(fields["uptime_seconds"]),
            iiod_pid=int(fields["iiod_pid"]),
            iiod_generation=int(fields["iiod_generation"]),
            iiod_start_ticks=int(fields["iiod_start_ticks"]),
            active_rx_buffers=int(fields["active_rx_buffers"]),
            active_tx_buffers=int(fields["active_tx_buffers"]),
            tandem_state=int(fields["tandem_state"]),
            fault_flags=int(fields["fault_flags"]),
            overflow_count=int(fields["overflow_count"]),
            tx1_gain_db=float(fields["tx1_gain_db"]),
            tx2_gain_db=float(fields["tx2_gain_db"]),
            dds_enabled=bool(int(fields["dds_enabled"])),
        )
    except (TypeError, ValueError) as error:
        raise MetadataSoakError("remote health report contains invalid values") from error


_HEALTH_SCRIPT = r"""set -eu
serial_expected="$1"; make_safe="$2"
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
test "$serial" = "$serial_expected"
firmware=$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)
boot_id=$(cat /proc/sys/kernel/random/boot_id)
uptime_seconds=$(awk '{print $1}' /proc/uptime)
iiod_pid=$(cat /var/run/iiod-child.pid)
iiod_generation=$(cat /run/iiod-generation)
iiod_start_ticks=$(awk '{print $22}' "/proc/$iiod_pid/stat")
phy=''; rx=''; dds=''; tandem=''
for d in /sys/bus/iio/devices/iio:device*; do
  case "$(cat "$d/name" 2>/dev/null || true)" in
    ad9361-phy) phy="$d" ;;
    cf-ad9361-lpc) rx="$d" ;;
    cf-ad9361-dds-core-lpc) dds="$d" ;;
    tandem-agc) tandem="$d" ;;
  esac
done
test -n "$phy" && test -n "$rx" && test -n "$dds" && test -n "$tandem"
if test "$make_safe" = 1; then
  printf '%s\n' -80 >"$phy/out_voltage0_hardwaregain"
  printf '%s\n' -80 >"$phy/out_voltage1_hardwaregain"
  printf '%s\n' 0 >"$dds/buffer/enable"
  for f in "$dds"/scan_elements/out_voltage[0-3]_en; do
    test ! -e "$f" || printf '%s\n' 0 >"$f"
  done
  for f in "$dds"/out_altvoltage*_raw "$dds"/out_altvoltage*_scale; do
    test ! -e "$f" || printf '%s\n' 0 >"$f"
  done
fi
active_rx_buffers=$(cat "$rx/buffer/enable")
active_tx_buffers=$(cat "$dds/buffer/enable")
dds_enabled=$active_tx_buffers
for f in "$dds"/scan_elements/out_voltage[0-3]_en \
  "$dds"/out_altvoltage*_raw "$dds"/out_altvoltage*_scale; do
  test ! -e "$f" || awk -v value="$(cat "$f")" 'BEGIN { if (value != 0) exit 1 }' || dds_enabled=1
done
emit serial "$serial"
emit firmware_version "$firmware"
emit boot_id "$boot_id"
emit uptime_seconds "$uptime_seconds"
emit iiod_pid "$iiod_pid"
emit iiod_generation "$iiod_generation"
emit iiod_start_ticks "$iiod_start_ticks"
emit active_rx_buffers "$active_rx_buffers"
emit active_tx_buffers "$active_tx_buffers"
emit tandem_state "$(cat "$tandem/state")"
emit fault_flags "$(cat "$tandem/fault_flags")"
emit overflow_count "$(cat "$tandem/overflow_count")"
emit tx1_gain_db "$(awk '{print $1}' "$phy/out_voltage0_hardwaregain")"
emit tx2_gain_db "$(awk '{print $1}' "$phy/out_voltage1_hardwaregain")"
emit dds_enabled "$dds_enabled"
"""


def prepare_metadata_soak(
    target: str,
    serial: str,
    *,
    slots: int,
    profile_id: str = TANDEM_AGC_V7_RAM_POLICY.profile_id,
) -> MetadataSoakPlan:
    """Prepare an immutable exact-profile network soak plan."""

    try:
        address = ipaddress.ip_address(target.removeprefix("ip:"))
    except ValueError as error:
        raise MetadataSoakError("metadata soak target must be a private IPv4 literal") from error
    if address.version != 4 or not address.is_private:
        raise MetadataSoakError("metadata soak target must be a private IPv4 literal")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", serial):
        raise MetadataSoakError("metadata soak serial must be one exact non-empty value")
    if not 1 <= slots <= MAX_SLOTS:
        raise MetadataSoakError(f"metadata soak slots must be between 1 and {MAX_SLOTS}")
    profile = STANDALONE_FLASH_PROFILES.get(profile_id)
    if profile is None or not profile.tandem_agc or profile.metadata_abi != 2:
        raise MetadataSoakError("metadata soak requires a known ABI-2 tandem profile")
    return MetadataSoakPlan(
        profile_id=profile_id,
        target=str(address),
        serial=serial,
        slots=slots,
        expected_firmware=profile.policy.device_firmware,
        expected_metadata_abi=profile.metadata_abi,
        matrix=SOAK_MATRIX,
        lo_frequencies_hz=RETUNE_FREQUENCIES_HZ,
        maximum_close_seconds=MAX_CLOSE_SECONDS,
        slot_period_seconds=SLOT_PERIOD_SECONDS,
        confirmation_phrase=f"SOAK METADATA {serial} {slots}",
    )


def execute_metadata_soak(
    plan: MetadataSoakPlan,
    *,
    report_path: Path,
    health_probe: MetadataHealthProbe,
    slot_runner: MetadataSlotRunner,
    monotonic_clock: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> MetadataSoakReport:
    """Execute a bounded soak, fail closed, and always enforce TX cleanup."""

    started = time.time_ns()
    initial: MetadataHealth | None = None
    checkpoints: list[MetadataSoakCheckpoint] = []
    final: MetadataHealth | None = None
    failure: BaseException | None = None
    try:
        initial = health_probe.inspect()
        _validate_initial(plan, initial)
        campaign_start = monotonic_clock()
        for slot in range(plan.slots):
            scheduled_offset = slot * plan.slot_period_seconds
            remaining = campaign_start + scheduled_offset - monotonic_clock()
            if remaining > 0:
                sleeper(remaining)
            elif remaining < -MAX_SCHEDULE_OVERRUN_SECONDS:
                raise MetadataSoakError(
                    "metadata slot schedule overran; refusing an unscheduled catch-up burst"
                )
            actual_start = monotonic_clock()
            cell = plan.matrix[slot % len(plan.matrix)]
            result = slot_runner(plan, cell, slot)
            _validate_slot(plan, cell, slot, result)
            health = health_probe.inspect()
            _validate_checkpoint(initial, health)
            checkpoints.append(
                MetadataSoakCheckpoint(
                    slot=slot,
                    scheduled_offset_seconds=scheduled_offset,
                    start_lateness_seconds=actual_start - (campaign_start + scheduled_offset),
                    matrix_cell=cell,
                    result=result,
                    health=health,
                )
            )
    except BaseException as error:
        failure = error
    try:
        final = health_probe.ensure_tx_safe()
        if not final.tx_safe:
            raise MetadataSoakError("final TX-safe cleanup did not read back")
        if final.active_rx_buffers:
            raise MetadataSoakError("active RX buffer leaked after final cleanup")
        if final.tandem_state != 0:
            raise MetadataSoakError("tandem owner leaked after final cleanup")
        if final.fault_flags or final.overflow_count:
            raise MetadataSoakError("tandem fault or overflow remained after final cleanup")
        if initial is not None:
            _validate_process_identity(initial, final)
    except BaseException as cleanup_error:
        if failure is None:
            failure = cleanup_error
        else:
            failure = MetadataSoakError(f"{failure}; final cleanup failed: {cleanup_error}")

    report = MetadataSoakReport(
        started_at_unix_ns=started,
        finished_at_unix_ns=time.time_ns(),
        outcome="pass" if failure is None else "fail",
        plan=plan,
        initial_health=initial,
        checkpoints=tuple(checkpoints),
        final_health=final,
        error=None if failure is None else f"{type(failure).__name__}: {failure}",
    )
    _write_report(report_path, report)
    if failure is not None:
        raise MetadataSoakError(str(failure)) from failure
    return report


def _validate_initial(plan: MetadataSoakPlan, health: MetadataHealth) -> None:
    if health.serial != plan.serial:
        raise MetadataSoakError("remote serial does not match the soak plan")
    if health.firmware_version != plan.expected_firmware:
        raise MetadataSoakError("remote firmware does not match the soak profile")
    _validate_idle(health)


def _validate_checkpoint(initial: MetadataHealth, health: MetadataHealth) -> None:
    if health.serial != initial.serial or health.firmware_version != initial.firmware_version:
        raise MetadataSoakError("radio identity changed during metadata soak")
    _validate_process_identity(initial, health)
    _validate_idle(health)


def _validate_process_identity(initial: MetadataHealth, health: MetadataHealth) -> None:
    if health.boot_id != initial.boot_id:
        raise MetadataSoakError("Linux boot ID changed during metadata soak")
    if health.iiod_generation != initial.iiod_generation:
        raise MetadataSoakError("iiOD generation changed during metadata soak")
    if health.iiod_pid != initial.iiod_pid or health.iiod_start_ticks != initial.iiod_start_ticks:
        raise MetadataSoakError("iiOD process changed during metadata soak")


def _validate_idle(health: MetadataHealth) -> None:
    if health.active_rx_buffers:
        raise MetadataSoakError("active RX buffer leaked after metadata lifecycle")
    if health.active_tx_buffers:
        raise MetadataSoakError("active TX buffer leaked after metadata lifecycle")
    if health.tandem_state != 0:
        raise MetadataSoakError("tandem owner leaked after metadata lifecycle")
    if health.fault_flags:
        raise MetadataSoakError("tandem fault remained after metadata lifecycle")
    if health.overflow_count:
        raise MetadataSoakError("tandem overflow remained after metadata lifecycle")
    if not health.tx_safe:
        raise MetadataSoakError("radio TX state is not safe")


def _validate_slot(
    plan: MetadataSoakPlan,
    cell: MetadataMatrixCell,
    slot: int,
    result: MetadataSlotResult,
) -> None:
    if result.slot != slot or result.context_count != 1:
        raise MetadataSoakError("slot result does not describe exactly one context")
    if result.retunes != len(plan.lo_frequencies_hz):
        raise MetadataSoakError("slot did not complete all eight retunes")
    expected_los = (
        plan.lo_frequencies_hz
        if slot % 2 == 0
        else tuple(reversed(plan.lo_frequencies_hz))
    )
    if len(result.lo_readbacks_hz) != len(expected_los) or any(
        abs(actual - expected) > MAX_LO_ERROR_HZ
        for actual, expected in zip(result.lo_readbacks_hz, expected_los, strict=True)
    ):
        raise MetadataSoakError("slot LO readbacks exceeded the quantization tolerance")
    expected_frames = len(plan.lo_frequencies_hz) * cell.refills
    if result.metadata_frames != expected_frames:
        raise MetadataSoakError("slot metadata frame count is incomplete")
    if result.maximum_close_seconds > plan.maximum_close_seconds:
        raise MetadataSoakError("metadata buffer close exceeded the bounded deadline")
    if not result.settings_restored:
        raise MetadataSoakError("slot did not restore the original RX settings")


def _write_report(path: Path, report: MetadataSoakReport) -> None:
    destination = path.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report.model_dump(mode="json"), stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
