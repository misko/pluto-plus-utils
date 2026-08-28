"""Bounded abrupt-disconnect recovery qualification for device DDR bursts."""

from __future__ import annotations

import gc
import ipaddress
import json
import multiprocessing
import os
import re
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any, Protocol, cast

from pydantic import Field, model_validator

from pluto_plus.bootstrap_firmware import STANDALONE_FLASH_PROFILES
from pluto_plus.hardware.base import restore_settings_exact
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.hardware.preflight import inspect_iio_environment
from pluto_plus.metadata_ladder import run_metadata_continuity_ladder
from pluto_plus.metadata_soak import MetadataHealth, MetadataHealthProbe
from pluto_plus.models import ApiModel

MAX_CYCLES = 100
MIN_DISCONNECT_DELAY_MS = 10
MAX_DISCONNECT_DELAY_MS = 1_000
DEFAULT_DISCONNECT_DELAY_MS = 50
VICTIM_SAMPLE_RATE_HZ = 25_000_000
VICTIM_RF_BANDWIDTH_HZ = 20_000_000
VICTIM_SAMPLES_PER_FRAME = 1_000_000
VICTIM_FRAMES = 50
VICTIM_IQ_BYTES = VICTIM_SAMPLES_PER_FRAME * 4 * VICTIM_FRAMES
RECOVERY_DDR_FRAMES = 2
RECOVERY_ORDINARY_SAMPLE_RATE_HZ = 1_250_000
RECOVERY_ORDINARY_SAMPLES_PER_FRAME = 262_144
RECOVERY_ORDINARY_FRAMES = 2
KERNEL_BUFFERS = 4
VICTIM_READY_TIMEOUT_SECONDS = 15.0
VICTIM_STOP_TIMEOUT_SECONDS = 5.0


class DdrRecoveryError(RuntimeError):
    """A recovery precondition, workload, or lifecycle invariant failed."""


class DdrRecoveryPlan(ApiModel):
    profile_id: str
    target: str
    serial: str
    cycles: int = Field(ge=1, le=MAX_CYCLES)
    expected_firmware: str
    expected_metadata_abi: int = Field(ge=3, le=3)
    disconnect_delay_ms: int = Field(ge=MIN_DISCONNECT_DELAY_MS, le=MAX_DISCONNECT_DELAY_MS)
    sample_rate_hz: int = Field(gt=0)
    rf_bandwidth_hz: int = Field(gt=0)
    victim_samples_per_frame: int = Field(gt=0)
    victim_frames: int = Field(gt=0)
    victim_iq_bytes: int = Field(gt=0)
    recovery_ddr_frames: int = Field(gt=0)
    kernel_buffers: int = Field(ge=4)
    confirmation_phrase: str

    @model_validator(mode="after")
    def validate_fixed_release_geometry(self) -> DdrRecoveryPlan:
        if self.victim_iq_bytes != self.victim_samples_per_frame * 4 * self.victim_frames:
            raise ValueError("DDR recovery victim byte geometry does not close")
        if self.victim_iq_bytes != VICTIM_IQ_BYTES:
            raise ValueError("DDR recovery must use the reviewed 200 MB victim geometry")
        return self


class DdrRecoveryProbe(ApiModel):
    mode: str
    samples_per_frame: int = Field(gt=0)
    requested_frames: int = Field(gt=0)
    observed_frames: int = Field(gt=0)
    missing_sample_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    overflow_count: int = Field(ge=0)
    observed_fraction: float = Field(ge=0.0, le=1.0)
    elapsed_seconds: float = Field(gt=0)
    passed: bool

    @model_validator(mode="after")
    def validate_pass(self) -> DdrRecoveryProbe:
        expected = (
            self.observed_frames == self.requested_frames
            and self.observed_fraction >= 0.95
            and self.overflow_count == 0
        )
        if self.passed is not expected:
            raise ValueError("DDR recovery probe pass result is non-canonical")
        return self


class DdrRecoveryCycleResult(ApiModel):
    cycle: int = Field(ge=0)
    channel: int = Field(ge=0, le=1)
    victim_exit_code: int
    disconnect_delay_ms: int = Field(ge=MIN_DISCONNECT_DELAY_MS, le=MAX_DISCONNECT_DELAY_MS)
    ddr_probe: DdrRecoveryProbe
    ordinary_probe: DdrRecoveryProbe
    settings_restored: bool

    @model_validator(mode="after")
    def validate_recovery(self) -> DdrRecoveryCycleResult:
        if self.victim_exit_code >= 0:
            raise ValueError("victim did not exit from an abrupt signal")
        if not self.ddr_probe.passed or not self.ordinary_probe.passed:
            raise ValueError("post-disconnect recovery probe failed")
        if not self.settings_restored:
            raise ValueError("post-disconnect RX settings were not restored")
        return self


class DdrRecoveryCheckpoint(ApiModel):
    cycle: int = Field(ge=0)
    result: DdrRecoveryCycleResult
    health: MetadataHealth


class DdrRecoveryReport(ApiModel):
    schema_version: int = 1
    started_at_unix_ns: int
    finished_at_unix_ns: int
    outcome: str
    plan: DdrRecoveryPlan
    initial_health: MetadataHealth | None = None
    checkpoints: tuple[DdrRecoveryCheckpoint, ...] = ()
    final_health: MetadataHealth | None = None
    error: str | None = None


class DdrRecoveryCycleRunner(Protocol):
    def __call__(
        self, plan: DdrRecoveryPlan, cycle: int, channel: int
    ) -> DdrRecoveryCycleResult: ...


def prepare_ddr_recovery(
    target: str,
    serial: str,
    *,
    cycles: int,
    profile_id: str,
    disconnect_delay_ms: int = DEFAULT_DISCONNECT_DELAY_MS,
) -> DdrRecoveryPlan:
    """Prepare an exact-profile, fixed-geometry recovery campaign."""

    try:
        address = ipaddress.ip_address(target.removeprefix("ip:"))
    except ValueError as error:
        raise DdrRecoveryError("DDR recovery target must be a private IPv4 literal") from error
    if address.version != 4 or not address.is_private:
        raise DdrRecoveryError("DDR recovery target must be a private IPv4 literal")
    if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", serial):
        raise DdrRecoveryError("DDR recovery serial must be one exact non-empty value")
    if not 1 <= cycles <= MAX_CYCLES:
        raise DdrRecoveryError(f"DDR recovery cycles must be between 1 and {MAX_CYCLES}")
    if not MIN_DISCONNECT_DELAY_MS <= disconnect_delay_ms <= MAX_DISCONNECT_DELAY_MS:
        raise DdrRecoveryError(
            "DDR recovery disconnect delay must be between "
            f"{MIN_DISCONNECT_DELAY_MS} and {MAX_DISCONNECT_DELAY_MS} ms"
        )
    profile = STANDALONE_FLASH_PROFILES.get(profile_id)
    if (
        profile is None
        or profile.metadata_abi != 3
        or profile.ddr_burst_max_iq_bytes is None
        or profile.ddr_burst_max_iq_bytes < VICTIM_IQ_BYTES
    ):
        raise DdrRecoveryError("DDR recovery requires a known ABI-3 200 MB burst profile")
    return DdrRecoveryPlan(
        profile_id=profile_id,
        target=str(address),
        serial=serial,
        cycles=cycles,
        expected_firmware=profile.policy.device_firmware,
        expected_metadata_abi=profile.metadata_abi,
        disconnect_delay_ms=disconnect_delay_ms,
        sample_rate_hz=VICTIM_SAMPLE_RATE_HZ,
        rf_bandwidth_hz=VICTIM_RF_BANDWIDTH_HZ,
        victim_samples_per_frame=VICTIM_SAMPLES_PER_FRAME,
        victim_frames=VICTIM_FRAMES,
        victim_iq_bytes=VICTIM_IQ_BYTES,
        recovery_ddr_frames=RECOVERY_DDR_FRAMES,
        kernel_buffers=KERNEL_BUFFERS,
        confirmation_phrase=f"QUALIFY DDR RECOVERY {serial} {cycles}",
    )


def execute_ddr_recovery(
    plan: DdrRecoveryPlan,
    *,
    report_path: Path,
    health_probe: MetadataHealthProbe,
    cycle_runner: DdrRecoveryCycleRunner,
) -> DdrRecoveryReport:
    """Run the campaign, fail closed, and persist evidence on pass or failure."""

    started = time.time_ns()
    initial: MetadataHealth | None = None
    checkpoints: list[DdrRecoveryCheckpoint] = []
    final: MetadataHealth | None = None
    failure: BaseException | None = None
    try:
        initial = health_probe.inspect()
        _validate_initial(plan, initial)
        for cycle in range(plan.cycles):
            channel = cycle % 2
            result = cycle_runner(plan, cycle, channel)
            if result.cycle != cycle or result.channel != channel:
                raise DdrRecoveryError("cycle result does not match the requested recovery cell")
            health = health_probe.inspect()
            _validate_checkpoint(initial, health)
            checkpoints.append(DdrRecoveryCheckpoint(cycle=cycle, result=result, health=health))
    except BaseException as error:
        failure = error
    try:
        final = health_probe.ensure_tx_safe()
        _validate_idle(final)
        if initial is not None:
            _validate_process_identity(initial, final)
    except BaseException as cleanup_error:
        if failure is None:
            failure = cleanup_error
        else:
            failure = DdrRecoveryError(f"{failure}; final cleanup failed: {cleanup_error}")
    report = DdrRecoveryReport(
        started_at_unix_ns=started,
        finished_at_unix_ns=time.time_ns(),
        outcome="pass" if failure is None else "fail",
        plan=plan,
        initial_health=initial,
        checkpoints=tuple(checkpoints),
        final_health=final,
        error=None if failure is None else f"{type(failure).__name__}: {failure}",
    )
    write_ddr_recovery_report(report_path, report)
    if failure is not None:
        raise DdrRecoveryError(str(failure)) from failure
    return report


def run_live_ddr_recovery_cycle(
    plan: DdrRecoveryPlan, cycle: int, channel: int
) -> DdrRecoveryCycleResult:
    """Kill one active burst client, then immediately prove DDR and ordinary reuse."""

    uri = f"ip:{plan.target}"
    radio = _new_radio(plan)
    radio.open()
    original = radio.read_settings()
    radio.close()
    victim_exit_code = _kill_live_burst_client(plan, channel)
    failure: BaseException | None = None
    ddr_probe: DdrRecoveryProbe | None = None
    ordinary_probe: DdrRecoveryProbe | None = None
    restored = False
    try:
        ddr_report = run_metadata_continuity_ladder(
            uri=uri,
            serial=plan.serial,
            sample_rate_hz=plan.sample_rate_hz,
            rf_bandwidth_hz=plan.rf_bandwidth_hz,
            metadata_abi=3,
            channels=(channel,),
            samples_per_channel=(plan.victim_samples_per_frame,),
            frames=plan.recovery_ddr_frames,
            kernel_buffers=plan.kernel_buffers,
            ddr_burst=True,
        )
        ddr_probe = _probe_from_ladder("ddr", ddr_report)
        ordinary_report = run_metadata_continuity_ladder(
            uri=uri,
            serial=plan.serial,
            sample_rate_hz=RECOVERY_ORDINARY_SAMPLE_RATE_HZ,
            rf_bandwidth_hz=RECOVERY_ORDINARY_SAMPLE_RATE_HZ,
            metadata_abi=3,
            channels=(channel,),
            samples_per_channel=(RECOVERY_ORDINARY_SAMPLES_PER_FRAME,),
            frames=RECOVERY_ORDINARY_FRAMES,
            kernel_buffers=plan.kernel_buffers,
            ddr_burst=False,
        )
        ordinary_probe = _probe_from_ladder("ordinary", ordinary_report)
    except BaseException as error:
        failure = error
    try:
        restore_radio = _new_radio(plan)
        restore_radio.open()
        try:
            restored = restore_settings_exact(restore_radio, original).restored == original
        finally:
            restore_radio.close()
    except BaseException as restore_error:
        if failure is None:
            failure = restore_error
        else:
            failure = DdrRecoveryError(f"{failure}; RX restore failed: {restore_error}")
    if failure is not None:
        raise DdrRecoveryError(str(failure)) from failure
    if ddr_probe is None or ordinary_probe is None:
        raise DdrRecoveryError("post-disconnect recovery probes did not complete")
    return DdrRecoveryCycleResult(
        cycle=cycle,
        channel=channel,
        victim_exit_code=victim_exit_code,
        disconnect_delay_ms=plan.disconnect_delay_ms,
        ddr_probe=ddr_probe,
        ordinary_probe=ordinary_probe,
        settings_restored=restored,
    )


def _new_radio(plan: DdrRecoveryPlan) -> IioRadioDevice:
    return IioRadioDevice(
        f"ip:{plan.target}",
        serial=plan.serial,
        radio_id=plan.serial,
        expected_metadata_abi=3,
    )


def _kill_live_burst_client(plan: DdrRecoveryPlan, channel: int) -> int:
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_burst_victim_worker,
        args=(plan.model_dump(mode="json"), channel, child),
    )
    process.start()
    child.close()
    try:
        if not parent.poll(VICTIM_READY_TIMEOUT_SECONDS):
            raise DdrRecoveryError("burst victim did not reach active refill before deadline")
        message = cast(dict[str, Any], parent.recv())
        if message.get("state") != "refill-started":
            raise DdrRecoveryError(str(message.get("error") or "burst victim failed to arm"))
        if (
            message.get("requested_bytes") != plan.victim_iq_bytes
            or message.get("admitted_bytes") != plan.victim_iq_bytes
            or message.get("frames") != plan.victim_frames
        ):
            raise DdrRecoveryError("burst victim admission readback is not exact")
        time.sleep(plan.disconnect_delay_ms / 1_000)
        if not process.is_alive():
            raise DdrRecoveryError("burst victim completed before the abrupt disconnect")
        process.terminate()
        process.join(VICTIM_STOP_TIMEOUT_SECONDS)
        if process.is_alive():
            process.kill()
            process.join(VICTIM_STOP_TIMEOUT_SECONDS)
        if process.is_alive() or process.exitcode is None or process.exitcode >= 0:
            raise DdrRecoveryError("burst victim did not terminate from an abrupt signal")
        return process.exitcode
    finally:
        parent.close()
        if process.is_alive():
            process.kill()
            process.join(VICTIM_STOP_TIMEOUT_SECONDS)


def _burst_victim_worker(raw_plan: dict[str, Any], channel: int, connection: Any) -> None:
    radio: IioRadioDevice | None = None
    capture: Any | None = None
    try:
        plan = DdrRecoveryPlan.model_validate(raw_plan)
        environment = inspect_iio_environment(require_usb=False)
        if not environment.healthy:
            raise DdrRecoveryError(
                f"burst victim IIO environment failed: {environment.actionable_message}"
            )
        radio = _new_radio(plan)
        radio.open()
        current = radio.read_settings()
        actual = radio.apply_settings(
            current.model_copy(
                update={
                    "sample_rate_hz": plan.sample_rate_hz,
                    "bandwidth_hz": plan.rf_bandwidth_hz,
                    "channels": (channel,),
                }
            )
        )
        if (
            round(actual.sample_rate_hz) != plan.sample_rate_hz
            or round(actual.bandwidth_hz) != plan.rf_bandwidth_hz
            or tuple(actual.channels) != (channel,)
        ):
            raise DdrRecoveryError("burst victim RX settings did not read back exactly")
        capture = radio.begin_metadata_capture(
            plan.victim_samples_per_frame,
            kernel_buffers=plan.kernel_buffers,
            ddr_burst_bytes=plan.victim_iq_bytes,
        )
        connection.send(
            {
                "state": "refill-started",
                "requested_bytes": capture.ddr_burst_requested_bytes,
                "admitted_bytes": capture.ddr_burst_admitted_bytes,
                "frames": capture.ddr_burst_frames,
            }
        )
        capture.read_block()
        connection.send({"state": "unexpected-completion"})
    except BaseException as error:
        with suppress(BaseException):
            connection.send({"state": "failed", "error": f"{type(error).__name__}: {error}"})
    finally:
        if capture is not None:
            capture.close()
        if radio is not None:
            radio.close()
        connection.close()
        gc.collect()


def _probe_from_ladder(mode: str, report: Any) -> DdrRecoveryProbe:
    if report.failures or len(report.cells) != 1:
        detail = "; ".join(f"{item.error_type}: {item.message}" for item in report.failures)
        raise DdrRecoveryError(f"post-disconnect {mode} probe failed: {detail or 'no cell'}")
    cell = report.cells[0]
    return DdrRecoveryProbe(
        mode=mode,
        samples_per_frame=cell.samples_per_channel,
        requested_frames=cell.requested_frames,
        observed_frames=cell.observed_frames,
        missing_sample_count=cell.missing_sample_count,
        gap_count=cell.gap_count,
        overflow_count=cell.overflow_count,
        observed_fraction=cell.observed_fraction,
        elapsed_seconds=cell.elapsed_seconds,
        passed=cell.passed,
    )


def _validate_initial(plan: DdrRecoveryPlan, health: MetadataHealth) -> None:
    if health.serial != plan.serial:
        raise DdrRecoveryError("remote serial does not match the recovery plan")
    if health.firmware_version != plan.expected_firmware:
        raise DdrRecoveryError("remote firmware does not match the recovery profile")
    _validate_idle(health)


def _validate_checkpoint(initial: MetadataHealth, health: MetadataHealth) -> None:
    if health.serial != initial.serial or health.firmware_version != initial.firmware_version:
        raise DdrRecoveryError("radio identity changed during DDR recovery")
    _validate_process_identity(initial, health)
    _validate_idle(health)


def _validate_process_identity(initial: MetadataHealth, health: MetadataHealth) -> None:
    if health.boot_id != initial.boot_id:
        raise DdrRecoveryError("Linux boot ID changed during DDR recovery")
    if health.iiod_generation != initial.iiod_generation:
        raise DdrRecoveryError("iiOD generation changed during DDR recovery")
    if health.iiod_pid != initial.iiod_pid or health.iiod_start_ticks != initial.iiod_start_ticks:
        raise DdrRecoveryError("iiOD process changed during DDR recovery")


def _validate_idle(health: MetadataHealth) -> None:
    if health.active_rx_buffers or health.active_tx_buffers:
        raise DdrRecoveryError("IIO buffer ownership leaked during DDR recovery")
    if health.tandem_state != 0:
        raise DdrRecoveryError("tandem ownership leaked during DDR recovery")
    if health.fault_flags or health.overflow_count:
        raise DdrRecoveryError("tandem fault or overflow remained during DDR recovery")
    if not health.tx_safe:
        raise DdrRecoveryError("radio TX state is not safe")


def write_ddr_recovery_report(path: Path, report: DdrRecoveryReport) -> None:
    """Atomically create a private canonical JSON recovery report."""

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
        if destination.exists():
            raise DdrRecoveryError("refusing to replace an existing DDR recovery report")
        os.link(temporary, destination)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
