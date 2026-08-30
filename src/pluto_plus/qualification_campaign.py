"""Release-candidate authoritative gain-timeline hardware campaign."""

from __future__ import annotations

import ipaddress
import uuid
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, field_validator, model_validator

from pluto_plus.metadata_ladder import (
    MetadataContinuityLadderReport,
    run_metadata_continuity_ladder,
)
from pluto_plus.models import ApiModel
from pluto_plus.radio_lock import acquire_radio_lock
from pluto_plus.release_candidate import (
    FileIdentity,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseCandidateRamReceipt,
    RuntimeObservation,
    load_private_contract,
    model_file_identity,
    write_private_contract,
)
from pluto_plus.release_candidate_lifecycle import (
    ReleaseCandidateLifecycleError,
    execute_candidate_ram,
    validate_password_file,
)
from pluto_plus.release_candidate_linux import LinuxReleaseCandidateBackend

QUALIFICATION_PLAN_SCHEMA = "pluto-plus-utils.gain-timeline-qualification-plan.v1"
QUALIFICATION_REPORT_SCHEMA = "pluto-plus-utils.gain-timeline-qualification-report.v1"
PHYSICAL_LAN_LOCK_KEY = "__global_physical_lan_192.168.1.0_24__"
DEFAULT_SAMPLE_RATE_HZ = 20_000_000
DEFAULT_SAMPLES_PER_CHANNEL = 262_144
REGRESSION_FRAME_COUNTS = (200, 600)
REGRESSION_REPETITIONS = 2
SOAK_FRAME_COUNT = 5_000

QualificationTransport = Literal["usb", "physical-ip"]
QualificationBuffering = Literal["ordinary", "ring-200mb"]
QualificationMode = Literal["hold", "auto"]
QualificationLayout = Literal["single-rx0", "dual"]
QualificationTier = Literal["regression", "soak"]


class QualificationCampaignError(RuntimeError):
    """The candidate campaign failed or could not prove cleanup."""

    def __init__(
        self,
        message: str,
        *,
        report: GainTimelineQualificationReport | None = None,
        report_sha256: str | None = None,
    ) -> None:
        super().__init__(message)
        self.report = report
        self.report_sha256 = report_sha256


class GainTimelineQualificationPlan(ApiModel):
    schema_id: Literal[
        "pluto-plus-utils.gain-timeline-qualification-plan.v1"
    ] = Field("pluto-plus-utils.gain-timeline-qualification-plan.v1", alias="schema")
    schema_version: Literal[1] = 1
    campaign_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    created_at: datetime
    operation_plan: FileIdentity
    candidate_plan: FileIdentity
    serial: str = Field(min_length=1, max_length=128)
    physical_ip: str
    report_path: Path
    sample_rate_hz: Literal[20_000_000] = 20_000_000
    rf_bandwidth_hz: Literal[20_000_000] = 20_000_000
    samples_per_channel: Literal[262_144] = 262_144
    kernel_buffers: Literal[4] = 4
    ddr_ring_iq_bytes: Literal[200_000_000] = 200_000_000
    regression_frame_counts: tuple[Literal[200], Literal[600]] = (200, 600)
    regression_repetitions: Literal[2] = 2
    soak_frame_count: Literal[5_000] = 5_000
    ordinary_layouts: tuple[Literal["single-rx0"], Literal["dual"]] = (
        "single-rx0",
        "dual",
    )
    ring_layouts: tuple[Literal["single-rx0"]] = ("single-rx0",)
    confirmation_phrase: str
    hardware_accessed: Literal[False] = False

    @field_validator("created_at")
    @classmethod
    def validate_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("qualification creation time must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator("physical_ip")
    @classmethod
    def validate_physical_ip(cls, value: str) -> str:
        try:
            address = ipaddress.ip_address(value)
        except ValueError as error:
            raise ValueError("physical qualification endpoint must be literal IPv4") from error
        if address.version != 4 or address not in ipaddress.ip_network("192.168.1.0/24"):
            raise ValueError("physical qualification endpoint must be within 192.168.1.0/24")
        if address == ipaddress.ip_address("192.168.1.0") or address == ipaddress.ip_address(
            "192.168.1.255"
        ):
            raise ValueError("physical qualification endpoint must be a host address")
        return str(address)

    @field_validator("report_path")
    @classmethod
    def validate_report_path(cls, value: Path) -> Path:
        if not value.is_absolute() or ".." in value.parts:
            raise ValueError("qualification report path must be absolute and normalized")
        return value

    @model_validator(mode="after")
    def validate_relationships(self) -> GainTimelineQualificationPlan:
        expected = f"QUALIFY GAIN TIMELINE {self.serial} {self.campaign_id}"
        if self.confirmation_phrase != expected:
            raise ValueError(f"qualification confirmation must be exactly {expected!r}")
        if self.report_path in {self.operation_plan.path, self.candidate_plan.path}:
            raise ValueError("qualification report must not overwrite an input contract")
        return self


class GainTimelineQualificationCase(ApiModel):
    transport: QualificationTransport
    buffering: QualificationBuffering
    tandem_mode: QualificationMode
    layout: QualificationLayout
    tier: QualificationTier
    frames: int = Field(ge=200, le=SOAK_FRAME_COUNT)
    repetition: int = Field(ge=1, le=REGRESSION_REPETITIONS)

    @model_validator(mode="after")
    def validate_supported_case(self) -> GainTimelineQualificationCase:
        if self.buffering == "ring-200mb" and self.layout != "single-rx0":
            raise ValueError("DDR ring qualification supports only the single-RX layout")
        if self.tier == "regression":
            valid_tier = (
                self.frames in REGRESSION_FRAME_COUNTS
                and 1 <= self.repetition <= REGRESSION_REPETITIONS
            )
        else:
            valid_tier = self.frames == SOAK_FRAME_COUNT and self.repetition == 1
        if not valid_tier:
            raise ValueError("qualification tier/frame/repetition tuple is not canonical")
        return self


class GainTimelineQualificationCaseResult(ApiModel):
    case: GainTimelineQualificationCase
    report: MetadataContinuityLadderReport | None = None
    error: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def validate_result(self) -> GainTimelineQualificationCaseResult:
        if (self.report is None) == (self.error is None):
            raise ValueError("qualification case requires exactly one report or error")
        return self


class GainTimelineQualificationReport(ApiModel):
    schema_id: Literal[
        "pluto-plus-utils.gain-timeline-qualification-report.v1"
    ] = Field("pluto-plus-utils.gain-timeline-qualification-report.v1", alias="schema")
    schema_version: Literal[1] = 1
    campaign_plan: FileIdentity
    started_at: datetime
    completed_at: datetime
    outcome: Literal["pass", "failed", "unknown"]
    planned_case_count: Literal[60] = 60
    boot_receipt: ReleaseCandidateRamReceipt | None = None
    cases: tuple[GainTimelineQualificationCaseResult, ...] = ()
    restored_runtime: RuntimeObservation | None = None
    persistent_qspi_unchanged: bool = False
    errors: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_outcome(self) -> GainTimelineQualificationReport:
        if self.completed_at < self.started_at:
            raise ValueError("qualification completion precedes its start")
        if self.outcome == "pass":
            if (
                self.boot_receipt is None
                or self.boot_receipt.outcome != "pass"
                or len(self.cases) != self.planned_case_count
                or tuple(item.case for item in self.cases) != qualification_cases()
                or any(item.report is None for item in self.cases)
                or self.restored_runtime is None
                or not self.persistent_qspi_unchanged
                or self.errors
            ):
                raise ValueError("passing qualification lacks complete evidence or cleanup")
        elif not self.errors:
            raise ValueError("non-passing qualification must explain its failure")
        if self.restored_runtime is not None and not self.persistent_qspi_unchanged:
            raise ValueError("restored runtime must prove unchanged persistent QSPI")
        return self


class QualificationCampaignBackend(Protocol):
    def radio_lock(self, serial: str) -> AbstractContextManager[None]: ...

    def physical_lan_lock(self) -> AbstractContextManager[None]: ...

    def boot_candidate(
        self,
        operation_path: Path,
        *,
        password_path: Path,
        confirmation: str,
    ) -> tuple[ReleaseCandidateRamReceipt, str]: ...

    def restore_persistent(
        self,
        receipt: ReleaseCandidateRamReceipt,
        *,
        password_path: Path,
    ) -> RuntimeObservation: ...


class LinuxQualificationCampaignBackend:
    """Linux lifecycle adapter with shared per-radio and physical-LAN locks."""

    def __init__(
        self,
        *,
        operation: ReleaseCandidateOperationPlan,
        state_root: Path,
        radio_lock_root: Path,
        tool_repository: str,
        tool_version: str,
        tool_source_commit: str,
        timeout_s: float,
    ) -> None:
        self.operation = operation
        self.state_root = state_root
        self.radio_lock_root = radio_lock_root
        self.tool_repository = tool_repository
        self.tool_version = tool_version
        self.tool_source_commit = tool_source_commit
        self.timeout_s = timeout_s
        self._device_backend: LinuxReleaseCandidateBackend | None = None

    @contextmanager
    def radio_lock(self, serial: str) -> Iterator[None]:
        with acquire_radio_lock(serial, root=self.radio_lock_root):
            yield

    @contextmanager
    def physical_lan_lock(self) -> Iterator[None]:
        with acquire_radio_lock(PHYSICAL_LAN_LOCK_KEY, root=self.radio_lock_root):
            yield

    def boot_candidate(
        self,
        operation_path: Path,
        *,
        password_path: Path,
        confirmation: str,
    ) -> tuple[ReleaseCandidateRamReceipt, str]:
        self._device_backend = LinuxReleaseCandidateBackend(
            state_root=self.state_root,
            timeout_s=self.timeout_s,
            radio_lock_root=self.radio_lock_root,
            _prelocked_radio_serial=self.operation.target.serial,
        )
        return execute_candidate_ram(
            operation_path,
            password_path=password_path,
            confirmation=confirmation,
            backend=self._device_backend,
            tool_repository=self.tool_repository,
            tool_version=self.tool_version,
            tool_source_commit=self.tool_source_commit,
            timeout_s=self.timeout_s,
        )

    def restore_persistent(
        self,
        receipt: ReleaseCandidateRamReceipt,
        *,
        password_path: Path,
    ) -> RuntimeObservation:
        if receipt.pre_runtime is None or receipt.post_runtime is None:
            raise QualificationCampaignError(
                "candidate receipt lacks runtimes required for persistent restore"
            )
        backend = self._device_backend or LinuxReleaseCandidateBackend(
            state_root=self.state_root,
            timeout_s=self.timeout_s,
            radio_lock_root=self.radio_lock_root,
            _prelocked_radio_serial=self.operation.target.serial,
        )
        password = validate_password_file(password_path)
        return backend.restore_persistent_runtime(
            self.operation.target,
            candidate_runtime=receipt.post_runtime,
            expected_firmware=receipt.pre_runtime.firmware_version,
            password=password,
            ssh_host=self.operation.ssh_host,
            timeout_s=self.timeout_s,
        )


def prepare_gain_timeline_qualification(
    operation_path: Path,
    *,
    physical_ip: str,
    report_path: Path,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    campaign_id_factory: Callable[[], str] = lambda: uuid.uuid4().hex,
) -> GainTimelineQualificationPlan:
    """Build a read-only, single-radio campaign from immutable candidate inputs."""

    selected_operation = operation_path.expanduser().absolute()
    operation = load_private_contract(selected_operation, ReleaseCandidateOperationPlan)
    candidate = load_private_contract(operation.candidate_plan.path, ReleaseCandidatePlan)
    if model_file_identity(operation.candidate_plan.path, candidate) != operation.candidate_plan:
        raise QualificationCampaignError("operation does not bind current candidate-plan bytes")
    if candidate.expected_runtime.metadata_abi != "frame-metadata-v4":
        raise QualificationCampaignError("gain-timeline qualification requires metadata ABI 4")
    if operation.receipt_path.exists() or operation.receipt_path.is_symlink():
        raise QualificationCampaignError("candidate RAM receipt destination already exists")
    selected_report = report_path.expanduser().absolute()
    if selected_report.exists() or selected_report.is_symlink():
        raise QualificationCampaignError("qualification report destination already exists")
    campaign_id = campaign_id_factory()
    return GainTimelineQualificationPlan(
        schema="pluto-plus-utils.gain-timeline-qualification-plan.v1",
        campaign_id=campaign_id,
        created_at=now(),
        operation_plan=model_file_identity(selected_operation, operation),
        candidate_plan=operation.candidate_plan,
        serial=operation.target.serial,
        physical_ip=physical_ip,
        report_path=selected_report,
        confirmation_phrase=(
            f"QUALIFY GAIN TIMELINE {operation.target.serial} {campaign_id}"
        ),
    )


def qualification_cases() -> tuple[GainTimelineQualificationCase, ...]:
    """Return the frozen 60-cell release matrix in deterministic order."""

    cases: list[GainTimelineQualificationCase] = []
    tiers: tuple[tuple[QualificationTier, int, int], ...] = tuple(
        ("regression", frames, repetition)
        for frames in REGRESSION_FRAME_COUNTS
        for repetition in range(1, REGRESSION_REPETITIONS + 1)
    ) + (("soak", SOAK_FRAME_COUNT, 1),)
    for transport in ("usb", "physical-ip"):
        for buffering in ("ordinary", "ring-200mb"):
            for tandem_mode in ("hold", "auto"):
                layouts: tuple[QualificationLayout, ...] = (
                    ("single-rx0", "dual")
                    if buffering == "ordinary"
                    else ("single-rx0",)
                )
                for layout in layouts:
                    for tier, frames, repetition in tiers:
                        cases.append(
                            GainTimelineQualificationCase(
                                transport=transport,
                                buffering=buffering,
                                tandem_mode=tandem_mode,
                                layout=layout,
                                tier=tier,
                                frames=frames,
                                repetition=repetition,
                            )
                        )
    return tuple(cases)


def execute_gain_timeline_qualification(
    plan_path: Path,
    *,
    password_path: Path,
    confirmation: str,
    backend: QualificationCampaignBackend,
    ladder_runner: Callable[..., MetadataContinuityLadderReport] = (
        run_metadata_continuity_ladder
    ),
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> tuple[GainTimelineQualificationReport, str]:
    """RAM-boot, qualify, and always restore one exact radio to persistent QSPI."""

    selected_plan = plan_path.expanduser().absolute()
    plan = load_private_contract(selected_plan, GainTimelineQualificationPlan)
    if confirmation != plan.confirmation_phrase:
        raise QualificationCampaignError(
            f"confirmation must be exactly {plan.confirmation_phrase!r}"
        )
    operation = load_private_contract(plan.operation_plan.path, ReleaseCandidateOperationPlan)
    candidate = load_private_contract(plan.candidate_plan.path, ReleaseCandidatePlan)
    if (
        model_file_identity(plan.operation_plan.path, operation) != plan.operation_plan
        or model_file_identity(plan.candidate_plan.path, candidate) != plan.candidate_plan
        or operation.candidate_plan != plan.candidate_plan
        or operation.target.serial != plan.serial
        or candidate.expected_runtime.metadata_abi != "frame-metadata-v4"
    ):
        raise QualificationCampaignError("qualification inputs changed or are inconsistent")
    if plan.report_path.exists() or plan.report_path.is_symlink():
        raise QualificationCampaignError("qualification report destination already exists")

    started_at = now()
    errors: list[str] = []
    results: list[GainTimelineQualificationCaseResult] = []
    boot_receipt: ReleaseCandidateRamReceipt | None = None
    restored: RuntimeObservation | None = None
    with backend.radio_lock(plan.serial):
        try:
            boot_receipt, _boot_digest = backend.boot_candidate(
                plan.operation_plan.path,
                password_path=password_path,
                confirmation=operation.confirmation_phrase,
            )
            if boot_receipt.outcome != "pass" or boot_receipt.post_runtime is None:
                raise QualificationCampaignError("candidate RAM boot did not pass")
            usb_cases = tuple(item for item in qualification_cases() if item.transport == "usb")
            ip_cases = tuple(
                item for item in qualification_cases() if item.transport == "physical-ip"
            )
            if not _run_cases(
                usb_cases,
                plan=plan,
                runner=ladder_runner,
                results=results,
                errors=errors,
            ):
                raise QualificationCampaignError(errors[-1])
            with backend.physical_lan_lock():
                if not _run_cases(
                    ip_cases,
                    plan=plan,
                    runner=ladder_runner,
                    results=results,
                    errors=errors,
                ):
                    raise QualificationCampaignError(errors[-1])
        except ReleaseCandidateLifecycleError as error:
            boot_receipt = error.receipt
            errors.append(f"{type(error).__name__}: {error}")
        except Exception as error:
            errors.append(f"{type(error).__name__}: {error}")
        finally:
            if boot_receipt is not None and _receipt_is_candidate_runtime(
                boot_receipt, candidate
            ):
                try:
                    restored = backend.restore_persistent(
                        boot_receipt,
                        password_path=password_path,
                    )
                except Exception as error:
                    errors.append(f"persistent restore: {type(error).__name__}: {error}")

    qspi_unchanged = bool(
        restored is not None
        and boot_receipt is not None
        and boot_receipt.pre_runtime is not None
        and restored.qspi == boot_receipt.pre_runtime.qspi
    )
    passed = (
        boot_receipt is not None
        and boot_receipt.outcome == "pass"
        and len(results) == len(qualification_cases())
        and all(item.report is not None for item in results)
        and restored is not None
        and qspi_unchanged
        and not errors
    )
    outcome: Literal["pass", "failed", "unknown"] = (
        "pass" if passed else "failed" if restored is not None else "unknown"
    )
    if not passed and not errors:
        errors.append("qualification did not produce complete passing evidence")
    report = GainTimelineQualificationReport(
        schema="pluto-plus-utils.gain-timeline-qualification-report.v1",
        campaign_plan=model_file_identity(selected_plan, plan),
        started_at=started_at,
        completed_at=now(),
        outcome=outcome,
        boot_receipt=boot_receipt,
        cases=tuple(results),
        restored_runtime=restored,
        persistent_qspi_unchanged=qspi_unchanged,
        errors=tuple(errors),
    )
    identity = write_private_contract(plan.report_path, report)
    if not passed:
        raise QualificationCampaignError(
            errors[-1],
            report=report,
            report_sha256=identity.sha256,
        )
    return report, identity.sha256


def _run_cases(
    cases: tuple[GainTimelineQualificationCase, ...],
    *,
    plan: GainTimelineQualificationPlan,
    runner: Callable[..., MetadataContinuityLadderReport],
    results: list[GainTimelineQualificationCaseResult],
    errors: list[str],
) -> bool:
    for case in cases:
        try:
            report = runner(
                uri="usb:" if case.transport == "usb" else f"ip:{plan.physical_ip}",
                serial=plan.serial,
                sample_rate_hz=plan.sample_rate_hz,
                rf_bandwidth_hz=plan.rf_bandwidth_hz,
                metadata_abi=4,
                channels=(0,) if case.layout == "single-rx0" else (0, 1),
                samples_per_channel=(plan.samples_per_channel,),
                frames=case.frames,
                kernel_buffers=plan.kernel_buffers,
                ddr_ring_bytes=(
                    plan.ddr_ring_iq_bytes if case.buffering == "ring-200mb" else 0
                ),
                tandem_mode=case.tandem_mode,
                acceptance_mode="continuity",
            )
            _validate_case_report(case, report, plan)
            results.append(GainTimelineQualificationCaseResult(case=case, report=report))
        except Exception as error:
            message = f"{_case_name(case)}: {type(error).__name__}: {error}"
            results.append(GainTimelineQualificationCaseResult(case=case, error=message))
            errors.append(message)
            return False
    return True


def _validate_case_report(
    case: GainTimelineQualificationCase,
    report: MetadataContinuityLadderReport,
    plan: GainTimelineQualificationPlan,
) -> None:
    expected_ring = plan.ddr_ring_iq_bytes if case.buffering == "ring-200mb" else 0
    if (
        report.serial != plan.serial
        or report.metadata_abi != 4
        or report.sample_rate_hz != plan.sample_rate_hz
        or report.rf_bandwidth_hz != plan.rf_bandwidth_hz
        or report.channels != ((0,) if case.layout == "single-rx0" else (0, 1))
        or report.tandem_mode != case.tandem_mode
        or report.ddr_ring_requested_iq_bytes != expected_ring
        or report.failures
        or not report.original_settings_restored
        or len(report.cells) != 1
    ):
        raise QualificationCampaignError("metadata ladder identity or closure is not exact")
    cell = report.cells[0]
    if (
        cell.requested_frames != case.frames
        or cell.observed_frames != case.frames
        or cell.tandem_metadata_frames != case.frames
        or cell.authoritative_gain_timeline_frames != case.frames
        or cell.missing_sample_count
        or cell.gap_count
        or cell.overflow_count
        or not cell.passed
    ):
        raise QualificationCampaignError("metadata ladder is not gapless and authoritative")
    if expected_ring and (
        cell.ddr_ring_status is None or cell.ddr_ring_status.version != 2
    ):
        raise QualificationCampaignError("ABI4 DDR ring case lacks terminal status v2")


def _receipt_is_candidate_runtime(
    receipt: ReleaseCandidateRamReceipt,
    candidate: ReleaseCandidatePlan,
) -> bool:
    return bool(
        receipt.post_runtime is not None
        and receipt.pre_runtime is not None
        and receipt.post_runtime.firmware_version
        == candidate.expected_runtime.firmware_version
        and receipt.post_runtime.qspi == receipt.pre_runtime.qspi
    )


def _case_name(case: GainTimelineQualificationCase) -> str:
    return (
        f"{case.transport}/{case.buffering}/{case.tandem_mode}/{case.layout}/"
        f"{case.tier}-{case.frames}-r{case.repetition}"
    )
