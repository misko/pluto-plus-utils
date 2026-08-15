"""Application composition shared by API, CLI-facing daemon, and tests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from collections.abc import Callable
from contextlib import suppress
from pathlib import Path
from typing import BinaryIO

from pluto_plus.analysis import AnalysisService
from pluto_plus.artifacts import verify_artifact
from pluto_plus.catalog import Catalog
from pluto_plus.controller import RadioController, SpectrumSubscription
from pluto_plus.doctor import CANONICAL_POLICY, diagnose_radio
from pluto_plus.errors import (
    ArtifactNotFoundError,
    FirmwareObjectNotFoundError,
    FirmwareUnavailableError,
    RadioBusyError,
    RadioNotFoundError,
)
from pluto_plus.firmware import (
    FirmwareExecutionError,
    FirmwareImageError,
    FirmwareManager,
    FirmwareMode,
    FirmwarePlan,
    FirmwareReceipt,
    LocalFirmwareFilesystem,
    PlannedFirmware,
    RadioFirmwareIdentity,
)
from pluto_plus.hardware.base import RadioDevice
from pluto_plus.models import (
    AnalysisRequest,
    AnalysisResult,
    ArtifactSummary,
    DoctorReport,
    FirmwareImageSummary,
    RadioSnapshot,
    RadioState,
    ScanJob,
    ScanRequest,
    ScanResult,
    SettingsPatch,
    StreamJob,
    StreamRequest,
)


class PlutoService:
    def __init__(
        self,
        state_root: Path,
        devices: tuple[RadioDevice, ...],
        *,
        firmware_manager: FirmwareManager | None = None,
        capture_free_bytes: Callable[[Path], int] | None = None,
        capture_reserve_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.state_root = state_root
        state_root.mkdir(parents=True, exist_ok=True)
        self._state_lock = _acquire_state_lock(state_root)
        self._controllers: dict[str, RadioController] = {}
        try:
            _recover_incomplete_files(state_root)
            self.catalog = Catalog(state_root / "catalog.sqlite3")
            self.catalog.recover_interrupted_jobs()
            _reconcile_completed_records(state_root, self.catalog)
            self.analysis = AnalysisService(state_root / "analysis")
            self.firmware_manager = firmware_manager
            self._firmware_filesystem = LocalFirmwareFilesystem()
            self._firmware_images: dict[str, tuple[FirmwareImageSummary, Path]] = {}
            self._firmware_plans: dict[str, FirmwarePlan] = {}
            self._firmware_receipts: dict[str, FirmwareReceipt] = {}
            for device in devices:
                controller = RadioController(
                    device,
                    state_root / "captures",
                    self.catalog,
                    capture_free_bytes=capture_free_bytes,
                    capture_reserve_bytes=capture_reserve_bytes,
                )
                if controller.radio_id in self._controllers:
                    controller.close()
                    raise ValueError(f"duplicate radio id: {controller.radio_id}")
                self._controllers[controller.radio_id] = controller
        except BaseException:
            for controller in self._controllers.values():
                with suppress(BaseException):
                    controller.close()
            _release_state_lock(self._state_lock)
            raise

    def list_radios(self) -> list[RadioSnapshot]:
        return [self._controllers[key].snapshot() for key in sorted(self._controllers)]

    def get_radio(self, radio_id: str) -> RadioSnapshot:
        return self._controller(radio_id).snapshot()

    def doctor(self, radio_id: str | None = None) -> list[DoctorReport] | DoctorReport:
        """Run fresh, read-only canonical setup checks for one or all managed radios."""

        def report(controller: RadioController) -> DoctorReport:
            return diagnose_radio(
                controller.snapshot(),
                controller.diagnostic_facts(),
                firmware_helper_available=self.firmware_manager is not None,
            )

        if radio_id is not None:
            return report(self._controller(radio_id))
        return [report(self._controllers[key]) for key in sorted(self._controllers)]

    def update_settings(self, radio_id: str, patch: SettingsPatch) -> RadioSnapshot:
        return self._controller(radio_id).update_settings(patch)

    def recover_radio(self, radio_id: str) -> RadioSnapshot:
        return self._controller(radio_id).recover()

    def start_stream(self, radio_id: str, request: StreamRequest) -> StreamJob:
        return self._controller(radio_id).start_stream(request)

    def stop_stream(self, radio_id: str) -> StreamJob:
        return self._controller(radio_id).stop_stream()

    def list_jobs(self, radio_id: str | None = None) -> list[StreamJob]:
        if radio_id is not None:
            return self._controller(radio_id).list_jobs()
        managed = set(self._controllers)
        return [job for job in self.catalog.list_stream_jobs() if job.radio_id in managed]

    def get_job(self, job_id: str) -> StreamJob:
        job = self.catalog.get_stream_job(job_id)
        if job is not None and job.radio_id in self._controllers:
            return job
        raise KeyError(f"unknown stream job: {job_id}")

    def subscribe(self, radio_id: str) -> SpectrumSubscription:
        return self._controller(radio_id).broker.subscribe()

    def start_scan(self, radio_id: str, request: ScanRequest) -> ScanJob:
        return self._controller(radio_id).start_scan(request)

    def stop_scan(self, radio_id: str) -> ScanJob:
        return self._controller(radio_id).stop_scan()

    def list_scan_jobs(self, radio_id: str | None = None) -> list[ScanJob]:
        if radio_id is not None:
            return self._controller(radio_id).list_scan_jobs()
        managed = set(self._controllers)
        return [job for job in self.catalog.list_scan_jobs() if job.radio_id in managed]

    def get_scan_job(self, job_id: str) -> ScanJob:
        job = self.catalog.get_scan_job(job_id)
        if job is not None and job.radio_id in self._controllers:
            return job
        raise KeyError(f"unknown scan job: {job_id}")

    def list_scans(self) -> list[ScanResult]:
        return self.catalog.list_scans()

    def get_scan(self, scan_id: str) -> ScanResult:
        scan = self.catalog.get_scan(scan_id)
        if scan is None:
            raise ArtifactNotFoundError(f"unknown scan: {scan_id}")
        return scan

    def list_artifacts(self) -> list[ArtifactSummary]:
        return self.catalog.list_artifacts()

    def get_artifact(self, artifact_id: str) -> ArtifactSummary:
        artifact = self.catalog.get_artifact(artifact_id)
        if artifact is None:
            raise ArtifactNotFoundError(f"unknown artifact: {artifact_id}")
        return artifact

    def run_analysis(self, request: AnalysisRequest) -> AnalysisResult:
        artifact = self.get_artifact(request.artifact_id)
        if not verify_artifact(artifact):
            raise ValueError("capture artifact digest verification failed")
        result = self.analysis.analyze(artifact, request.analyzer, request.parameters)
        self.catalog.put_analysis(result)
        return result

    def list_analyses(self, artifact_id: str | None = None) -> list[AnalysisResult]:
        return self.catalog.list_analyses(artifact_id)

    def get_analysis(self, analysis_id: str) -> AnalysisResult:
        result = self.catalog.get_analysis(analysis_id)
        if result is None:
            raise ArtifactNotFoundError(f"unknown analysis: {analysis_id}")
        return result

    def firmware_status(self) -> dict[str, object]:
        return {
            "available": self.firmware_manager is not None,
            "modes": tuple(mode.value for mode in FirmwareMode),
            "maximum_upload_bytes": 128 * 1024 * 1024,
            "safety": "plan-token-execute",
        }

    def stage_firmware_image(self, filename: str, data: bytes) -> FirmwareImageSummary:
        self._require_firmware()
        if Path(filename).name != filename or filename in {"", ".", ".."}:
            raise ValueError("firmware filename must be one plain basename")
        if Path(filename).suffix.lower() not in {".dfu", ".frm"}:
            raise ValueError("firmware upload must be a .dfu or .frm file")
        if not data:
            raise ValueError("firmware upload cannot be empty")
        if len(data) > 128 * 1024 * 1024:
            raise ValueError("firmware upload exceeds 128 MiB")
        digest = hashlib.sha256(data).hexdigest()
        destination = self.state_root / "firmware" / "incoming" / digest / filename
        try:
            existing = destination.read_bytes()
        except FileNotFoundError:
            self._firmware_filesystem.write_atomic(destination, data)
        else:
            if existing != data:
                raise RuntimeError("content-addressed firmware upload collision")
        summary = FirmwareImageSummary(
            image_id=digest,
            original_name=filename,
            sha256=digest,
            size=len(data),
        )
        self._firmware_images[digest] = (summary, destination)
        return summary

    def list_firmware_images(self) -> list[FirmwareImageSummary]:
        self._require_firmware()
        return sorted(
            (item[0] for item in self._firmware_images.values()),
            key=lambda item: item.original_name,
        )

    def create_firmware_plan(
        self,
        radio_id: str,
        image_id: str,
        mode: FirmwareMode,
        *,
        expected_firmware_version: str | None = None,
    ) -> PlannedFirmware:
        manager = self._require_firmware()
        controller = self._controller(radio_id)
        snapshot = controller.snapshot()
        if snapshot.state is not RadioState.READY:
            raise RadioBusyError(f"radio cannot plan firmware while {snapshot.state}")
        if mode is FirmwareMode.VOLATILE_DFU:
            supported = snapshot.capabilities.supports_volatile_firmware
        else:
            supported = snapshot.capabilities.supports_persistent_firmware
        if not supported:
            raise FirmwareUnavailableError(
                f"radio {radio_id!r} does not advertise support for {mode.value}"
            )
        identity = snapshot.identity
        if identity.usb_path is None or identity.firmware_version is None:
            raise FirmwareUnavailableError(
                "firmware planning requires an attested USB path and firmware version"
            )
        try:
            _summary, source = self._firmware_images[image_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(
                f"unknown firmware image: {image_id}"
            ) from error
        planned = manager.create_plan(
            RadioFirmwareIdentity(
                serial=identity.serial,
                usb_sysfs_path=identity.usb_path,
                observed_firmware=identity.firmware_version,
            ),
            source,
            mode,
            expected_firmware=expected_firmware_version,
        )
        self._firmware_plans[planned.plan.plan_id] = planned.plan
        return planned

    def create_canonical_firmware_plan(
        self,
        radio_id: str,
        image_id: str,
        mode: FirmwareMode,
    ) -> PlannedFirmware:
        """Plan only the immutable image selected by the shipped doctor policy."""

        try:
            summary, _source = self._firmware_images[image_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(
                f"unknown firmware image: {image_id}"
            ) from error
        if summary.sha256 != CANONICAL_POLICY.asset_sha256:
            raise FirmwareImageError(
                "uploaded image SHA-256 does not match the selected canonical release: "
                f"expected {CANONICAL_POLICY.asset_sha256}, got {summary.sha256}"
            )
        return self.create_firmware_plan(
            radio_id,
            image_id,
            mode,
            expected_firmware_version=CANONICAL_POLICY.device_firmware,
        )

    def execute_firmware_plan(
        self, plan_id: str, confirmation_token: str
    ) -> FirmwareReceipt:
        manager = self._require_firmware()
        try:
            plan = self._firmware_plans[plan_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(f"unknown firmware plan: {plan_id}") from error
        controller = self._controller_for_serial(plan.radio.serial)
        try:
            receipt = manager.execute(
                plan,
                confirmation_token,
                before_mutation=controller.prepare_firmware_mutation,
                after_mutation=controller.recover_after_firmware_mutation,
            )
        except FirmwareExecutionError as error:
            self._firmware_receipts[error.receipt.receipt_id] = error.receipt
            raise
        self._firmware_receipts[receipt.receipt_id] = receipt
        return receipt

    def list_firmware_receipts(self) -> list[FirmwareReceipt]:
        self._require_firmware()
        return sorted(
            self._firmware_receipts.values(),
            key=lambda item: item.started_at,
            reverse=True,
        )

    def close(self) -> None:
        errors: list[BaseException] = []
        for controller in self._controllers.values():
            try:
                controller.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            details = "; ".join(f"{type(error).__name__}: {error}" for error in errors)
            raise RuntimeError(f"one or more radios failed to close: {details}") from errors[0]
        _release_state_lock(self._state_lock)

    def _controller(self, radio_id: str) -> RadioController:
        try:
            return self._controllers[radio_id]
        except KeyError as error:
            raise RadioNotFoundError(f"unknown radio: {radio_id}") from error

    def _require_firmware(self) -> FirmwareManager:
        if self.firmware_manager is None:
            raise FirmwareUnavailableError(
                "firmware operations require an explicitly configured privileged executor"
            )
        return self.firmware_manager

    def _controller_for_serial(self, serial: str) -> RadioController:
        matches = [
            controller
            for controller in self._controllers.values()
            if controller.snapshot().identity.serial == serial
        ]
        if len(matches) != 1:
            raise RadioNotFoundError(
                f"expected exactly one managed radio with serial {serial!r}; found {len(matches)}"
            )
        return matches[0]


def _recover_incomplete_files(state_root: Path) -> None:
    """Preserve incomplete crash remnants as failed evidence before accepting work."""

    partial_root = state_root / "captures" / ".partial"
    failed_root = state_root / "captures" / ".failed"
    if partial_root.is_dir():
        failed_root.mkdir(parents=True, exist_ok=True)
        for partial in sorted(partial_root.iterdir()):
            destination = _unused_recovery_path(failed_root / partial.name)
            if partial.is_dir():
                failure = partial / "failure.json"
                if not failure.exists():
                    with failure.open("x", encoding="utf-8") as stream:
                        json.dump(
                            {
                                "type": "Interrupted",
                                "message": "daemon restarted before capture finalization",
                            },
                            stream,
                            sort_keys=True,
                        )
                        stream.write("\n")
                        stream.flush()
                        os.fsync(stream.fileno())
            os.replace(partial, destination)
        _fsync_directory(failed_root)
        _fsync_directory(partial_root)
        _fsync_directory(failed_root.parent)

    scans_root = state_root / "scans"
    if scans_root.is_dir():
        failed_scans = scans_root / ".failed"
        for partial in sorted(scans_root.glob("*.json.partial")):
            failed_scans.mkdir(parents=True, exist_ok=True)
            destination = _unused_recovery_path(failed_scans / partial.name)
            os.replace(partial, destination)
        if failed_scans.exists():
            _fsync_directory(failed_scans)
            _fsync_directory(scans_root)


def _reconcile_completed_records(state_root: Path, catalog: Catalog) -> None:
    """Index atomically committed files left behind before their SQLite commit."""

    scans_root = state_root / "scans"
    if scans_root.is_dir():
        for path in sorted(scans_root.glob("*.json")):
            try:
                result = ScanResult.model_validate_json(path.read_text())
            except (OSError, ValueError):
                continue
            if Path(result.path).resolve() != path.resolve():
                continue
            if catalog.get_scan(result.scan_id) is None:
                catalog.put_scan(result)

    captures_root = state_root / "captures"
    if not captures_root.is_dir():
        return
    for directory in sorted(captures_root.iterdir()):
        if not directory.is_dir() or directory.name.startswith("."):
            continue
        artifact_id = directory.name
        if catalog.get_artifact(artifact_id) is not None:
            continue
        metadata_path = directory / f"{artifact_id}.sigmf-meta"
        try:
            metadata = json.loads(metadata_path.read_text())
            global_metadata = metadata["global"]
            capture_metadata = metadata["pluto:capture"]
            settings = capture_metadata["initial_settings"]
            radio = global_metadata["pluto:radio"]
            artifact = ArtifactSummary(
                artifact_id=artifact_id,
                radio_id=radio["radio_id"],
                created_at=global_metadata["pluto:created_at"],
                path=str(directory),
                sample_count=capture_metadata["sample_count"],
                receiver_count=capture_metadata["receiver_count"],
                sample_rate_hz=settings["sample_rate_hz"],
                center_frequency_hz=settings["center_frequency_hz"],
                sha256=global_metadata["pluto:sha256"],
                label=(
                    None
                    if global_metadata.get("core:description") == "Pluto+ IQ capture"
                    else global_metadata.get("core:description")
                ),
            )
        except (KeyError, OSError, TypeError, ValueError):
            continue
        try:
            valid = verify_artifact(artifact)
        except OSError:
            valid = False
        if valid:
            catalog.put_artifact(artifact)


def _unused_recovery_path(preferred: Path) -> Path:
    if not preferred.exists():
        return preferred
    index = 1
    while True:
        candidate = preferred.with_name(f"{preferred.name}.recovered-{index}")
        if not candidate.exists():
            return candidate
        index += 1


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _acquire_state_lock(state_root: Path) -> BinaryIO:
    stream = (state_root / ".plutod.lock").open("a+b")
    try:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as error:
        stream.close()
        raise RuntimeError(
            f"state directory is already owned by another daemon: {state_root}"
        ) from error
    return stream


def _release_state_lock(stream: BinaryIO) -> None:
    if stream.closed:
        return
    fcntl.flock(stream.fileno(), fcntl.LOCK_UN)
    stream.close()
