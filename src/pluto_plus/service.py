"""Application composition shared by API, CLI-facing daemon, and tests."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from collections.abc import Callable, Mapping
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
    FirmwareTransport,
    LocalFirmwareFilesystem,
    PlannedFirmware,
    RadioFirmwareIdentity,
)
from pluto_plus.hardware.base import RadioDevice
from pluto_plus.inventory import (
    LocalUsbPluto,
    RadioInventoryReport,
    build_radio_inventory,
    scan_local_usb_plutos,
)
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
    Transport,
)
from pluto_plus.network_config import (
    NetworkAddressMode,
    NetworkConfigManager,
    NetworkConfigObservation,
    NetworkConfigPlan,
    NetworkConfigPlanNotFoundError,
    NetworkConfigReceipt,
    NetworkConfigUnavailableError,
    NetworkInterface,
    PlannedNetworkConfig,
)
from pluto_plus.setup import (
    CanonicalSetupManager,
    PlannedSetup,
    SetupError,
    SetupIdentity,
    SetupPlan,
    SetupPlanNotFoundError,
    SetupReceipt,
    SetupUnavailableError,
)


class PlutoService:
    def __init__(
        self,
        state_root: Path,
        devices: tuple[RadioDevice, ...],
        *,
        discovered_radios: tuple[RadioSnapshot, ...] = (),
        firmware_manager: FirmwareManager | None = None,
        ip_firmware_managers: Mapping[str, FirmwareManager] | None = None,
        network_config_managers: Mapping[str, NetworkConfigManager] | None = None,
        setup_manager: CanonicalSetupManager | None = None,
        local_usb_inventory: Callable[[], tuple[LocalUsbPluto, ...]] | None = None,
        capture_free_bytes: Callable[[Path], int] | None = None,
        capture_reserve_bytes: int = 64 * 1024 * 1024,
    ) -> None:
        self.state_root = state_root
        state_root.mkdir(parents=True, exist_ok=True)
        self._state_lock = _acquire_state_lock(state_root)
        self._controllers: dict[str, RadioController] = {}
        self._local_usb_inventory = local_usb_inventory or scan_local_usb_plutos
        self._discovered_radios = {
            snapshot.identity.radio_id: snapshot for snapshot in discovered_radios
        }
        if len(self._discovered_radios) != len(discovered_radios):
            _release_state_lock(self._state_lock)
            raise ValueError("duplicate discovered radio id")
        try:
            _recover_incomplete_files(state_root)
            self.catalog = Catalog(state_root / "catalog.sqlite3")
            self.catalog.recover_interrupted_jobs()
            _reconcile_completed_records(state_root, self.catalog)
            self.analysis = AnalysisService(state_root / "analysis")
            self.firmware_manager = firmware_manager
            self.ip_firmware_managers = dict(ip_firmware_managers or {})
            if any(
                manager.transport is not FirmwareTransport.SSH_FRM
                for manager in self.ip_firmware_managers.values()
            ):
                raise ValueError("IP firmware managers must use ssh_frm transport")
            self.network_config_managers = dict(network_config_managers or {})
            self.setup_manager = setup_manager
            self._firmware_filesystem = LocalFirmwareFilesystem()
            self._firmware_images: dict[str, tuple[FirmwareImageSummary, Path]] = {}
            self._firmware_plans: dict[str, FirmwarePlan] = {}
            self._firmware_plan_managers: dict[str, FirmwareManager] = {}
            self._firmware_receipts: dict[str, FirmwareReceipt] = {}
            self._setup_plans: dict[str, SetupPlan] = {}
            self._network_config_plans: dict[str, NetworkConfigPlan] = {}
            self._network_config_plan_managers: dict[str, NetworkConfigManager] = {}
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
                self._discovered_radios.pop(controller.radio_id, None)
        except BaseException:
            for controller in self._controllers.values():
                with suppress(BaseException):
                    controller.close()
            _release_state_lock(self._state_lock)
            raise

    def list_radios(self) -> list[RadioSnapshot]:
        managed = [self._controllers[key].snapshot() for key in sorted(self._controllers)]
        discovered = [
            self._discovered_radios[key] for key in sorted(self._discovered_radios)
        ]
        return managed + discovered

    def radio_inventory(self) -> RadioInventoryReport:
        """Return a fresh daemon-host USB and known-network correlation."""

        return build_radio_inventory(self.list_radios(), self._local_usb_inventory())

    def get_radio(self, radio_id: str) -> RadioSnapshot:
        controller = self._controllers.get(radio_id)
        if controller is not None:
            return controller.snapshot()
        try:
            return self._discovered_radios[radio_id]
        except KeyError as error:
            raise RadioNotFoundError(f"unknown radio: {radio_id}") from error

    def doctor(self, radio_id: str | None = None) -> list[DoctorReport] | DoctorReport:
        """Run fresh, read-only canonical setup checks for one or all managed radios."""

        def report(controller: RadioController) -> DoctorReport:
            snapshot = controller.snapshot()
            facts = controller.diagnostic_facts()
            if self.setup_manager is not None:
                identity = snapshot.identity
                if identity.usb_path is not None and identity.firmware_version is not None:
                    try:
                        observation = self.setup_manager.inspect(
                            SetupIdentity(
                                serial=identity.serial,
                                usb_sysfs_path=identity.usb_path,
                                observed_firmware=identity.firmware_version,
                            )
                        )
                    except SetupError:
                        # Doctor remains useful when the optional privileged reader is
                        # unavailable. Unknown is safer than stale or inferred state.
                        pass
                    else:
                        facts.update(
                            {
                                "uboot": observation.uboot,
                                "boot_provenance": observation.boot_provenance,
                                "phy_model": observation.live_phy_model,
                                "rx_scan_channels": observation.rx_scan_channels,
                            }
                        )
            return diagnose_radio(
                snapshot,
                facts,
                firmware_helper_available=(
                    self.firmware_manager is not None
                    or (
                        snapshot.identity.radio_id in self.ip_firmware_managers
                        and not self.ip_firmware_managers[
                            snapshot.identity.radio_id
                        ].key_reconciliation_required
                    )
                    or self.setup_manager is not None
                ),
            )

        def discovered_report(snapshot: RadioSnapshot) -> DoctorReport:
            identity = snapshot.identity
            return diagnose_radio(
                snapshot,
                {
                    "model": identity.model,
                    "phy_model": None,
                    "rx_scan_channels": (),
                    "boot_provenance": None,
                    "uboot": None,
                },
                firmware_helper_available=False,
            )

        if radio_id is not None:
            controller = self._controllers.get(radio_id)
            if controller is not None:
                return report(controller)
            try:
                return discovered_report(self._discovered_radios[radio_id])
            except KeyError as error:
                raise RadioNotFoundError(f"unknown radio: {radio_id}") from error
        return [
            *(report(self._controllers[key]) for key in sorted(self._controllers)),
            *(
                discovered_report(self._discovered_radios[key])
                for key in sorted(self._discovered_radios)
            ),
        ]

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
        usb_available = self.firmware_manager is not None
        ssh_radio_ids = tuple(sorted(self.ip_firmware_managers))
        ssh_enrollments = {
            radio_id: {
                "key_reconciliation_required": manager.key_reconciliation_required,
                "mutation_available": not manager.key_reconciliation_required,
            }
            for radio_id, manager in sorted(self.ip_firmware_managers.items())
        }
        return {
            "available": usb_available or bool(ssh_radio_ids),
            "modes": tuple(mode.value for mode in FirmwareMode),
            "transports": {
                FirmwareTransport.USB.value: {"available": usb_available},
                FirmwareTransport.SSH_FRM.value: {
                    "available": bool(ssh_radio_ids),
                    "enrolled_radio_ids": ssh_radio_ids,
                    "enrollments": ssh_enrollments,
                },
            },
            "maximum_upload_bytes": 128 * 1024 * 1024,
            "safety": "plan-token-execute",
        }

    def enroll_ip_firmware_manager(
        self, radio_id: str, manager: FirmwareManager
    ) -> None:
        """Attach one explicitly configured SSH executor before serving requests."""

        if manager.transport is not FirmwareTransport.SSH_FRM:
            raise ValueError("IP firmware manager must use ssh_frm transport")
        controller = self._controller(radio_id)
        if controller.snapshot().identity.serial != radio_id:
            raise ValueError("SSH firmware enrollment must use the exact managed serial")
        if radio_id in self.ip_firmware_managers:
            raise ValueError(f"duplicate SSH firmware enrollment for {radio_id!r}")
        if self._firmware_plans:
            raise RuntimeError("cannot add SSH firmware enrollment after planning has begun")
        self.ip_firmware_managers[radio_id] = manager

    def setup_status(self) -> dict[str, object]:
        return {
            "helper_available": self.setup_manager is not None,
            "safety": "inspect-plan-token-execute-receipt",
            "profile_id": CANONICAL_POLICY.profile_id,
        }

    def enroll_network_config_manager(
        self, radio_id: str, manager: NetworkConfigManager
    ) -> None:
        """Attach one explicit pinned-SSH config manager before serving requests."""

        controller = self._controller(radio_id)
        identity = controller.snapshot().identity
        if identity.serial != radio_id or manager.identity.serial != identity.serial:
            raise ValueError("network-config enrollment must use the exact managed serial")
        if identity.uri != f"ip:{manager.identity.endpoint}":
            raise ValueError("network-config enrollment endpoint does not match managed IIO")
        if radio_id in self.network_config_managers:
            raise ValueError(f"duplicate network-config enrollment for {radio_id!r}")
        if self._network_config_plans:
            raise RuntimeError("cannot enroll network config after planning has begun")
        self.network_config_managers[radio_id] = manager

    def network_config_status(self) -> dict[str, object]:
        return {
            "available": bool(self.network_config_managers),
            "enrolled_radio_ids": sorted(self.network_config_managers),
            "safety": "redacted-read-structured-plan-token-execute",
            "mutable_fields": [
                "ipaddr",
                "ipaddr_host",
                "netmask",
                "ipaddr_eth",
                "netmask_eth",
            ],
        }

    def inspect_network_config(self, radio_id: str) -> NetworkConfigObservation:
        manager = self._network_config_manager(radio_id)
        snapshot = self._controller(radio_id).snapshot()
        if snapshot.identity.serial != manager.identity.serial:
            raise NetworkConfigUnavailableError("managed radio identity does not match enrollment")
        return manager.inspect()

    def create_network_config_plan(
        self,
        radio_id: str,
        *,
        interface: NetworkInterface,
        mode: NetworkAddressMode,
        address: str | None,
        netmask: str | None,
        host_address: str | None,
    ) -> PlannedNetworkConfig:
        manager = self._network_config_manager(radio_id)
        controller = self._controller(radio_id)
        snapshot = controller.snapshot()
        if snapshot.state is not RadioState.READY:
            raise RadioBusyError(
                f"radio cannot plan network configuration while {snapshot.state}"
            )
        planned = manager.create_plan(
            interface=interface,
            mode=mode,
            address=address,
            netmask=netmask,
            host_address=host_address,
        )
        self._network_config_plans[planned.plan.plan_id] = planned.plan
        self._network_config_plan_managers[planned.plan.plan_id] = manager
        return planned

    def execute_network_config_plan(
        self,
        plan_id: str,
        confirmation_token: str,
        operator_confirmation: str,
    ) -> NetworkConfigReceipt:
        try:
            plan = self._network_config_plans[plan_id]
            manager = self._network_config_plan_managers[plan_id]
        except KeyError as error:
            raise NetworkConfigPlanNotFoundError(
                f"unknown network-config plan: {plan_id}"
            ) from error
        controller = self._controller_for_serial(plan.identity.serial)
        return manager.execute(
            plan,
            confirmation_token,
            operator_confirmation,
            before_mutation=controller.prepare_radio_mutation,
            after_mutation=controller.recover_after_radio_mutation,
        )

    def list_network_config_receipts(self) -> list[NetworkConfigReceipt]:
        receipts = {
            receipt.receipt_id: receipt
            for manager in self.network_config_managers.values()
            for receipt in manager.list_receipts()
        }
        return sorted(
            receipts.values(), key=lambda item: item.started_at, reverse=True
        )

    def create_canonical_setup_plan(self, radio_id: str) -> PlannedSetup:
        manager = self._require_setup()
        controller = self._controller(radio_id)
        snapshot = controller.snapshot()
        if snapshot.state is not RadioState.READY:
            raise RadioBusyError(f"radio cannot plan setup while {snapshot.state}")
        identity = snapshot.identity
        if identity.usb_path is None or identity.firmware_version is None:
            raise SetupUnavailableError(
                "setup planning requires an attested USB path and firmware version"
            )
        planned = manager.create_plan(
            SetupIdentity(
                serial=identity.serial,
                usb_sysfs_path=identity.usb_path,
                observed_firmware=identity.firmware_version,
            )
        )
        self._setup_plans[planned.plan.plan_id] = planned.plan
        return planned

    def execute_setup_plan(self, plan_id: str, confirmation_token: str) -> SetupReceipt:
        manager = self._require_setup()
        try:
            plan = self._setup_plans[plan_id]
        except KeyError as error:
            raise SetupPlanNotFoundError(f"unknown setup plan: {plan_id}") from error
        controller = self._controller_for_serial(plan.identity.serial)
        return manager.execute(
            plan,
            confirmation_token,
            before_mutation=controller.prepare_radio_mutation,
            after_mutation=lambda: controller.recover_after_radio_mutation(
                require_paired_rx=True
            ),
        )

    def list_setup_receipts(self) -> list[SetupReceipt]:
        return self._require_setup().list_receipts()

    def reconcile_setup_receipt(self, receipt_id: str) -> SetupReceipt:
        """Re-attest an uncertain setup attempt without invoking any mutation callback."""

        return self._require_setup().reconcile(receipt_id)

    def stage_firmware_image(self, filename: str, data: bytes) -> FirmwareImageSummary:
        self._require_any_firmware()
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
        self._require_any_firmware()
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
        transport: FirmwareTransport = FirmwareTransport.USB,
    ) -> PlannedFirmware:
        manager = self._firmware_manager_for(radio_id, transport)
        controller = self._controller(radio_id)
        snapshot = controller.snapshot()
        if snapshot.state is not RadioState.READY:
            raise RadioBusyError(f"radio cannot plan firmware while {snapshot.state}")
        identity = snapshot.identity
        if transport is FirmwareTransport.USB:
            if mode is FirmwareMode.VOLATILE_DFU:
                supported = snapshot.capabilities.supports_volatile_firmware
            else:
                supported = snapshot.capabilities.supports_persistent_firmware
            if not supported:
                raise FirmwareUnavailableError(
                    f"radio {radio_id!r} does not advertise support for {mode.value}"
                )
            if identity.usb_path is None or identity.firmware_version is None:
                raise FirmwareUnavailableError(
                    "firmware planning requires an attested USB path and firmware version"
                )
            firmware_identity = RadioFirmwareIdentity(
                serial=identity.serial,
                usb_sysfs_path=identity.usb_path,
                observed_firmware=identity.firmware_version,
            )
        else:
            if mode is not FirmwareMode.PERSISTENT_QSPI:
                raise FirmwareUnavailableError("ssh_frm supports persistent_qspi only")
            if identity.transport is not Transport.IIO_IP:
                raise FirmwareUnavailableError(
                    "ssh_frm requires an explicitly managed network-IIO radio"
                )
            if identity.firmware_version is None:
                raise FirmwareUnavailableError(
                    "SSH firmware planning requires an observed managed firmware version"
                )
            firmware_identity = manager.observe_identity(identity.serial)
            if firmware_identity.observed_firmware != identity.firmware_version:
                raise FirmwareUnavailableError(
                    "fresh enrolled SSH identity does not match the managed radio snapshot"
                )
        try:
            _summary, source = self._firmware_images[image_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(f"unknown firmware image: {image_id}") from error
        if (
            transport is FirmwareTransport.SSH_FRM
            and expected_firmware_version != CANONICAL_POLICY.device_firmware
        ):
            raise FirmwareImageError(
                "ssh_frm is restricted to the hardware-qualified canonical firmware"
            )
        planned = manager.create_plan(
            firmware_identity,
            source,
            mode,
            expected_firmware=expected_firmware_version,
            transport=transport,
        )
        if transport is FirmwareTransport.SSH_FRM and not (
            _summary.sha256 == CANONICAL_POLICY.asset_sha256
            or (
                planned.plan.fit_sha256 == CANONICAL_POLICY.fit_body_sha256
                and planned.plan.fit_size == CANONICAL_POLICY.fit_body_size
            )
        ):
            raise FirmwareImageError(
                "ssh_frm image FIT body does not match the hardware-qualified canonical firmware"
            )
        self._firmware_plans[planned.plan.plan_id] = planned.plan
        self._firmware_plan_managers[planned.plan.plan_id] = manager
        return planned

    def create_canonical_firmware_plan(
        self,
        radio_id: str,
        image_id: str,
        mode: FirmwareMode,
        *,
        transport: FirmwareTransport = FirmwareTransport.USB,
    ) -> PlannedFirmware:
        """Plan only the immutable image selected by the shipped doctor policy."""

        try:
            summary, _source = self._firmware_images[image_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(f"unknown firmware image: {image_id}") from error
        if (
            transport is FirmwareTransport.USB
            and summary.sha256 != CANONICAL_POLICY.asset_sha256
        ):
            raise FirmwareImageError(
                "uploaded image SHA-256 does not match the selected canonical release: "
                f"expected {CANONICAL_POLICY.asset_sha256}, got {summary.sha256}"
            )
        return self.create_firmware_plan(
            radio_id,
            image_id,
            mode,
            expected_firmware_version=CANONICAL_POLICY.device_firmware,
            transport=transport,
        )

    def execute_firmware_plan(
        self,
        plan_id: str,
        confirmation_token: str,
        *,
        operator_confirmation: str | None = None,
    ) -> FirmwareReceipt:
        self._require_any_firmware()
        try:
            plan = self._firmware_plans[plan_id]
            manager = self._firmware_plan_managers[plan_id]
        except KeyError as error:
            raise FirmwareObjectNotFoundError(f"unknown firmware plan: {plan_id}") from error
        controller = self._controller_for_serial(plan.radio.serial)
        try:
            receipt = manager.execute(
                plan,
                confirmation_token,
                before_mutation=controller.prepare_firmware_mutation,
                after_mutation=controller.recover_after_firmware_mutation,
                operator_confirmation=operator_confirmation,
            )
        except FirmwareExecutionError as error:
            self._firmware_receipts[error.receipt.receipt_id] = error.receipt
            raise
        self._firmware_receipts[receipt.receipt_id] = receipt
        return receipt

    def list_firmware_receipts(self) -> list[FirmwareReceipt]:
        managers = self._require_any_firmware()
        receipts = {
            receipt.receipt_id: receipt
            for manager in managers
            for receipt in manager.list_receipts()
        }
        receipts.update(self._firmware_receipts)
        return sorted(
            receipts.values(),
            key=lambda item: item.started_at,
            reverse=True,
        )

    def reconcile_firmware_receipt(self, receipt_id: str) -> FirmwareReceipt:
        """Re-attest an uncertain firmware receipt; never retries the flash."""

        matches = [
            manager
            for manager in self._require_any_firmware()
            if any(receipt.receipt_id == receipt_id for receipt in manager.list_receipts())
        ]
        if len(matches) != 1:
            raise FirmwareObjectNotFoundError(f"unknown firmware receipt: {receipt_id}")
        receipt = matches[0].reconcile(receipt_id)
        self._firmware_receipts[receipt.receipt_id] = receipt
        return receipt

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

    def _require_any_firmware(self) -> tuple[FirmwareManager, ...]:
        managers = tuple(
            manager
            for manager in (self.firmware_manager, *self.ip_firmware_managers.values())
            if manager is not None
        )
        if not managers:
            raise FirmwareUnavailableError(
                "firmware operations require an explicitly configured privileged executor"
            )
        return managers

    def _firmware_manager_for(
        self, radio_id: str, transport: FirmwareTransport
    ) -> FirmwareManager:
        if transport is FirmwareTransport.USB:
            return self._require_firmware()
        try:
            return self.ip_firmware_managers[radio_id]
        except KeyError as error:
            raise FirmwareUnavailableError(
                f"radio {radio_id!r} has no explicit ssh_frm enrollment"
            ) from error

    def _require_setup(self) -> CanonicalSetupManager:
        if self.setup_manager is None:
            raise SetupUnavailableError(
                "canonical setup requires an explicitly configured privileged helper"
            )
        return self.setup_manager

    def _network_config_manager(self, radio_id: str) -> NetworkConfigManager:
        try:
            return self.network_config_managers[radio_id]
        except KeyError as error:
            raise NetworkConfigUnavailableError(
                f"radio {radio_id!r} has no explicit network-config enrollment"
            ) from error

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
