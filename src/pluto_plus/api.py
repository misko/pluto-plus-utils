"""Versioned HTTP and WebSocket surface for the Pluto+ daemon."""

from __future__ import annotations

import asyncio
import queue
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from pluto_plus import __version__
from pluto_plus.admin import (
    AdminAuthenticationError,
    AdminMutationPolicy,
    AdminPolicyUnavailableError,
    AdminSecureTransportRequiredError,
    admin_transport_is_secure,
)
from pluto_plus.errors import (
    AnalyzerNotFoundError,
    ArtifactNotFoundError,
    FirmwareObjectNotFoundError,
    FirmwareUnavailableError,
    RadioBusyError,
    RadioConfigurationError,
    RadioNotFoundError,
    RevisionConflictError,
)
from pluto_plus.firmware import (
    FirmwareAuthorizationError,
    FirmwareError,
    FirmwareExecutionError,
    FirmwareMode,
    FirmwareTransport,
)
from pluto_plus.inventory import RadioInventoryReport
from pluto_plus.models import (
    AnalysisRequest,
    AnalysisResult,
    ArtifactSummary,
    DoctorReport,
    FirmwareExecuteRequest,
    FirmwareImageSummary,
    FirmwarePlanRequest,
    NetworkConfigPlanRequest,
    RadioSnapshot,
    ScanJob,
    ScanRequest,
    ScanResult,
    SettingsPatch,
    StreamJob,
    StreamRequest,
)
from pluto_plus.network_config import (
    NetworkAddressMode,
    NetworkConfigAuthorizationError,
    NetworkConfigExecutionError,
    NetworkConfigPlanNotFoundError,
    NetworkConfigPreconditionError,
    NetworkConfigUnavailableError,
    NetworkInterface,
)
from pluto_plus.service import PlutoService
from pluto_plus.setup import (
    SetupAuthorizationError,
    SetupError,
    SetupExecutionError,
    SetupPlanNotFoundError,
    SetupPreconditionError,
    SetupReceiptNotFoundError,
    SetupUnavailableError,
)

API_PREFIX = "/api/v1"
WATERFALL_MIN_FRAME_INTERVAL_S = 1 / 12


def _error(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def create_app(
    service: PlutoService,
    *,
    static_directory: str | Path | None = None,
    admin_policy: AdminMutationPolicy | None = None,
) -> FastAPI:
    """Build a daemon app around an already-composed service.

    The caller owns service construction. The app owns its lifetime after creation
    and closes all radio controllers during application shutdown.
    """

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        try:
            yield
        finally:
            service.close()

    app = FastAPI(
        title="Pluto+ daemon",
        version=__version__,
        lifespan=lifespan,
    )
    app.state.pluto_service = service

    def require_admin(request: Request, *, mutation: bool) -> None:
        if not _admin_transport_secure(request):
            raise AdminSecureTransportRequiredError(
                "privileged operations require HTTPS or a loopback/Unix-socket connection"
            )
        if admin_policy is None:
            raise AdminPolicyUnavailableError(
                "privileged HTTP operations require explicit admin authentication"
            )
        browser_request = mutation and any(
            header in request.headers
            for header in ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")
        )
        admin_policy.authorize(
            authorization=request.headers.get("authorization"),
            origin=request.headers.get("origin"),
            browser_request=browser_request,
        )

    def _admin_transport_secure(request: Request) -> bool:
        server = request.scope.get("server")
        server_host = (
            str(server[0])
            if isinstance(server, (tuple, list)) and server
            else None
        )
        return admin_transport_is_secure(
            scheme=request.url.scheme,
            client_host=None if request.client is None else request.client.host,
            server_host=server_host,
        )

    @app.exception_handler(RadioNotFoundError)
    async def radio_not_found(_request: Request, error: RadioNotFoundError) -> JSONResponse:
        return _error("radio_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(ArtifactNotFoundError)
    async def artifact_not_found(_request: Request, error: ArtifactNotFoundError) -> JSONResponse:
        return _error("artifact_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(AnalyzerNotFoundError)
    async def analyzer_not_found(_request: Request, error: AnalyzerNotFoundError) -> JSONResponse:
        return _error("analyzer_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(RevisionConflictError)
    async def revision_conflict(_request: Request, error: RevisionConflictError) -> JSONResponse:
        return _error("revision_conflict", str(error), status.HTTP_409_CONFLICT)

    @app.exception_handler(RadioBusyError)
    async def radio_busy(_request: Request, error: RadioBusyError) -> JSONResponse:
        return _error("radio_busy", str(error), status.HTTP_409_CONFLICT)

    @app.exception_handler(RadioConfigurationError)
    async def radio_configuration(
        _request: Request, error: RadioConfigurationError
    ) -> JSONResponse:
        return _error(
            "radio_configuration_failed",
            str(error),
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(FirmwareUnavailableError)
    async def firmware_unavailable(
        _request: Request, error: FirmwareUnavailableError
    ) -> JSONResponse:
        return _error("firmware_unavailable", str(error), status.HTTP_503_SERVICE_UNAVAILABLE)

    @app.exception_handler(FirmwareObjectNotFoundError)
    async def firmware_object_not_found(
        _request: Request, error: FirmwareObjectNotFoundError
    ) -> JSONResponse:
        return _error("firmware_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(FirmwareAuthorizationError)
    async def firmware_authorization(
        _request: Request, error: FirmwareAuthorizationError
    ) -> JSONResponse:
        return _error("firmware_authorization_failed", str(error), status.HTTP_403_FORBIDDEN)

    @app.exception_handler(FirmwareExecutionError)
    async def firmware_execution(_request: Request, error: FirmwareExecutionError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {"code": "firmware_execution_failed", "message": str(error)},
                "receipt": jsonable_encoder(error.receipt),
            },
        )

    @app.exception_handler(FirmwareError)
    async def firmware_error(_request: Request, error: FirmwareError) -> JSONResponse:
        return _error(
            "firmware_validation_failed",
            str(error),
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(NetworkConfigUnavailableError)
    async def network_config_unavailable(
        _request: Request, error: NetworkConfigUnavailableError
    ) -> JSONResponse:
        return _error(
            "network_config_unavailable",
            str(error),
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(NetworkConfigPlanNotFoundError)
    async def network_config_plan_not_found(
        _request: Request, error: NetworkConfigPlanNotFoundError
    ) -> JSONResponse:
        return _error(
            "network_config_plan_not_found",
            str(error),
            status.HTTP_404_NOT_FOUND,
        )

    @app.exception_handler(NetworkConfigAuthorizationError)
    async def network_config_authorization(
        _request: Request, error: NetworkConfigAuthorizationError
    ) -> JSONResponse:
        return _error(
            "network_config_authorization_failed",
            str(error),
            status.HTTP_403_FORBIDDEN,
        )

    @app.exception_handler(NetworkConfigPreconditionError)
    async def network_config_precondition(
        _request: Request, error: NetworkConfigPreconditionError
    ) -> JSONResponse:
        return _error(
            "network_config_precondition_failed",
            str(error),
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    @app.exception_handler(NetworkConfigExecutionError)
    async def network_config_execution(
        _request: Request, error: NetworkConfigExecutionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {
                    "code": "network_config_execution_failed",
                    "message": str(error),
                },
                "receipt": jsonable_encoder(error.receipt),
            },
        )

    @app.exception_handler(AdminPolicyUnavailableError)
    async def admin_unavailable(
        _request: Request, error: AdminPolicyUnavailableError
    ) -> JSONResponse:
        return _error(
            "admin_authentication_unavailable",
            str(error),
            status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    @app.exception_handler(AdminAuthenticationError)
    async def admin_authentication(
        _request: Request, error: AdminAuthenticationError
    ) -> JSONResponse:
        return _error("admin_authentication_failed", str(error), status.HTTP_403_FORBIDDEN)

    @app.exception_handler(AdminSecureTransportRequiredError)
    async def admin_secure_transport_required(
        _request: Request, error: AdminSecureTransportRequiredError
    ) -> JSONResponse:
        return _error(
            "admin_secure_transport_required",
            str(error),
            status.HTTP_426_UPGRADE_REQUIRED,
        )

    @app.exception_handler(SetupUnavailableError)
    async def setup_unavailable(_request: Request, error: SetupUnavailableError) -> JSONResponse:
        return _error("setup_unavailable", str(error), status.HTTP_503_SERVICE_UNAVAILABLE)

    @app.exception_handler(SetupAuthorizationError)
    async def setup_authorization(
        _request: Request, error: SetupAuthorizationError
    ) -> JSONResponse:
        return _error("setup_authorization_failed", str(error), status.HTTP_403_FORBIDDEN)

    @app.exception_handler(SetupPlanNotFoundError)
    async def setup_plan_not_found(
        _request: Request, error: SetupPlanNotFoundError
    ) -> JSONResponse:
        return _error("setup_plan_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(SetupReceiptNotFoundError)
    async def setup_receipt_not_found(
        _request: Request, error: SetupReceiptNotFoundError
    ) -> JSONResponse:
        return _error("setup_receipt_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @app.exception_handler(SetupPreconditionError)
    async def setup_precondition(_request: Request, error: SetupPreconditionError) -> JSONResponse:
        return _error("setup_precondition_failed", str(error), status.HTTP_409_CONFLICT)

    @app.exception_handler(SetupExecutionError)
    async def setup_execution(_request: Request, error: SetupExecutionError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {"code": "setup_execution_failed", "message": str(error)},
                "receipt": {
                    "receipt_id": error.receipt.receipt_id,
                    "success": error.receipt.success,
                    "outcome": error.receipt.outcome,
                    "failure_phase": error.receipt.failure_phase,
                    "completed_phases": error.receipt.completed_phases,
                    "backup_path": error.receipt.backup_path,
                    "backup_sha256": error.receipt.backup_sha256,
                    "reconciliation_required": error.receipt.reconciliation_required,
                },
            },
        )

    @app.exception_handler(SetupError)
    async def setup_error(_request: Request, error: SetupError) -> JSONResponse:
        return _error("setup_failed", str(error), status.HTTP_422_UNPROCESSABLE_CONTENT)

    router = APIRouter(prefix=API_PREFIX)

    @router.get("/health")
    def health() -> dict[str, Any]:
        radios = service.list_radios()
        return {
            "status": "ok",
            "version": __version__,
            "radio_count": len(radios),
            "managed_radio_count": sum(radio.managed for radio in radios),
            "discovered_radio_count": sum(not radio.managed for radio in radios),
        }

    @router.get("/radios", response_model=list[RadioSnapshot])
    def list_radios() -> list[RadioSnapshot]:
        return service.list_radios()

    @router.get("/inventory", response_model=RadioInventoryReport)
    def radio_inventory() -> RadioInventoryReport:
        """Correlate fresh daemon-host USB topology with known network radios."""

        return service.radio_inventory()

    @router.get("/radios/{radio_id}", response_model=RadioSnapshot)
    def get_radio(radio_id: str) -> RadioSnapshot:
        return service.get_radio(radio_id)

    @router.get("/doctor", response_model=list[DoctorReport])
    def doctor_all() -> Any:
        return service.doctor()

    @router.get("/radios/{radio_id}/doctor", response_model=DoctorReport)
    def doctor_radio(radio_id: str) -> Any:
        return service.doctor(radio_id)

    @router.get("/setup")
    def setup_status(request: Request) -> dict[str, object]:
        setup = service.setup_status()
        helper_available = bool(setup["helper_available"])
        return {
            **setup,
            "admin_authentication_configured": admin_policy is not None,
            "secure_transport": _admin_transport_secure(request),
            "available": (
                helper_available and admin_policy is not None and _admin_transport_secure(request)
            ),
            "transport_guidance": "Use HTTPS or an SSH tunnel to loopback for privileged actions.",
            "allowed_origins": (
                [] if admin_policy is None else sorted(admin_policy.allowed_origins)
            ),
        }

    @router.post(
        "/radios/{radio_id}/doctor/setup-plans",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def create_canonical_setup_plan(radio_id: str, request: Request) -> Any:
        require_admin(request, mutation=True)
        return service.create_canonical_setup_plan(radio_id)

    @router.post(
        "/setup/executions",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def execute_setup_plan(payload: FirmwareExecuteRequest, request: Request) -> Any:
        require_admin(request, mutation=True)
        return service.execute_setup_plan(payload.plan_id, payload.confirmation_token)

    @router.get("/setup/receipts", response_model=None)
    def list_setup_receipts(request: Request) -> Any:
        require_admin(request, mutation=False)
        return service.list_setup_receipts()

    @router.post(
        "/setup/receipts/{receipt_id}/reconcile",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def reconcile_setup_receipt(receipt_id: str, request: Request) -> Any:
        require_admin(request, mutation=True)
        return service.reconcile_setup_receipt(receipt_id)

    @router.get("/radios/{radio_id}/settings", response_model=RadioSnapshot)
    def get_settings(radio_id: str) -> RadioSnapshot:
        """Return revision plus requested and read-back settings as one transaction view."""

        return service.get_radio(radio_id)

    @router.get("/network-config", response_model=None)
    def network_config_status(request: Request) -> Any:
        configured = service.network_config_status()
        return {
            **configured,
            "admin_authentication_configured": admin_policy is not None,
            "secure_transport": _admin_transport_secure(request),
            "available": bool(configured["available"])
            and admin_policy is not None
            and _admin_transport_secure(request),
            "transport_guidance": (
                "Use HTTPS, loopback through an SSH tunnel, or a Unix socket for "
                "config.txt access."
            ),
        }

    @router.get("/radios/{radio_id}/config", response_model=None)
    def inspect_network_config(radio_id: str, request: Request) -> Any:
        require_admin(request, mutation=False)
        return service.inspect_network_config(radio_id)

    @router.post(
        "/radios/{radio_id}/config/plans",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def create_network_config_plan(
        radio_id: str, payload: NetworkConfigPlanRequest, request: Request
    ) -> Any:
        require_admin(request, mutation=True)
        return service.create_network_config_plan(
            radio_id,
            interface=NetworkInterface(payload.interface),
            mode=NetworkAddressMode(payload.mode),
            address=payload.address,
            netmask=payload.netmask,
            host_address=payload.host_address,
        )

    @router.post(
        "/network-config/executions",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def execute_network_config_plan(
        payload: FirmwareExecuteRequest, request: Request
    ) -> Any:
        require_admin(request, mutation=True)
        return service.execute_network_config_plan(
            payload.plan_id,
            payload.confirmation_token,
            payload.operator_confirmation or "",
        )

    @router.get("/network-config/receipts", response_model=None)
    def list_network_config_receipts(request: Request) -> Any:
        require_admin(request, mutation=False)
        return service.list_network_config_receipts()

    @router.patch("/radios/{radio_id}/settings", response_model=RadioSnapshot)
    def update_settings(radio_id: str, patch: SettingsPatch) -> RadioSnapshot:
        return service.update_settings(radio_id, patch)

    @router.post("/radios/{radio_id}/recover", response_model=RadioSnapshot)
    def recover_radio(radio_id: str) -> RadioSnapshot:
        return service.recover_radio(radio_id)

    @router.post(
        "/radios/{radio_id}/streams",
        response_model=StreamJob,
        status_code=status.HTTP_201_CREATED,
    )
    def start_stream(radio_id: str, request: StreamRequest) -> StreamJob:
        return service.start_stream(radio_id, request)

    @router.delete("/radios/{radio_id}/streams/current", response_model=StreamJob)
    def stop_stream(radio_id: str) -> StreamJob:
        return service.stop_stream(radio_id)

    @router.post(
        "/radios/{radio_id}/streams/{job_id}/release",
        status_code=status.HTTP_204_NO_CONTENT,
    )
    def release_preview(radio_id: str, job_id: str) -> None:
        service.release_preview(radio_id, job_id)

    @router.post(
        "/radios/{radio_id}/scans",
        response_model=ScanJob,
        status_code=status.HTTP_201_CREATED,
    )
    def start_scan(radio_id: str, request: ScanRequest) -> ScanJob:
        return service.start_scan(radio_id, request)

    @router.delete("/radios/{radio_id}/scans/current", response_model=ScanJob)
    def stop_scan(radio_id: str) -> ScanJob:
        return service.stop_scan(radio_id)

    @router.get("/scan-jobs", response_model=list[ScanJob])
    def list_scan_jobs(radio_id: str | None = Query(default=None)) -> list[ScanJob]:
        return service.list_scan_jobs(radio_id)

    @router.get("/scan-jobs/{job_id}", response_model=ScanJob)
    def get_scan_job(job_id: str) -> ScanJob | JSONResponse:
        try:
            return service.get_scan_job(job_id)
        except KeyError as error:
            return _error("scan_job_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @router.get("/scans", response_model=list[ScanResult])
    def list_scans() -> list[ScanResult]:
        return service.list_scans()

    @router.get("/scans/{scan_id}", response_model=ScanResult)
    def get_scan(scan_id: str) -> ScanResult | JSONResponse:
        try:
            return service.get_scan(scan_id)
        except ArtifactNotFoundError as error:
            return _error("scan_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @router.get("/jobs", response_model=list[StreamJob])
    def list_jobs(radio_id: str | None = Query(default=None)) -> list[StreamJob]:
        return service.list_jobs(radio_id)

    @router.get("/jobs/{job_id}", response_model=StreamJob)
    def get_job(job_id: str) -> StreamJob | JSONResponse:
        try:
            return service.get_job(job_id)
        except KeyError as error:
            return _error("job_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @router.get("/artifacts", response_model=list[ArtifactSummary])
    def list_artifacts() -> list[ArtifactSummary]:
        return service.list_artifacts()

    @router.get("/artifacts/{artifact_id}", response_model=ArtifactSummary)
    def get_artifact(artifact_id: str) -> ArtifactSummary:
        return service.get_artifact(artifact_id)

    @router.get("/analyzers")
    def list_analyzers() -> dict[str, tuple[str, ...]]:
        return {"analyzers": service.analysis.analyzer_names}

    @router.post(
        "/analyses",
        response_model=AnalysisResult,
        status_code=status.HTTP_201_CREATED,
    )
    def run_analysis(request: AnalysisRequest) -> AnalysisResult | JSONResponse:
        try:
            return service.run_analysis(request)
        except ValueError as error:
            return _error(
                "invalid_analysis_parameters",
                str(error),
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )

    @router.get("/analyses", response_model=list[AnalysisResult])
    def list_analyses(
        artifact_id: str | None = Query(default=None),
    ) -> list[AnalysisResult]:
        return service.list_analyses(artifact_id)

    @router.get("/analyses/{analysis_id}", response_model=AnalysisResult)
    def get_analysis(analysis_id: str) -> AnalysisResult | JSONResponse:
        try:
            return service.get_analysis(analysis_id)
        except ArtifactNotFoundError as error:
            return _error("analysis_not_found", str(error), status.HTTP_404_NOT_FOUND)

    @router.get("/firmware")
    def firmware_status(request: Request) -> dict[str, object]:
        firmware = service.firmware_status()
        helper_available = bool(firmware["available"])
        return {
            **firmware,
            "helper_available": helper_available,
            "admin_authentication_configured": admin_policy is not None,
            "secure_transport": _admin_transport_secure(request),
            "available": (
                helper_available and admin_policy is not None and _admin_transport_secure(request)
            ),
            "transport_guidance": "Use HTTPS or an SSH tunnel to loopback for privileged actions.",
        }

    @router.post(
        "/firmware/images",
        response_model=FirmwareImageSummary,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_firmware_image(
        request: Request,
        filename: str = Query(..., min_length=1, max_length=255),
    ) -> FirmwareImageSummary | JSONResponse:
        require_admin(request, mutation=True)
        maximum = 128 * 1024 * 1024
        payload = bytearray()
        async for chunk in request.stream():
            payload.extend(chunk)
            if len(payload) > maximum:
                return _error(
                    "firmware_upload_too_large",
                    "firmware upload exceeds 128 MiB",
                    status.HTTP_413_CONTENT_TOO_LARGE,
                )
        try:
            return service.stage_firmware_image(filename, bytes(payload))
        except ValueError as error:
            return _error(
                "invalid_firmware_upload",
                str(error),
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )

    @router.get("/firmware/images", response_model=list[FirmwareImageSummary])
    def list_firmware_images() -> list[FirmwareImageSummary]:
        return service.list_firmware_images()

    @router.post(
        "/radios/{radio_id}/firmware/plans",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def create_firmware_plan(radio_id: str, payload: FirmwarePlanRequest, request: Request) -> Any:
        require_admin(request, mutation=True)
        try:
            mode = FirmwareMode(payload.mode)
        except ValueError:
            return _error(
                "invalid_firmware_mode",
                f"unsupported firmware mode: {payload.mode}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        try:
            transport = FirmwareTransport(payload.transport)
        except ValueError:
            return _error(
                "invalid_firmware_transport",
                f"unsupported firmware transport: {payload.transport}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        if transport is FirmwareTransport.SSH_FRM:
            return _error(
                "ssh_firmware_requires_canonical_route",
                "ssh_frm plans must use the canonical doctor firmware-plan route",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        return service.create_firmware_plan(
            radio_id,
            payload.image_id,
            mode,
            expected_firmware_version=payload.expected_firmware_version,
            transport=transport,
        )

    @router.post(
        "/radios/{radio_id}/doctor/firmware-plans",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def create_canonical_firmware_plan(
        radio_id: str, payload: FirmwarePlanRequest, request: Request
    ) -> Any:
        require_admin(request, mutation=True)
        try:
            mode = FirmwareMode(payload.mode)
        except ValueError:
            return _error(
                "invalid_firmware_mode",
                f"unsupported firmware mode: {payload.mode}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        try:
            transport = FirmwareTransport(payload.transport)
        except ValueError:
            return _error(
                "invalid_firmware_transport",
                f"unsupported firmware transport: {payload.transport}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        return service.create_canonical_firmware_plan(
            radio_id, payload.image_id, mode, transport=transport
        )

    @router.post(
        "/firmware/executions",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def execute_firmware_plan(payload: FirmwareExecuteRequest, request: Request) -> Any:
        require_admin(request, mutation=True)
        return service.execute_firmware_plan(
            payload.plan_id,
            payload.confirmation_token,
            operator_confirmation=payload.operator_confirmation,
        )

    @router.get("/firmware/receipts", response_model=None)
    def list_firmware_receipts(request: Request) -> Any:
        require_admin(request, mutation=False)
        return service.list_firmware_receipts()

    @router.post("/firmware/receipts/{receipt_id}/reconcile", response_model=None)
    def reconcile_firmware_receipt(receipt_id: str, request: Request) -> Any:
        require_admin(request, mutation=True)
        return service.reconcile_firmware_receipt(receipt_id)

    async def waterfall(websocket: WebSocket, radio_id: str) -> None:
        try:
            subscription = service.subscribe(radio_id)
        except RadioNotFoundError as error:
            await websocket.close(code=4404, reason=str(error))
            return

        await websocket.accept()
        receive_task = asyncio.create_task(websocket.receive())
        next_frame_at = 0.0
        try:
            while True:
                if receive_task.done():
                    event = receive_task.result()
                    if event["type"] == "websocket.disconnect":
                        break
                    receive_task = asyncio.create_task(websocket.receive())
                delay = next_frame_at - asyncio.get_running_loop().time()
                if delay > 0:
                    await asyncio.sleep(delay)
                    if receive_task.done():
                        continue
                try:
                    frame = await asyncio.to_thread(subscription.frames.get, True, 0.25)
                except queue.Empty:
                    continue
                # A disconnect may have arrived while the bounded broker wait was
                # running. Observe it before attempting another write.
                if receive_task.done():
                    continue
                await websocket.send_text(frame.model_dump_json())
                next_frame_at = (
                    asyncio.get_running_loop().time() + WATERFALL_MIN_FRAME_INTERVAL_S
                )
        except WebSocketDisconnect:
            pass
        finally:
            if not receive_task.done():
                receive_task.cancel()
            with suppress(asyncio.CancelledError, RuntimeError, WebSocketDisconnect):
                await receive_task
            subscription.close()

    router.add_api_websocket_route("/ws/radios/{radio_id}/waterfall", waterfall)
    # Kept as a compatibility alias for early clients built against the REST-shaped path.
    router.add_api_websocket_route("/radios/{radio_id}/waterfall", waterfall)

    app.include_router(router)

    selected_static = (
        Path(static_directory)
        if static_directory is not None
        else Path(__file__).resolve().with_name("static")
    )
    if (selected_static / "index.html").is_file():
        app.mount("/static", StaticFiles(directory=selected_static), name="web-assets")

        @app.get("/", include_in_schema=False, response_class=FileResponse)
        def web_ui() -> FileResponse:
            return FileResponse(selected_static / "index.html")

    return app
