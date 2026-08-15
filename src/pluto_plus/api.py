"""Versioned HTTP and WebSocket surface for the Pluto+ daemon."""

from __future__ import annotations

import asyncio
import queue
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, Query, Request, WebSocket, WebSocketDisconnect, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from pluto_plus import __version__
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
)
from pluto_plus.models import (
    AnalysisRequest,
    AnalysisResult,
    ArtifactSummary,
    DoctorReport,
    FirmwareExecuteRequest,
    FirmwareImageSummary,
    FirmwarePlanRequest,
    RadioSnapshot,
    ScanJob,
    ScanRequest,
    ScanResult,
    SettingsPatch,
    StreamJob,
    StreamRequest,
)
from pluto_plus.service import PlutoService

API_PREFIX = "/api/v1"


def _error(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )


def create_app(
    service: PlutoService,
    *,
    static_directory: str | Path | None = None,
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
    async def firmware_execution(
        _request: Request, error: FirmwareExecutionError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": {"code": "firmware_execution_failed", "message": str(error)},
                "receipt": {
                    "receipt_id": error.receipt.receipt_id,
                    "success": error.receipt.success,
                },
            },
        )

    @app.exception_handler(FirmwareError)
    async def firmware_error(_request: Request, error: FirmwareError) -> JSONResponse:
        return _error(
            "firmware_validation_failed",
            str(error),
            status.HTTP_422_UNPROCESSABLE_CONTENT,
        )

    router = APIRouter(prefix=API_PREFIX)

    @router.get("/health")
    def health() -> dict[str, Any]:
        radios = service.list_radios()
        return {
            "status": "ok",
            "version": __version__,
            "radio_count": len(radios),
        }

    @router.get("/radios", response_model=list[RadioSnapshot])
    def list_radios() -> list[RadioSnapshot]:
        return service.list_radios()

    @router.get("/radios/{radio_id}", response_model=RadioSnapshot)
    def get_radio(radio_id: str) -> RadioSnapshot:
        return service.get_radio(radio_id)

    @router.get("/doctor", response_model=list[DoctorReport])
    def doctor_all() -> Any:
        return service.doctor()

    @router.get("/radios/{radio_id}/doctor", response_model=DoctorReport)
    def doctor_radio(radio_id: str) -> Any:
        return service.doctor(radio_id)

    @router.get("/radios/{radio_id}/settings", response_model=RadioSnapshot)
    def get_settings(radio_id: str) -> RadioSnapshot:
        """Return revision plus requested and read-back settings as one transaction view."""

        return service.get_radio(radio_id)

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
    def firmware_status() -> dict[str, object]:
        return service.firmware_status()

    @router.post(
        "/firmware/images",
        response_model=FirmwareImageSummary,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_firmware_image(
        request: Request,
        filename: str = Query(..., min_length=1, max_length=255),
    ) -> FirmwareImageSummary | JSONResponse:
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
    def create_firmware_plan(
        radio_id: str, request: FirmwarePlanRequest
    ) -> Any:
        try:
            mode = FirmwareMode(request.mode)
        except ValueError:
            return _error(
                "invalid_firmware_mode",
                f"unsupported firmware mode: {request.mode}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        return service.create_firmware_plan(
            radio_id,
            request.image_id,
            mode,
            expected_firmware_version=request.expected_firmware_version,
        )

    @router.post(
        "/radios/{radio_id}/doctor/firmware-plans",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def create_canonical_firmware_plan(
        radio_id: str, request: FirmwarePlanRequest
    ) -> Any:
        try:
            mode = FirmwareMode(request.mode)
        except ValueError:
            return _error(
                "invalid_firmware_mode",
                f"unsupported firmware mode: {request.mode}",
                status.HTTP_422_UNPROCESSABLE_CONTENT,
            )
        return service.create_canonical_firmware_plan(radio_id, request.image_id, mode)

    @router.post(
        "/firmware/executions",
        status_code=status.HTTP_201_CREATED,
        response_model=None,
    )
    def execute_firmware_plan(request: FirmwareExecuteRequest) -> Any:
        return service.execute_firmware_plan(request.plan_id, request.confirmation_token)

    @router.get("/firmware/receipts", response_model=None)
    def list_firmware_receipts() -> Any:
        return service.list_firmware_receipts()

    async def waterfall(websocket: WebSocket, radio_id: str) -> None:
        try:
            subscription = service.subscribe(radio_id)
        except RadioNotFoundError as error:
            await websocket.close(code=4404, reason=str(error))
            return

        await websocket.accept()
        receive_task = asyncio.create_task(websocket.receive())
        try:
            while True:
                if receive_task.done():
                    event = receive_task.result()
                    if event["type"] == "websocket.disconnect":
                        break
                    receive_task = asyncio.create_task(websocket.receive())
                try:
                    frame = await asyncio.to_thread(subscription.frames.get, True, 0.25)
                except queue.Empty:
                    continue
                # A disconnect may have arrived while the bounded broker wait was
                # running. Observe it before attempting another write.
                if receive_task.done():
                    continue
                await websocket.send_text(frame.model_dump_json())
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
