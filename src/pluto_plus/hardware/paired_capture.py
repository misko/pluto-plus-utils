"""One-shot finite paired IIO recording, not RF detection or persistent hopping.

External ownership/firmware/RF attestation is mandatory. Native clients retain
their existing ABI, fault and reset-epoch restrictions. This module never uses
native cancellation, retunes a radio, installs coefficients, or claims lock.
"""

from __future__ import annotations

import hashlib
import json
import os
import queue
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol

from pluto_plus.hardware.fine_schedule import (
    FineLedgerState,
    FineScheduleLedger,
    FineScheduleManifest,
    validate_fine_batch,
)
from pluto_plus.hardware.pilot_iio import (
    PilotArmedEvent,
    PilotCapture,
    PilotCaptureEvent,
    PilotIioClient,
    PilotIqChunkEvent,
    PilotOriginEvent,
    PilotSnapshot,
    PilotTerminalEvent,
)
from pluto_plus.hardware.pss_control import PssFineStartReceipt, PssTrackerControlReceipt
from pluto_plus.hardware.pss_iio import (
    PssAcquisitionHealth,
    PssBatchReceipt,
    PssGracefulCloseReceipt,
    PssIioClient,
    PssMapChunk,
    PssMapReassembler,
    PssPhaseMap,
)
from pluto_plus.hardware.pss_stop import PssMapStopReceipt
from pluto_plus.hardware.pss_stop_control import PssMapStopOperation
from pluto_plus.hardware.source_support import (
    ObservationIdentity,
    ProcessingProfile,
    SourceInterval,
    map_support,
    pilot_slice_support,
)

_SAMPLES = 5_000_000
_REFILL = 25_000
_MAP_SPAN = 1_280_000
_MIN_COMMON = 15_000_000
_PROFILE = ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_STOP_V1


@dataclass(frozen=True, slots=True)
class PairedAttestation:
    """Caller-supplied fresh owner evidence; not manufactured from IIO metadata."""

    observation: ObservationIdentity
    raw: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.observation, ObservationIdentity)
            or self.observation.profile is not _PROFILE
            or type(self.raw) is not bytes
            or not 1 <= len(self.raw) <= 65_536
        ):
            raise ValueError("a bounded external paired15/ABI1.6 attestation is required")


@dataclass(frozen=True, slots=True)
class PairedFinePlan:
    """Explicit diagnostic timing plan; no inferred candidate or RF qualification.

    Offset names a source coordinate relative to the first actual pilot center.
    The caller supplies phase/cadence and coefficient generation. We do not
    invent detection seeds or infer a fine lock from successful packet delivery.
    """

    first_center_offset: int
    period_q32_32: int
    request_base: int
    count: int
    coefficient_generation: int

    def __post_init__(self) -> None:
        for name in (
            "first_center_offset",
            "period_q32_32",
            "request_base",
            "count",
            "coefficient_generation",
        ):
            if type(getattr(self, name)) is not int or getattr(self, name) <= 0:
                raise ValueError(f"{name} must be a positive integer")
        if self.count > 1024 or self.count % 16:
            raise ValueError("finite fine count must be <=1024 and divisible by16")
        if (
            self.request_base + self.count - 1 > 0xFFFFFFFF
            or self.coefficient_generation > 0xFFFFFFFF
            or not 1 << 32 <= self.period_q32_32 < 1 << 64
        ):
            raise ValueError("fine request/coefficient/period arithmetic exceeds its ABI")
        separation = ((self.count - 1) * self.period_q32_32) >> 32
        if separation < _MIN_COMMON:
            raise ValueError("fine anchor separation must span at least one source second")
        if (
            self.first_center_offset < 65_536
            or self.first_center_offset + separation + 1024 >= 6 * _SAMPLES
        ):
            raise ValueError("fine support and stop margin must fit the two-second pilot envelope")

    def manifest(self, observation: ObservationIdentity, first_center: int) -> FineScheduleManifest:
        return FineScheduleManifest(
            observation,
            f"paired-{observation.visit_id}",
            first_center + self.first_center_offset,
            self.period_q32_32,
            self.request_base,
            self.count,
            self.coefficient_generation,
        )


class PairedBackend(Protocol):
    """Composable real transport boundary; offline doubles cannot qualify hardware."""

    def attest(self, observation: ObservationIdentity) -> tuple[PssTrackerControlReceipt, ...]: ...
    def open_maps(self) -> None: ...
    def capture_pilot(
        self,
        observation: ObservationIdentity,
        events: queue.Queue[PilotCaptureEvent],
        cancelled: threading.Event,
    ) -> PilotCapture: ...
    def read_health(self) -> PssAcquisitionHealth: ...
    def read_maps(self) -> PssBatchReceipt: ...
    def stop(self, observation: ObservationIdentity, *, request: bool) -> PssMapStopOperation: ...
    def open_fine(self, manifest: FineScheduleManifest) -> PssFineStartReceipt: ...
    def read_fine(self) -> PssBatchReceipt: ...
    def fine_control(self, observation: ObservationIdentity) -> PssTrackerControlReceipt: ...
    def close(self) -> tuple[PssGracefulCloseReceipt, ...]: ...


class NativePairedBackend:
    """Three independently bounded public clients under one external owner.

    connect() performs real IIO operations only when explicitly called. Context
    construction retains libiio's connection timeout. No device discovery or
    automatic recovery/reopening occurs here.
    """

    def __init__(self, pilot: PilotIioClient, maps: PssIioClient, fine: PssIioClient) -> None:
        if len({id(pilot.context), id(maps.context), id(fine.context)}) != 3:
            raise ValueError("pilot, maps and fine must own distinct IIO contexts")
        self.pilot, self.maps, self.fine = pilot, maps, fine

    @classmethod
    def connect(
        cls, uri: str, observation: ObservationIdentity, *, iio_module: Any | None = None
    ) -> NativePairedBackend:
        if observation.profile is not _PROFILE:
            raise ValueError("only explicit shared15 boundary-stop observations are supported")
        clients: list[PilotIioClient | PssIioClient] = []
        try:
            maps = PssIioClient.connect(
                uri,
                expected_serial=observation.serial,
                iio_module=iio_module,
                experimental_shared_xfft=True,
                experimental_boundary_stop=True,
            )
            clients.append(maps)
            fine = PssIioClient.connect(
                uri,
                expected_serial=observation.serial,
                iio_module=iio_module,
                experimental_shared_xfft=True,
                experimental_boundary_stop=True,
            )
            clients.append(fine)
            pilot = PilotIioClient.connect(
                uri,
                expected_serial=observation.serial,
                expected_boot_id=observation.boot_id,
                source_rate_hz=observation.source_rate_hz,
                iio_module=iio_module,
            )
            clients.append(pilot)
            result = cls(pilot, maps, fine)
            result.attest(observation)
            return result
        except BaseException as error:
            for client in reversed(clients):
                try:
                    if isinstance(client, PssIioClient):
                        client.close_gracefully(readers_joined=True)
                    else:
                        client.close()
                except BaseException as cleanup:
                    error.add_note(f"paired failed-connect cleanup: {cleanup}")
            raise

    def attest(self, observation: ObservationIdentity) -> tuple[PssTrackerControlReceipt, ...]:
        for client in (self.pilot, self.maps, self.fine):
            attrs = {str(key): str(value) for key, value in client.context.attrs.items()}
            serials = [
                attrs[key] for key in ("hw_serial", "usb,serial", "serial") if attrs.get(key)
            ]
            if not serials or any(value != observation.serial for value in serials):
                raise ValueError("paired context serial aliases disagree with owner")
            if attrs.get("boot_id") != observation.boot_id:
                raise ValueError("paired context lacks the exact expected boot identity")
        controls = (
            self.maps.read_tracker_control(observation),
            self.fine.read_tracker_control(observation),
        )
        if any(not receipt.complete for receipt in controls):
            raise ValueError("paired context control/identity evidence is incomplete")
        return controls

    def open_maps(self) -> None:
        self.maps.open_maps(refill_chunks=200, batch_mode=True, timeout_ms=1000)

    def capture_pilot(
        self,
        observation: ObservationIdentity,
        events: queue.Queue[PilotCaptureEvent],
        cancelled: threading.Event,
    ) -> PilotCapture:
        return self.pilot.capture(
            visit_id=observation.visit_id,
            samples=_SAMPLES,
            refill_samples=_REFILL,
            timeout_ms=5000,
            progress_queue=events,
            cancel_event=cancelled,
        )

    def read_health(self) -> PssAcquisitionHealth:
        return self.maps.read_acquisition_health(timeout_ms=1000)

    def read_maps(self) -> PssBatchReceipt:
        return self.maps.read_map_batch(timeout_ms=1000)

    def stop(self, observation: ObservationIdentity, *, request: bool) -> PssMapStopOperation:
        if request:
            return self.maps.request_map_stop(
                observation, ticket=1, timeout_ms=1000, budget_ms=5000
            )
        return self.maps.read_map_stop(observation, timeout_ms=1000, budget_ms=5000)

    def open_fine(self, manifest: FineScheduleManifest) -> PssFineStartReceipt:
        return self.fine.open_fine_receipted(
            manifest, refill_results=16, timeout_ms=1000, budget_ms=5000
        )

    def read_fine(self) -> PssBatchReceipt:
        return self.fine.read_fine_batch(timeout_ms=1000)

    def fine_control(self, observation: ObservationIdentity) -> PssTrackerControlReceipt:
        return self.fine.read_tracker_control(observation, timeout_ms=1000, budget_ms=5000)

    def close(self) -> tuple[PssGracefulCloseReceipt, ...]:
        receipts: list[PssGracefulCloseReceipt] = []
        errors: list[BaseException] = []
        for client in (self.fine, self.maps):
            try:
                receipts.append(client.close_gracefully(readers_joined=True, timeout_ms=1000))
            except BaseException as error:
                errors.append(error)
                receipt = getattr(error, "receipt", None)
                if isinstance(receipt, PssGracefulCloseReceipt):
                    receipts.append(receipt)
        try:
            self.pilot.close()
        except BaseException as error:
            errors.append(error)
        if errors:
            interrupted = next(
                (error for error in errors if isinstance(error, (KeyboardInterrupt, SystemExit))),
                None,
            )
            if interrupted is not None:
                interrupted.paired_cleanup_receipts = tuple(receipts)  # type: ignore[union-attr]
                raise interrupted
            failure = RuntimeError("paired cleanup incomplete: " + "; ".join(map(str, errors)))
            failure.paired_cleanup_receipts = tuple(receipts)  # type: ignore[attr-defined]
            raise failure
        return tuple(receipts)


class _Journal:
    """Append-only file/dir-fsynced evidence. No preexisting output is replaced."""

    def __init__(self, path: Path) -> None:
        self.path = path.absolute()
        if self.path.resolve(strict=False) != self.path or not self.path.parent.is_dir():
            raise ValueError("new evidence directory must have an existing non-aliased parent")
        self.path.mkdir(exist_ok=False)
        self.lock = threading.RLock()
        self.ordinal = 0
        self.failed = False
        self._sync_dir(self.path.parent)

    @staticmethod
    def _sync_dir(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _file(self, name: str, raw: bytes) -> dict[str, Any]:
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,240}", name):
            raise ValueError("evidence filenames must be bounded basenames")
        path = self.path / name
        with path.open("xb") as target:
            if target.write(raw) != len(raw):
                raise OSError("short evidence write")
            target.flush()
            os.fsync(target.fileno())
        self._sync_dir(self.path)
        return {"path": name, "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

    def _encode(self, value: Any, prefix: str) -> Any:
        if isinstance(value, bytes):
            return {"artifact": self._file(prefix + ".bin", value)}
        if is_dataclass(value) and not isinstance(value, type):
            return {
                field.name: self._encode(getattr(value, field.name), prefix + "-" + field.name)
                for field in fields(value)
            }
        if isinstance(value, Enum):
            return value.value
        if isinstance(value, (tuple, list)):
            return [self._encode(item, f"{prefix}-{index}") for index, item in enumerate(value)]
        if isinstance(value, dict):
            return {
                str(key): self._encode(item, prefix + "-" + str(key)) for key, item in value.items()
            }
        if value is None or isinstance(value, (str, int, float, bool)):
            return value
        raise TypeError(f"unsupported evidence type: {type(value).__name__}")

    def put(self, kind: str, value: Any) -> dict[str, Any]:
        with self.lock:
            if self.failed:
                raise OSError("evidence journal is quarantined after a storage failure")
            prefix = f"{self.ordinal:05d}-{kind}"
            self.ordinal += 1
            try:
                document = self._encode(value, prefix)
                return self._file(
                    prefix + ".json",
                    (
                        json.dumps(document, sort_keys=True, allow_nan=False, separators=(",", ":"))
                        + "\n"
                    ).encode(),
                )
            except BaseException:
                self.failed = True
                raise


def _map_from_batch(batch: PssBatchReceipt, *, index: int, stream_id: str | None) -> PssPhaseMap:
    if (
        not isinstance(batch, PssBatchReceipt)
        or not batch.complete
        or batch.stream != "map"
        or batch.batch_index != index
        or batch.rate_msps != 15
        or batch.abi_version != 0x10006
        or batch.requested_scans != 200
        or batch.scan_bytes != 256
        or batch.buffer_step != 256
        or batch.buffer_bytes != 51200
        or batch.raw is None
        or len(batch.raw) != 51200
        or (stream_id is not None and batch.stream_id != stream_id)
    ):
        raise ValueError("map batch shape/stream/sequence is not the admitted one-map refill")
    for attrs in (batch.attributes_before, batch.attributes_after):
        if attrs is None or attrs.errors or attrs.fault_flags != 0:
            raise ValueError("map native batch has missing/failed health")
    assembler = PssMapReassembler()
    phase_map = None
    for ordinal in range(200):
        raw = batch.raw[ordinal * 256 : (ordinal + 1) * 256]
        if any(raw[236:]):
            raise ValueError("map native padding is nonzero")
        chunk = PssMapChunk.decode(
            raw[:236], allow_experimental_shared_xfft=True, allow_experimental_boundary_stop=True
        )
        if chunk != batch.scans[ordinal].decoded:
            raise ValueError("map scan differs from its retained raw bytes")
        phase_map = assembler.add(chunk)
    if phase_map is None:
        raise ValueError("map refill did not reassemble one complete map")
    return phase_map


def require_terminal_delivery(
    stop: PssMapStopReceipt, health: PssAcquisitionHealth, maps: tuple[PssPhaseMap, ...]
) -> None:
    """Published ticket -> serialized driver counters -> exact host prefix."""
    stop.require_boundary_complete(expected_ticket=1)
    if PssAcquisitionHealth.decode(health.raw) != health:
        raise ValueError("health fields differ from raw evidence")
    health.require_fault_free()
    if not maps or not stop.has_map:
        raise ValueError("paired terminal requires actual complete maps")
    if health.abi_version != 0x10006 or health.declared_rate_msps != 15:
        raise ValueError("terminal health is not the paired15 stop contract")
    for index, phase_map in enumerate(maps):
        if (
            phase_map.abi_version != 0x10006
            or phase_map.generation != index + 1
            or (index and phase_map.start_index != maps[index - 1].start_index + _MAP_SPAN)
        ):
            raise ValueError("terminal maps are not one exact ABI1.6 generation/source prefix")
    if (
        stop.terminal_generation != len(maps)
        or maps[-1].generation != len(maps)
        or stop.terminal_candidate_start != maps[-1].start_index
        or stop.terminal_candidate_end != maps[-1].start_index + _MAP_SPAN
        or health.words[7] != len(maps)
        or health.words[8] != len(maps) * 200
        or health.words[10]
        or health.acquisition_enabled
    ):
        raise ValueError("terminal publication, driver delivery, and host map prefix disagree")


@dataclass(frozen=True, slots=True)
class PairedCaptureReceipt:
    observation: ObservationIdentity
    output: Path
    finite_transport_complete: bool
    common_support: SourceInterval | None
    maps_received: int
    fine_results_received: int
    pilot_bytes_received: int
    errors: tuple[str, ...]
    cleanup_complete: bool
    unjoined_workers: tuple[str, ...]
    final_artifact: dict[str, Any] | None
    persistent_30_300_second_qualified: bool = False
    rf_or_lock_qualified: bool = False


class PairedCaptureError(RuntimeError):
    def __init__(self, receipt: PairedCaptureReceipt) -> None:
        super().__init__("finite paired recording incomplete: " + "; ".join(receipt.errors))
        self.receipt = receipt


class FinitePairedRecorder:
    """One invocation, two seconds of PIL1, >=one-second joined anchor envelope.

    The backend is exclusively transferred to this owner; nobody else may read
    or control its clients. On an unjoined native call, clients remain owned and
    quarantined here: never concurrently destroy them. A later explicit
    join_and_close() can finish cleanup, but cannot retroactively qualify data.
    """

    def __init__(
        self,
        backend: PairedBackend,
        observation: ObservationIdentity,
        fine_plan: PairedFinePlan,
        attest: Callable[[], PairedAttestation],
    ) -> None:
        if observation.profile is not _PROFILE or not callable(attest):
            raise ValueError("explicit paired15 stop profile and external attestor required")
        if not isinstance(fine_plan, PairedFinePlan):
            raise ValueError("an explicit finite fine plan is required")
        self.backend, self.observation, self.fine_plan, self.attest = (
            backend,
            observation,
            fine_plan,
            attest,
        )
        self.cancelled = threading.Event()
        self._cancel_requested = threading.Event()
        self._terminal_lock = threading.Lock()
        self._terminal_started = False
        self._used = False
        self._closed = False
        self._close_lock = threading.Lock()
        self._cleanup_error: BaseException | None = None
        self._threads: list[threading.Thread] = []
        self._cleanup: tuple[PssGracefulCloseReceipt, ...] = ()

    def cancel(self) -> bool:
        """Request cooperative cancellation before terminal sealing begins.

        False means the terminal decision has already been admitted. This short
        lock is never held across native IIO or disk writes. Internal shutdown
        uses a separate signal and cannot hide a late external cancellation.
        """
        with self._terminal_lock:
            if self._terminal_started:
                return False
            self._cancel_requested.set()
            self.cancelled.set()
            return True

    def join_and_close(
        self, *, timeout_seconds: float = 5.0
    ) -> tuple[PssGracefulCloseReceipt, ...]:
        if not 0 < timeout_seconds <= 60:
            raise ValueError("join timeout must be in (0,60] seconds")
        self.cancelled.set()
        deadline = time.monotonic() + timeout_seconds
        for worker in self._threads:
            worker.join(max(0, deadline - time.monotonic()))
        if any(worker.is_alive() for worker in self._threads):
            raise RuntimeError("native readers remain unjoined; no context was destroyed")
        with self._close_lock:
            if not self._closed:
                self._closed = True  # Never repeat native destruction after uncertain close.
                try:
                    self._cleanup = self.backend.close()
                except BaseException as error:
                    self._cleanup_error = error
            if self._cleanup_error is not None:
                raise self._cleanup_error
            return self._cleanup

    def record(self, output: Path, *, deadline_seconds: float = 10.0) -> PairedCaptureReceipt:
        if self._used or self._closed or self.cancelled.is_set():
            raise ValueError("recorder is cancelled or already used; map epoch cannot restart")
        if type(deadline_seconds) not in (int, float) or not 2 < deadline_seconds <= 60:
            raise ValueError("recording deadline must lie in (2,60] seconds")
        self._used = True
        journal = _Journal(output)
        events: queue.Queue[PilotCaptureEvent] = queue.Queue(maxsize=32)
        origin_ready = threading.Event()
        state_lock = threading.Lock()
        state: dict[str, Any] = {"maps": [], "fine_count": 0, "errors": []}
        interrupted: BaseException | None = None
        deadline = time.monotonic() + deadline_seconds
        persisted_iq_hash = hashlib.sha256()
        persisted_iq_bytes = 0
        event_identity = None
        armed_seen = False
        terminal_seen = False

        def check() -> None:
            if self.cancelled.is_set() or time.monotonic() >= deadline:
                raise TimeoutError("paired recording cancelled or deadline expired")

        def fail(label: str, error: BaseException) -> None:
            nonlocal interrupted
            self.cancelled.set()
            with state_lock:
                if isinstance(error, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                    interrupted = error
                state["errors"].append(f"{label}: {type(error).__name__}: {str(error)[:4096]}")
            retained: dict[str, Any] = {"type": type(error).__name__, "message": str(error)[:4096]}
            for name in (
                "receipt",
                "raw",
                "partial_iq",
                "snapshots",
                "cleanup_errors",
                "progress_errors",
                "pss_batch_raw",
                "pss_batch_receipt",
                "pss_fine_start_receipt",
                "paired_cleanup_receipts",
            ):
                value = getattr(error, name, None)
                if value is not None:
                    retained[name] = value
            try:
                journal.put(label + "-failure", retained)
            except BaseException as storage:
                with state_lock:
                    if isinstance(storage, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                        interrupted = storage
                    state["errors"].append(f"failure evidence persistence: {storage}")

        def worker(label: str, action: Callable[[], None]) -> None:
            try:
                action()
            except BaseException as error:
                fail(label, error)

        def wait_for(event: threading.Event) -> None:
            while not event.wait(0.01):
                check()
            check()

        def pilot_work() -> None:
            result = self.backend.capture_pilot(self.observation, events, self.cancelled)
            journal.put("pilot-authoritative", result)
            with state_lock:
                state["pilot"] = result

        def fine_work() -> None:
            wait_for(origin_ready)
            with state_lock:
                origin: PilotOriginEvent = state["origin"]
            manifest = self.fine_plan.manifest(self.observation, origin.first_source_center)
            control = self.backend.fine_control(self.observation)
            journal.put("fine-preflight", control)
            if (
                not control.complete
                or control.current_index is None
                or manifest.first_center < control.current_index + 65_536
                or control.value("packets_delivered") != 0
            ):
                raise ValueError("fine preflight lacks fresh epoch, health, or future lead")
            started = self.backend.open_fine(manifest)
            journal.put("fine-start", started)
            if not started.complete or started.manifest != manifest:
                raise ValueError("native fine startup incomplete")
            with state_lock:
                state["fine_manifest"] = manifest
            ledger = FineScheduleLedger(manifest)
            while ledger.state is FineLedgerState.ACTIVE:
                check()
                batch = self.backend.read_fine()
                journal.put("fine-raw-batch", batch)
                result = validate_fine_batch(ledger, batch, observation=self.observation)
                journal.put("fine-ledger", result)
                ledger = result.after
                with state_lock:
                    state["fine_count"] = ledger.accepted_count
                if not result.accepted:
                    raise ValueError("fine batch failed exact raw/request/support validation")
            terminal = self.backend.fine_control(self.observation)
            journal.put("fine-terminal", terminal)
            if (
                not terminal.complete
                or ledger.state is not FineLedgerState.COMPLETE
                or terminal.value("schedule_submitted") != manifest.count
                or terminal.value("packets_delivered") != manifest.count
                or any(
                    terminal.value(name) != 0
                    for name in (
                        "fault_flags",
                        "buffer_push_failures",
                        "packet_validation_failures",
                    )
                )
            ):
                raise ValueError("fine driver submission/delivery/health does not reconcile")
            with state_lock:
                state["fine_complete"] = True

        def map_work() -> None:
            stream_id = None
            requested = False
            while True:
                check()
                health = self.backend.read_health()
                journal.put("map-health", health)
                if PssAcquisitionHealth.decode(health.raw) != health:
                    raise ValueError("map health differs from raw receipt")
                health.require_fault_free()
                with state_lock:
                    maps = tuple(state["maps"])
                    manifest = state.get("fine_manifest")
                if (
                    health.words[7] < len(maps)
                    or health.words[7] > 40
                    or health.words[8] != health.words[7] * 200
                ):
                    raise ValueError(
                        "driver map delivery counters regressed or exceed finite bound"
                    )
                if (
                    not requested
                    and manifest is not None
                    and maps
                    and maps[-1].start_index + _MAP_SPAN
                    >= manifest.capture_at(manifest.count - 1).stop
                ):
                    operation = self.backend.stop(self.observation, request=True)
                    journal.put("stop-request", operation)
                    if not operation.complete or operation.observed_accepted_ticket != 1:
                        raise ValueError("stop request acceptance is unverified")
                    requested = True
                if requested:
                    operation = self.backend.stop(self.observation, request=False)
                    journal.put("stop-read", operation)
                    if not operation.complete or operation.after is None:
                        raise ValueError("stop observation incomplete")
                    terminal = operation.after
                    if terminal.failed or terminal.failure_reasons:
                        raise ValueError("stop retained a real hardware failure")
                    if terminal.terminal_valid:
                        terminal.require_boundary_complete(expected_ticket=1)
                        if terminal.terminal_generation < len(maps):
                            raise ValueError("host map prefix exceeds terminal generation")
                        if terminal.terminal_generation == len(maps):
                            # Refresh after terminal; an earlier health sample
                            # may precede the final IRQ/release accounting.
                            health = self.backend.read_health()
                            journal.put("map-terminal-health", health)
                            require_terminal_delivery(terminal, health, maps)
                            with state_lock:
                                state["stop"] = terminal
                                state["map_complete"] = True
                            return
                # Only issue a full-map native refill once the same-lock driver
                # receipt proves all200 chunks were enqueued. This avoids an
                # odd-terminal-map / nonexistent-second-map watermark wait.
                if health.words[7] > len(maps):
                    batch = self.backend.read_maps()
                    journal.put("map-raw-batch", batch)
                    phase_map = _map_from_batch(batch, index=len(maps), stream_id=stream_id)
                    if phase_map.generation != len(maps) + 1 or (
                        maps and phase_map.start_index != maps[-1].start_index + _MAP_SPAN
                    ):
                        raise ValueError("host map generations/source intervals are discontinuous")
                    journal.put("map-reassembled", phase_map)
                    stream_id = batch.stream_id
                    with state_lock:
                        state["maps"].append(phase_map)
                else:
                    self.cancelled.wait(0.005)

        try:
            external = self.attest()
            if (
                not isinstance(external, PairedAttestation)
                or external.observation != self.observation
            ):
                raise ValueError("external owner/boot/processing attestation mismatch")
            journal.put("owner-before", external)
            journal.put("context-before", self.backend.attest(self.observation))
            initial = self.backend.stop(self.observation, request=False)
            journal.put("stop-preflight", initial)
            if (
                not initial.complete
                or initial.after is None
                # A fresh epoch has NO state, ticket, historical bounds, fault
                # reason or rejected-command residue beyond its magic/version.
                or any(initial.after.words[2:])
            ):
                raise ValueError("one-shot recorder requires an unused stop/map reset epoch")
            self.backend.open_maps()  # This flushes; it MUST precede pilot ARM.
            for label, action in (("maps", map_work), ("fine", fine_work), ("pilot", pilot_work)):
                thread = threading.Thread(
                    target=worker, args=(label, action), name=f"paired-{label}", daemon=True
                )
                self._threads.append(thread)
                thread.start()
            while any(thread.is_alive() for thread in self._threads) or not events.empty():
                check()
                try:
                    event = events.get(timeout=0.02)
                except queue.Empty:
                    continue
                identity = event.identity
                if (
                    identity.serial != self.observation.serial
                    or identity.boot_id != self.observation.boot_id
                    or identity.visit_id != self.observation.visit_id
                    or identity.source_rate_hz != 15_000_000
                    or identity.requested_samples != _SAMPLES
                    or identity.refill_samples != _REFILL
                    or identity.output_rate_hz != 2_500_000
                    or (event_identity is not None and identity != event_identity)
                ):
                    raise ValueError("pilot event identity differs from the joined observation")
                event_identity = identity
                journal.put("pilot-progress", event)
                if terminal_seen:
                    raise ValueError("pilot progress arrived after terminal event")
                if isinstance(event, PilotArmedEvent):
                    if armed_seen:
                        raise ValueError("duplicate pilot ARM event")
                    armed_seen = True
                elif isinstance(event, PilotOriginEvent):
                    if not armed_seen or origin_ready.is_set():
                        raise ValueError("duplicate pilot origin")
                    if (
                        PilotSnapshot.decode(event.snapshot.raw) != event.snapshot
                        or event.received_samples != _REFILL
                    ):
                        raise ValueError("pilot origin does not bind raw snapshot and first refill")
                    with state_lock:
                        state["origin"] = event
                    origin_ready.set()
                elif isinstance(event, PilotIqChunkEvent):
                    if not origin_ready.is_set() or event.output_offset * 4 != persisted_iq_bytes:
                        raise ValueError("pilot durable progress has a missing/reordered prefix")
                    if len(event.iq) != _REFILL * 4:
                        raise ValueError("pilot progress is not one exact refill")
                    persisted_iq_hash.update(event.iq)
                    persisted_iq_bytes += len(event.iq)
                elif isinstance(event, PilotTerminalEvent):
                    terminal_seen = True
                    if (
                        not event.complete
                        or event.failure
                        or event.cleanup_errors
                        or event.progress_errors
                        or event.received_bytes != _SAMPLES * 4
                        or event.published_iq_bytes != persisted_iq_bytes
                        or event.iq_sha256 != persisted_iq_hash.hexdigest()
                    ):
                        raise ValueError("pilot terminal event contradicts its durable prefix")
            check()
        except BaseException as error:
            fail("recorder", error)

        common = None
        try:
            check()
            if state["errors"]:
                raise ValueError("one or more producer/storage/control operations failed")
            result = state.get("pilot")
            manifest = state.get("fine_manifest")
            if (
                not isinstance(result, PilotCapture)
                or not isinstance(manifest, FineScheduleManifest)
                or not state.get("map_complete")
                or not state.get("fine_complete")
                or result.serial != self.observation.serial
                or result.boot_id != self.observation.boot_id
                or result.visit_id != self.observation.visit_id
                or result.source_rate_hz != 15_000_000
                or event_identity is None
                or result.session_id != event_identity.session_id
                or result.snapshot_origin is None
                or "origin" not in state
                or result.snapshot_origin != state["origin"].snapshot
                or not terminal_seen
                or len(result.iq) != _SAMPLES * 4
                or persisted_iq_bytes != len(result.iq)
                or persisted_iq_hash.hexdigest() != result.iq_sha256
                or hashlib.sha256(result.iq).hexdigest() != result.iq_sha256
            ):
                raise ValueError(
                    "joint producer completion or persisted pilot prefix is incomplete"
                )
            pilot = pilot_slice_support(
                result.snapshot_final,
                observation=self.observation,
                expected_samples=_SAMPLES,
                received_bytes=len(result.iq),
                start=0,
                stop=_SAMPLES,
            )
            # An unknown FFT origin can make the initial conservative history
            # underflow. Keep that complete map explicitly unobservable; never
            # clamp the missing history into a qualifying support interval.
            supports = [
                map_support(item, observation=self.observation)
                for item in state["maps"]
                if item.start_index >= 446
            ]
            journal.put(
                "map-history-unobservable",
                [item.generation for item in state["maps"] if item.start_index < 446],
            )
            admitted = [
                item for item in supports if pilot.raw_inputs.contains(item.processing_inputs)
            ]
            if not admitted:
                raise ValueError(
                    "no complete map processing envelope lies within pilot raw support"
                )
            coarse = SourceInterval(
                admitted[0].candidate_starts.start, admitted[-1].candidate_starts.stop
            )
            fine_envelope = SourceInterval(
                manifest.capture_at(0).start, manifest.capture_at(manifest.count - 1).stop
            )
            if not pilot.raw_inputs.contains(fine_envelope) or not coarse.contains(fine_envelope):
                raise ValueError("complete fine-search support lies outside paired coverage")
            anchors = SourceInterval(
                manifest.center_at(0), manifest.center_at(manifest.count - 1) + 1
            )
            common = coarse.intersection(pilot.centers.bounds)
            common = common.intersection(anchors) if common is not None else None
            if common is None or common.samples < _MIN_COMMON:
                raise ValueError(
                    "actual common map/pilot/fine anchor envelope is less than one second"
                )
            journal.put(
                "joined-support",
                {
                    "common_anchor_envelope": common,
                    "pilot": pilot,
                    "maps": supports,
                    "fine_manifest": manifest,
                    "fine_samples_are_sparse_search_windows_not_continuous_iq": True,
                },
            )
            journal.put("context-after", self.backend.attest(self.observation))
            check()
        except BaseException as error:
            fail("qualification", error)

        cleanup_complete = False
        try:
            cleanup = self.join_and_close()
            journal.put("joined-cleanup", cleanup)
            if any(item.errors or item.native_cancel_used for item in cleanup):
                raise ValueError("joined native cleanup receipt is incomplete")
            external = self.attest()
            if (
                not isinstance(external, PairedAttestation)
                or external.observation != self.observation
            ):
                raise ValueError("post-cleanup external owner/boot/processing attestation changed")
            journal.put("owner-after", external)
            cleanup_complete = True
        except BaseException as error:
            fail("cleanup", error)
        unjoined = tuple(thread.name for thread in self._threads if thread.is_alive())
        pilot_result = state.get("pilot")
        count = (
            len(pilot_result.iq) if isinstance(pilot_result, PilotCapture) else persisted_iq_bytes
        )
        with self._terminal_lock:
            self._terminal_started = True
            if self._cancel_requested.is_set():
                state["errors"].append("external cancellation accepted before terminal sealing")
            if time.monotonic() >= deadline:
                state["errors"].append("recording deadline expired before terminal sealing")
        errors = tuple(state["errors"])
        complete = not errors and cleanup_complete and not unjoined and common is not None
        final_artifact = None
        try:
            final_artifact = journal.put(
                "terminal",
                {
                    "status": "FINITE_PAIRED_TRANSPORT_COMPLETE" if complete else "INCOMPLETE",
                    "observation": self.observation,
                    "common_anchor_envelope": common,
                    "maps_received": len(state["maps"]),
                    "fine_results_received": state["fine_count"],
                    "pilot_bytes_received": count,
                    "errors": errors,
                    "cleanup_complete": cleanup_complete,
                    "unjoined_workers": unjoined,
                    "persistent_30_300_second_qualified": False,
                    "rf_or_lock_qualified": False,
                    "fine_is_not_continuous_iq": True,
                    "rf_retuning_or_coefficient_writes_performed": False,
                    "scheduler_configuration_restored": False,
                },
            )
        except BaseException as error:
            errors += (f"terminal persistence: {error}",)
            complete = False
            if isinstance(error, (KeyboardInterrupt, SystemExit)) and interrupted is None:
                interrupted = error
        receipt = PairedCaptureReceipt(
            self.observation,
            journal.path,
            complete,
            common,
            len(state["maps"]),
            state["fine_count"],
            count,
            errors,
            cleanup_complete,
            unjoined,
            final_artifact,
        )
        if interrupted is not None:
            interrupted.paired_capture_receipt = receipt  # type: ignore[attr-defined]
            interrupted.add_note(f"Partial paired recording retained at {journal.path}")
            raise interrupted
        if not complete:
            raise PairedCaptureError(receipt)
        return receipt
