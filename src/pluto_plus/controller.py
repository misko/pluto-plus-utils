"""Exclusive per-radio ownership, capture lifecycle, and live spectrum fan-out."""

from __future__ import annotations

import os
import queue
import shutil
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from pluto_plus.artifacts import CaptureWriter
from pluto_plus.catalog import Catalog
from pluto_plus.errors import (
    RadioBusyError,
    RadioConfigurationError,
    RadioSetupRequiredError,
    RevisionConflictError,
)
from pluto_plus.hardware.base import RadioDevice, SampleBlock, restore_settings_exact
from pluto_plus.models import (
    JobState,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    ScanJob,
    ScanPoint,
    ScanRequest,
    ScanResult,
    SettingsPatch,
    SpectrumFrame,
    StreamJob,
    StreamRequest,
    Transport,
    utc_now,
)
from pluto_plus.radio_lock import acquire_radio_lock


class SpectrumSubscription:
    def __init__(
        self,
        broker: SpectrumBroker,
        subscription_id: str,
        frames: queue.Queue[SpectrumFrame],
    ) -> None:
        self._broker = broker
        self._subscription_id = subscription_id
        self.frames = frames

    def close(self) -> None:
        self._broker.unsubscribe(self._subscription_id)

    def __enter__(self) -> SpectrumSubscription:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()


class SpectrumBroker:
    """Bounded latest-frame fan-out; consumers can never block acquisition."""

    def __init__(self, *, max_subscribers: int = 64) -> None:
        if max_subscribers < 1:
            raise ValueError("max_subscribers must be positive")
        self._lock = threading.Lock()
        self._subscribers: dict[str, queue.Queue[SpectrumFrame]] = {}
        self._max_subscribers = max_subscribers

    def subscribe(self) -> SpectrumSubscription:
        subscription_id = uuid.uuid4().hex
        frames: queue.Queue[SpectrumFrame] = queue.Queue(maxsize=2)
        with self._lock:
            if len(self._subscribers) >= self._max_subscribers:
                raise RadioBusyError("live spectrum subscriber limit reached")
            self._subscribers[subscription_id] = frames
        return SpectrumSubscription(self, subscription_id, frames)

    def unsubscribe(self, subscription_id: str) -> None:
        with self._lock:
            self._subscribers.pop(subscription_id, None)

    def publish(self, frame: SpectrumFrame) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers.values())
        for frames in subscribers:
            try:
                frames.put_nowait(frame)
            except queue.Full:
                with suppress(queue.Empty):
                    frames.get_nowait()
                with suppress(queue.Full):
                    frames.put_nowait(frame)


@dataclass(slots=True)
class _ActiveStream:
    job_id: str
    request: StreamRequest
    stop: threading.Event
    thread: threading.Thread


@dataclass(slots=True)
class _ActiveScan:
    job_id: str
    stop: threading.Event
    thread: threading.Thread


class RadioController:
    def __init__(
        self,
        device: RadioDevice,
        artifact_root: Path,
        catalog: Catalog,
        *,
        capture_free_bytes: Callable[[Path], int] | None = None,
        capture_reserve_bytes: int = 64 * 1024 * 1024,
        max_in_memory_jobs: int = 256,
        shutdown_timeout_s: float = 15,
        max_spectrum_subscribers: int = 64,
        radio_lock_root: Path | None = None,
    ) -> None:
        if capture_reserve_bytes < 0:
            raise ValueError("capture_reserve_bytes cannot be negative")
        if max_in_memory_jobs < 1:
            raise ValueError("max_in_memory_jobs must be positive")
        if shutdown_timeout_s < 0:
            raise ValueError("shutdown_timeout_s cannot be negative")
        self._device = device
        self._artifact_root = artifact_root
        self._artifact_root.mkdir(parents=True, exist_ok=True)
        self._catalog = catalog
        self._lock = threading.RLock()
        self._device_lock = threading.Lock()
        self._broker = SpectrumBroker(max_subscribers=max_spectrum_subscribers)
        self._capture_free_bytes = capture_free_bytes or _filesystem_free_bytes
        self._capture_reserve_bytes = capture_reserve_bytes
        self._max_in_memory_jobs = max_in_memory_jobs
        self._shutdown_timeout_s = shutdown_timeout_s
        self._revision = 0
        self._state = RadioState.OFFLINE
        self._requested = RadioSettings()
        self._actual = RadioSettings()
        self._last_error: str | None = None
        self._setup_required = False
        self._setup_diagnostic_facts: dict[str, object] = {}
        self._active: _ActiveStream | None = None
        self._active_scan: _ActiveScan | None = None
        self._radio_lock_manager: Any | None = None
        self._jobs = {
            job.job_id: job
            for job in self._catalog.list_stream_jobs(self._device.identity.radio_id)[
                :max_in_memory_jobs
            ]
        }
        self._scan_jobs = {
            job.job_id: job
            for job in self._catalog.list_scan_jobs(self._device.identity.radio_id)[
                :max_in_memory_jobs
            ]
        }
        if radio_lock_root is not None and self._device.identity.transport in {
            Transport.IIO_USB,
            Transport.DIRECT_USB,
        }:
            self._radio_lock_manager = acquire_radio_lock(
                self._device.identity.serial,
                root=radio_lock_root,
            )
            self._radio_lock_manager.__enter__()
        try:
            self._open()
        except BaseException:
            self._release_radio_lock()
            raise

    @property
    def radio_id(self) -> str:
        return self._device.identity.radio_id

    @property
    def broker(self) -> SpectrumBroker:
        return self._broker

    def snapshot(self) -> RadioSnapshot:
        with self._lock:
            return RadioSnapshot(
                identity=self._device.identity,
                capabilities=self._device.capabilities,
                state=self._state,
                revision=self._revision,
                requested_settings=self._requested,
                actual_settings=self._actual,
                activity_id=(
                    self._active.job_id
                    if self._active is not None
                    else (None if self._active_scan is None else self._active_scan.job_id)
                ),
                last_error=self._last_error,
                updated_at=utc_now(),
            )

    def diagnostic_facts(self) -> dict[str, object]:
        """Return device-specific passive facts without changing radio state."""

        with self._lock:
            if self._setup_required:
                return dict(self._setup_diagnostic_facts)
        reader = getattr(self._device, "diagnostic_facts", None)
        if not callable(reader):
            return {}
        facts = reader()
        return dict(facts) if isinstance(facts, dict) else dict(facts)

    @property
    def setup_required(self) -> bool:
        """Whether startup safely identified a radio needing canonical setup."""

        with self._lock:
            return self._setup_required

    def update_settings(self, patch: SettingsPatch) -> RadioSnapshot:
        with self._lock:
            if patch.expected_revision != self._revision:
                raise RevisionConflictError(
                    f"expected revision {patch.expected_revision}, "
                    f"current revision is {self._revision}"
                )
            if self._state not in (RadioState.READY, RadioState.STREAMING):
                raise RadioBusyError(f"radio cannot be configured while {self._state}")
            if (
                self._state is RadioState.STREAMING
                and self._active is not None
                and self._active.request.persist
                and any(
                    getattr(patch, field) is not None
                    for field in (
                        "center_frequency_hz",
                        "sample_rate_hz",
                        "bandwidth_hz",
                        "channels",
                    )
                )
            ):
                raise RadioBusyError(
                    "persistent capture locks frequency, sample rate, bandwidth, and channels"
                )
            previous_state = self._state
            if previous_state is RadioState.READY:
                self._state = RadioState.CONFIGURING
            requested = _merge_settings(self._requested, patch)
        try:
            with self._device_lock:
                actual = self._device.apply_settings(requested)
            _validate_readback(requested, actual)
        except Exception as error:
            with self._lock:
                self._state = previous_state
                self._last_error = f"{type(error).__name__}: {error}"
            raise RadioConfigurationError(str(error)) from error
        with self._lock:
            self._requested = requested
            self._actual = actual
            self._revision += 1
            self._state = previous_state
            self._last_error = None
            return self.snapshot()

    def start_stream(self, request: StreamRequest) -> StreamJob:
        with self._lock:
            if self._state is not RadioState.READY or self._active is not None:
                raise RadioBusyError(f"radio cannot start a stream while {self._state}")
            if request.persist:
                self._admit_persistent_capture(request)
            job_id = uuid.uuid4().hex
            now = utc_now()
            job = StreamJob(
                job_id=job_id,
                radio_id=self.radio_id,
                state=JobState.RUNNING,
                persist=request.persist,
                created_at=now,
                started_at=now,
            )
            stop = threading.Event()
            thread = threading.Thread(
                target=self._run_stream,
                args=(job_id, request, stop),
                name=f"pluto-stream-{self.radio_id}",
                daemon=True,
            )
            self._catalog.put_stream_job(job)
            self._prune_jobs(self._jobs)
            self._jobs[job_id] = job
            self._active = _ActiveStream(job_id, request, stop, thread)
            self._state = RadioState.STREAMING
            thread.start()
            return job

    def stop_stream(self) -> StreamJob:
        with self._lock:
            active = self._active
            if active is None:
                raise RadioBusyError("radio has no active stream")
            active.stop.set()
            thread = active.thread
            job_id = active.job_id
        thread.join(timeout=self._shutdown_timeout_s)
        if thread.is_alive():
            raise RadioBusyError(
                f"radio stream did not stop within {self._shutdown_timeout_s:g} seconds"
            )
        return self.get_job(job_id)

    def release_preview(self, job_id: str) -> bool:
        """Stop only the exact active non-persistent preview owned by a UI page.

        The idempotent false result is deliberate: a delayed page-unload beacon
        must never stop a newer preview or a bounded persistent capture.
        """

        with self._lock:
            active = self._active
            if active is None or active.job_id != job_id or active.request.persist:
                return False
            active.stop.set()
            thread = active.thread
        thread.join(timeout=self._shutdown_timeout_s)
        if thread.is_alive():
            raise RadioBusyError(
                f"radio preview did not stop within {self._shutdown_timeout_s:g} seconds"
            )
        return True

    def get_job(self, job_id: str) -> StreamJob:
        with self._lock:
            job = self._jobs.get(job_id)
        if job is None:
            job = self._catalog.get_stream_job(job_id)
        if job is None or job.radio_id != self.radio_id:
            raise KeyError(f"unknown stream job: {job_id}")
        return job

    def list_jobs(self) -> list[StreamJob]:
        return self._catalog.list_stream_jobs(self.radio_id)

    def start_scan(self, request: ScanRequest) -> ScanJob:
        with self._lock:
            if self._state is not RadioState.READY or self._active_scan is not None:
                raise RadioBusyError(f"radio cannot start a scan while {self._state}")
            job_id = uuid.uuid4().hex
            now = utc_now()
            job = ScanJob(
                job_id=job_id,
                radio_id=self.radio_id,
                state=JobState.RUNNING,
                created_at=now,
                started_at=now,
            )
            stop = threading.Event()
            thread = threading.Thread(
                target=self._run_scan,
                args=(job_id, request, stop),
                name=f"pluto-scan-{self.radio_id}",
                daemon=True,
            )
            self._catalog.put_scan_job(job)
            self._prune_jobs(self._scan_jobs)
            self._scan_jobs[job_id] = job
            self._active_scan = _ActiveScan(job_id, stop, thread)
            self._state = RadioState.SCANNING
            thread.start()
            return job

    def stop_scan(self) -> ScanJob:
        with self._lock:
            active = self._active_scan
            if active is None:
                raise RadioBusyError("radio has no active scan")
            active.stop.set()
            thread = active.thread
            job_id = active.job_id
        thread.join(timeout=self._shutdown_timeout_s)
        if thread.is_alive():
            raise RadioBusyError(
                f"radio scan did not stop within {self._shutdown_timeout_s:g} seconds"
            )
        return self.get_scan_job(job_id)

    def get_scan_job(self, job_id: str) -> ScanJob:
        with self._lock:
            job = self._scan_jobs.get(job_id)
        if job is None:
            job = self._catalog.get_scan_job(job_id)
        if job is None or job.radio_id != self.radio_id:
            raise KeyError(f"unknown scan job: {job_id}")
        return job

    def list_scan_jobs(self) -> list[ScanJob]:
        return self._catalog.list_scan_jobs(self.radio_id)

    def prepare_firmware_mutation(self) -> None:
        """Quiesce this controller after a firmware plan has been re-attested."""

        self.prepare_radio_mutation()

    def prepare_radio_mutation(self) -> None:
        """Quiesce this controller for an authorized exact-radio mutation."""

        with self._lock:
            if self._state is not RadioState.READY:
                raise RadioBusyError(f"radio cannot enter firmware mode while {self._state}")
            self._state = RadioState.FLASHING
            self._last_error = None
        try:
            with self._device_lock:
                self._device.close()
        except Exception as error:
            with self._lock:
                self._state = RadioState.ERROR
                self._last_error = f"{type(error).__name__}: {error}"
            raise

    def prepare_setup_mutation(self) -> None:
        """Quiesce a ready radio or one degraded solely for canonical setup."""

        with self._lock:
            if self._state is RadioState.READY:
                pass
            elif self._state is RadioState.ERROR and self._setup_required:
                self._state = RadioState.FLASHING
                self._last_error = None
                return
            else:
                raise RadioBusyError(f"radio cannot enter setup mode while {self._state}")
        self.prepare_radio_mutation()

    def recover_after_firmware_mutation(self) -> None:
        """Reopen and re-attest the radio after any authorized mutation attempt."""

        self.recover_after_radio_mutation()

    def recover_after_radio_mutation(self, *, require_paired_rx: bool = False) -> None:
        """Reopen, re-attest, and optionally prove one paired dual-RX read."""

        with self._lock:
            if self._state is not RadioState.FLASHING:
                raise RadioBusyError(f"radio cannot recover from firmware while {self._state}")
            self._state = RadioState.VERIFYING
            expected_serial = self._device.identity.serial
        try:
            with self._device_lock:
                self._device.open()
                actual = self._device.read_settings()
                if require_paired_rx:
                    if set(actual.channels) != {0, 1}:
                        raise RadioConfigurationError(
                            "canonical setup verification requires both receiver channels"
                        )
                    block = self._device.read_block(1024)
                    if block.samples.shape != (2, 1024):
                        raise RadioConfigurationError(
                            "canonical setup paired receiver verification returned "
                            f"{block.samples.shape}, expected (2, 1024)"
                        )
            if self._device.identity.serial != expected_serial:
                raise RadioConfigurationError(
                    f"reopened serial {self._device.identity.serial!r}, "
                    f"expected {expected_serial!r}"
                )
        except Exception as error:
            with self._lock:
                self._state = RadioState.ERROR
                self._last_error = f"{type(error).__name__}: {error}"
            raise
        with self._lock:
            self._requested = actual
            self._actual = actual
            self._revision += 1
            self._state = RadioState.READY
            self._last_error = None
            self._setup_required = False
            self._setup_diagnostic_facts = {}

    def recover(self) -> RadioSnapshot:
        """Close stale resources and reopen an errored/offline radio by exact identity."""

        with self._lock:
            if self._state not in (RadioState.ERROR, RadioState.OFFLINE):
                raise RadioBusyError(f"radio cannot recover while {self._state}")
            if self._active is not None or self._active_scan is not None:
                raise RadioBusyError("radio activity has not quiesced for recovery")
            expected_serial = self._device.identity.serial
            self._state = RadioState.RECOVERING
        try:
            with self._device_lock:
                self._device.close()
                self._device.open()
                actual = self._device.read_settings()
            if self._device.identity.serial != expected_serial:
                raise RadioConfigurationError(
                    f"recovered serial {self._device.identity.serial!r}, "
                    f"expected {expected_serial!r}"
                )
        except Exception as error:
            with self._lock:
                self._state = RadioState.ERROR
                self._last_error = f"{type(error).__name__}: {error}"
            raise RadioConfigurationError(str(error)) from error
        with self._lock:
            self._requested = actual
            self._actual = actual
            self._revision += 1
            self._state = RadioState.READY
            self._last_error = None
            self._setup_required = False
            self._setup_diagnostic_facts = {}
            return self.snapshot()

    def close(self) -> None:
        with self._lock:
            active = self._active
            active_scan = self._active_scan
            if active is not None:
                active.stop.set()
                thread = active.thread
            else:
                thread = None
            if active_scan is not None:
                active_scan.stop.set()
                scan_thread = active_scan.thread
            else:
                scan_thread = None
        if thread is not None:
            thread.join(timeout=self._shutdown_timeout_s)
        if scan_thread is not None:
            scan_thread.join(timeout=self._shutdown_timeout_s)
        alive = [
            name
            for name, worker in (("stream", thread), ("scan", scan_thread))
            if worker is not None and worker.is_alive()
        ]
        if alive:
            with self._lock:
                self._state = RadioState.ERROR
                self._last_error = f"shutdown timed out waiting for {', '.join(alive)} worker"
            raise RadioBusyError(self._last_error)
        with self._device_lock:
            self._device.close()
        with self._lock:
            self._state = RadioState.OFFLINE
        self._release_radio_lock()

    def _release_radio_lock(self) -> None:
        manager, self._radio_lock_manager = self._radio_lock_manager, None
        if manager is not None:
            manager.__exit__(None, None, None)

    def _open(self) -> None:
        try:
            with self._device_lock:
                self._device.open()
                settings = self._device.read_settings()
        except RadioSetupRequiredError as error:
            reader = getattr(self._device, "diagnostic_facts", None)
            facts = reader() if callable(reader) else {}
            self._setup_diagnostic_facts = (
                dict(facts) if isinstance(facts, Mapping) else {}
            )
            with suppress(Exception), self._device_lock:
                self._device.close()
            self._state = RadioState.ERROR
            self._last_error = f"{type(error).__name__}: {error}"
            self._setup_required = True
            return
        except Exception as error:
            with suppress(Exception), self._device_lock:
                self._device.close()
            self._state = RadioState.ERROR
            self._last_error = f"{type(error).__name__}: {error}"
            raise
        self._requested = settings
        self._actual = settings
        self._state = RadioState.READY
        self._setup_required = False
        self._setup_diagnostic_facts = {}

    def _run_stream(self, job_id: str, request: StreamRequest, stop: threading.Event) -> None:
        writer: CaptureWriter | None = None
        try:
            with self._lock:
                initial_settings = self._actual
            if request.persist:
                writer = CaptureWriter(
                    self._artifact_root,
                    radio=self._device.identity,
                    settings=initial_settings,
                    label=request.label,
                )
            target_samples = request.sample_count
            if target_samples is None and request.duration_s is not None:
                target_samples = round(request.duration_s * initial_settings.sample_rate_hz)
            captured = 0
            sequence = 0
            last_publish = 0.0
            while not stop.is_set() and (target_samples is None or captured < target_samples):
                count = request.block_size
                if target_samples is not None:
                    count = min(count, target_samples - captured)
                with self._device_lock:
                    block = self._device.read_block(count)
                with self._lock:
                    settings = self._actual
                    revision = self._revision
                if writer is not None:
                    writer.append(block, settings, revision)
                now = time.monotonic()
                if block.samples.shape[1] >= 256 and (sequence == 0 or now - last_publish >= 0.05):
                    self._broker.publish(
                        spectrum_frame(
                            block,
                            radio_id=self.radio_id,
                            activity_id=job_id,
                            sequence=sequence,
                            revision=revision,
                            settings=settings,
                            fft_size=min(request.fft_size, block.samples.shape[1]),
                        )
                    )
                    last_publish = now
                captured += block.samples.shape[1]
                sequence += 1
            artifact = None if writer is None else writer.finalize()
            if artifact is not None:
                self._catalog.put_artifact(artifact)
            with self._lock:
                current = self._jobs[job_id]
                completed = current.model_copy(
                    update={
                        "state": JobState.CANCELED if stop.is_set() else JobState.COMPLETE,
                        "finished_at": utc_now(),
                        "artifact_id": None if artifact is None else artifact.artifact_id,
                    }
                )
                self._catalog.put_stream_job(completed)
                self._jobs[job_id] = completed
                self._last_error = None
        except Exception as error:
            if writer is not None:
                writer.fail(error)
            with self._lock:
                current = self._jobs[job_id]
                failed = current.model_copy(
                    update={
                        "state": JobState.FAILED,
                        "finished_at": utc_now(),
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
                with suppress(Exception):
                    self._catalog.put_stream_job(failed)
                self._jobs[job_id] = failed
                self._last_error = f"{type(error).__name__}: {error}"
                self._state = RadioState.ERROR
        finally:
            with self._lock:
                if self._active is not None and self._active.job_id == job_id:
                    self._active = None
                if self._state is RadioState.STREAMING:
                    self._state = RadioState.READY

    def _run_scan(self, job_id: str, request: ScanRequest, stop: threading.Event) -> None:
        with self._lock:
            original = self._actual
        points: list[ScanPoint] = []
        restored = False
        try:
            point_count = int(
                (request.stop_frequency_hz - request.start_frequency_hz) // request.step_hz
            ) + 1
            for index in range(point_count):
                if stop.is_set():
                    break
                center = request.start_frequency_hz + index * request.step_hz
                settings = RadioSettings(
                    center_frequency_hz=center,
                    sample_rate_hz=request.sample_rate_hz,
                    bandwidth_hz=request.bandwidth_hz,
                    gain_mode=request.gain_mode,
                    gain_db=request.gain_db,
                    channels=request.channels,
                )
                with self._device_lock:
                    actual = self._device.apply_settings(settings)
                    _validate_readback(settings, actual)
                    for _discard in range(request.settle_buffers):
                        self._device.read_block(request.samples_per_frequency)
                    block = self._device.read_block(request.samples_per_frequency)
                with self._lock:
                    self._requested = settings
                    self._actual = actual
                    self._revision += 1
                points.append(_scan_point(block, actual, request.fft_size))
            with self._device_lock:
                restored_actual = restore_settings_exact(self._device, original).restored
            restored = True
            with self._lock:
                self._requested = original
                self._actual = restored_actual
                self._revision += 1
            scan_id = uuid.uuid4().hex
            destination = self._artifact_root.parent / "scans" / f"{scan_id}.json"
            destination.parent.mkdir(parents=True, exist_ok=True)
            result = ScanResult(
                scan_id=scan_id,
                radio_id=self.radio_id,
                created_at=self._scan_jobs[job_id].created_at,
                finished_at=utc_now(),
                request=request,
                points=tuple(points),
                path=str(destination),
            )
            temporary = destination.with_suffix(".json.partial")
            with temporary.open("x", encoding="utf-8") as stream:
                stream.write(result.model_dump_json(indent=2) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, destination)
            _fsync_directory(destination.parent)
            self._catalog.put_scan(result)
            with self._lock:
                current = self._scan_jobs[job_id]
                completed = current.model_copy(
                    update={
                        "state": JobState.CANCELED if stop.is_set() else JobState.COMPLETE,
                        "finished_at": utc_now(),
                        "scan_id": scan_id,
                    }
                )
                self._catalog.put_scan_job(completed)
                self._scan_jobs[job_id] = completed
                self._last_error = None
        except Exception as error:
            if not restored:
                try:
                    with self._device_lock:
                        restored_actual = restore_settings_exact(self._device, original).restored
                    with self._lock:
                        self._requested = original
                        self._actual = restored_actual
                        self._revision += 1
                    restored = True
                except Exception as restore_error:
                    error = RuntimeError(
                        f"scan failed: {error}; settings restore failed: {restore_error}"
                    )
            with self._lock:
                current = self._scan_jobs[job_id]
                failed = current.model_copy(
                    update={
                        "state": JobState.FAILED,
                        "finished_at": utc_now(),
                        "error": f"{type(error).__name__}: {error}",
                    }
                )
                with suppress(Exception):
                    self._catalog.put_scan_job(failed)
                self._scan_jobs[job_id] = failed
                self._last_error = f"{type(error).__name__}: {error}"
                if not restored:
                    self._state = RadioState.ERROR
        finally:
            with self._lock:
                if self._active_scan is not None and self._active_scan.job_id == job_id:
                    self._active_scan = None
                if self._state is RadioState.SCANNING:
                    self._state = RadioState.READY

    def _admit_persistent_capture(self, request: StreamRequest) -> None:
        settings = self._actual
        sample_count = request.sample_count
        if sample_count is None:
            assert request.duration_s is not None
            sample_count = round(request.duration_s * settings.sample_rate_hz)
        required = sample_count * len(settings.channels) * 4 + self._capture_reserve_bytes
        available = self._capture_free_bytes(self._artifact_root)
        if available < required:
            raise RadioBusyError(
                "insufficient capture storage: "
                f"requires {required} bytes including reserve, {available} available"
            )

    def _prune_jobs(self, jobs: dict[str, StreamJob] | dict[str, ScanJob]) -> None:
        excess = len(jobs) - self._max_in_memory_jobs + 1
        if excess <= 0:
            return
        terminal = sorted(
            (job for job in jobs.values() if job.state not in (JobState.PENDING, JobState.RUNNING)),
            key=lambda item: item.created_at,
        )
        for job in terminal[:excess]:
            jobs.pop(job.job_id, None)


def _merge_settings(current: RadioSettings, patch: SettingsPatch) -> RadioSettings:
    changes = {
        name: getattr(patch, name)
        for name in patch.model_fields_set
        if name != "expected_revision"
    }
    gain_mode = changes.get("gain_mode")
    if gain_mode is not None and "gain_db" not in changes:
        changes["gain_db"] = None if gain_mode != "manual" else current.gain_db
    document = current.model_dump()
    document.update(changes)
    return RadioSettings.model_validate(document)


def _validate_readback(requested: RadioSettings, actual: RadioSettings) -> None:
    numeric_fields = ("center_frequency_hz", "sample_rate_hz", "bandwidth_hz")
    for field in numeric_fields:
        expected = float(getattr(requested, field))
        observed = float(getattr(actual, field))
        tolerance = max(1.0, abs(expected) * 1e-6)
        if abs(expected - observed) > tolerance:
            raise RadioConfigurationError(
                f"{field} readback mismatch: requested {expected}, observed {observed}"
            )
    if requested.gain_mode != actual.gain_mode:
        raise RadioConfigurationError("gain mode readback mismatch")
    if requested.channels != actual.channels:
        raise RadioConfigurationError("receiver channel readback mismatch")
    if (
        requested.gain_db is not None
        and actual.gain_db is not None
        and abs(requested.gain_db - actual.gain_db) > 0.25
    ):
        raise RadioConfigurationError("manual gain readback mismatch")


def spectrum_frame(
    block: SampleBlock,
    *,
    radio_id: str,
    activity_id: str,
    sequence: int,
    revision: int,
    settings: RadioSettings,
    fft_size: int,
) -> SpectrumFrame:
    if fft_size < 2:
        raise ValueError("spectrum frame requires at least two samples")
    fft_size = 1 << (fft_size.bit_length() - 1)
    window = np.hanning(fft_size).astype(np.float32)
    scale = float(np.sum(window * window))
    rows = []
    for receiver in block.samples:
        transformed = np.fft.fftshift(np.fft.fft(receiver[:fft_size] * window))
        power = 10 * np.log10(np.abs(transformed) ** 2 / scale + np.finfo(float).tiny)
        rows.append(tuple(float(value) for value in power.astype(np.float32)))
    return SpectrumFrame(
        radio_id=radio_id,
        activity_id=activity_id,
        sequence=sequence,
        utc_ns=block.utc_ns,
        configuration_revision=revision,
        center_frequency_hz=settings.center_frequency_hz,
        sample_rate_hz=settings.sample_rate_hz,
        bin_width_hz=settings.sample_rate_hz / fft_size,
        receiver_power_db=tuple(rows),
    )


def _scan_point(block: SampleBlock, settings: RadioSettings, fft_size: int) -> ScanPoint:
    window = np.hanning(fft_size).astype(np.float32)
    scale = float(np.sum(window * window))
    offsets = np.fft.fftshift(np.fft.fftfreq(fft_size, 1 / settings.sample_rate_hz))
    mean_power: list[float] = []
    peak_power: list[float] = []
    peak_offset: list[float] = []
    for receiver in block.samples:
        transformed = np.fft.fftshift(np.fft.fft(receiver[:fft_size] * window))
        power = 10 * np.log10(np.abs(transformed) ** 2 / scale + np.finfo(float).tiny)
        peak = int(np.argmax(power))
        mean_power.append(
            float(10 * np.log10(np.mean(np.abs(receiver) ** 2) + np.finfo(float).tiny))
        )
        peak_power.append(float(power[peak]))
        peak_offset.append(float(offsets[peak]))
    return ScanPoint(
        center_frequency_hz=settings.center_frequency_hz,
        utc_ns=block.utc_ns,
        receiver_mean_power_db=tuple(mean_power),
        receiver_peak_power_db=tuple(peak_power),
        receiver_peak_offset_hz=tuple(peak_offset),
    )


def _filesystem_free_bytes(path: Path) -> int:
    return shutil.disk_usage(path).free


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
