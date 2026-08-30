from __future__ import annotations

import os
import stat
import threading
from pathlib import Path

import pytest

from pluto_plus.artifacts import CaptureWriter, verify_artifact
from pluto_plus.catalog import Catalog
from pluto_plus.controller import RadioController, SpectrumBroker, spectrum_frame
from pluto_plus.errors import RadioBusyError
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import (
    JobState,
    RadioState,
    ScanJob,
    ScanPoint,
    ScanRequest,
    ScanResult,
    StreamJob,
    StreamRequest,
    utc_now,
)
from pluto_plus.service import PlutoService

# These deadlines detect a stuck worker; they are not performance assertions.  Leave
# enough headroom for fsync and first-use NumPy work on contended CI runners.
_BACKGROUND_JOB_TIMEOUT_S = 30.0


class _SignalingCatalog(Catalog):
    def __init__(self, path: Path) -> None:
        self._terminal_jobs = threading.Condition()
        self._terminal_stream_jobs: set[str] = set()
        self._terminal_scan_jobs: set[str] = set()
        super().__init__(path)

    def put_stream_job(self, job: StreamJob) -> None:
        super().put_stream_job(job)
        if job.state not in (JobState.PENDING, JobState.RUNNING):
            with self._terminal_jobs:
                self._terminal_stream_jobs.add(job.job_id)
                self._terminal_jobs.notify_all()

    def put_scan_job(self, job: ScanJob) -> None:
        super().put_scan_job(job)
        if job.state not in (JobState.PENDING, JobState.RUNNING):
            with self._terminal_jobs:
                self._terminal_scan_jobs.add(job.job_id)
                self._terminal_jobs.notify_all()

    def wait_stream(self, job_id: str) -> None:
        with self._terminal_jobs:
            assert self._terminal_jobs.wait_for(
                lambda: job_id in self._terminal_stream_jobs,
                timeout=_BACKGROUND_JOB_TIMEOUT_S,
            ), f"stream job {job_id} did not finish"

    def wait_scan(self, job_id: str) -> None:
        with self._terminal_jobs:
            assert self._terminal_jobs.wait_for(
                lambda: job_id in self._terminal_scan_jobs,
                timeout=_BACKGROUND_JOB_TIMEOUT_S,
            ), f"scan job {job_id} did not finish"


class _BlockingRadio(FakeRadioDevice):
    def __init__(self) -> None:
        super().__init__("blocked")
        self.entered_read = threading.Event()
        self.release_read = threading.Event()

    def read_block(self, sample_count: int):  # type: ignore[no-untyped-def]
        self.entered_read.set()
        if not self.release_read.wait(_BACKGROUND_JOB_TIMEOUT_S):
            raise TimeoutError("test did not release blocked radio")
        return super().read_block(sample_count)


def test_startup_preserves_partial_files_and_fails_interrupted_jobs(tmp_path: Path) -> None:
    capture_partial = tmp_path / "captures" / ".partial" / "capture-before-crash"
    capture_partial.mkdir(parents=True)
    (capture_partial / "capture-before-crash.sigmf-data").write_bytes(b"partial")
    scans = tmp_path / "scans"
    scans.mkdir()
    (scans / "scan-before-crash.json.partial").write_text("partial")

    created = utc_now()
    catalog = Catalog(tmp_path / "catalog.sqlite3")
    catalog.put_stream_job(
        StreamJob(
            job_id="stream-before-crash",
            radio_id="fake-a",
            state=JobState.RUNNING,
            persist=True,
            created_at=created,
            started_at=created,
        )
    )
    catalog.put_scan_job(
        ScanJob(
            job_id="scan-before-crash",
            radio_id="fake-a",
            state=JobState.RUNNING,
            created_at=created,
            started_at=created,
        )
    )
    # Merely opening the catalog is not daemon-start authority to fail live jobs.
    assert Catalog(tmp_path / "catalog.sqlite3").get_stream_job(
        "stream-before-crash"
    ).state is JobState.RUNNING  # type: ignore[union-attr]

    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a"),))
    try:
        stream = service.get_job("stream-before-crash")
        scan = service.get_scan_job("scan-before-crash")
        assert stream.state is JobState.FAILED
        assert scan.state is JobState.FAILED
        assert stream.finished_at is not None
        assert scan.finished_at is not None
        assert stream.error == "Interrupted: daemon restarted before job completion"
        assert scan.error == "Interrupted: daemon restarted before job completion"

        recovered_capture = tmp_path / "captures" / ".failed" / "capture-before-crash"
        assert (recovered_capture / "capture-before-crash.sigmf-data").read_bytes() == b"partial"
        assert "daemon restarted" in (recovered_capture / "failure.json").read_text()
        assert not capture_partial.exists()
        assert (
            tmp_path / "scans" / ".failed" / "scan-before-crash.json.partial"
        ).read_text() == "partial"
    finally:
        service.close()


def test_low_disk_rejects_persistent_capture_before_job_admission(tmp_path: Path) -> None:
    service = PlutoService(
        tmp_path,
        (FakeRadioDevice("fake-a"),),
        capture_free_bytes=lambda _path: 8_191,
        capture_reserve_bytes=0,
    )
    try:
        with pytest.raises(RadioBusyError, match="insufficient capture storage"):
            service.start_stream(
                "fake-a",
                StreamRequest(
                    sample_count=1_024,
                    block_size=1_024,
                    fft_size=1_024,
                    persist=True,
                ),
            )
        assert service.list_jobs() == []
        assert service.get_radio("fake-a").state is RadioState.READY
        assert not any((tmp_path / "captures" / ".partial").glob("*"))
    finally:
        service.close()


def test_startup_reconciles_committed_capture_and_scan_files(tmp_path: Path) -> None:
    device = FakeRadioDevice("fake-a")
    device.open()
    settings = device.read_settings()
    block = device.read_block(1_024)
    device.close()
    writer = CaptureWriter(
        tmp_path / "captures",
        radio=device.identity,
        settings=settings,
        label="orphaned catalog commit",
        artifact_id="committed-capture",
    )
    writer.append(block, settings, 0)
    committed_artifact = writer.finalize()

    scans = tmp_path / "scans"
    scans.mkdir()
    scan_path = scans / "committed-scan.json"
    now = utc_now()
    committed_scan = ScanResult(
        scan_id="committed-scan",
        radio_id="fake-a",
        created_at=now,
        finished_at=now,
        request=ScanRequest(
            start_frequency_hz=900_000_000,
            stop_frequency_hz=900_000_000,
            step_hz=1_000_000,
            samples_per_frequency=1_024,
            fft_size=256,
        ),
        points=(
            ScanPoint(
                center_frequency_hz=900_000_000,
                utc_ns=block.utc_ns,
                receiver_mean_power_db=(-10.0, -11.0),
                receiver_peak_power_db=(-2.0, -3.0),
                receiver_peak_offset_hz=(0.0, 0.0),
            ),
        ),
        path=str(scan_path),
    )
    scan_path.write_text(committed_scan.model_dump_json())
    (scans / "corrupt.json").write_text("not json")
    incomplete_capture = tmp_path / "captures" / "invalid-complete"
    incomplete_capture.mkdir()
    (incomplete_capture / "invalid-complete.sigmf-meta").write_text("{}")

    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a"),))
    try:
        recovered_artifact = service.get_artifact(committed_artifact.artifact_id)
        assert recovered_artifact.sha256 == committed_artifact.sha256
        assert recovered_artifact.label == "orphaned catalog commit"
        assert verify_artifact(recovered_artifact)
        assert service.get_scan(committed_scan.scan_id) == committed_scan
    finally:
        service.close()


def test_state_root_has_exactly_one_live_daemon_owner(tmp_path: Path) -> None:
    first = PlutoService(tmp_path, (FakeRadioDevice("fake-a"),))
    try:
        with pytest.raises(RuntimeError, match="already owned by another daemon"):
            PlutoService(tmp_path, (FakeRadioDevice("fake-b"),))
        assert first.get_radio("fake-a").state is RadioState.READY
    finally:
        first.close()

    replacement = PlutoService(tmp_path, (FakeRadioDevice("fake-b"),))
    try:
        assert replacement.get_radio("fake-b").state is RadioState.READY
    finally:
        replacement.close()


def test_scan_commit_syncs_file_and_parent_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    synced_modes: list[int] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        synced_modes.append(os.fstat(descriptor).st_mode)
        real_fsync(descriptor)

    monkeypatch.setattr("pluto_plus.controller.os.fsync", record_fsync)
    catalog = _SignalingCatalog(tmp_path / "catalog.sqlite3")
    controller = RadioController(FakeRadioDevice("fake-a"), tmp_path / "captures", catalog)
    try:
        job = controller.start_scan(
            ScanRequest(
                start_frequency_hz=900_000_000,
                stop_frequency_hz=900_000_000,
                step_hz=1_000_000,
                samples_per_frequency=1_024,
                fft_size=256,
                settle_buffers=0,
            )
        )
        active_scan = controller._active_scan  # noqa: SLF001
        assert active_scan is not None
        worker = active_scan.thread
        catalog.wait_scan(job.job_id)
        worker.join(_BACKGROUND_JOB_TIMEOUT_S)
        assert not worker.is_alive()
        assert any(stat.S_ISREG(mode) for mode in synced_modes)
        assert any(stat.S_ISDIR(mode) for mode in synced_modes)
        assert not list((tmp_path / "scans").glob("*.partial"))
    finally:
        controller.close()


def test_timed_out_shutdown_does_not_close_device_under_live_worker(
    tmp_path: Path,
) -> None:
    device = _BlockingRadio()
    catalog = _SignalingCatalog(tmp_path / "catalog.sqlite3")
    controller = RadioController(
        device,
        tmp_path / "captures",
        catalog,
        shutdown_timeout_s=0.01,
    )
    job = controller.start_stream(StreamRequest(block_size=1_024, fft_size=1_024))
    active = controller._active  # noqa: SLF001
    assert active is not None
    worker = active.thread
    assert device.entered_read.wait(_BACKGROUND_JOB_TIMEOUT_S)

    with pytest.raises(RadioBusyError, match="shutdown timed out"):
        controller.close()
    assert controller.snapshot().state is RadioState.ERROR

    device.release_read.set()
    catalog.wait_stream(job.job_id)
    worker.join(_BACKGROUND_JOB_TIMEOUT_S)
    assert not worker.is_alive()
    assert controller.recover().state is RadioState.READY
    controller.close()


def test_spectrum_and_job_history_are_bounded_without_losing_durable_jobs(
    tmp_path: Path,
) -> None:
    broker = SpectrumBroker(max_subscribers=1)
    subscription = broker.subscribe()
    with pytest.raises(RadioBusyError, match="subscriber limit"):
        broker.subscribe()

    device = FakeRadioDevice("fake-a")
    device.open()
    settings = device.read_settings()
    block = device.read_block(256)
    device.close()
    for sequence in range(100):
        broker.publish(
            spectrum_frame(
                block,
                radio_id="fake-a",
                activity_id="soak",
                sequence=sequence,
                revision=0,
                settings=settings,
                fft_size=256,
            )
        )
    assert subscription.frames.qsize() == 2
    assert [subscription.frames.get_nowait().sequence for _ in range(2)] == [98, 99]
    subscription.close()

    catalog = _SignalingCatalog(tmp_path / "catalog.sqlite3")
    controller = RadioController(
        FakeRadioDevice("fake-a"),
        tmp_path / "captures",
        catalog,
        max_in_memory_jobs=3,
        capture_reserve_bytes=0,
    )
    job_ids: list[str] = []
    try:
        for _ in range(12):
            job = controller.start_stream(
                StreamRequest(
                    sample_count=1_024,
                    block_size=1_024,
                    fft_size=256,
                    persist=True,
                )
            )
            catalog.wait_stream(job.job_id)
            active = controller._active  # noqa: SLF001
            if active is not None:
                active.thread.join(_BACKGROUND_JOB_TIMEOUT_S)
                assert not active.thread.is_alive()
            job_ids.append(job.job_id)
        assert len(controller._jobs) <= 3  # noqa: SLF001
        assert len(controller.list_jobs()) == 12
        assert controller.get_job(job_ids[0]).state is JobState.COMPLETE
        assert len(catalog.list_artifacts()) == 12
        assert all(verify_artifact(artifact) for artifact in catalog.list_artifacts())
        assert not list((tmp_path / "captures" / ".partial").glob("*"))
        assert controller.snapshot().state is RadioState.READY
    finally:
        controller.close()


def test_short_deterministic_capture_and_scan_soak(tmp_path: Path) -> None:
    catalog = _SignalingCatalog(tmp_path / "catalog.sqlite3")
    controller = RadioController(
        FakeRadioDevice("fake-a"),
        tmp_path / "captures",
        catalog,
        max_in_memory_jobs=4,
        capture_reserve_bytes=0,
    )
    try:
        for _ in range(24):
            job = controller.start_stream(
                StreamRequest(
                    sample_count=1_024,
                    block_size=1_024,
                    fft_size=256,
                    persist=True,
                )
            )
            catalog.wait_stream(job.job_id)
            active = controller._active  # noqa: SLF001
            if active is not None:
                active.thread.join(_BACKGROUND_JOB_TIMEOUT_S)
                assert not active.thread.is_alive()
        for index in range(6):
            frequency = 900_000_000 + index * 1_000_000
            scan_job = controller.start_scan(
                ScanRequest(
                    start_frequency_hz=frequency,
                    stop_frequency_hz=frequency,
                    step_hz=1_000_000,
                    samples_per_frequency=1_024,
                    fft_size=256,
                    settle_buffers=0,
                )
            )
            catalog.wait_scan(scan_job.job_id)
            active_scan = controller._active_scan  # noqa: SLF001
            if active_scan is not None:
                active_scan.thread.join(_BACKGROUND_JOB_TIMEOUT_S)
                assert not active_scan.thread.is_alive()

        assert len(catalog.list_artifacts()) == 24
        assert len(catalog.list_scans()) == 6
        assert len(controller.list_jobs()) == 24
        assert len(controller.list_scan_jobs()) == 6
        assert len(controller._jobs) <= 4  # noqa: SLF001
        assert len(controller._scan_jobs) <= 4  # noqa: SLF001
        assert controller.snapshot().state is RadioState.READY
    finally:
        controller.close()
