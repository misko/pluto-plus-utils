from __future__ import annotations

import time

import pytest
from pydantic import ValidationError

from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import JobState, RadioState, ScanRequest
from pluto_plus.service import PlutoService


def _wait(service: PlutoService, job_id: str, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.get_scan_job(job_id).state is not JobState.RUNNING:
            return
        time.sleep(0.01)
    raise AssertionError("scan did not finish")


def test_scan_contract_rejects_reversed_or_excessive_plans() -> None:
    with pytest.raises(ValidationError, match="cannot be below"):
        ScanRequest(
            start_frequency_hz=1_000_000_000,
            stop_frequency_hz=900_000_000,
            step_hz=1_000_000,
        )
    with pytest.raises(ValidationError, match="4096"):
        ScanRequest(
            start_frequency_hz=100_000_000,
            stop_frequency_hz=6_000_000_000,
            step_hz=1_000_000,
        )


def test_scan_is_exclusive_persisted_and_restores_settings(tmp_path) -> None:
    device = FakeRadioDevice("fake-a")
    service = PlutoService(tmp_path, (device,))
    original = service.get_radio("fake-a").actual_settings
    request = ScanRequest(
        start_frequency_hz=900_000_000,
        stop_frequency_hz=904_000_000,
        step_hz=2_000_000,
        sample_rate_hz=1_000_000,
        bandwidth_hz=1_000_000,
        samples_per_frequency=4096,
        fft_size=1024,
        settle_buffers=1,
    )
    try:
        job = service.start_scan("fake-a", request)
        _wait(service, job.job_id)

        complete = service.get_scan_job(job.job_id)
        assert complete.state is JobState.COMPLETE
        assert complete.scan_id is not None
        result = service.get_scan(complete.scan_id)
        assert [point.center_frequency_hz for point in result.points] == [
            900_000_000,
            902_000_000,
            904_000_000,
        ]
        assert all(len(point.receiver_mean_power_db) == 2 for point in result.points)
        snapshot = service.get_radio("fake-a")
        assert snapshot.state is RadioState.READY
        assert snapshot.actual_settings == original
        assert snapshot.requested_settings == original
        assert snapshot.revision == 4  # three scan tunes plus one restoration
        assert service.list_scans() == [result]
    finally:
        service.close()


def test_scan_can_be_canceled_and_still_restores_settings(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a", realtime=True),))
    original = service.get_radio("fake-a").actual_settings
    try:
        job = service.start_scan(
            "fake-a",
            ScanRequest(
                start_frequency_hz=900_000_000,
                stop_frequency_hz=920_000_000,
                step_hz=1_000_000,
                sample_rate_hz=100_000,
                bandwidth_hz=100_000,
                samples_per_frequency=4096,
                fft_size=1024,
            ),
        )
        stopped = service.stop_scan("fake-a")
        assert stopped.job_id == job.job_id
        assert stopped.state is JobState.CANCELED
        assert service.get_radio("fake-a").actual_settings == original
    finally:
        service.close()
