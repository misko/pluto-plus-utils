from __future__ import annotations

import time

import pytest

from pluto_plus.artifacts import verify_artifact
from pluto_plus.errors import RadioBusyError, RevisionConflictError
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import (
    AnalysisRequest,
    GainMode,
    JobState,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    SettingsPatch,
    StreamRequest,
    Transport,
)
from pluto_plus.service import PlutoService


def _wait_for_job(service: PlutoService, job_id: str, timeout: float = 5) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service.get_job(job_id).state not in (JobState.PENDING, JobState.RUNNING):
            return
        time.sleep(0.01)
    raise AssertionError(f"job {job_id} did not finish")


def test_service_capture_analysis_vertical_slice(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a"),))
    try:
        snapshot = service.get_radio("fake-a")
        assert snapshot.state is RadioState.READY
        assert snapshot.actual_settings.channels == (0, 1)

        job = service.start_stream(
            "fake-a",
            StreamRequest(
                sample_count=16_384,
                block_size=4096,
                fft_size=2048,
                persist=True,
                label="vertical",
            ),
        )
        _wait_for_job(service, job.job_id)
        completed = service.get_job(job.job_id)
        assert completed.state is JobState.COMPLETE
        assert completed.artifact_id is not None

        artifact = service.get_artifact(completed.artifact_id)
        assert artifact.sample_count == 16_384
        assert verify_artifact(artifact)

        analysis = service.run_analysis(
            AnalysisRequest(
                artifact_id=artifact.artifact_id,
                analyzer="spectrum",
                parameters={"fft_size": 2048},
            )
        )
        expected = 125_000
        for peak in analysis.result["peaks"]:
            assert peak["offset_hz"] == pytest.approx(expected, abs=artifact.sample_rate_hz / 2048)
        assert service.get_analysis(analysis.analysis_id) == analysis
    finally:
        service.close()


def test_passive_network_inventory_is_visible_without_opening_a_controller(tmp_path) -> None:
    passive = RadioSnapshot(
        identity=RadioIdentity(
            radio_id="PASSIVE",
            serial="PASSIVE",
            uri="ip:192.0.2.20",
            transport=Transport.IIO_IP,
            model="Pluto inventory",
            firmware_version="v1",
        ),
        capabilities=RadioCapabilities(supports_live_tuning=False),
        managed=False,
        state=RadioState.OFFLINE,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
        last_error="Discovered read-only; not owned by this daemon",
    )
    service = PlutoService(
        tmp_path,
        (FakeRadioDevice("managed"),),
        discovered_radios=(passive,),
    )
    try:
        snapshots = service.list_radios()
        assert [snapshot.identity.radio_id for snapshot in snapshots] == [
            "managed",
            "PASSIVE",
        ]
        assert snapshots[0].managed is True
        assert service.get_radio("PASSIVE") == passive
        report = service.doctor("PASSIVE")
        assert report.radio_id == "PASSIVE"
    finally:
        service.close()


def test_settings_are_revision_guarded_and_read_back(tmp_path) -> None:
    device = FakeRadioDevice("fake-a")
    service = PlutoService(tmp_path, (device,))
    try:
        updated = service.update_settings(
            "fake-a",
            SettingsPatch(
                expected_revision=0,
                center_frequency_hz=1_000_000_000,
                gain_mode=GainMode.SLOW_ATTACK,
            ),
        )
        assert updated.revision == 1
        assert updated.requested_settings == updated.actual_settings
        assert updated.actual_settings.gain_mode is GainMode.SLOW_ATTACK
        assert updated.actual_settings.gain_db is None
        assert device.apply_count == 1

        with pytest.raises(RevisionConflictError):
            service.update_settings(
                "fake-a", SettingsPatch(expected_revision=0, bandwidth_hz=1_000_000)
            )
        assert device.apply_count == 1
    finally:
        service.close()


def test_live_spectrum_is_bounded_and_does_not_block_capture(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a"),))
    subscription = service.subscribe("fake-a")
    try:
        job = service.start_stream(
            "fake-a",
            StreamRequest(sample_count=32_768, block_size=4096, fft_size=1024),
        )
        _wait_for_job(service, job.job_id)
        frame = subscription.frames.get(timeout=1)
        assert frame.radio_id == "fake-a"
        assert len(frame.receiver_power_db) == 2
        assert subscription.frames.qsize() <= 2
    finally:
        subscription.close()
        service.close()


def test_only_one_stream_can_own_a_radio(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a", realtime=True),))
    try:
        service.start_stream("fake-a", StreamRequest(block_size=1024, fft_size=1024))
        with pytest.raises(RadioBusyError):
            service.start_stream("fake-a", StreamRequest(sample_count=1024))
        stopped = service.stop_stream("fake-a")
        assert stopped.state is JobState.CANCELED
    finally:
        service.close()


def test_preview_can_tune_but_persistent_capture_locks_frequency_axes(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice("fake-a", realtime=True),))
    try:
        service.start_stream(
            "fake-a",
            StreamRequest(
                duration_s=2,
                block_size=1024,
                fft_size=1024,
                persist=True,
            ),
        )
        with pytest.raises(RadioBusyError, match="persistent capture locks"):
            service.update_settings(
                "fake-a",
                SettingsPatch(expected_revision=0, center_frequency_hz=1_000_000_000),
            )
        gain = service.update_settings(
            "fake-a", SettingsPatch(expected_revision=0, gain_db=35)
        )
        assert gain.revision == 1
        service.stop_stream("fake-a")

        service.start_stream("fake-a", StreamRequest(block_size=1024, fft_size=1024))
        tuned = service.update_settings(
            "fake-a",
            SettingsPatch(expected_revision=1, center_frequency_hz=1_000_000_000),
        )
        assert tuned.revision == 2
        service.stop_stream("fake-a")
    finally:
        service.close()


def test_failed_stream_can_be_explicitly_recovered(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    device = FakeRadioDevice("fake-a")
    service = PlutoService(tmp_path, (device,))

    def fail_read(_sample_count: int) -> None:
        raise OSError("synthetic disconnect")

    try:
        monkeypatch.setattr(device, "read_block", fail_read)
        job = service.start_stream(
            "fake-a", StreamRequest(sample_count=1024, block_size=1024, fft_size=1024)
        )
        _wait_for_job(service, job.job_id)
        assert service.get_radio("fake-a").state is RadioState.ERROR

        recovered = service.recover_radio("fake-a")
        assert recovered.state is RadioState.READY
        assert recovered.revision == 1
        assert recovered.last_error is None
    finally:
        service.close()
