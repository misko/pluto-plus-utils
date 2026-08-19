from __future__ import annotations

import time
from collections.abc import Iterator
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from pluto_plus.api import API_PREFIX, WATERFALL_MIN_FRAME_INTERVAL_S, create_app
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.models import RadioSettings
from pluto_plus.service import PlutoService


@pytest.fixture
def api(
    tmp_path: Path,
) -> Iterator[tuple[TestClient, PlutoService, FakeRadioDevice]]:
    device = FakeRadioDevice(realtime=True)
    service = PlutoService(tmp_path / "state", (device,))
    with TestClient(create_app(service)) as client:
        yield client, service, device


def _wait_for_job(client: TestClient, job_id: str, timeout: float = 5) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = client.get(f"{API_PREFIX}/jobs/{job_id}")
        assert response.status_code == 200
        document = response.json()
        if document["state"] not in ("pending", "running"):
            return document
        time.sleep(0.01)
    pytest.fail(f"job {job_id} did not finish within {timeout} seconds")


def _capture(client: TestClient, sample_count: int = 4096) -> dict[str, object]:
    response = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={
            "sample_count": sample_count,
            "block_size": 4096,
            "fft_size": 256,
            "persist": True,
            "label": "API test capture",
        },
    )
    assert response.status_code == 201
    return _wait_for_job(client, response.json()["job_id"])


def test_health_and_radio_inventory(api: tuple[TestClient, PlutoService, FakeRadioDevice]) -> None:
    client, _service, _device = api

    health = client.get(f"{API_PREFIX}/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"
    assert health.json()["radio_count"] == 1
    assert health.json()["managed_radio_count"] == 1
    assert health.json()["discovered_radio_count"] == 0

    radios = client.get(f"{API_PREFIX}/radios")
    assert radios.status_code == 200
    assert [radio["identity"]["radio_id"] for radio in radios.json()] == ["fake-001"]

    radio = client.get(f"{API_PREFIX}/radios/fake-001")
    assert radio.status_code == 200
    assert radio.json()["state"] == "ready"
    assert radio.json()["revision"] == 0
    assert radio.json()["identity"]["transport"] == "fake"

    settings = client.get(f"{API_PREFIX}/radios/fake-001/settings")
    assert settings.status_code == 200
    assert settings.json()["revision"] == 0
    assert settings.json()["requested_settings"] == settings.json()["actual_settings"]

    doctor = client.get(f"{API_PREFIX}/radios/fake-001/doctor")
    assert doctor.status_code == 200
    assert doctor.json()["radio_id"] == "fake-001"
    assert doctor.json()["healthy"] is False
    assert doctor.json()["canonical_policy"]["profile_id"] == "libiio-continuous-metadata"

    all_reports = client.get(f"{API_PREFIX}/doctor")
    assert all_reports.status_code == 200
    assert [report["radio_id"] for report in all_reports.json()] == ["fake-001"]


def test_full_inventory_route_correlates_daemon_host_usb_topology(tmp_path: Path) -> None:
    local = LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-8",
        bus_number=3,
        device_number=11,
        product="PlutoSDR+ with timestamp support",
        serial="fake-001",
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )
    service = PlutoService(
        tmp_path / "inventory-state",
        (FakeRadioDevice(serial="fake-001"),),
        local_usb_inventory=lambda: (local,),
    )
    with TestClient(create_app(service)) as client:
        response = client.get(f"{API_PREFIX}/inventory")

    assert response.status_code == 200
    report = response.json()
    assert report["records"][0]["serial"] == "fake-001"
    assert report["records"][0]["classification"] == "simulated"
    assert report["records"][0]["terminal_devices"] == ["/dev/ttyACM0"]


def test_settings_are_revision_guarded(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, device = api

    updated = client.patch(
        f"{API_PREFIX}/radios/fake-001/settings",
        json={"expected_revision": 0, "center_frequency_hz": 1_200_000_000},
    )
    assert updated.status_code == 200
    assert updated.json()["revision"] == 1
    assert updated.json()["requested_settings"]["center_frequency_hz"] == 1_200_000_000
    assert updated.json()["actual_settings"]["center_frequency_hz"] == 1_200_000_000
    assert device.apply_count == 1

    conflict = client.patch(
        f"{API_PREFIX}/radios/fake-001/settings",
        json={"expected_revision": 0, "center_frequency_hz": 915_000_000},
    )
    assert conflict.status_code == 409
    assert conflict.json()["error"]["code"] == "revision_conflict"
    assert device.apply_count == 1


def test_configuration_failure_has_stable_error(
    api: tuple[TestClient, PlutoService, FakeRadioDevice], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _service, device = api

    def fail_configuration(_settings: RadioSettings) -> RadioSettings:
        raise OSError("synthetic configuration failure")

    monkeypatch.setattr(device, "apply_settings", fail_configuration)
    response = client.patch(
        f"{API_PREFIX}/radios/fake-001/settings",
        json={"expected_revision": 0, "center_frequency_hz": 1_000_000_000},
    )
    assert response.status_code == 422
    assert response.json() == {
        "error": {
            "code": "radio_configuration_failed",
            "message": "synthetic configuration failure",
        }
    }


def test_stream_lifecycle_busy_error_and_job_filter(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    started = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={"block_size": 4096, "fft_size": 256},
    )
    assert started.status_code == 201
    job_id = started.json()["job_id"]

    busy = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={"sample_count": 4096, "block_size": 4096, "fft_size": 256},
    )
    assert busy.status_code == 409
    assert busy.json()["error"]["code"] == "radio_busy"

    jobs = client.get(f"{API_PREFIX}/jobs", params={"radio_id": "fake-001"})
    assert jobs.status_code == 200
    assert [job["job_id"] for job in jobs.json()] == [job_id]

    stopped = client.delete(f"{API_PREFIX}/radios/fake-001/streams/current")
    assert stopped.status_code == 200
    assert stopped.json()["job_id"] == job_id
    assert stopped.json()["state"] == "canceled"


def test_capture_artifact_and_analysis_workflow(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    job = _capture(client)
    assert job["state"] == "complete"
    artifact_id = job["artifact_id"]
    assert isinstance(artifact_id, str)

    artifacts = client.get(f"{API_PREFIX}/artifacts")
    assert artifacts.status_code == 200
    assert [artifact["artifact_id"] for artifact in artifacts.json()] == [artifact_id]

    artifact = client.get(f"{API_PREFIX}/artifacts/{artifact_id}")
    assert artifact.status_code == 200
    assert artifact.json()["sample_count"] == 4096
    assert artifact.json()["receiver_count"] == 2

    analyzers = client.get(f"{API_PREFIX}/analyzers")
    assert analyzers.status_code == 200
    assert analyzers.json() == {
        "analyzers": [
            "carrier",
            "dual_receiver",
            "freq_ladder",
            "occupancy",
            "quality",
            "spectrum",
        ]
    }

    analyzed = client.post(
        f"{API_PREFIX}/analyses",
        json={
            "artifact_id": artifact_id,
            "analyzer": "spectrum",
            "parameters": {"fft_size": 256},
        },
    )
    assert analyzed.status_code == 201
    analysis_id = analyzed.json()["analysis_id"]
    assert analyzed.json()["result"]["fft_size"] == 256

    analyses = client.get(f"{API_PREFIX}/analyses", params={"artifact_id": artifact_id})
    assert analyses.status_code == 200
    assert [analysis["analysis_id"] for analysis in analyses.json()] == [analysis_id]

    detail = client.get(f"{API_PREFIX}/analyses/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json() == analyzed.json()


def test_not_found_and_invalid_analysis_errors_are_stable(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    missing_radio = client.get(f"{API_PREFIX}/radios/missing")
    assert missing_radio.status_code == 404
    assert missing_radio.json()["error"]["code"] == "radio_not_found"

    missing_job = client.get(f"{API_PREFIX}/jobs/missing")
    assert missing_job.status_code == 404
    assert missing_job.json()["error"]["code"] == "job_not_found"

    missing_artifact = client.get(f"{API_PREFIX}/artifacts/missing")
    assert missing_artifact.status_code == 404
    assert missing_artifact.json()["error"]["code"] == "artifact_not_found"

    missing_analysis = client.get(f"{API_PREFIX}/analyses/missing")
    assert missing_analysis.status_code == 404
    assert missing_analysis.json()["error"]["code"] == "analysis_not_found"

    job = _capture(client)
    artifact_id = job["artifact_id"]
    assert isinstance(artifact_id, str)

    missing_analyzer = client.post(
        f"{API_PREFIX}/analyses",
        json={"artifact_id": artifact_id, "analyzer": "missing"},
    )
    assert missing_analyzer.status_code == 404
    assert missing_analyzer.json()["error"]["code"] == "analyzer_not_found"

    invalid_parameters = client.post(
        f"{API_PREFIX}/analyses",
        json={
            "artifact_id": artifact_id,
            "analyzer": "spectrum",
            "parameters": {"fft_size": 300},
        },
    )
    assert invalid_parameters.status_code == 422
    assert invalid_parameters.json()["error"]["code"] == "invalid_analysis_parameters"


@pytest.mark.parametrize(
    "path",
    [
        f"{API_PREFIX}/ws/radios/missing/waterfall",
        f"{API_PREFIX}/radios/missing/waterfall",
    ],
)
def test_unknown_waterfall_radio_closes_with_stable_code(
    api: tuple[TestClient, PlutoService, FakeRadioDevice], path: str
) -> None:
    client, _service, _device = api
    with pytest.raises(WebSocketDisconnect) as caught, client.websocket_connect(path):
        pass
    assert getattr(caught.value, "code", None) == 4404


def test_waterfall_websocket_streams_spectrum_frames(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    started = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={"block_size": 4096, "fft_size": 256},
    )
    assert started.status_code == 201

    with client.websocket_connect(f"{API_PREFIX}/ws/radios/fake-001/waterfall") as websocket:
        frame = websocket.receive_json()
        assert frame["schema_version"] == 1
        assert frame["radio_id"] == "fake-001"
        assert frame["activity_id"] == started.json()["job_id"]
        assert frame["sequence"] >= 0
        assert frame["bin_width_hz"] == pytest.approx(2_500_000 / 256)
        assert len(frame["receiver_power_db"]) == 2
        assert all(len(receiver) == 256 for receiver in frame["receiver_power_db"])

    stopped = client.delete(f"{API_PREFIX}/radios/fake-001/streams/current")
    assert stopped.status_code == 200


def test_page_release_endpoint_is_exact_idempotent_and_preview_only(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    started = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={"block_size": 4096, "fft_size": 256},
    ).json()

    stale = client.post(
        f"{API_PREFIX}/radios/fake-001/streams/stale-job/release",
        content=b"",
    )
    assert stale.status_code == 204
    assert client.get(f"{API_PREFIX}/radios/fake-001").json()["state"] == "streaming"

    released = client.post(
        f"{API_PREFIX}/radios/fake-001/streams/{started['job_id']}/release",
        content=b"",
    )
    assert released.status_code == 204
    assert client.get(f"{API_PREFIX}/radios/fake-001").json()["state"] == "ready"


def test_waterfall_websocket_rate_is_bounded_for_browser_responsiveness(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    assert WATERFALL_MIN_FRAME_INTERVAL_S >= 1 / 12
    started = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={"block_size": 4096, "fft_size": 256},
    )
    assert started.status_code == 201

    with client.websocket_connect(f"{API_PREFIX}/ws/radios/fake-001/waterfall") as websocket:
        websocket.receive_json()
        started_wait = time.monotonic()
        websocket.receive_json()
        elapsed = time.monotonic() - started_wait
        assert elapsed >= WATERFALL_MIN_FRAME_INTERVAL_S * 0.7

    assert client.delete(f"{API_PREFIX}/radios/fake-001/streams/current").status_code == 200


def test_slow_waterfall_consumer_does_not_block_capture(
    api: tuple[TestClient, PlutoService, FakeRadioDevice],
) -> None:
    client, _service, _device = api
    started = client.post(
        f"{API_PREFIX}/radios/fake-001/streams",
        json={
            "sample_count": 250_000,
            "block_size": 4096,
            "fft_size": 256,
            "persist": True,
        },
    )
    assert started.status_code == 201

    with client.websocket_connect(f"{API_PREFIX}/ws/radios/fake-001/waterfall"):
        completed = _wait_for_job(client, started.json()["job_id"])
        assert completed["state"] == "complete"
        assert completed["artifact_id"] is not None


def test_embedded_static_ui_is_served_when_present(tmp_path: Path) -> None:
    static_root = tmp_path / "static"
    static_root.mkdir()
    (static_root / "index.html").write_text("<!doctype html><title>Pluto UI</title>")
    (static_root / "app.js").write_text("document.title = 'loaded';")
    service = PlutoService(tmp_path / "state", (FakeRadioDevice(),))

    with TestClient(create_app(service, static_directory=static_root)) as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Pluto UI" in response.text
        assert response.headers["content-type"].startswith("text/html")
        assert client.get("/static/app.js").status_code == 200
        assert client.get(f"{API_PREFIX}/health").status_code == 200
