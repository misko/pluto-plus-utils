from __future__ import annotations

import json
import time
from typing import Any

import httpx
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pluto_plus.api import create_app
from pluto_plus.cli import ApiClient, app
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.service import PlutoService


def test_scan_api_vertical_slice(tmp_path) -> None:
    service = PlutoService(tmp_path, (FakeRadioDevice(),))
    with TestClient(create_app(service)) as client:
        started = client.post(
            "/api/v1/radios/fake-001/scans",
            json={
                "start_frequency_hz": 900_000_000,
                "stop_frequency_hz": 902_000_000,
                "step_hz": 1_000_000,
                "sample_rate_hz": 1_000_000,
                "bandwidth_hz": 1_000_000,
                "samples_per_frequency": 2048,
                "fft_size": 1024,
                "settle_buffers": 0,
            },
        )
        assert started.status_code == 201
        job_id = started.json()["job_id"]
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            job = client.get(f"/api/v1/scan-jobs/{job_id}").json()
            if job["state"] != "running":
                break
            time.sleep(0.01)
        assert job["state"] == "complete"
        result = client.get(f"/api/v1/scans/{job['scan_id']}")
        assert result.status_code == 200
        assert len(result.json()["points"]) == 3


def test_scan_cli_posts_explicit_plan(monkeypatch) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, json={"job_id": "scan-job", "state": "running"})

    monkeypatch.setattr(
        ApiClient,
        "_new_client",
        staticmethod(
            lambda endpoint: httpx.Client(
                base_url="http://test/api/v1/", transport=httpx.MockTransport(handler)
            )
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "start",
            "fake-001",
            "--start",
            "900000000",
            "--stop",
            "902000000",
            "--step",
            "1000000",
        ],
    )
    assert result.exit_code == 0, result.output
    assert requests[0].url.path == "/api/v1/radios/fake-001/scans"
    body: dict[str, Any] = json.loads(requests[0].content)
    assert body["start_frequency_hz"] == 900_000_000
    assert body["stop_frequency_hz"] == 902_000_000
