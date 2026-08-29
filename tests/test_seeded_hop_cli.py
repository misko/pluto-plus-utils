"""CLI wiring of the seeded-hop decode: one capture in, one honest summary out."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from pluto_plus.cli import ApiClient, app
from pluto_plus.seeded_hop import DEFAULT_SEED

runner = CliRunner()

ARGUMENTS = [
    "--rung-start-hz",
    "11.0e9",
    "--rung-stop-hz",
    "11.00171e9",
    "--points",
    "20",
    "--hop-seconds",
    "0.010",
    "--lo-hz",
    "9.75e9",
]
RESULT: dict[str, Any] = {
    "receiver": 0,
    "confident": True,
    "warnings": [],
    "comb": {"offset_hz": -105_810.5, "sharpness": 10_164.4, "confident": True},
    "epoch": {"shift_seconds": 0.0311296, "sharpness_sigma": 1137.3, "confident": True},
    "measured_point_count": 20,
    "median_frequency_error_hz": -105_998.2,
    "frequency_error_stdev_hz": 55.2,
    "points": [
        {
            "point": index,
            "nominal_rf_hz": 11.0e9 + 90_000 * index,
            "nominal_if_hz": 1.25e9 + 90_000 * index,
            "measured_if_hz": 1.25e9 + 90_000 * index - 106_000,
            "frequency_error_hz": -106_000.0,
            "strong_frame_count": 190,
            "rejection": None,
            "measured": True,
        }
        for index in range(20)
    ],
}


@pytest.fixture
def api_transport(monkeypatch: pytest.MonkeyPatch) -> list[httpx.Request]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST" and request.url.path.endswith("/analyses"):
            body = json.loads(request.content)
            if body["artifact_id"] != "artifact-1":
                return httpx.Response(
                    404,
                    json={"error": {"code": "artifact_not_found", "message": "unknown"}},
                )
            return httpx.Response(
                201,
                json={
                    "analysis_id": "analysis-1",
                    "artifact_id": "artifact-1",
                    "analyzer": "seeded_hop",
                    "analyzer_version": "1",
                    "result": RESULT,
                },
            )
        return httpx.Response(404, json={"error": {"code": "not_found", "message": "?"}})

    monkeypatch.setattr(
        ApiClient,
        "_new_client",
        staticmethod(
            lambda endpoint: httpx.Client(
                base_url="http://test/api/v1/", transport=httpx.MockTransport(handler)
            )
        ),
    )
    return requests


def _invoke(*extra: str, artifact: str = "artifact-1") -> Any:
    return runner.invoke(app, ["calibrate", "seeded-hop", artifact, *ARGUMENTS, *extra])


def test_the_capture_is_analysed_by_the_daemon_and_summarised(
    api_transport: list[httpx.Request],
) -> None:
    result = _invoke("--frame-size", "1024", "--threshold-db", "12")

    assert result.exit_code == 0, result.output
    assert [request.url.path for request in api_transport] == ["/api/v1/analyses"]
    body = json.loads(api_transport[0].content)
    assert body["analyzer"] == "seeded_hop"
    assert body["artifact_id"] == "artifact-1"
    parameters = body["parameters"]
    assert parameters["seed"] == DEFAULT_SEED
    assert parameters["points"] == 20
    assert parameters["hop_seconds"] == 0.010
    assert parameters["lo_hz"] == 9.75e9
    assert parameters["jitter"] == 0.0
    assert parameters["period_cycles"] == 1
    assert parameters["frame_size"] == 1024
    assert parameters["threshold_db"] == 12
    assert parameters["receiver"] == 0

    payload = json.loads(result.stdout)
    assert payload["analysis_id"] == "analysis-1"
    assert payload["confident"] is True
    assert payload["measured_point_count"] == 20
    assert payload["point_count"] == 20
    assert payload["comb_offset_hz"] == pytest.approx(-105_810.5)
    assert payload["epoch_sharpness_sigma"] == pytest.approx(1137.3)
    assert payload["median_frequency_error_hz"] == pytest.approx(-105_998.2)
    assert len(payload["points"]) == 20
    assert payload["points"][0]["frequency_error_hz"] == pytest.approx(-106_000.0)


def test_the_seed_is_shared_state_and_is_parsed_in_either_base(
    api_transport: list[httpx.Request],
) -> None:
    assert _invoke("--seed", "0xdeadbeef").exit_code == 0
    assert json.loads(api_transport[-1].content)["parameters"]["seed"] == 0xDEADBEEF

    assert _invoke("--seed", "1234").exit_code == 0
    assert json.loads(api_transport[-1].content)["parameters"]["seed"] == 1234

    rejected = _invoke("--seed", "coffee")
    assert rejected.exit_code == 2
    assert json.loads(rejected.stderr)["error"]["code"] == "invalid_seed"

    too_large = _invoke("--seed", str(2**64))
    assert too_large.exit_code == 2
    assert json.loads(too_large.stderr)["error"]["code"] == "invalid_seed"


def test_low_confidence_is_passed_through_rather_than_swallowed(
    api_transport: list[httpx.Request],
) -> None:
    RESULT["confident"] = False
    RESULT["warnings"] = ["comb_search_is_flat", "too_few_points_measured"]
    RESULT["measured_point_count"] = 0
    try:
        result = _invoke()
    finally:
        RESULT["confident"] = True
        RESULT["warnings"] = []
        RESULT["measured_point_count"] = 20

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["confident"] is False
    assert payload["warnings"] == ["comb_search_is_flat", "too_few_points_measured"]
    assert payload["measured_point_count"] == 0


def test_bad_inputs_and_daemon_errors_are_structured(
    api_transport: list[httpx.Request],
) -> None:
    blank = _invoke(artifact=" artifact-1")
    assert blank.exit_code == 2
    assert json.loads(blank.stderr)["error"]["code"] == "invalid_artifact_id"

    unknown = _invoke(artifact="artifact-9")
    assert unknown.exit_code == 4
    assert json.loads(unknown.stderr)["error"]["code"] == "artifact_not_found"
