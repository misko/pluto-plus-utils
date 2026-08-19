"""CLI aggregation of several observed-ladder analyses into one separated fit."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from typer.testing import CliRunner

from pluto_plus.cli import ApiClient, app
from pluto_plus.freq_ladder import FreqLadderBurst, FreqLadderSchedule

runner = CliRunner()

LO_HZ = 9.75e9
LNB_ERROR_HZ = 94_000.0
CLOCK_ERROR = 8.94e-6
LADDER = FreqLadderSchedule(
    rung_start_hz=10.30e9, rung_stop_hz=10.70e9, rung_count=5, total_seconds=0.6
)
ARGUMENTS = [
    "--rung-start-hz",
    "10.30e9",
    "--rung-stop-hz",
    "10.70e9",
    "--rung-count",
    "5",
    "--total-seconds",
    "0.6",
    "--lo-hz",
    "9.75e9",
]


def _burst(rung: int, epoch_seconds: float, *, drift_hz: float = 0.0) -> dict[str, Any]:
    nominal_if = LADDER.rung_frequency_hz(rung) - LO_HZ
    error = -CLOCK_ERROR * nominal_if - LNB_ERROR_HZ + drift_hz
    row = FreqLadderBurst(
        artifact_id=f"artifact-{rung}",
        receiver=0,
        first_frame=3,
        last_frame=3 + rung,
        frame_count=rung + 1,
        complete=True,
        start_seconds=0.02,
        center_seconds=0.03,
        epoch_seconds=epoch_seconds,
        duration_seconds=rung * LADDER.unit_seconds,
        duration_lower_seconds=rung * LADDER.unit_seconds,
        duration_upper_seconds=rung * LADDER.unit_seconds,
        rung_estimate=float(rung),
        rung_offset=0.0,
        rung=rung,
        identified=True,
        lo_hz=LO_HZ,
        nominal_rf_hz=LADDER.rung_frequency_hz(rung),
        nominal_if_hz=nominal_if,
        measured_frequency_hz=nominal_if + error,
        frequency_error_hz=error,
        snr_db=72.0,
    )
    return dict(row.model_dump(mode="json"))


@pytest.fixture
def api_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[httpx.Request], dict[str, list[dict[str, Any]]]]:
    requests: list[httpx.Request] = []
    bursts: dict[str, list[dict[str, Any]]] = {
        f"artifact-{rung}": [_burst(rung, 1.0e9 + rung)] for rung in LADDER.rungs
    }

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST" and request.url.path.endswith("/analyses"):
            body = json.loads(request.content)
            artifact_id = body["artifact_id"]
            if artifact_id not in bursts:
                return httpx.Response(
                    404,
                    json={"error": {"code": "artifact_not_found", "message": artifact_id}},
                )
            return httpx.Response(
                201,
                json={
                    "analysis_id": f"analysis-{artifact_id}",
                    "artifact_id": artifact_id,
                    "analyzer": "freq_ladder",
                    "analyzer_version": "1",
                    "result": {"bursts": bursts[artifact_id]},
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
    return requests, bursts


def _invoke(*extra: str, artifacts: list[str] | None = None) -> Any:
    selected = artifacts or [f"artifact-{rung}" for rung in LADDER.rungs]
    return runner.invoke(app, ["calibrate", "freq-ladder", *selected, *ARGUMENTS, *extra])


def test_each_artifact_is_analysed_by_the_daemon_then_fitted_together(
    api_transport: tuple[list[httpx.Request], dict[str, list[dict[str, Any]]]],
) -> None:
    requests, _ = api_transport

    result = _invoke("--frame-size", "8192", "--threshold-db", "30")

    assert result.exit_code == 0, result.output
    assert [request.url.path for request in requests] == ["/api/v1/analyses"] * 5
    body = json.loads(requests[0].content)
    assert body["artifact_id"] == "artifact-1"
    assert body["analyzer"] == "freq_ladder"
    assert body["parameters"]["rung_count"] == 5
    assert body["parameters"]["lo_hz"] == LO_HZ
    assert body["parameters"]["frame_size"] == 8192
    assert body["parameters"]["threshold_db"] == 30
    assert body["parameters"]["receiver"] == 0

    payload = json.loads(result.stdout)
    assert payload["artifact_ids"] == [f"artifact-{rung}" for rung in LADDER.rungs]
    assert payload["analysis_ids"] == [f"analysis-artifact-{rung}" for rung in LADDER.rungs]
    assert payload["burst_count"] == 5
    assert payload["identified_burst_count"] == 5
    assert payload["rungs"] == [1, 2, 3, 4, 5]
    fit = payload["fit"]
    assert fit["receiver_clock_error_ppm"] == pytest.approx(CLOCK_ERROR * 1e6, abs=1e-6)
    assert fit["lnb_lo_error_hz"] == pytest.approx(LNB_ERROR_HZ, abs=1e-3)
    assert fit["uncertainty_method"] == "leave_one_rung_out"
    assert fit["warnings"] == ["single_monotonic_pass_confounds_drift_with_slope"]


def test_multiple_passes_enable_the_drift_term(
    api_transport: tuple[list[httpx.Request], dict[str, list[dict[str, Any]]]],
) -> None:
    _, bursts = api_transport
    for rows in bursts.values():
        rows.clear()
    for pass_index in range(3):
        for rung in LADDER.rungs:
            epoch = 1.0e9 + 100 * pass_index + rung
            bursts[f"artifact-{rung}"].append(
                _burst(rung, epoch, drift_hz=-5.0 * (epoch - 1.0e9))
            )

    result = _invoke()

    assert result.exit_code == 0, result.output
    fit = json.loads(result.stdout)["fit"]
    assert fit["drift_included"] is True
    assert fit["drift_hz_per_second"] == pytest.approx(-5.0, abs=1e-6)
    assert fit["warnings"] == []


def test_too_few_rungs_fails_with_a_structured_error(
    api_transport: tuple[list[httpx.Request], dict[str, list[dict[str, Any]]]],
) -> None:
    result = _invoke(artifacts=["artifact-1", "artifact-5"])

    assert result.exit_code == 4
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "freq_ladder_fit_failed"
    assert "3 distinct rungs" in error["message"]


def test_daemon_errors_and_bad_inputs_are_structured(
    api_transport: tuple[list[httpx.Request], dict[str, list[dict[str, Any]]]],
) -> None:
    unknown = _invoke(artifacts=["artifact-1", "artifact-9"])
    assert unknown.exit_code == 4
    assert json.loads(unknown.stderr)["error"]["code"] == "artifact_not_found"

    duplicated = _invoke(artifacts=["artifact-1", "artifact-1", "artifact-3"])
    assert duplicated.exit_code == 2
    assert json.loads(duplicated.stderr)["error"]["code"] == "duplicate_artifact_id"

    blank = _invoke(artifacts=["artifact-1", " artifact-2"])
    assert blank.exit_code == 2
    assert json.loads(blank.stderr)["error"]["code"] == "invalid_artifact_id"

    drifting = _invoke("--drift", "maybe")
    assert drifting.exit_code == 2
    assert json.loads(drifting.stderr)["error"]["code"] == "invalid_drift_mode"
