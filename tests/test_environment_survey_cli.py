from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.environment_survey import (
    EnvironmentSurveyEmitterInventory,
    EnvironmentSurveyPlan,
    SurveyEmitter,
)
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.release_candidate import load_private_contract, write_private_contract
from pluto_plus.release_candidate_linux import ToolSourceAttestation

runner = CliRunner()
SERIAL = "winbond-db6968136727402c"
SOURCE = ToolSourceAttestation(
    repository="misko/pluto-plus-utils",
    commit="2" * 40,
)


def _local() -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-7",
        bus_number=3,
        device_number=29,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480.0,
        interface_count=7,
    )


def _inventory_args(tmp_path: Path) -> list[str]:
    inventory = EnvironmentSurveyEmitterInventory(
        schema="pluto-plus-utils.environment-survey-emitter-inventory.v1",
        state="worst-normal",
        emitters=(
            SurveyEmitter(
                emitter_id="internal-ap-24",
                band="2.4-ghz",
                channel="6",
                center_hz=2_437_000_000,
                occupied_start_hz=2_427_000_000,
                occupied_stop_hz=2_447_000_000,
                channel_width_hz=20_000_000,
                power_setting="normal",
                traffic_state="worst-normal",
            ),
        ),
    )
    inventory_path = tmp_path / "emitter-inventory.json"
    identity = write_private_contract(inventory_path.absolute(), inventory)
    return [
        "--emitter-inventory",
        str(identity.path),
        "--emitter-inventory-sha256",
        identity.sha256,
    ]


def test_environment_survey_help_exposes_only_local_rx_plan_execute_verify() -> None:
    result = runner.invoke(app, ["environment-survey", "--help"])

    assert result.exit_code == 0, result.output
    assert "plan" in result.output
    assert "execute" in result.output
    assert "receipt-verify" in result.output
    assert "fleet-select" in result.output
    assert "fleet-verify" in result.output
    root = get_command(app)
    survey = root.commands["environment-survey"]  # type: ignore[attr-defined]

    def options(command_name: str) -> set[str]:
        command = survey.commands[command_name]  # type: ignore[attr-defined]
        return {option for parameter in command.params for option in getattr(parameter, "opts", ())}

    assert options("plan") == {
        "--serial",
        "--usb-path",
        "--emitter-inventory",
        "--emitter-inventory-sha256",
        "--result-root",
        "--output",
        "--ensure-mute",
        "--tool-repository",
    }
    execute_options = options("execute")
    assert execute_options == {
        "--plan",
        "--expected-plan-sha256",
        "--confirm",
        "--ensure-mute",
        "--tool-repository",
    }
    assert not any(
        fragment in option
        for option in execute_options
        for fragment in ("ssh", "route", "dfu", "qspi", "tx-enable")
    )
    assert options("receipt-verify") == {"receipt", "--tool-repository"}
    assert options("fleet-select") == {
        "--manifest",
        "--receipt",
        "--emitter-inventory",
        "--emitter-inventory-sha256",
        "--output",
        "--tool-repository",
    }
    assert options("fleet-verify") == {"selection", "--tool-repository"}


def test_plan_cli_is_passive_private_and_prints_exact_execute_phrase(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    results = tmp_path / "results"
    results.mkdir(mode=0o700)
    plans = tmp_path / "plans"
    plans.mkdir(mode=0o700)
    output = plans / "survey-plan.json"
    inventory_args = _inventory_args(plans)
    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: (_local(),))
    monkeypatch.setattr(
        "pluto_plus.release_candidate_linux.attest_clean_tool_repository",
        lambda _path, **_kwargs: SOURCE,
    )

    result = runner.invoke(
        app,
        [
            "environment-survey",
            "plan",
            "--serial",
            SERIAL,
            "--usb-path",
            "/sys/bus/usb/devices/3-7",
            *inventory_args,
            "--result-root",
            str(results),
            "--output",
            str(output),
            "--ensure-mute",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["mode"] == "passive_plan"
    assert document["hardware_accessed"] is False
    assert document["pluto_tx_authorized"] is False
    assert document["ssh_authorized"] is False
    assert f"--expected-plan-sha256 {document['sha256']}" in document["next_command"]
    assert "--ensure-mute --confirm" in document["next_command"]
    retained = load_private_contract(output.absolute(), EnvironmentSurveyPlan)
    assert retained.target.usb_uri == "usb:3.29.5"
    assert retained.parameters.occupied_2_4_spans_hz[0].start_hz == 2_427_000_000
    assert retained.parameters.occupied_2_4_spans_hz[0].stop_hz == 2_447_000_000
    assert retained.emitter_inventory.emitters[0].emitter_id == "internal-ap-24"
    assert retained.parameters.center_frequencies_hz == tuple(
        range(2_400_000_000, 2_490_000_001, 1_000_000)
    )
    assert retained.parameters.sample_rate_hz == 2_500_000
    assert retained.parameters.rf_bandwidth_hz == 1_500_000
    assert retained.parameters.manual_gain_db == 40.0
    assert retained.parameters.windows_per_center == 32
    assert retained.parameters.samples_per_window == 65_536
    assert retained.parameters.fft_size == 4_096
    assert retained.parameters.stft_hop_samples == 2_048
    assert retained.parameters.minimum_free_space_bytes == 5_368_709_120
    assert output.stat().st_mode & 0o777 == 0o600


def test_plan_cli_refuses_missing_explicit_mute_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def scan() -> tuple[LocalUsbPluto, ...]:
        nonlocal called
        called = True
        return (_local(),)

    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", scan)
    result = runner.invoke(
        app,
        [
            "environment-survey",
            "plan",
            "--serial",
            SERIAL,
            "--usb-path",
            "/sys/bus/usb/devices/3-7",
            "--emitter-inventory",
            str(tmp_path / "unused.json"),
            "--emitter-inventory-sha256",
            "0" * 64,
            "--result-root",
            str(tmp_path),
            "--output",
            str(tmp_path / "plan.json"),
        ],
    )

    assert result.exit_code == 2
    assert called is False
    assert "explicit --ensure-mute" in result.stderr


def test_plan_cli_rejects_removed_analysis_knobs_before_inventory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def scan() -> tuple[LocalUsbPluto, ...]:
        nonlocal called
        called = True
        return (_local(),)

    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", scan)
    result = runner.invoke(
        app,
        [
            "environment-survey",
            "plan",
            "--serial",
            SERIAL,
            "--usb-path",
            "/sys/bus/usb/devices/3-7",
            "--emitter-inventory",
            str(tmp_path / "unused.json"),
            "--emitter-inventory-sha256",
            "0" * 64,
            "--result-root",
            str(tmp_path),
            "--output",
            str(tmp_path / "plan.json"),
            "--ensure-mute",
            "--sample-rate",
            "1000000",
        ],
    )

    assert result.exit_code == 2
    assert called is False
    assert "No such option: --sample-rate" in result.output


def test_fleet_select_rejects_bad_inventory_pin_before_source_or_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    called = False

    def attest(_path: Path, **_kwargs: object) -> ToolSourceAttestation:
        nonlocal called
        called = True
        return SOURCE

    monkeypatch.setattr("pluto_plus.release_candidate_linux.attest_clean_tool_repository", attest)
    result = runner.invoke(
        app,
        [
            "environment-survey",
            "fleet-select",
            "--manifest",
            str(tmp_path / "manifest.json"),
            "--receipt",
            str(tmp_path / "receipt.json"),
            "--emitter-inventory",
            str(tmp_path / "inventory.json"),
            "--emitter-inventory-sha256",
            "BAD",
            "--output",
            str(tmp_path / "selection.json"),
        ],
    )

    assert result.exit_code == 2
    assert "exactly 64 lowercase" in result.stderr
    assert called is False
