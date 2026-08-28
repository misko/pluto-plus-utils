from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.ddr_recovery import (
    DdrRecoveryCycleResult,
    DdrRecoveryError,
    DdrRecoveryProbe,
    execute_ddr_recovery,
    prepare_ddr_recovery,
)
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus
from pluto_plus.metadata_soak import MetadataHealth

SERIAL = "104000b29905000e17000800065934759d"
PROFILE = "ddr-burst-v1-rc2-ram"
runner = CliRunner()


def _health(**updates: Any) -> MetadataHealth:
    values: dict[str, Any] = {
        "serial": SERIAL,
        "firmware_version": "v0.42-plutoplus-spf-ddr-burst-v1-rc2",
        "boot_id": "boot-a",
        "uptime_seconds": 100.0,
        "iiod_pid": 456,
        "iiod_generation": 7,
        "iiod_start_ticks": 1234,
        "active_rx_buffers": 0,
        "active_tx_buffers": 0,
        "tandem_state": 0,
        "fault_flags": 0,
        "overflow_count": 0,
        "tx1_gain_db": -80.0,
        "tx2_gain_db": -80.0,
        "dds_enabled": False,
    }
    values.update(updates)
    return MetadataHealth(**values)


def _probe(mode: str) -> DdrRecoveryProbe:
    return DdrRecoveryProbe(
        mode=mode,
        samples_per_frame=1_000_000 if mode == "ddr" else 262_144,
        requested_frames=2,
        observed_frames=2,
        missing_sample_count=0,
        gap_count=0,
        overflow_count=0,
        observed_fraction=1.0,
        elapsed_seconds=0.1,
        passed=True,
    )


def _cycle(cycle: int, channel: int) -> DdrRecoveryCycleResult:
    return DdrRecoveryCycleResult(
        cycle=cycle,
        channel=channel,
        victim_exit_code=-15,
        disconnect_delay_ms=50,
        ddr_probe=_probe("ddr"),
        ordinary_probe=_probe("ordinary"),
        settings_restored=True,
    )


class _HealthProbe:
    def __init__(self, health: MetadataHealth | None = None) -> None:
        self.health = health or _health()
        self.inspect_calls = 0
        self.safe_calls = 0

    def inspect(self) -> MetadataHealth:
        self.inspect_calls += 1
        return self.health

    def ensure_tx_safe(self) -> MetadataHealth:
        self.safe_calls += 1
        return self.health


def test_prepare_ddr_recovery_locks_release_geometry_and_profile() -> None:
    plan = prepare_ddr_recovery("192.168.1.15", SERIAL, cycles=20, profile_id=PROFILE)

    assert plan.expected_metadata_abi == 3
    assert plan.victim_iq_bytes == 200_000_000
    assert plan.sample_rate_hz == 25_000_000
    assert plan.victim_frames == 50
    assert plan.kernel_buffers == 4
    assert plan.confirmation_phrase == f"QUALIFY DDR RECOVERY {SERIAL} 20"

    with pytest.raises(DdrRecoveryError, match="ABI-3 200 MB"):
        prepare_ddr_recovery(
            "192.168.1.15",
            SERIAL,
            cycles=1,
            profile_id="single-rx-metadata-rc1-ram",
        )


def test_execute_alternates_receivers_and_attests_every_cycle(tmp_path: Path) -> None:
    plan = prepare_ddr_recovery("192.168.1.15", SERIAL, cycles=4, profile_id=PROFILE)
    health = _HealthProbe()
    requested: list[tuple[int, int]] = []

    def run(_plan: object, cycle: int, channel: int) -> DdrRecoveryCycleResult:
        requested.append((cycle, channel))
        return _cycle(cycle, channel)

    report_path = tmp_path / "report.json"
    report = execute_ddr_recovery(
        plan,
        report_path=report_path,
        health_probe=health,
        cycle_runner=run,
    )

    assert report.outcome == "pass"
    assert requested == [(0, 0), (1, 1), (2, 0), (3, 1)]
    assert health.inspect_calls == 5
    assert health.safe_calls == 1
    assert len(report.checkpoints) == 4
    assert report_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(report_path.read_text())["outcome"] == "pass"


def test_execute_writes_failure_evidence_and_still_enforces_tx_safe(tmp_path: Path) -> None:
    plan = prepare_ddr_recovery("192.168.1.15", SERIAL, cycles=2, profile_id=PROFILE)
    health = _HealthProbe()
    report_path = tmp_path / "failed.json"

    def fail(_plan: object, _cycle: int, _channel: int) -> DdrRecoveryCycleResult:
        raise TimeoutError("immediate reopen stalled")

    with pytest.raises(DdrRecoveryError, match="immediate reopen stalled"):
        execute_ddr_recovery(
            plan,
            report_path=report_path,
            health_probe=health,
            cycle_runner=fail,
        )

    document = json.loads(report_path.read_text())
    assert document["outcome"] == "fail"
    assert "immediate reopen stalled" in document["error"]
    assert health.safe_calls == 1


def test_execute_rejects_iiod_restart_as_false_recovery(tmp_path: Path) -> None:
    plan = prepare_ddr_recovery("192.168.1.15", SERIAL, cycles=1, profile_id=PROFILE)

    class RestartProbe(_HealthProbe):
        def inspect(self) -> MetadataHealth:
            self.inspect_calls += 1
            return _health(iiod_pid=456 if self.inspect_calls == 1 else 999)

    with pytest.raises(DdrRecoveryError, match="iiOD process changed"):
        execute_ddr_recovery(
            plan,
            report_path=tmp_path / "restart.json",
            health_probe=RestartProbe(),
            cycle_runner=lambda _plan, cycle, channel: _cycle(cycle, channel),
        )


@pytest.fixture
def healthy_environment(monkeypatch: Any) -> None:
    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment",
        lambda **_kwargs: IioEnvironmentReport(
            healthy=True,
            status=IioEnvironmentStatus.READY,
            message="ready",
            python_executable="/venv/python",
            pyadi_path="/venv/adi/__init__.py",
            pylibiio_path="/venv/iio.py",
            native_libiio_candidate="libiio.so.0",
            native_libiio_path="/usr/lib/libiio.so.0",
            libiio_version="0.25",
            backends=("ip",),
        ),
    )


def test_cli_dry_run_is_non_mutating_and_exact() -> None:
    result = runner.invoke(
        app,
        [
            "radio",
            "qualify-ddr-recovery",
            "192.168.1.15",
            "--expect-serial",
            SERIAL,
            "--cycles",
            "20",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.stdout)
    assert document["execute"] is False
    assert document["plan"]["victim_iq_bytes"] == 200_000_000
    assert document["confirmation_phrase"] == f"QUALIFY DDR RECOVERY {SERIAL} 20"


def test_cli_execute_forwards_pinned_health_and_live_runner(
    tmp_path: Path, monkeypatch: Any, healthy_environment: None
) -> None:
    known_hosts = tmp_path / "known_hosts"
    password = tmp_path / "password"
    report_path = tmp_path / "report.json"
    known_hosts.write_text("192.168.1.15 ssh-ed25519 AAAATEST\n")
    password.write_text("analog\n")
    known_hosts.chmod(0o600)
    password.chmod(0o600)
    calls: list[dict[str, Any]] = []

    class Transport:
        def __init__(self, **kwargs: Any) -> None:
            calls.append({"transport": kwargs})

    class Probe:
        def __init__(self, transport: object, *, serial: str) -> None:
            calls.append({"probe": {"transport": transport, "serial": serial}})

    def execute(plan: object, **kwargs: Any) -> object:
        calls.append({"execute": {"plan": plan, **kwargs}})
        return SimpleNamespace(model_dump=lambda **_kwargs: {"outcome": "pass"})

    monkeypatch.setattr("pluto_plus.cli.BoundSshTransport", Transport)
    monkeypatch.setattr("pluto_plus.cli.SshMetadataHealthProbe", Probe)
    monkeypatch.setattr("pluto_plus.cli.execute_ddr_recovery", execute)

    result = runner.invoke(
        app,
        [
            "radio",
            "qualify-ddr-recovery",
            "192.168.1.15",
            "--expect-serial",
            SERIAL,
            "--cycles",
            "2",
            "--ssh-known-hosts-file",
            str(known_hosts),
            "--ssh-password-file",
            str(password),
            "--report",
            str(report_path),
            "--execute",
            "--confirm",
            f"QUALIFY DDR RECOVERY {SERIAL} 2",
        ],
    )

    assert result.exit_code == 0, result.output
    assert calls[0]["transport"]["known_hosts_file"] == known_hosts.resolve()
    assert calls[1]["probe"]["serial"] == SERIAL
    execution = calls[2]["execute"]
    assert execution["report_path"] == report_path.resolve()
    assert execution["cycle_runner"].__name__ == "run_live_ddr_recovery_cycle"
