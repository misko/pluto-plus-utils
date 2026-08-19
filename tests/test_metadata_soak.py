from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

import pluto_plus.metadata_soak as metadata_soak
from pluto_plus.metadata_soak import (
    MetadataHealth,
    MetadataMatrixCell,
    MetadataSlotResult,
    MetadataSoakError,
    MetadataSoakPlan,
    SshMetadataHealthProbe,
    _metadata_phase,
    _restore_live_rx_settings,
    execute_metadata_soak,
    prepare_metadata_soak,
)

SERIAL = "104000b29905000e17000800065934759d"
FIRMWARE = "v0.40-plutoplus-spf-tandem-agc-v7"


def _health(**changes: object) -> MetadataHealth:
    values: dict[str, object] = {
        "serial": SERIAL,
        "firmware_version": FIRMWARE,
        "boot_id": "1f9b9fd2-837d-47bd-a6aa-cd58df6b35a0",
        "uptime_seconds": 1000.0,
        "iiod_pid": 180,
        "iiod_generation": 1,
        "iiod_start_ticks": 319,
        "active_rx_buffers": 0,
        "active_tx_buffers": 0,
        "tandem_state": 0,
        "fault_flags": 0,
        "overflow_count": 0,
        "tx1_gain_db": -80.0,
        "tx2_gain_db": -80.0,
        "dds_enabled": False,
    }
    values.update(changes)
    return MetadataHealth(**values)  # type: ignore[arg-type]


class FakeProbe:
    def __init__(self, snapshots: list[MetadataHealth]) -> None:
        self.snapshots = snapshots
        self.safe_calls = 0

    def inspect(self) -> MetadataHealth:
        return self.snapshots.pop(0)

    def ensure_tx_safe(self) -> MetadataHealth:
        self.safe_calls += 1
        return _health(uptime_seconds=1001.0)


class FakeSshTransport:
    def __init__(self, output: str) -> None:
        self.output = output
        self.calls: list[tuple[str, bytes | None, float]] = []

    def run(
        self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15
    ) -> str:
        self.calls.append((command, stdin, timeout_s))
        return self.output


def _health_output(**changes: object) -> str:
    health = _health(**changes)
    values = {
        "serial": health.serial,
        "firmware_version": health.firmware_version,
        "boot_id": health.boot_id,
        "uptime_seconds": health.uptime_seconds,
        "iiod_pid": health.iiod_pid,
        "iiod_generation": health.iiod_generation,
        "iiod_start_ticks": health.iiod_start_ticks,
        "active_rx_buffers": health.active_rx_buffers,
        "active_tx_buffers": health.active_tx_buffers,
        "tandem_state": health.tandem_state,
        "fault_flags": health.fault_flags,
        "overflow_count": health.overflow_count,
        "tx1_gain_db": health.tx1_gain_db,
        "tx2_gain_db": health.tx2_gain_db,
        "dds_enabled": int(health.dds_enabled),
    }
    return "\n".join(f"PPU\t{key}\t{value}" for key, value in values.items()) + "\n"


def _slot_result(slot: int) -> MetadataSlotResult:
    return MetadataSlotResult(
        slot=slot,
        context_count=1,
        retunes=8,
        metadata_frames=8,
        maximum_close_seconds=0.05,
        settings_restored=True,
        lo_readbacks_hz=(
            959_687_500,
            1_190_312_500,
            1_209_687_500,
            1_440_312_500,
            1_459_687_500,
            1_690_312_500,
            1_709_687_500,
            1_940_312_500,
        )
        if slot % 2 == 0
        else (
            1_940_312_500,
            1_709_687_500,
            1_690_312_500,
            1_459_687_500,
            1_440_312_500,
            1_209_687_500,
            1_190_312_500,
            959_687_500,
        ),
    )


def test_prepare_soak_is_exact_profile_and_bounded() -> None:
    plan = prepare_metadata_soak(
        "192.168.1.15",
        SERIAL,
        profile_id="tandem-agc-v7-release-ram",
        slots=9,
    )

    assert plan.target == "192.168.1.15"
    assert plan.expected_firmware == FIRMWARE
    assert plan.expected_metadata_abi == 2
    assert len(plan.matrix) == 9
    assert plan.lo_frequencies_hz == (
        959_687_500,
        1_190_312_500,
        1_209_687_500,
        1_440_312_500,
        1_459_687_500,
        1_690_312_500,
        1_709_687_500,
        1_940_312_500,
    )

    for profile in ("libiio-continuous-metadata", "unknown"):
        with pytest.raises(MetadataSoakError, match="ABI-2 tandem"):
            prepare_metadata_soak("192.168.1.15", SERIAL, profile_id=profile, slots=1)
    for target in ("radio.local", "8.8.8.8"):
        with pytest.raises(MetadataSoakError, match="private IPv4"):
            prepare_metadata_soak(target, SERIAL, slots=1)
    with pytest.raises(MetadataSoakError, match="serial"):
        prepare_metadata_soak("192.168.1.15", "SERIAL; reboot", slots=1)
    with pytest.raises(MetadataSoakError, match="between 1 and 936"):
        prepare_metadata_soak("192.168.1.15", SERIAL, slots=937)


def test_ssh_health_probe_uses_fixed_script_and_strict_parser() -> None:
    transport = FakeSshTransport(_health_output())
    probe = SshMetadataHealthProbe(transport, serial=SERIAL)

    assert probe.inspect().boot_id == _health().boot_id
    assert probe.ensure_tx_safe().tx_safe
    assert transport.calls[0][0] == f"/bin/sh -s -- {SERIAL} 0"
    assert transport.calls[1][0] == f"/bin/sh -s -- {SERIAL} 1"
    assert transport.calls[0][1] == transport.calls[1][1]
    assert b"iiod-generation" in (transport.calls[0][1] or b"")

    bad = FakeSshTransport(_health_output() + "PPU\tserial\tduplicate\n")
    with pytest.raises(MetadataSoakError, match="malformed or duplicated"):
        SshMetadataHealthProbe(bad, serial=SERIAL).inspect()


def test_live_phase_errors_preserve_slot_frequency_and_refill() -> None:
    with pytest.raises(
        MetadataSoakError,
        match=(
            r"slot=2 phase=metadata_refill frequency_hz=915000000 refill=3 "
            r"operation=buffer_refill: OSError"
        ),
    ), _metadata_phase(
        2,
        "metadata_refill",
        frequency=915_000_000,
        refill=3,
        operation="buffer_refill",
    ):
        raise OSError(16, "Device or resource busy")


def test_spawn_worker_preloads_validated_iio_before_radio_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    messages: list[dict[str, object]] = []

    class Connection:
        def send(self, message: dict[str, object]) -> None:
            messages.append(message)

        def close(self) -> None:
            pass

    monkeypatch.setattr(
        metadata_soak,
        "inspect_iio_environment",
        lambda **_kwargs: SimpleNamespace(
            healthy=False,
            actionable_message="explicit native libiio could not be loaded",
        ),
    )

    def unexpected_radio_access(*_args: object) -> MetadataSlotResult:
        raise AssertionError("radio access must follow child IIO preflight")

    monkeypatch.setattr(metadata_soak, "_execute_live_metadata_slot", unexpected_radio_access)
    plan = prepare_metadata_soak("192.168.1.15", SERIAL, slots=1)
    metadata_soak._metadata_slot_worker(
        plan.model_dump(mode="json"),
        plan.matrix[0].model_dump(mode="json"),
        0,
        Connection(),
    )

    assert messages == [
        {
            "outcome": "fail",
            "error": (
                "MetadataSoakError: metadata slot worker IIO environment failed: "
                "explicit native libiio could not be loaded"
            ),
        }
    ]


def test_restore_errors_preserve_exact_operation() -> None:
    class RestoreFailure:
        def rx_destroy_buffer(self) -> None:
            pass

        def __setattr__(self, name: str, value: object) -> None:
            if name == "sample_rate":
                raise OSError(16, "Device or resource busy")
            object.__setattr__(self, name, value)

    settings = {
        "rx_enabled_channels": (0, 1),
        "sample_rate": 2_500_000,
        "rx_rf_bandwidth": 2_500_000,
        "rx_lo": 1_000_000_000,
        "rx_buffer_size": 100_000,
        "gain_control_mode_chan0": "manual",
        "gain_control_mode_chan1": "manual",
        "rx_hardwaregain_chan0": 30.0,
        "rx_hardwaregain_chan1": 30.0,
    }

    with pytest.raises(
        MetadataSoakError,
        match=r"slot=4 phase=settings_restore operation=sample_rate_write: OSError",
    ):
        _restore_live_rx_settings(RestoreFailure(), settings, slot=4)


def test_soak_passes_matrix_and_writes_atomic_report(tmp_path: Path) -> None:
    plan = prepare_metadata_soak("192.168.1.15", SERIAL, slots=3)
    probe = FakeProbe(
        [
            _health(),
            _health(uptime_seconds=1001.0),
            _health(uptime_seconds=1002.0),
            _health(uptime_seconds=1003.0),
        ]
    )
    calls: list[tuple[int, int, int]] = []
    sleeps: list[float] = []

    def run_slot(
        _plan: MetadataSoakPlan, cell: MetadataMatrixCell, slot: int
    ) -> MetadataSlotResult:
        calls.append((slot, cell.sample_rate_hz, cell.refills))
        return _slot_result(slot).model_copy(
            update={"metadata_frames": len(plan.lo_frequencies_hz) * cell.refills}
        )

    report_path = tmp_path / "soak.json"
    report = execute_metadata_soak(
        plan,
        report_path=report_path,
        health_probe=probe,
        slot_runner=run_slot,
        monotonic_clock=lambda: 0.0,
        sleeper=sleeps.append,
    )

    assert report.outcome == "pass"
    assert calls == [(0, 1_250_000, 1), (1, 1_250_000, 2), (2, 1_250_000, 4)]
    assert probe.safe_calls == 1
    assert sleeps == pytest.approx([plan.slot_period_seconds, 2 * plan.slot_period_seconds])
    assert json.loads(report_path.read_text())["outcome"] == "pass"
    assert report.final_health is not None and report.final_health.tx_safe


def test_soak_refuses_catch_up_burst(tmp_path: Path) -> None:
    plan = prepare_metadata_soak("192.168.1.15", SERIAL, slots=1)
    probe = FakeProbe([_health()])
    values = iter((0.0, 2.0))

    with pytest.raises(MetadataSoakError, match="refusing an unscheduled catch-up burst"):
        execute_metadata_soak(
            plan,
            report_path=tmp_path / "overrun.json",
            health_probe=probe,
            slot_runner=lambda _plan, _cell, slot: _slot_result(slot),
            monotonic_clock=lambda: next(values),
            sleeper=lambda _seconds: None,
        )

    assert json.loads((tmp_path / "overrun.json").read_text())["outcome"] == "fail"


@pytest.mark.parametrize(
    ("changed", "message"),
    [
        ({"boot_id": "new-boot"}, "boot ID changed"),
        ({"iiod_generation": 2}, "iiOD generation changed"),
        ({"iiod_pid": 181}, "iiOD process changed"),
        ({"active_rx_buffers": 1}, "active RX buffer leaked"),
        ({"tandem_state": 2}, "tandem owner leaked"),
        ({"fault_flags": 1}, "tandem fault"),
    ],
)
def test_soak_fails_closed_on_lifecycle_invariant(
    tmp_path: Path, changed: dict[str, object], message: str
) -> None:
    plan = prepare_metadata_soak("192.168.1.15", SERIAL, slots=1)
    probe = FakeProbe([_health(), _health(**changed)])
    report_path = tmp_path / "failed.json"

    with pytest.raises(MetadataSoakError, match=message):
        execute_metadata_soak(
            plan,
            report_path=report_path,
            health_probe=probe,
            slot_runner=lambda _plan, cell, slot: _slot_result(slot).model_copy(
                update={"metadata_frames": len(plan.lo_frequencies_hz) * cell.refills}
            ),
        )

    assert probe.safe_calls == 1
    document = json.loads(report_path.read_text())
    assert document["outcome"] == "fail"
    assert message in document["error"]


def test_soak_preserves_failure_and_runs_tx_cleanup(tmp_path: Path) -> None:
    plan = prepare_metadata_soak("192.168.1.15", SERIAL, slots=1)
    probe = FakeProbe([_health()])

    def fail(
        _plan: MetadataSoakPlan, _cell: MetadataMatrixCell, _slot: int
    ) -> MetadataSlotResult:
        raise BrokenPipeError("injected EPIPE")

    with pytest.raises(MetadataSoakError, match="injected EPIPE"):
        execute_metadata_soak(
            plan,
            report_path=tmp_path / "epipe.json",
            health_probe=probe,
            slot_runner=fail,
        )

    assert probe.safe_calls == 1
    assert json.loads((tmp_path / "epipe.json").read_text())["outcome"] == "fail"
