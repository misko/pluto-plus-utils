from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from pluto_plus.ddr_ring import DdrRingFinalStatus
from pluto_plus.metadata_ladder import (
    MetadataContinuityCell,
    MetadataContinuityLadderReport,
)
from pluto_plus.qualification_campaign import (
    GainTimelineQualificationCase,
    GainTimelineQualificationPlan,
    QualificationCampaignError,
    execute_gain_timeline_qualification,
    prepare_gain_timeline_qualification,
    qualification_cases,
)
from pluto_plus.release_candidate import (
    CleanupReceipt,
    ContentIdentity,
    ExpectedRuntime,
    FileIdentity,
    HostRouteReceipt,
    QspiObservation,
    ReleaseCandidateOperationPlan,
    ReleaseCandidatePlan,
    ReleaseCandidateRamReceipt,
    RuntimeObservation,
    SafeState,
    TransitionReceipt,
    UsbInventoryTarget,
    model_file_identity,
    write_private_contract,
)

NOW = datetime(2026, 8, 30, 12, 0, tzinfo=UTC)
SERIAL = "winbond-db6968136727402c"
MODEL = "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)"
PERSISTENT = "v0.44"
CANDIDATE = "v0.45-gain-timeline"


def _safe() -> SafeState:
    return SafeState(
        tx_gain_db=(-80.0, -80.0),
        dds_raw=(0,) * 8,
        dds_scale=(0.0,) * 8,
        dac_selectors=(3, 3, 3, 3),
        tandem_state="IDLE",
        fifo_level=0,
        fault_flags=0,
    )


def _runtime(firmware: str, boot_digit: str) -> RuntimeObservation:
    return RuntimeObservation(
        serial=SERIAL,
        topology="3-7",
        usb_uri="usb:3.29.5",
        hardware_model=MODEL,
        firmware_version=firmware,
        metadata_abi="frame-metadata-v4",
        capabilities=("authoritative-gain-timeline",),
        boot_id=(
            f"{boot_digit * 8}-{boot_digit * 4}-4{boot_digit * 3}-"
            f"8{boot_digit * 3}-{boot_digit * 12}"
        ),
        qspi=QspiObservation(bytes=31_457_280, sha256="9" * 64),
        safe_state=_safe(),
    )


def _contracts(root: Path) -> tuple[Path, ReleaseCandidateOperationPlan, ReleaseCandidatePlan]:
    candidate = ReleaseCandidatePlan(
        candidate_id="1" * 32,
        created_at=NOW,
        source_repository="misko/plutosdr-fw",
        source_commit="2" * 40,
        device_tool_repository="misko/pluto-plus-utils",
        device_tool_version="0.1.0",
        device_tool_source_commit="3" * 40,
        artifact_index=FileIdentity(
            path=root / "candidate-index.json", bytes=100, sha256="4" * 64
        ),
        dfu=FileIdentity(path=root / "candidate.dfu", bytes=101, sha256="5" * 64),
        fit=ContentIdentity(bytes=100, sha256="6" * 64),
        expected_runtime=ExpectedRuntime(
            firmware_version=CANDIDATE,
            hardware_model=MODEL,
            metadata_abi="frame-metadata-v4",
            capabilities=("authoritative-gain-timeline",),
        ),
    )
    candidate_path = root / "candidate-plan.json"
    candidate_identity = write_private_contract(candidate_path, candidate)
    target = UsbInventoryTarget(
        serial=SERIAL,
        topology="3-7",
        sysfs_path=Path("/sys/bus/usb/devices/3-7"),
        bus_number=3,
        device_number=29,
        network_interface="enx00e02215c53b",
        source_ipv4="192.168.2.10",
    )
    operation = ReleaseCandidateOperationPlan(
        plan_id="7" * 32,
        created_at=NOW,
        candidate_plan=candidate_identity,
        usb_inventory=FileIdentity(
            path=root / "usb-inventory.json", bytes=100, sha256="8" * 64
        ),
        target=target,
        expected_current_firmware=PERSISTENT,
        receipt_path=root / SERIAL / "ram-receipt.json",
        confirmation_phrase=f"RAM BOOT RELEASE CANDIDATE {SERIAL}",
    )
    operation_path = root / "operation-plan.json"
    write_private_contract(operation_path, operation)
    return operation_path, operation, candidate


def _receipt(
    operation_path: Path,
    operation: ReleaseCandidateOperationPlan,
    candidate: ReleaseCandidatePlan,
) -> ReleaseCandidateRamReceipt:
    pre = _runtime(PERSISTENT, "1")
    post = _runtime(CANDIDATE, "2")
    return ReleaseCandidateRamReceipt(
        schema="pluto-plus-utils.release-candidate-ram-receipt.v1",
        receipt_id="a" * 32,
        outcome="pass",
        started_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        tool_repository="misko/pluto-plus-utils",
        tool_version="0.1.0",
        tool_source_commit="3" * 40,
        operation_plan=model_file_identity(operation_path, operation),
        candidate_plan=operation.candidate_plan,
        candidate_dfu=ContentIdentity(bytes=candidate.dfu.bytes, sha256=candidate.dfu.sha256),
        candidate_fit=candidate.fit,
        target=operation.target,
        expected_firmware=CANDIDATE,
        expected_hardware_model=MODEL,
        expected_metadata_abi="frame-metadata-v4",
        required_capabilities=("authoritative-gain-timeline",),
        pre_runtime=pre,
        post_runtime=post,
        host_route=HostRouteReceipt(
            destination="192.168.2.1/32",
            interface=operation.target.network_interface,
            source=operation.target.source_ipv4,
            release_verified=True,
        ),
        transition=TransitionReceipt(
            topology=operation.target.topology,
            sealed_input=True,
            download_completed=True,
            detach_completed=True,
        ),
        cleanup=CleanupReceipt(verified=True),
    )


class _Backend:
    def __init__(self, receipt: ReleaseCandidateRamReceipt) -> None:
        self.receipt = receipt
        self.events: list[str] = []

    @contextmanager
    def radio_lock(self, serial: str) -> Iterator[None]:
        self.events.append(f"radio-enter:{serial}")
        try:
            yield
        finally:
            self.events.append(f"radio-exit:{serial}")

    @contextmanager
    def physical_lan_lock(self) -> Iterator[None]:
        self.events.append("lan-enter")
        try:
            yield
        finally:
            self.events.append("lan-exit")

    def boot_candidate(
        self,
        operation_path: Path,
        *,
        password_path: Path,
        confirmation: str,
    ) -> tuple[ReleaseCandidateRamReceipt, str]:
        del operation_path, password_path, confirmation
        self.events.append("boot")
        return self.receipt, "b" * 64

    def restore_persistent(
        self,
        receipt: ReleaseCandidateRamReceipt,
        *,
        password_path: Path,
    ) -> RuntimeObservation:
        del receipt, password_path
        self.events.append("restore")
        return _runtime(PERSISTENT, "3")


def _ladder(**kwargs: Any) -> MetadataContinuityLadderReport:
    sample_ladder = tuple(int(item) for item in kwargs["samples_per_channel"])
    frames = int(kwargs["frames"])
    channels = tuple(kwargs["channels"])
    ring_bytes = int(kwargs["ddr_ring_bytes"])
    cells: list[MetadataContinuityCell] = []
    for samples in sample_ladder:
        observed = samples * frames
        iq_bytes = observed * len(channels) * 4
        frame_bytes = samples * len(channels) * 4
        admitted = ring_bytes // frame_bytes * frame_bytes if ring_bytes else 0
        capacity = admitted // frame_bytes if admitted else 0
        prefix_frames = min(frames, capacity)
        status = (
            None
            if not ring_bytes
            else DdrRingFinalStatus(
                version=2,
                state="complete",
                terminal_reason="target_complete",
                error_code=0,
                requested_capacity_iq_bytes=ring_bytes,
                admitted_capacity_iq_bytes=admitted,
                target_frames=frames,
                produced_frames=frames,
                consumed_frames=frames,
                high_water_frames=prefix_frames,
                wrap_count=frames // capacity,
                producer_position=frames % capacity,
                consumer_position=frames % capacity,
                last_contiguous_sample_sequence=1_000 + observed,
                first_unavailable_sample_sequence=None,
                failure_frame_index=None,
                failure_sample_sequence=None,
            )
        )
        cells.append(
            MetadataContinuityCell(
                samples_per_channel=samples,
                requested_frames=frames,
                observed_frames=frames,
                observed_sample_count=observed,
                device_span_sample_count=observed,
                first_sample_sequence=1_000,
                last_sample_sequence_exclusive=1_000 + observed,
                missing_sample_count=0,
                gap_count=0,
                overflow_count=0,
                iq_bytes=iq_bytes,
                elapsed_seconds=1.0,
                achieved_payload_mbps=iq_bytes / 1_000_000,
                achieved_payload_mibps=iq_bytes / (1024 * 1024),
                observed_fraction=1.0,
                tandem_metadata_frames=frames,
                authoritative_gain_timeline_frames=frames,
                gain_observation_interval_samples=samples,
                ddr_ring_status=status,
                ddr_ring_prefix_frames=prefix_frames,
                ddr_ring_prefix_iq_bytes=prefix_frames * frame_bytes,
                ddr_ring_prefix_contiguous=bool(status),
                passed=True,
            )
        )
    return MetadataContinuityLadderReport(
        serial=kwargs["serial"],
        uri=kwargs["uri"],
        transport="iio_usb" if kwargs["uri"] == "usb:" else "iio_ip",
        model=MODEL,
        firmware_version=CANDIDATE,
        metadata_abi=4,
        sample_rate_hz=kwargs["sample_rate_hz"],
        rf_bandwidth_hz=kwargs["rf_bandwidth_hz"],
        channels=channels,
        kernel_buffers=kwargs["kernel_buffers"],
        tandem_mode=kwargs["tandem_mode"],
        acceptance_mode=kwargs["acceptance_mode"],
        ddr_ring_requested_iq_bytes=ring_bytes,
        cells=tuple(cells),
        failures=(),
        largest_passing_samples_per_channel=sample_ladder[0],
        original_settings_restored=True,
    )


def _plan(root: Path) -> tuple[Path, _Backend]:
    operation_path, operation, candidate = _contracts(root)
    plan = prepare_gain_timeline_qualification(
        operation_path,
        physical_ip="192.168.1.20",
        report_path=root / "qualification-report.json",
        now=lambda: NOW,
        campaign_id_factory=lambda: "c" * 32,
    )
    plan_path = root / "qualification-plan.json"
    write_private_contract(plan_path, plan)
    return plan_path, _Backend(_receipt(operation_path, operation, candidate))


def test_frozen_campaign_has_exact_matrix_and_named_issue_regressions() -> None:
    cases = qualification_cases()
    matrix = tuple(case for case in cases if case.profile == "matrix")
    issue_49 = tuple(
        case for case in cases if case.profile == "issue-49-usb-enodata"
    )
    issue_54_max = tuple(case for case in cases if case.profile == "issue-54-ip-max")
    issue_54_ladders = tuple(
        case for case in cases if case.profile == "issue-54-ip-ladder"
    )

    assert len(cases) == 187
    assert len(matrix) == 60
    assert len(issue_49) == 64
    assert len(issue_54_max) == 60
    assert len(issue_54_ladders) == 3
    assert not any(case.buffering == "ring-200mb" and case.layout == "dual" for case in cases)
    assert {case.frames for case in matrix} == {200, 600, 5_000}
    assert {case.transport for case in cases} == {"usb", "physical-ip"}
    assert {case.tandem_mode for case in cases} == {"hold", "auto"}
    assert {case.repetition for case in issue_49} == set(range(1, 65))
    assert all(
        (
            case.transport,
            case.sample_rate_hz,
            case.samples_per_channel,
            case.frames,
            case.kernel_buffers,
        )
        == ("usb", 1_000_000, (100_000,), 100, 8)
        for case in issue_49
    )
    for sample_rate_hz in (2_500_000, 3_000_000, 5_000_000):
        at_rate = tuple(
            case for case in issue_54_max if case.sample_rate_hz == sample_rate_hz
        )
        assert len(at_rate) == 20
        assert {case.repetition for case in at_rate} == set(range(1, 21))
        ladder = tuple(
            case for case in issue_54_ladders if case.sample_rate_hz == sample_rate_hz
        )
        assert len(ladder) == 1
        assert ladder[0].samples_per_channel == (
            4_194_304,
            2_097_152,
            1_048_576,
            524_288,
        )
    with pytest.raises(ValidationError, match="single-RX"):
        GainTimelineQualificationCase(
            transport="usb",
            buffering="ring-200mb",
            tandem_mode="hold",
            layout="dual",
            tier="regression",
            frames=200,
            repetition=1,
        )


def test_plan_rejects_dual_as_a_ring_layout(tmp_path: Path) -> None:
    operation_path, _operation, _candidate = _contracts(tmp_path)
    plan = prepare_gain_timeline_qualification(
        operation_path,
        physical_ip="192.168.1.20",
        report_path=tmp_path / "report.json",
        now=lambda: NOW,
        campaign_id_factory=lambda: "c" * 32,
    )

    with pytest.raises(ValidationError):
        GainTimelineQualificationPlan.model_validate(
            plan.model_dump(mode="python", by_alias=True) | {"ring_layouts": ["dual"]}
        )


def test_campaign_runs_usb_then_locked_ip_and_restores_persistent_qspi(
    tmp_path: Path,
) -> None:
    plan_path, backend = _plan(tmp_path)
    plan = GainTimelineQualificationPlan.model_validate_json(plan_path.read_bytes())

    report, digest = execute_gain_timeline_qualification(
        plan_path,
        password_path=tmp_path / "password",
        confirmation=plan.confirmation_phrase,
        backend=backend,
        ladder_runner=_ladder,
        now=iter((NOW, NOW + timedelta(minutes=1))).__next__,
    )

    assert len(digest) == 64
    assert report.outcome == "pass"
    assert len(report.cases) == 187
    assert all(result.report is not None for result in report.cases)
    assert backend.events[:2] == [f"radio-enter:{SERIAL}", "boot"]
    assert backend.events[-2:] == ["restore", f"radio-exit:{SERIAL}"]
    assert backend.events.count("lan-enter") == backend.events.count("lan-exit") == 1
    assert backend.events.index("lan-enter") < backend.events.index("lan-exit")


def test_campaign_failure_is_receipted_after_verified_restore(tmp_path: Path) -> None:
    plan_path, backend = _plan(tmp_path)
    plan = GainTimelineQualificationPlan.model_validate_json(plan_path.read_bytes())

    def fail(**_kwargs: Any) -> MetadataContinuityLadderReport:
        raise RuntimeError("injected ladder failure")

    with pytest.raises(QualificationCampaignError) as raised:
        execute_gain_timeline_qualification(
            plan_path,
            password_path=tmp_path / "password",
            confirmation=plan.confirmation_phrase,
            backend=backend,
            ladder_runner=fail,
            now=iter((NOW, NOW + timedelta(minutes=1))).__next__,
        )

    assert raised.value.report is not None
    assert raised.value.report.outcome == "failed"
    assert raised.value.report.persistent_qspi_unchanged
    assert backend.events[-2:] == ["restore", f"radio-exit:{SERIAL}"]


def test_keyboard_interrupt_propagates_only_after_restore(tmp_path: Path) -> None:
    plan_path, backend = _plan(tmp_path)
    plan = GainTimelineQualificationPlan.model_validate_json(plan_path.read_bytes())

    def interrupt(**_kwargs: Any) -> MetadataContinuityLadderReport:
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        execute_gain_timeline_qualification(
            plan_path,
            password_path=tmp_path / "password",
            confirmation=plan.confirmation_phrase,
            backend=backend,
            ladder_runner=interrupt,
        )

    assert backend.events[-2:] == ["restore", f"radio-exit:{SERIAL}"]
