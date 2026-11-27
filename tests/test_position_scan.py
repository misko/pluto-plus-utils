from __future__ import annotations

import dataclasses
import json
import struct
import zlib
from types import SimpleNamespace

import pytest
from test_adaptive_scan_radio import Radio
from test_continuous_scan import Socket

from pluto_plus import adaptive_scan as old
from pluto_plus.adaptive_scan_client import AdaptiveScanTransportError
from pluto_plus.continuous_scan import ContinuousSetup, ContinuousVisit
from pluto_plus.position_scan import (
    PositionCapabilities,
    PositionClient,
    PositionSession,
    PositionSetup,
    PositionTerminal,
    PositionVisit,
    build_position_setup,
)
from pluto_plus.position_scan_radio import PositionRadioOwner, prepare_position_scan_radio
from pluto_plus.position_scan_record import FREQUENCIES, record_position_scan
from pluto_plus.position_scan_verify import verify_position_scan
from pluto_plus.radio_lock import RadioLockError, acquire_radio_lock


def test_recorder_holds_station_lock_and_cleanup_runs_on_start_failure(tmp_path):
    output = tmp_path / "capture"
    with acquire_radio_lock("serial"), pytest.raises(RadioLockError):
        record_position_scan("ip:192.168.1.15", "serial", output)
    assert not output.exists()
    cleaned = []

    def fail(*args, **kwargs):
        raise RuntimeError("START failed")

    def cleanup():
        with pytest.raises(RadioLockError), acquire_radio_lock("serial"):
            pytest.fail("cleanup ran outside lock")
        cleaned.append(True)

    with pytest.raises(RuntimeError, match="START failed"):
        record_position_scan(
            "ip:192.168.1.15", "serial", output, owner_factory=fail, after_close_hook=cleanup
        )
    assert cleaned == [True]
    assert json.loads((output / "capture.json").read_text())["error"]


def setup(digest=b"a" * 32):
    value = build_position_setup(
        session=1, generation=2, seed=3, frequencies_hz=FREQUENCIES, analysis_digest=digest
    )
    return dataclasses.replace(
        value,
        targets=tuple(
            dataclasses.replace(
                t,
                profile_image=bytes([t.channel]) * 16,
                profile_crc32=zlib.crc32(bytes([t.channel]) * 16),
            )
            for t in value.targets
        ),
    )


def test_failed_device_terminal_preserves_evidence_and_restores(tmp_path):
    @dataclasses.dataclass
    class Preparation:
        setup: PositionSetup

    class Owner:
        def __init__(self, uri, serial, plan, **kwargs):
            self.preparation = Preparation(dataclasses.replace(plan, targets=setup().targets))
            kwargs["before_start_hook"](self.preparation)
            self.session = SimpleNamespace(
                terminal=PositionTerminal(
                    session=plan.session,
                    generation=plan.generation,
                    final_counter=0,
                    restore_before=0,
                    restore_after=1,
                    planned=0,
                    delivered=0,
                    skipped=0,
                    invalid=0,
                    cancelled=0,
                    iq_bytes=0,
                    state=old.TerminalState.FAILED,
                    reason=1,
                    error=-5,
                )
            )

        def visits(self):
            return iter(())

        def close(self):
            return SimpleNamespace(restoration={"fastlock_inactive": True})

    output = tmp_path / "failed"
    with pytest.raises(RuntimeError, match="device scan failed"):
        record_position_scan("ip:192.168.1.15", "serial", output, owner_factory=Owner)
    report = json.loads((output / "capture.json").read_text())
    assert report["terminal"]["error"] == -5
    assert report["host_restoration"]["fastlock_inactive"]
    assert (output / "visits.bin").stat().st_size == 140


def visit(sequence=0, plan=None):
    plan = plan or setup()
    target = plan.targets[sequence % 24]
    start = (1 << 32) - 100_000 + sequence * 450_000
    return PositionVisit(
        session=plan.session,
        generation=plan.generation,
        visit=sequence,
        selection_counter=start - 220_000,
        transition_before=start - 220_000,
        load_after=start - 210_000,
        recall_before=start - 209_000,
        transition_after=start - 200_000,
        valid_start=start,
        valid_end=start + 200_000,
        frequency_hz=target.frequency_hz,
        verified_frequency_hz=target.frequency_hz - 2,
        iq_bytes=1_600_000,
        missing_samples_before=0,
        analog_bandwidth_hz=8_000_000,
        source_rate_hz=10_000_000,
        target=target.channel,
        profile=target.profile,
        result=old.VisitResult.COMPLETE,
        eligible_mask=0xFF_FFFF,
        effective_weight=65536,
        profile_crc32=123,
        original_profile_crc32=target.profile_crc32,
        slot_generation=sequence // 8 + 1,
        sweep=sequence // 24,
        plan_digest=plan.analysis_digest,
    )


@pytest.mark.parametrize(
    "record,codec",
    [
        (PositionCapabilities(), PositionCapabilities),
        (setup(), PositionSetup),
        (visit(23), PositionVisit),
    ],
)
def test_v6_canonical_round_trip_corruption_and_legacy_rejection(record, codec):
    raw = record.pack()
    assert codec.unpack(raw) == record
    for broken in old.corruptions(raw):
        with pytest.raises(old.AdaptiveScanProtocolError):
            codec.unpack(broken)
    if isinstance(record, PositionSetup):
        with pytest.raises(old.AdaptiveScanProtocolError):
            ContinuousSetup.unpack(raw)
    if isinstance(record, PositionVisit):
        with pytest.raises(old.AdaptiveScanProtocolError):
            ContinuousVisit.unpack(raw)


def test_multiple_wraps_rollover_delayed_receipts_and_bound_slot_state():
    session = PositionSession(PositionClient("fixture"), Socket(), "device", setup())
    delayed = [PositionVisit.unpack(visit(i).pack()) for i in range(96)]
    for item in delayed:
        session._validate_visit(item)
    assert session._last_valid_end > 1 << 32
    assert session._slot_generations == list(range(12, 13)) * 8
    wrong = dataclasses.replace(visit(96), slot_generation=1)
    with pytest.raises(AdaptiveScanTransportError, match="generation"):
        session._validate_visit(wrong)
    wrong = dataclasses.replace(visit(96), plan_digest=b"b" * 32)
    with pytest.raises(AdaptiveScanTransportError, match="plan"):
        session._validate_visit(wrong)


def test_old_device_rejected_before_radio_mutation():
    client = PositionClient("fixture", connector=lambda *_: Socket(b"-38\n"))
    with pytest.raises(AdaptiveScanTransportError):
        PositionRadioOwner.start(
            "ip:192.168.1.15",
            "serial",
            setup(),
            client_factory=lambda _: client,
            radio_factory=lambda *_: pytest.fail("radio mutated"),
        )


def test_prepare_24_immutable_profiles_and_failure_restore():
    radio = Radio("ip:192.168.1.15", "serial")
    receipt = prepare_position_scan_radio(
        "ip:192.168.1.15", "serial", setup(), radio_factory=lambda *_: radio
    )
    assert len(receipt.profile_words) == 24
    assert PositionSetup.unpack(receipt.setup.pack()) == receipt.setup
    assert radio.active is None
    for target in receipt.setup.targets[:8]:
        assert bytes(radio.profiles[target.profile]) == target.profile_image
    failed = Radio("ip:192.168.1.15", "serial", bad_recall=True)
    with pytest.raises(Exception, match="recall"):
        prepare_position_scan_radio(
            "ip:192.168.1.15", "serial", setup(), radio_factory=lambda *_: failed
        )
    assert failed.restored and failed.closed


def test_saved_iq_independent_verifier_rejects_rehashed_mislabel(tmp_path):
    @dataclasses.dataclass
    class Preparation:
        setup: PositionSetup

    class Owner:
        def __init__(self, uri, serial, plan, **kwargs):
            # Bind exactly the recorder's generated session/plan identity.
            prepared = dataclasses.replace(plan, targets=setup().targets)
            self.preparation = Preparation(prepared)
            kwargs["before_start_hook"](self.preparation)
            self.session = SimpleNamespace(terminal=None)
            self.prepared = prepared

        def visits(self):
            for sequence in range(48):
                yield SimpleNamespace(record=visit(sequence, self.prepared), iq=bytes(1_600_000))
            last = visit(47, self.prepared)
            self.session.terminal = PositionTerminal(
                session=self.prepared.session,
                generation=self.prepared.generation,
                final_counter=last.valid_end,
                restore_before=last.valid_end,
                restore_after=last.valid_end + 1,
                planned=48,
                delivered=48,
                skipped=0,
                invalid=0,
                cancelled=0,
                iq_bytes=48 * 1_600_000,
                state=old.TerminalState.COMPLETED,
                reason=2,
                error=0,
            )

        def close(self):
            return SimpleNamespace(restoration={"fastlock_inactive": True})

    output = tmp_path / "recording"
    record_position_scan("ip:192.168.1.15", "serial", output, owner_factory=Owner)
    result = verify_position_scan(output)
    assert result["complete"] == 48 and result["verified"]
    with (output / "visits.bin").open("r+b") as stream:
        stream.seek(4)
        raw = bytearray(stream.read(224))
        struct.pack_into("<I", raw, 112, 1)
        struct.pack_into("<I", raw, 220, zlib.crc32(raw[:220]))
        stream.seek(4)
        stream.write(raw)
    with pytest.raises(ValueError, match="identity/order"):
        verify_position_scan(output)
