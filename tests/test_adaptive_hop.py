"""Major-2 wire geometry only: no IIO, radio, worker or source-data access."""

import dataclasses as dc
import struct

import pytest
from test_persistent_hop import _active_status, _event, _profiles

from pluto_plus.adaptive_hop import (
    AdaptiveHopChoiceV2,
    AdaptiveHopEvidenceV2,
    AdaptiveHopMode,
    AdaptiveHopPolicyV2,
    AdaptiveHopRequestV2,
    AdaptiveHopStatusV2,
)
from pluto_plus.persistent_hop import (
    PersistentHopEvidenceV1,
    PersistentHopProtocolError,
    PersistentHopRequestV1,
    PersistentHopSessionState,
    PersistentHopStatusFlag,
    PersistentHopStatusV1,
    PersistentHopTerminalReason,
)
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1


def request(rate=2500000, mode=AdaptiveHopMode.ADAPTIVE):
    return AdaptiveHopRequestV2(
        PersistentHopRequestV1(
            71, rate, rate, 1000, rate * 120 // 1000, 10, 2500, rate * 300, _profiles()
        ),
        AdaptiveHopPolicyV2(9, mode),
    )


def evidence(r):
    first = _event()
    target = 1 if r.policy.mode == AdaptiveHopMode.SHADOW else 3
    profile = r.geometry.profiles[target]
    boundary = first.invalid_end_counter_exclusive + r.geometry.dwell_samples
    second = dc.replace(
        _event(sequence=1, dwell=1, invalid_start=boundary),
        from_profile_index=0,
        to_profile_index=target,
        fastlock_slot=profile.fastlock_profile_index,
        actual_lo_frequency_hz=profile.lo_hz,
    )
    return AdaptiveHopEvidenceV2(
        PersistentHopEvidenceV1(
            PersistentHopStatusFlag.RESTORE_REQUIRED,
            71,
            0,
            1000,
            boundary + r.geometry.dwell_samples + 11,
            PersistentHopSessionState.RUNNING,
            PersistentHopTerminalReason.NONE,
            0,
            (first, second),
        ),
        (
            AdaptiveHopChoiceV2(1000, 2**64 - 1, 0, 9, 0, 0, 0, 0, 0, r.policy.mode),
            AdaptiveHopChoiceV2(boundary, 0, 0, 9, 3, 1, 9, 246, 0, r.policy.mode),
        ),
    )


@pytest.mark.parametrize("rate", [2500000, 5000000])
@pytest.mark.parametrize("mode", list(AdaptiveHopMode))
def test_request_evidence_status_roundtrip_and_legacy_rejection(rate, mode):
    r = request(rate, mode)
    assert len(r.pack()) == 352 and AdaptiveHopRequestV2.unpack(r.pack()) == r
    e = evidence(r)
    assert len(e.pack()) == 64 + 2 * 144
    decoded = AdaptiveHopEvidenceV2.unpack(e.pack())
    assert decoded == e
    decoded.validate_binding(r)
    assert decoded.choices[1].proposed_target == 3
    assert decoded.geometry.events[1].to_profile_index == (1 if mode == 1 else 3)
    s = AdaptiveHopStatusV2(_active_status())
    assert AdaptiveHopStatusV2.unpack(s.pack()) == s
    for decoder, payload in (
        (PersistentHopRequestV1.unpack, r.pack()),
        (PersistentHopEvidenceV1.unpack, e.pack()),
        (PersistentHopStatusV1.unpack, s.pack()),
    ):
        with pytest.raises(PersistentHopProtocolError):
            decoder(payload)
    tandem = TandemSessionRequestV1(mode=TandemMode.HOLD)
    packet = r.append_to_tandem_request(tandem, 131072)
    assert packet[:104] == tandem.pack(131072, retention_frames=3)
    assert packet[104:] == r.pack()


@pytest.mark.parametrize("size", range(352))
def test_all_truncated_request_sizes_are_rejected(size):
    with pytest.raises(PersistentHopProtocolError):
        AdaptiveHopRequestV2.unpack(request().pack()[:size])


@pytest.mark.parametrize("offset", range(336, 352))
def test_request_reserved_bytes_are_rejected_without_mutating_input(offset):
    raw = bytearray(request().pack())
    raw[offset] = 1
    snapshot = bytes(raw)
    with pytest.raises(PersistentHopProtocolError):
        AdaptiveHopRequestV2.unpack(raw)
    assert bytes(raw) == snapshot


@pytest.mark.parametrize("offset", range(200, 208))
def test_decision_reserved_bytes_are_rejected(offset):
    raw = bytearray(evidence(request()).pack())
    raw[offset] = 1
    with pytest.raises(PersistentHopProtocolError):
        AdaptiveHopEvidenceV2.unpack(raw)


@pytest.mark.parametrize(
    "change",
    [
        dict(mode=0),
        dict(generation=0),
        dict(generation=True),
        dict(missed_dwells=0),
        dict(hop_budget_ms=119),
        dict(maximum_revisit_ms=100),
        dict(active_weight=0),
    ],
)
def test_invalid_policy(change):
    with pytest.raises(PersistentHopProtocolError):
        dc.replace(request().policy, **change).pack()


def test_bounded_but_unadvertised_policy_requires_explicit_pinning():
    policy = dc.replace(request().policy, cooldown_ms=2001)
    assert policy.pack()
    with pytest.raises(PersistentHopProtocolError):
        policy.require_pinned_policy()
    request().policy.require_pinned_policy()


@pytest.mark.parametrize(
    "change",
    [
        dict(generation=10),
        dict(mode=AdaptiveHopMode.SHADOW),
        dict(proposed_target=2),
        dict(basis_visit=1),
        dict(active_mask=255),
        dict(consecutive_misses=4),
    ],
)
def test_choice_corruption_or_wrong_binding_is_rejected(change):
    r = request()
    e = evidence(r)
    e = dc.replace(e, choices=(e.choices[0], dc.replace(e.choices[1], **change)))
    with pytest.raises(PersistentHopProtocolError):
        e.validate_binding(r)


def test_actual_from_target_and_dwell_geometry_are_validated():
    r = request()
    e = evidence(r)
    for changed in (
        dc.replace(e.geometry.events[1], from_profile_index=7),
        dc.replace(e.geometry.events[1], invalid_start_counter=1012),
    ):
        broken = dc.replace(
            e, geometry=dc.replace(e.geometry, events=(e.geometry.events[0], changed))
        )
        with pytest.raises(PersistentHopProtocolError):
            broken.validate_binding(r)


@pytest.mark.parametrize("offset,value", [(4, 1), (8, 1), (12, 31), (20, 9), (22, 9)])
def test_evidence_header_mutations_are_rejected(offset, value):
    raw = bytearray(evidence(request()).pack())
    struct.pack_into("<H" if offset in (4, 20, 22) else "<I", raw, offset, value)
    with pytest.raises(PersistentHopProtocolError):
        AdaptiveHopEvidenceV2.unpack(raw)
