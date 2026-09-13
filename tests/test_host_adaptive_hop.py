"""Host decision transport contracts; no hardware or radio access."""

import dataclasses as dc
import struct

import pytest
from test_adaptive_hop import evidence, request
from test_persistent_hop import _active_status

from pluto_plus.adaptive_hop import (
    AdaptiveHopEvidenceV2,
    AdaptiveHopRequestV2,
    AdaptiveHopStatusV2,
)
from pluto_plus.host_adaptive_hop import (
    HostAdaptiveHopEvidenceV3,
    HostAdaptiveHopRequestV3,
    HostAdaptiveHopStatusV3,
    HostDecisionConfigurationV1,
    HostDecisionOutcome,
    HostFeedbackV1,
    require_host_adaptive_capabilities,
)
from pluto_plus.persistent_hop import PersistentHopClientError, PersistentHopProtocolError
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1


def host_request(rx=0):
    base = request(10_000_000)
    return HostAdaptiveHopRequestV3(
        base.geometry, base.policy, HostDecisionConfigurationV1(rx, bytes(range(32)))
    )


def feedback(rx=0, start=2**53 + 2**32 - 1000):
    return HostFeedbackV1(
        71,
        9,
        23,
        18,
        18,
        start,
        start + 1_200_000,
        rx,
        7,
        HostDecisionOutcome.DETECTED,
        1,
        63,
        32,
        bytes(range(32)),
    )


@pytest.mark.parametrize("rx", [0, 1])
def test_native_rate_request_and_filter_binding_round_trip(rx):
    r = host_request(rx)
    packet = r.pack()
    assert len(packet) == 416
    assert struct.unpack_from("<HHI", packet, 4) == (3, 416, 0x7F)
    assert struct.unpack_from("<8I", packet, 352) == (1, rx, 2500000, 4, 0, 80, 40, 300000)
    assert packet[384:] == bytes(range(32))
    assert HostAdaptiveHopRequestV3.unpack(memoryview(packet)) == r
    with pytest.raises(PersistentHopProtocolError):
        AdaptiveHopRequestV2.unpack(packet)
    with pytest.raises(PersistentHopProtocolError):
        HostAdaptiveHopRequestV3.unpack(request().pack())
    tandem = TandemSessionRequestV1(mode=TandemMode.HOLD)
    combined = r.append_to_tandem_request(tandem, 262144, retention_frames=33)
    assert combined[:104] == tandem.pack(262144, retention_frames=33)
    assert combined[104:] == packet


def test_event_and_terminal_wrappers_keep_explicit_major_three():
    r = host_request()
    old = evidence(r)
    e = HostAdaptiveHopEvidenceV3(old.geometry, old.choices)
    e.validate_binding(r)
    assert HostAdaptiveHopEvidenceV3.unpack(e.pack()) == e
    s = HostAdaptiveHopStatusV3(_active_status())
    assert HostAdaptiveHopStatusV3.unpack(s.pack()) == s
    for parser, payload in (
        (AdaptiveHopEvidenceV2.unpack, e.pack()),
        (AdaptiveHopStatusV2.unpack, s.pack()),
        (HostAdaptiveHopEvidenceV3.unpack, old.pack()),
        (HostAdaptiveHopStatusV3.unpack, AdaptiveHopStatusV2(s.geometry).pack()),
    ):
        with pytest.raises(PersistentHopProtocolError):
            parser(payload)
    with pytest.raises(PersistentHopProtocolError):
        e.validate_binding(request())
    with pytest.raises(PersistentHopProtocolError):
        e.validate_binding(dc.replace(r, policy=dc.replace(r.policy, generation=10)))


@pytest.mark.parametrize("size", range(416))
def test_request_rejects_all_truncations(size):
    with pytest.raises(PersistentHopProtocolError):
        HostAdaptiveHopRequestV3.unpack(host_request().pack()[:size])


@pytest.mark.parametrize("offset", [4, 6, 8, 76, 336, 351, 352, 360, 364, 368, 372, 376, 380])
def test_request_rejects_unqualified_geometry_or_reserved_bytes(offset):
    raw = bytearray(host_request().pack())
    raw[offset] ^= 1
    before = bytes(raw)
    with pytest.raises(PersistentHopProtocolError):
        HostAdaptiveHopRequestV3.unpack(raw)
    assert bytes(raw) == before


@pytest.mark.parametrize("rx", [0, 1])
@pytest.mark.parametrize("start", [0, 2**32 - 1000, 2**53 + 2**32 - 1000])
def test_feedback_retains_exact_full_counters_and_physical_rx(rx, start):
    f = feedback(rx, start)
    raw = f.pack()
    assert len(raw) == 160
    assert struct.unpack_from("<QQ", raw, 48) == (start, start + 1200000)
    assert struct.unpack_from("<II", raw, 64) == (10000000, 2500000)
    assert struct.unpack_from("<I", raw, 72)[0] == rx
    assert HostFeedbackV1.unpack(raw) == f


@pytest.mark.parametrize("size", range(160))
def test_feedback_rejects_all_truncations(size):
    with pytest.raises(PersistentHopProtocolError):
        HostFeedbackV1.unpack(feedback().pack()[:size])


@pytest.mark.parametrize(
    "offset", [4, 6, 64, 68, 96, 100, 104, 108, 112, *range(116, 120), *range(152, 160)]
)
def test_feedback_rejects_wrong_geometry_and_reserved_bytes(offset):
    raw = bytearray(feedback().pack())
    raw[offset] ^= 1
    with pytest.raises(PersistentHopProtocolError):
        HostFeedbackV1.unpack(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"session_id": 0},
        {"generation": 0},
        {"stream_id": 0},
        {"visit": 2500},
        {"event_sequence": 19},
        {"valid_end": 1},
        {"receiver_id": 2},
        {"receiver_id": True},
        {"target_index": 8},
        {"outcome": 3},
        {"healthy": 0},
        {"screen_mask": 31},
        {"confirmation_mask": 0},
        {"confirmation_mask": 3},
        {"confirmation_mask": 64},
        {"configuration_sha256": bytes(32)},
        {"configuration_sha256": b"short"},
    ],
)
def test_feedback_cannot_promote_from_invalid_or_incomplete_evidence(changes):
    with pytest.raises(PersistentHopProtocolError):
        dc.replace(feedback(), **changes).pack()


def test_unknown_unhealthy_and_complete_negative_remain_distinct():
    unknown = dc.replace(
        feedback(),
        outcome=HostDecisionOutcome.UNKNOWN,
        healthy=0,
        screen_mask=0,
        confirmation_mask=0,
    )
    negative = dc.replace(
        feedback(),
        outcome=HostDecisionOutcome.NOT_DETECTED,
        confirmation_mask=0,
    )
    assert HostFeedbackV1.unpack(unknown.pack()) == unknown
    assert HostFeedbackV1.unpack(negative.pack()) == negative
    assert unknown.pack() != negative.pack()


def test_capability_admission_requires_feedback_but_no_radio_detector():
    attributes = {
        "iio,buffer-host-adaptive-hop-request": "3",
        "iio,buffer-host-adaptive-hop-event": "3",
        "iio,buffer-host-adaptive-hop-status": "3",
        "iio,buffer-host-adaptive-hop-feedback": "1",
        "iio,buffer-metadata-feedback": "1",
        "iio,buffer-adaptive-hop-modes": "shadow,adaptive",
        "iio,buffer-adaptive-hop-policy": "three-miss-two-second-v1",
    }
    require_host_adaptive_capabilities(attributes, host_request().policy)
    for key in attributes:
        with pytest.raises(PersistentHopClientError):
            require_host_adaptive_capabilities(
                {**attributes, key: "unsupported"}, host_request().policy
            )
