"""Single physical RX identity and exact native samples over actual adaptive visits."""

import dataclasses as dc

import numpy as np
import pytest
from test_adaptive_hop_stream import Capture

from pluto_plus.adaptive_hop import AdaptiveHopEvidenceV2, AdaptiveHopMode
from pluto_plus.adaptive_hop_stream import AdaptiveHopStreamV2
from pluto_plus.host_adaptive_hop import (
    HostAdaptiveHopEvidenceV3,
    HostAdaptiveHopRequestV3,
    HostAdaptiveHopRequestV4,
    HostAdaptiveHopStatusV3,
    HostDecisionConfigurationV1,
    HostDecisionConfigurationV2,
)
from pluto_plus.host_adaptive_hop_stream import HostAdaptiveHopStreamV3
from pluto_plus.persistent_hop import PersistentHopClientError, PersistentHopProtocolError


def setup(rx, mode=AdaptiveHopMode.ADAPTIVE, block=262144, delay=0):
    capture = Capture(10_000_000, mode, block, delay)
    request = HostAdaptiveHopRequestV3(
        capture.request.geometry,
        capture.request.policy,
        HostDecisionConfigurationV1(rx, bytes(range(32))),
    )
    return capture, request, HostAdaptiveHopStreamV3(request, samples_per_block=block)


def single_wire(wire, rx):
    evidence = AdaptiveHopEvidenceV2.unpack(wire.evidence)
    words = np.frombuffer(wire.iq_payload, dtype="<i2").reshape(-1, 4)
    return dc.replace(
        wire,
        evidence=HostAdaptiveHopEvidenceV3(evidence.geometry, evidence.choices).pack(),
        iq_payload=words[:, rx * 2 : rx * 2 + 2].tobytes(),
    )


def assert_samples(capture, sampled, rx):
    visit = sampled.visit
    expected = capture.expected(
        visit.valid_start_counter, visit.valid_end_counter_exclusive, visit.profile.target_index
    )
    assert sampled.receiver_id == rx
    assert sampled.samples.shape == (1, 1_200_000)
    np.testing.assert_array_equal(
        sampled.samples[0],
        expected[:, rx * 2] + expected[:, rx * 2 + 1] * np.complex64(1j),
    )


@pytest.mark.parametrize("rx", [0, 1])
@pytest.mark.parametrize("mode", list(AdaptiveHopMode))
@pytest.mark.parametrize("block,delay", [(262144, 0), (300007, 2)])
def test_native_samples_selected_rx_actual_allocation_and_bounded_retention(rx, mode, block, delay):
    capture, request, stream = setup(rx, mode, block, delay)
    seen = []
    assert stream.stream_generation is None
    for wire in capture.wires():
        for sampled in stream.feed(single_wire(wire, rx)):
            assert_samples(capture, sampled, rx)
            seen.append(sampled.visit)
        assert stream.retained_sample_count <= stream.maximum_retained_samples
        assert stream.stream_generation == 13
    receipt, final = stream.finish(HostAdaptiveHopStatusV3(capture.status().geometry))
    for sampled in final:
        assert_samples(capture, sampled, rx)
        seen.append(sampled.visit)
    assert receipt.request == request
    assert receipt.visits == tuple(seen)
    assert receipt.events == tuple(capture.events)
    assert receipt.choices == tuple(capture.choices)
    assert receipt.valid_sample_count == len(seen) * 1_200_000
    assert receipt.valid_sample_count + receipt.transition_invalid_sample_count == (
        receipt.duty_denominator_sample_count
    )
    assert receipt.valid_duty_ppm >= 950000
    assert not receipt.unclassified_sample_count
    assert not receipt.unreceived_tail_sample_count
    assert not stream.retained_sample_count
    assert receipt.stream_generation == 13
    if mode == AdaptiveHopMode.ADAPTIVE:
        assert receipt.target_coverage[4].visit_count == 0


@pytest.mark.parametrize("rx", [0, 1])
def test_cancel_reports_unreceived_tail_and_preserves_full_visits(rx):
    capture, _, stream = setup(rx)
    seen = []
    for sequence, wire in enumerate(capture.wires()):
        seen.extend(stream.feed(single_wire(wire, rx)))
        if sequence == 15:
            break
    status = capture.status(sequence=15, cancelled=True, extra_tail=103)
    receipt, final = stream.finish(HostAdaptiveHopStatusV3(status.geometry))
    for sampled in (*seen, *final):
        assert_samples(capture, sampled, rx)
    assert receipt.unreceived_tail_sample_count == 103
    assert receipt.unclassified_sample_count > 0
    assert receipt.valid_sample_count == len(receipt.visits) * 1_200_000


def test_major_three_never_admits_legacy_request_evidence_or_terminal():
    capture, request, stream = setup(1)
    with pytest.raises(PersistentHopClientError, match="major mismatch"):
        AdaptiveHopStreamV2(request, samples_per_block=262144)
    with pytest.raises(PersistentHopClientError, match="major mismatch"):
        HostAdaptiveHopStreamV3(Capture().request, samples_per_block=262144)
    wire = next(capture.wires())
    with pytest.raises(PersistentHopProtocolError, match="version mismatch"):
        stream.feed(wire)
    with pytest.raises(PersistentHopClientError, match="failed"):
        stream.feed(single_wire(wire, 1))
    _, _, stream = setup(1)
    with pytest.raises(PersistentHopClientError, match="major mismatch"):
        stream.finish(capture.status(sequence=0, cancelled=True))


@pytest.mark.parametrize("fault", ["dual-payload", "generation", "counter-gap"])
def test_corrupt_source_cannot_be_used_for_decisions(fault):
    capture, _, stream = setup(1)
    wires = iter(capture.wires())
    stream.feed(single_wire(next(wires), 1))
    wire = single_wire(next(wires), 1)
    if fault == "dual-payload":
        wire = dc.replace(wire, iq_payload=wire.iq_payload * 2)
    elif fault == "generation":
        wire = dc.replace(wire, stream_generation=14)
    else:
        evidence = HostAdaptiveHopEvidenceV3.unpack(wire.evidence)
        wire = dc.replace(
            wire,
            evidence=dc.replace(
                evidence,
                geometry=dc.replace(
                    evidence.geometry, block_first_counter=evidence.geometry.block_first_counter + 1
                ),
            ).pack(),
        )
    with pytest.raises(PersistentHopClientError):
        stream.feed(wire)
    assert stream.retained_sample_count == 0


def test_wide_request_retains_sparse_complete_visits_across_accounted_gap():
    block = 1_000_000
    capture = Capture(15_000_000, AdaptiveHopMode.ADAPTIVE, block)
    request = HostAdaptiveHopRequestV4(
        capture.request.geometry,
        capture.request.policy,
        HostDecisionConfigurationV2(0, bytes(range(32)), 15_000_000),
    )
    stream = HostAdaptiveHopStreamV3(request, samples_per_block=block)
    wires = [single_wire(wire, 0) for wire in capture.wires()]
    gap_index = next(
        index
        for index, wire in enumerate(wires[2:-2], start=2)
        if not HostAdaptiveHopEvidenceV3.unpack(wire.evidence).geometry.events
    )
    seen = []
    last_original = gap_index + 5
    for original_index, wire in enumerate(wires[: last_original + 1]):
        if original_index == gap_index:
            continue
        if original_index > gap_index:
            evidence = HostAdaptiveHopEvidenceV3.unpack(wire.evidence)
            wire = dc.replace(
                wire,
                evidence=dc.replace(
                    evidence,
                    geometry=dc.replace(
                        evidence.geometry,
                        buffer_sequence=evidence.geometry.buffer_sequence - 1,
                    ),
                ).pack(),
            )
        seen.extend(stream.feed(wire))
    status = capture.status(sequence=last_original, cancelled=True)
    receipt, final = stream.finish(
        HostAdaptiveHopStatusV3(
            dc.replace(status.geometry, last_block_sequence=last_original - 1)
        )
    )
    seen.extend(final)
    assert receipt.sparse is not None
    assert receipt.sparse.missing_sample_count == block
    assert receipt.sparse.retained_visit_indices == tuple(
        item.visit.event.dwell_index for item in seen
    )
    assert len(receipt.visits) == len(seen) < len(receipt.events)
    assert receipt.unclassified_sample_count >= block
