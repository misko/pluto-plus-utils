"""Replay actual visits through the feedback owner; no RF collection."""

import dataclasses as dc
import errno
from concurrent.futures import ThreadPoolExecutor

import pytest
from test_host_adaptive_hop_stream import setup, single_wire
from test_iio_host_adaptive_hop import plan
from test_iio_persistent_hop import SERIAL, URI

from pluto_plus.host_adaptive_hop import (
    HostAdaptiveHopStatusV3,
    HostDecisionOutcome,
    HostFeedbackV1,
)
from pluto_plus.host_adaptive_hop_client import HostAdaptiveHopClient, HostAdaptiveHopSession
from pluto_plus.persistent_hop import PersistentHopClientError


class ReplayBackend:
    uri = URI
    start_clock_bracket = None

    def __init__(self, capture, rx):
        self.capture, self.rx = capture, rx
        self.sequence = -1
        self.cancelled = False
        self.closed = 0
        self.feedback = []
        self.error = None

    def blocks(self):
        for sequence, wire in enumerate(self.capture.wires()):
            self.sequence = sequence
            yield single_wire(wire, self.rx)

    def read_status(self):
        return HostAdaptiveHopStatusV3(
            self.capture.status(
                sequence=self.sequence,
                cancelled=self.cancelled,
            ).geometry
        ).pack()

    def cancel(self):
        self.cancelled = True

    def close(self):
        self.closed += 1

    def submit_metadata_feedback(self, payload):
        if self.error:
            raise self.error
        self.feedback.append(HostFeedbackV1.unpack(payload))


def session(rx=0):
    capture, _, stream = setup(rx)
    backend = ReplayBackend(capture, rx)
    owner = HostAdaptiveHopClient(URI, expected_serial=SERIAL, backend_factory=lambda _: backend)
    owner._active = True
    selected = dc.replace(plan(rx), samples_per_block=capture.block)
    return HostAdaptiveHopSession(owner, backend, selected, stream), backend


def result(session, sampled):
    visit = sampled.visit
    return HostFeedbackV1(
        session.request.geometry.session_id,
        session.request.policy.generation,
        session.stream_generation,
        visit.event.dwell_index,
        visit.event.event_sequence,
        visit.valid_start_counter,
        visit.valid_end_counter_exclusive,
        sampled.receiver_id,
        visit.profile.target_index,
        HostDecisionOutcome.NOT_DETECTED,
        1,
        63,
        0,
        session.request.decision.configuration_sha256,
    )


@pytest.mark.parametrize("rx", [0, 1])
def test_full_replay_submits_ordered_feedback_and_marks_terminal_tail_unapplied(rx):
    s, backend = session(rx)
    accepted = []
    for sampled in s.visits():
        accepted.append(s.submit_feedback(result(s, sampled)))
    assert accepted == [True] * 33 + [False]
    assert len(backend.feedback) == 33
    assert [f.visit for f in backend.feedback] == list(range(33))
    assert all(f.receiver_id == rx and f.stream_id == 13 for f in backend.feedback)
    assert s.receipt.stream.request == s.request
    assert s.receipt.stream.valid_sample_count == 34 * 1_200_000
    assert backend.closed == 1
    assert s.close() == s.receipt and backend.closed == 1


def test_pending_host_result_drains_before_restoration_and_remains_unapplied():
    s, backend = session()
    pending = []
    callbacks = []

    def before_release():
        assert backend.closed == 0
        assert len(pending) == 1
        callbacks.append(s.submit_feedback(pending.pop()))

    for sampled in s.visits(before_release=before_release):
        feedback = result(s, sampled)
        if sampled.visit.event.dwell_index == 32:
            pending.append(feedback)
        else:
            s.submit_feedback(feedback)
    assert callbacks == [False] and not pending
    assert backend.closed == 1 and len(backend.feedback) == 32


def test_terminal_drain_failure_still_releases_backend():
    s, backend = session()

    def fail():
        raise RuntimeError("injected host drain failure")

    with pytest.raises(RuntimeError, match="drain failure"):
        for sampled in s.visits(before_release=fail):
            s.submit_feedback(result(s, sampled))
    assert backend.closed == 1


@pytest.mark.parametrize(
    "field,value",
    [
        ("session_id", 999),
        ("generation", 999),
        ("stream_id", 999),
        ("receiver_id", 1),
        ("configuration_sha256", bytes([1]) * 32),
        ("target_index", 7),
    ],
)
def test_feedback_must_match_emitted_source_before_backend_is_called(field, value):
    s, backend = session()
    iterator = s.visits()
    sampled = next(iterator)
    f = result(s, sampled)
    with pytest.raises(PersistentHopClientError, match="next actual source"):
        s.submit_feedback(dc.replace(f, **{field: value}))
    assert not backend.feedback
    assert s.submit_feedback(f)
    with pytest.raises(PersistentHopClientError, match="no emitted"):
        s.submit_feedback(f)
    s.close()
    iterator.close()
    assert backend.closed == 1


def test_reordered_and_counter_shifted_feedback_cannot_skip_a_source_visit():
    s, backend = session(1)
    iterator = s.visits()
    first, second = next(iterator), next(iterator)
    f = result(s, first)
    for wrong in (
        result(s, second),
        dc.replace(
            f,
            valid_start=f.valid_start + 2**32,
            valid_end=f.valid_end + 2**32,
        ),
    ):
        with pytest.raises(PersistentHopClientError, match="next actual source"):
            s.submit_feedback(wrong)
    assert not backend.feedback
    assert s.submit_feedback(f)
    assert s.submit_feedback(result(s, second))
    s.close()
    iterator.close()


def test_worker_cannot_submit_or_advance_the_iio_owner():
    s, backend = session()
    iterator = s.visits()
    f = result(s, next(iterator))
    with (
        ThreadPoolExecutor(max_workers=1) as pool,
        pytest.raises(PersistentHopClientError, match="acquisition thread"),
    ):
        pool.submit(s.submit_feedback, f).result()
    assert not backend.feedback
    assert s.submit_feedback(f)
    with (
        ThreadPoolExecutor(max_workers=1) as pool,
        pytest.raises(PersistentHopClientError, match="acquisition thread"),
    ):
        pool.submit(next, iterator).result()
    assert backend.closed == 0 and not backend.cancelled
    s.close()
    iterator.close()


@pytest.mark.parametrize("error_number", [errno.ESHUTDOWN, errno.ESTALE, errno.EIO])
def test_provider_rejection_never_claims_feedback_applied(error_number):
    s, backend = session()
    iterator = s.visits()
    f = result(s, next(iterator))
    backend.error = OSError(error_number, "synthetic provider rejection")
    if error_number == errno.ESHUTDOWN:
        assert s.submit_feedback(f) is False
    else:
        with pytest.raises(OSError) as raised:
            s.submit_feedback(f)
        assert raised.value.errno == error_number
        backend.error = None
        assert s.submit_feedback(f)
    s.close()
    iterator.close()
    assert backend.closed == 1
