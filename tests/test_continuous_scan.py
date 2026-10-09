from __future__ import annotations

import dataclasses
import json
import struct
from collections import deque

import pytest

from pluto_plus import adaptive_scan as old
from pluto_plus.adaptive_scan_client import AdaptiveScanTransportError
from pluto_plus.continuous_scan import (
    ContinuousCapabilities,
    ContinuousClient,
    ContinuousControl,
    ContinuousControlError,
    ContinuousSession,
    ContinuousSetup,
    ContinuousState,
    ContinuousStatus,
    ContinuousTerminal,
    ContinuousVisit,
    build_continuous_setup,
)


def setup():
    return build_continuous_setup(
        session=1,
        generation=2,
        seed=3,
        frequencies_hz=tuple(1_800_000_000 + index * 10_000_000 for index in range(8)),
        analysis_digest=b"a" * 32,
    )


def visit(sequence=0):
    target = sequence % 8
    start = (1 << 32) - 25000 + sequence * 100000
    return ContinuousVisit(
        session=1,
        generation=2,
        visit=sequence,
        selection_counter=start - 50000,
        transition_before=start - 50000,
        transition_after=start - 50000,
        valid_start=start,
        valid_end=start + 50000,
        frequency_hz=setup().targets[target].frequency_hz,
        iq_bytes=400000,
        missing_samples_before=0,
        analog_bandwidth_hz=2_000_000,
        source_rate_hz=2_500_000,
        target=target,
        profile=target,
        result=old.VisitResult.COMPLETE,
        eligible_mask=255,
        effective_weight=65536,
        profile_crc32=123,
    )


def status(request=1, state=ContinuousState.RUNNING):
    return ContinuousStatus(request, 1, 2, 0, 0, 0, 0, 0, 0, state, 0, 0, 0, 0, 0, 0, 0)


@pytest.mark.parametrize(
    "record,decoder,legacy",
    [
        (setup(), ContinuousSetup, old.ScanSetup),
        (ContinuousCapabilities(), ContinuousCapabilities, old.ScanCapabilities),
        (visit(), ContinuousVisit, old.ScanVisit),
        (ContinuousControl(1, 1, 2), ContinuousControl, None),
        (status(), ContinuousStatus, None),
    ],
)
def test_strict_new_codecs_old_versions_unchanged(record, decoder, legacy):
    raw = record.pack()
    assert decoder.unpack(raw) == record
    if legacy:
        assert decoder.unpack(bytearray(raw)) == record
        assert decoder.unpack(memoryview(raw)) == record
    for broken in old.corruptions(raw):
        with pytest.raises(old.AdaptiveScanProtocolError):
            decoder.unpack(broken)
    if legacy:
        with pytest.raises(old.AdaptiveScanProtocolError):
            legacy.unpack(raw)


class Socket:
    def __init__(self, response=b""):
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False

    def recv(self, size):
        result = bytes(self.response[:size])
        del self.response[:size]
        return result

    def sendall(self, data):
        self.sent.extend(data)

    def close(self):
        self.closed = True


def test_independent_status_and_stop_and_negotiation_failure():
    sockets = deque(
        [
            Socket(b"96\n" + ContinuousCapabilities().pack()),
            Socket(b"128\n" + status().pack()),
            Socket(b"128\n" + status(2, ContinuousState.STOPPING).pack()),
        ]
    )
    held = list(sockets)
    client = ContinuousClient("fixture", connector=lambda *_: sockets.popleft())
    assert client.capabilities().maximum_duration_ms == 0
    assert (
        client.control("cf-ad9361-lpc", ContinuousControl(1, 1, 2)).state == ContinuousState.RUNNING
    )
    assert (
        client.control("cf-ad9361-lpc", ContinuousControl(2, 1, 2), stop=True).state
        == ContinuousState.STOPPING
    )
    assert held[1].sent.startswith(b"SCANSTATUS cf-ad9361-lpc 48\n")
    assert held[2].sent.startswith(b"SCANSTOP cf-ad9361-lpc 48\n")
    assert all(item.closed for item in held)
    unsupported = ContinuousClient("fixture", connector=lambda *_: Socket(b"-38\n"))
    with pytest.raises(AdaptiveScanTransportError):
        unsupported.capabilities()
    stale = ContinuousClient("fixture", connector=lambda *_: Socket(b"128\n" + status().pack()))
    with pytest.raises(AdaptiveScanTransportError, match="stale"):
        stale.control("device", ContinuousControl(2, 1, 2))


def test_unbounded_absolute_visits_order_and_low_counter_rollover():
    client = ContinuousClient("fixture")
    session = ContinuousSession(client, Socket(), "device", setup())
    for sequence in range(17000):
        item = visit(sequence)
        session._validate_visit(item)
        assert item.sweep == sequence // 8
    assert session._visit_count == 17000
    assert session._last_valid_end > 1 << 32
    # No array indexed by the absolute visit is retained by the transport.
    assert not any(isinstance(value, (list, dict, deque)) for value in vars(session).values())
    wrong = dataclasses.replace(visit(17000), target=7)
    with pytest.raises(AdaptiveScanTransportError, match="order"):
        session._validate_visit(wrong)
    with pytest.raises(AdaptiveScanTransportError, match="geometry"):
        session._validate_visit(
            dataclasses.replace(visit(17000), valid_end=visit(17000).valid_end - 1)
        )


def test_partial_payload_geometry_uses_negotiated_receivers_and_complete_is_exact():
    item = dataclasses.replace(
        visit(), result=old.VisitResult.CANCELLED, valid_end=visit().valid_start + 100, iq_bytes=800
    )
    assert ContinuousVisit.unpack(item.pack()) == item
    session = ContinuousSession(ContinuousClient("fixture"), Socket(), "device", setup())
    session._validate_visit(item)
    single = dataclasses.replace(setup(), rx_mask=1)
    wrong = ContinuousSession(ContinuousClient("fixture"), Socket(), "device", single)
    with pytest.raises(AdaptiveScanTransportError, match="geometry"):
        wrong._validate_visit(item)
    with pytest.raises(old.AdaptiveScanProtocolError, match="50000"):
        dataclasses.replace(item, result=old.VisitResult.COMPLETE).pack()


def test_complete_requires_minimum_guard_but_partial_diagnostics_retained():
    item = dataclasses.replace(visit(), transition_after=visit().valid_start - 49999)
    session = ContinuousSession(ContinuousClient("fixture"), Socket(), "device", setup())
    with pytest.raises(AdaptiveScanTransportError, match="post-recall guard"):
        session._validate_visit(item)
    diagnostic = dataclasses.replace(item, result=old.VisitResult.CANCELLED)
    session._validate_visit(diagnostic)


def test_readscan_exact_iq_and_graceful_terminal():
    first = visit()
    terminal = ContinuousTerminal(
        session=1,
        generation=2,
        final_counter=first.valid_end,
        restore_before=first.valid_end,
        restore_after=first.valid_end + 1,
        planned=1,
        delivered=1,
        skipped=0,
        invalid=0,
        cancelled=0,
        iq_bytes=400000,
        state=old.TerminalState.COMPLETED,
        reason=2,
        error=0,
    )
    raw = (
        b"0\n160\n"
        + first.pack()
        + b"400000\n"
        + bytes(400000)
        + b"128\n"
        + terminal.pack()
        + b"0\n0\n"
    )
    socket = Socket(raw)
    client = ContinuousClient("fixture", connector=lambda *_: socket)
    session = client.start(setup())
    assert [len(item.iq) for item in session.visits()] == [400000]
    assert session.terminal == terminal
    session.close()
    assert socket.closed and socket.sent.endswith(b"CLOSE cf-ad9361-lpc\n")


@pytest.mark.parametrize("terminal_failure", [False, True])
@pytest.mark.parametrize("diagnostics_supported", [False, True])
def test_failure_diagnostics_are_retained_before_owned_stream_close(
    terminal_failure,
    diagnostics_supported,
):
    terminal = ContinuousTerminal(
        session=1,
        generation=2,
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
        error=-110,
    )
    data = b"128\n" + terminal.pack() + b"0\n" if terminal_failure else b"-5\n"
    stream = Socket(data)
    document = {
        "schema": "spf.scan-diagnostics/v1",
        "session": 1,
        "generation": 2,
        "first_error": -110,
        "restoration_error": -5,
    }
    payload = json.dumps(document).encode()
    diagnostic = Socket(
        str(len(payload)).encode() + b"\n" + payload if diagnostics_supported else b"-38\n"
    )
    requests = []

    def connect(*_):
        assert not stream.closed  # The provider still owns live diagnostics here.
        requests.append("diagnostics")
        return diagnostic

    client = ContinuousClient("fixture", connector=connect)
    session = ContinuousSession(client, stream, "device", setup())
    if terminal_failure:
        assert list(session.visits()) == []
        assert session.terminal == terminal
    else:
        with pytest.raises(AdaptiveScanTransportError, match="READSCAN failed with errno 5"):
            list(session.visits())
        assert stream.closed
    assert requests == ["diagnostics"]
    assert diagnostic.sent == b"SCANDIAG device 16\n" + struct.pack("<QQ", 1, 2)
    assert diagnostic.closed
    if diagnostics_supported:
        assert session.failure_diagnostics == document
    else:
        assert "unavailable_error" in session.failure_diagnostics


def test_rejected_independent_control_preserves_typed_errno():
    client = ContinuousClient("fixture", connector=lambda *_: Socket(b"-61\n"))
    with pytest.raises(ContinuousControlError) as caught:
        client.control("device", ContinuousControl(1, 1, 2))
    assert caught.value.errno == 61
    assert isinstance(caught.value, AdaptiveScanTransportError)
