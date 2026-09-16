from __future__ import annotations

from collections import deque

from pluto_plus.adaptive_scan import (
    ScanCapabilities,
    ScanSetup,
    ScanTarget,
    ScanTerminal,
    ScanVisit,
    TerminalState,
    VisitResult,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanClient


class ScriptedSocket:
    def __init__(self, response: bytes) -> None:
        self.response = bytearray(response)
        self.sent = bytearray()
        self.closed = False

    def sendall(self, data: bytes) -> None:
        self.sent.extend(data)

    def recv(self, size: int) -> bytes:
        result = bytes(self.response[:size])
        del self.response[:size]
        return result

    def close(self) -> None:
        self.closed = True


def setup() -> ScanSetup:
    return ScanSetup(
        session=11,
        generation=12,
        seed=13,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=8_000_000,
        duration_ms=2_000,
        dwell_ms=240,
        transition_budget_ms=10,
        maximum_revisit_ms=1_000,
        feedback_age_ms=1_000,
        application_delay_ms=1_000,
        decay_ms=5_000,
        maximum_boost=3,
        maximum_queue_bytes=200_000_000,
        maximum_queue_age_ms=5_000,
        maximum_queue_visits=50,
        analysis_digest=bytes(range(1, 33)),
        targets=(ScanTarget(1, 2, 2_400_000_000, 1, 0x12345678),),
    )


def test_capabilities_and_complete_stream_are_exact() -> None:
    request = setup()
    capabilities_socket = ScriptedSocket(b"96\n" + ScanCapabilities().pack())
    iq = b"\x01\x02\x03\x04" * 4
    visit = ScanVisit(
        session=request.session,
        generation=request.generation,
        visit=0,
        selection_counter=100,
        transition_before=101,
        transition_after=102,
        valid_start=110,
        valid_end=114,
        frequency_hz=request.targets[0].frequency_hz,
        iq_bytes=len(iq),
        missing_samples_before=0,
        analog_bandwidth_hz=request.analog_bandwidth_hz,
        source_rate_hz=request.source_rate_hz,
        target=0,
        profile=2,
        result=VisitResult.COMPLETE,
        eligible_mask=1,
        effective_weight=65536,
        profile_crc32=request.targets[0].profile_crc32,
    )
    terminal = ScanTerminal(
        session=request.session,
        generation=request.generation,
        final_counter=200,
        restore_before=201,
        restore_after=202,
        planned=1,
        delivered=1,
        skipped=0,
        invalid=0,
        cancelled=0,
        iq_bytes=len(iq),
        state=TerminalState.COMPLETED,
        reason=1,
        error=0,
        flags=1,
    )
    stream_socket = ScriptedSocket(
        b"0\n"
        + b"160\n"
        + visit.pack()
        + f"{len(iq)}\n".encode()
        + iq
        + b"128\n"
        + terminal.pack()
        + b"0\n"
        + b"0\n"
    )
    sockets = deque((capabilities_socket, stream_socket))
    client = AdaptiveScanClient(
        "192.0.2.1", connector=lambda _host, _port, _timeout: sockets.popleft()
    )

    assert client.capabilities() == ScanCapabilities()
    with client.start(request) as session:
        visits = list(session.visits())
        assert visits[0].record == visit and visits[0].iq == iq
        assert session.terminal == terminal

    assert capabilities_socket.sent == b"SCANCAPS 96\n"
    assert stream_socket.sent.startswith(b"OPENM cf-ad9361-lpc 1000000 00000003 352\n")
    assert request.pack() in stream_socket.sent
    assert stream_socket.sent.endswith(b"READSCAN cf-ad9361-lpc\nCLOSE cf-ad9361-lpc\n")
    assert capabilities_socket.closed and stream_socket.closed
