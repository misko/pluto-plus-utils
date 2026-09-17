"""Serial/RX admission and owned feedback, substituting all hardware calls."""

import dataclasses as dc
from types import SimpleNamespace

import pytest
from test_host_adaptive_hop import feedback
from test_iio_persistent_hop import SERIAL, URI, _FakeRadio, _plan

from pluto_plus.adaptive_hop import AdaptiveHopPolicyV2
from pluto_plus.hardware.iio_host_adaptive_hop import (
    IioHostAdaptiveHopBackend,
    iio_host_adaptive_hop_client,
)
from pluto_plus.host_adaptive_hop import (
    HostAdaptiveHopRequestV3,
    HostAdaptiveHopStatusV3,
    HostDecisionConfigurationV1,
)
from pluto_plus.host_adaptive_hop_client import HostAdaptiveHopClient
from pluto_plus.persistent_hop import (
    PersistentHopClientError,
    PersistentHopStatusV1,
    SingleRxPersistentHopPlanV2,
)
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

CAPS = {
    "iio,buffer-host-adaptive-hop-request": "3",
    "iio,buffer-host-adaptive-hop-event": "3",
    "iio,buffer-host-adaptive-hop-status": "3",
    "iio,buffer-host-adaptive-hop-feedback": "1",
    "iio,buffer-metadata-feedback": "1",
    "iio,buffer-adaptive-hop-modes": "shadow,adaptive",
    "iio,buffer-adaptive-hop-policy": "three-miss-two-second-v1",
}


def test_client_forwards_reviewed_radio_factory(monkeypatch):
    captured = {}

    class Client:
        def __init__(self, uri, *, expected_serial, backend_factory):
            captured.update(
                uri=uri,
                expected_serial=expected_serial,
                backend=backend_factory(uri),
            )

    def factory(*_):
        return _FakeRadio()

    monkeypatch.setattr("pluto_plus.hardware.iio_host_adaptive_hop.HostAdaptiveHopClient", Client)
    iio_host_adaptive_hop_client(URI, expected_serial=SERIAL, radio_factory=factory)

    assert captured["uri"] == URI
    assert captured["expected_serial"] == SERIAL
    assert captured["backend"]._radio_factory is factory


def plan(rx=0):
    original = _plan()
    values = {f.name: getattr(original, f.name) for f in dc.fields(original)}
    values.update(sample_rate_hz=10_000_000, rf_bandwidth_hz=10_000_000, receiver_id=rx)
    return SingleRxPersistentHopPlanV2(**values)


def setup(caps=None):
    radio = _FakeRadio()
    original = radio.iio_context_attributes()
    radio.iio_context_attributes = lambda: original | (CAPS if caps is None else caps)
    backend = IioHostAdaptiveHopBackend(
        URI, expected_serial=SERIAL, iio_module=SimpleNamespace(), radio_factory=lambda *_: radio
    )
    status = PersistentHopStatusV1.unpack(radio.capture.statuses[0])
    radio.capture.statuses = [HostAdaptiveHopStatusV3(status).pack()]
    return radio, backend


def start(backend, rx=0, *, requested_plan=None, direct_async_frames=0):
    return HostAdaptiveHopClient(
        URI, expected_serial=SERIAL, backend_factory=lambda _: backend
    ).start(
        plan(rx) if requested_plan is None else requested_plan,
        policy=AdaptiveHopPolicyV2(9),
        session_id=17,
        decision=HostDecisionConfigurationV1(rx, bytes(range(32))),
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        direct_async_frames=direct_async_frames,
    )


@pytest.mark.parametrize("rx", [0, 1])
def test_major_three_open_selects_exact_rx_and_submits_on_existing_capture(rx):
    radio, backend = setup()
    session = start(backend, rx)
    assert radio.geometry == (10_000_000, 10_000_000, (rx,), 40.0)
    assert len(radio.open_request) == 104 + 416
    assert HostAdaptiveHopRequestV3.unpack(radio.open_request[104:]) == session.request
    packets = []
    radio.capture.submit_metadata_feedback = packets.append
    backend.submit_metadata_feedback(feedback(rx).pack())
    assert packets == [feedback(rx).pack()]
    receipt = backend.close()
    assert receipt.receive_buffer_closed and receipt.fastlock_inactive
    assert radio.restored == radio.original


@pytest.mark.parametrize("rx", [0, 1])
def test_unprepared_fastlock_crcs_are_bound_before_wire_validation(rx):
    radio, backend = setup()
    original = plan(rx)
    unprepared = dc.replace(
        original,
        profiles=tuple(dc.replace(profile, profile_crc32=0) for profile in original.profiles),
    )
    session = start(backend, rx, requested_plan=unprepared)
    request = HostAdaptiveHopRequestV3.unpack(radio.open_request[104:])
    assert all(profile.profile_crc32 for profile in request.geometry.profiles)
    assert request == session.request
    assert all(profile.profile_crc32 == 0 for profile in unprepared.profiles)
    assert backend.close().fastlock_inactive
    assert radio.restored == radio.original


def test_missing_prepared_crc_still_fails_before_buffer_start():
    radio, backend = setup()
    original = plan()
    unprepared = dc.replace(
        original,
        profiles=tuple(dc.replace(profile, profile_crc32=0) for profile in original.profiles),
    )
    backend.prepare_plan = lambda _: unprepared
    with pytest.raises(ValueError, match="CRC must be non-zero"):
        start(backend, requested_plan=unprepared)
    assert radio.open_request is None and radio.closed


@pytest.mark.parametrize("name", [*CAPS, "hw_serial"])
def test_missing_capability_or_wrong_radio_fails_before_receiver_preparation(name):
    radio, backend = setup({**CAPS, name: "wrong"})
    with pytest.raises(PersistentHopClientError):
        start(backend)
    assert radio.closed and radio.geometry is None and radio.open_request is None


def test_request_rx_cannot_differ_from_prepared_physical_rx():
    radio, backend = setup()
    backend.open()
    prepared = backend.prepare_plan(plan(1))
    request = HostAdaptiveHopRequestV3(
        prepared.request(session_id=17),
        AdaptiveHopPolicyV2(9),
        HostDecisionConfigurationV1(0, bytes(range(32))),
    )
    with pytest.raises(PersistentHopClientError, match="physical RX"):
        backend.start(
            request.append_to_tandem_request(
                TandemSessionRequestV1(mode=TandemMode.HOLD), prepared.samples_per_block
            ),
            samples_per_block=prepared.samples_per_block,
            kernel_buffers=prepared.kernel_buffers,
        )
    assert radio.open_request is None
    assert backend.close().fastlock_inactive


def test_initial_legacy_status_is_rejected_and_hardware_restored():
    radio, backend = setup()
    radio.capture.statuses = [
        PersistentHopStatusV1.unpack(
            HostAdaptiveHopStatusV3.unpack(radio.capture.statuses[0]).geometry.pack()
        ).pack()
    ]
    with pytest.raises(ValueError, match="version mismatch"):
        start(backend)
    assert radio.closed and radio.capture.closed and radio.restored == radio.original


def test_feedback_interleaved_direct_open_defers_status_until_first_frame():
    radio, backend = setup()
    radio.capture.rearmed = 0
    radio.capture.rearm_direct_async = lambda: setattr(
        radio.capture, "rearmed", radio.capture.rearmed + 1
    )
    _session = start(backend, direct_async_frames=1)
    assert radio.open_kwargs["direct_async_frames"] == 1
    assert radio.open_kwargs["drop_backlog_on_overrun"] is False
    assert len(radio.capture.statuses) == 1
    backend.rearm_direct_async()
    assert radio.capture.rearmed == 1
    backend.close()
