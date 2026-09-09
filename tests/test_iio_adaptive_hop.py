"""Concrete backend preflight and cleanup, with every hardware call substituted."""

import dataclasses as dc
from types import SimpleNamespace

import pytest
from test_iio_persistent_hop import SERIAL, URI, _FakeRadio, _plan

from pluto_plus.adaptive_hop import (
    AdaptiveHopEvidenceV2,
    AdaptiveHopPolicyV2,
    AdaptiveHopRequestV2,
    AdaptiveHopStatusV2,
)
from pluto_plus.adaptive_hop_client import AdaptiveHopClient
from pluto_plus.hardware.iio_adaptive_hop import IioAdaptiveHopBackend
from pluto_plus.hardware.iio_persistent_hop import IioPersistentHopBackend
from pluto_plus.persistent_hop import (
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopStatusV1,
)
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

CAPS = {
    "iio,buffer-adaptive-hop-request": "2",
    "iio,buffer-adaptive-hop-event": "2",
    "iio,buffer-adaptive-hop-status": "2",
    "iio,buffer-adaptive-hop-modes": "shadow,adaptive",
    "iio,buffer-adaptive-hop-policy": "three-miss-two-second-v1",
    "iio,buffer-scanner-glrt-mode": "positive-only-v1",
}


class Extension:
    def __init__(self, mode="normal"):
        self.mode, self.failures = mode, []

    def negotiate(self, request, attrs, *, drain_supported):
        if self.mode == "raise":
            raise ValueError("synthetic negotiation error")
        return request if self.mode == "unavailable" else b"LGO1-fixture-only" + request

    def unwrap(self, data):
        return data

    def fail(self, error):
        self.failures.append(error)


def setup(mode="normal", caps=None):
    radio = _FakeRadio()
    original_attrs = radio.iio_context_attributes()
    radio.iio_context_attributes = lambda: original_attrs | (CAPS if caps is None else caps)
    extension = None if mode == "missing" else Extension(mode)
    backend = IioAdaptiveHopBackend(
        URI,
        expected_serial=SERIAL,
        iio_module=SimpleNamespace(),
        radio_factory=lambda *_: radio,
        metadata_extension=extension,
    )
    return radio, backend, extension


@pytest.mark.parametrize("name", list(CAPS))
def test_missing_adaptive_capability_refuses_before_profile_preparation(name):
    radio, backend, _ = setup(caps={k: v for k, v in CAPS.items() if k != name})
    client = AdaptiveHopClient(URI, expected_serial=SERIAL, backend_factory=lambda _: backend)
    with pytest.raises(PersistentHopClientError, match="capabilities"):
        client.start(
            _plan(),
            session_id=17,
            policy=AdaptiveHopPolicyV2(9),
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert radio.closed and radio.geometry is None and radio.open_request is None


@pytest.mark.parametrize("mode", ["missing", "raise", "unavailable"])
def test_detector_negotiation_failure_never_opens_unlabeled_fixed_capture(mode):
    radio, backend, extension = setup(mode)
    client = AdaptiveHopClient(URI, expected_serial=SERIAL, backend_factory=lambda _: backend)
    with pytest.raises(PersistentHopClientError, match="detector|negotiation"):
        client.start(
            _plan(),
            session_id=17,
            policy=AdaptiveHopPolicyV2(9),
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert radio.closed and radio.open_request is None
    if mode != "missing":
        assert radio.restored == radio.original and extension.failures
    else:
        assert radio.geometry is None


def test_real_backend_v2_prefix_binding_and_exact_restoration():
    radio, backend, _ = setup()
    raw = radio.capture._blocks[0]
    v2 = AdaptiveHopEvidenceV2(PersistentHopEvidenceV1.unpack(raw.sidecar), ())
    radio.capture._blocks[0] = dc.replace(raw, sidecar=v2.pack())
    backend.open()
    plan = backend.prepare_plan(_plan())
    request = AdaptiveHopRequestV2(plan.request(session_id=17), AdaptiveHopPolicyV2(9))
    payload = request.append_to_tandem_request(
        TandemSessionRequestV1(mode=TandemMode.HOLD), plan.samples_per_block
    )
    backend.start(
        payload, samples_per_block=plan.samples_per_block, kernel_buffers=plan.kernel_buffers
    )
    assert radio.open_request == b"LGO1-fixture-only" + payload
    wire = next(backend.blocks())
    assert AdaptiveHopEvidenceV2.unpack(wire.evidence) == v2 and wire.stream_generation == 99
    receipt = backend.close()
    assert receipt.original_settings == receipt.restored_settings
    assert receipt.receive_buffer_closed and receipt.fastlock_inactive and radio.closed


def test_v2_sidecar_cannot_bypass_base_counter_binding():
    radio, backend, _ = setup()
    raw = radio.capture._blocks[0]
    base = PersistentHopEvidenceV1.unpack(raw.sidecar)
    v2 = AdaptiveHopEvidenceV2(dc.replace(base, block_first_counter=101), ())
    radio.capture._blocks[0] = dc.replace(raw, sidecar=v2.pack())
    backend.open()
    plan = backend.prepare_plan(_plan())
    request = AdaptiveHopRequestV2(plan.request(session_id=17), AdaptiveHopPolicyV2(9))
    backend.start(
        request.append_to_tandem_request(
            TandemSessionRequestV1(mode=TandemMode.HOLD), plan.samples_per_block
        ),
        samples_per_block=plan.samples_per_block,
        kernel_buffers=plan.kernel_buffers,
    )
    with pytest.raises(PersistentHopClientError, match="ABI-3"):
        next(backend.blocks())
    assert backend.close().receive_buffer_closed


def test_legacy_backend_still_refuses_v2_before_open():
    radio = _FakeRadio()
    backend = IioPersistentHopBackend(
        URI, expected_serial=SERIAL, iio_module=SimpleNamespace(), radio_factory=lambda *_: radio
    )
    backend.open()
    plan = backend.prepare_plan(_plan())
    request = AdaptiveHopRequestV2(plan.request(session_id=17), AdaptiveHopPolicyV2(9))
    with pytest.raises(PersistentHopClientError, match="wrong size"):
        backend.start(
            request.append_to_tandem_request(
                TandemSessionRequestV1(mode=TandemMode.HOLD), plan.samples_per_block
            ),
            samples_per_block=plan.samples_per_block,
            kernel_buffers=plan.kernel_buffers,
        )
    assert radio.open_request is None
    assert backend.close().fastlock_inactive


def test_bad_initial_status_restores_and_releases_client():
    radio, backend, _ = setup()
    # Fake status has V1 bytes: the adaptive client must reject, not reinterpret.
    client = AdaptiveHopClient(URI, expected_serial=SERIAL, backend_factory=lambda _: backend)
    with pytest.raises(ValueError, match="adaptive"):
        client.start(
            _plan(),
            session_id=17,
            policy=AdaptiveHopPolicyV2(9),
            tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
        )
    assert radio.capture.closed and radio.closed and radio.restored == radio.original


def test_close_without_any_iq_preserves_empty_cancel_inventory():
    radio, backend, _ = setup()
    original_status = PersistentHopStatusV1.unpack(radio.capture.statuses[0])
    radio.capture.statuses = [
        AdaptiveHopStatusV2(
            dc.replace(original_status, first_counter=0, last_block_end_counter=0)
        ).pack()
    ]

    def cancel():
        radio.capture.cancelled = True
        from test_iio_persistent_hop import _status

        from pluto_plus.persistent_hop import PersistentHopSessionState

        status = PersistentHopStatusV1.unpack(_status(PersistentHopSessionState.CANCELLED))
        radio.capture.statuses.append(
            AdaptiveHopStatusV2(
                dc.replace(status, first_counter=0, final_counter=0, last_block_end_counter=0)
            ).pack()
        )

    radio.capture.request_cancel = cancel
    client = AdaptiveHopClient(URI, expected_serial=SERIAL, backend_factory=lambda _: backend)
    session = client.start(
        _plan(),
        session_id=17,
        policy=AdaptiveHopPolicyV2(9),
        tandem_request=TandemSessionRequestV1(mode=TandemMode.HOLD),
    )
    # The deliberately minimal extension has no finish callback. Its error is
    # advisory and must not change source accounting or restoration.
    receipt = session.close()
    assert not receipt.stream.events and not receipt.stream.valid_sample_count
    assert receipt.metadata_extension_error and receipt.host_lifecycle.receive_buffer_closed
    assert session.close() is receipt
    assert not session.take_terminal_visits()
