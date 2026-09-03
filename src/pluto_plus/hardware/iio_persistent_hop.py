"""Concrete physical-LAN libiio backend for persistent hopping."""

from __future__ import annotations

import ctypes
import dataclasses
import importlib
import zlib
from collections.abc import Callable, Iterator, Mapping
from types import ModuleType
from typing import Any

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import IioRadioDevice, IioReceiverSettingsReadback
from pluto_plus.hardware.iio_metadata import IioRawSidecarCaptureSession
from pluto_plus.models import Transport
from pluto_plus.persistent_hop import (
    PERSISTENT_HOP_EXCLUDED_SERIAL,
    PERSISTENT_HOP_REQUEST_BYTES,
    PERSISTENT_HOP_STATUS_BYTES,
    PersistentHopBackend,
    PersistentHopClient,
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopHostLifecycleReceiptV1,
    PersistentHopPlanV1,
    PersistentHopReceiverSettingsV1,
    PersistentHopRequestV1,
    PersistentHopSessionState,
    PersistentHopWireBlock,
    require_allowed_serial,
    require_physical_lan_uri,
)

_TANDEM_REQUEST_BYTES = 104


class IioPersistentHopBackend(PersistentHopBackend):
    """One libiio context from pre-arm through terminal HOPT and restoration.

    The same exact-IP context performs identity admission, volatile Fast Lock
    programming, metadata OPEN, HOPS refills, HOPT reads, cancellation, and
    final host-side restoration.  It never scans for or falls back to USB.
    """

    def __init__(
        self,
        uri: str,
        *,
        expected_serial: str,
        adi_module: ModuleType | Any | None = None,
        iio_module: ModuleType | Any | None = None,
        radio_factory: Callable[[str, str], IioRadioDevice] | None = None,
    ) -> None:
        self._uri = require_physical_lan_uri(uri)
        self._expected_serial = require_allowed_serial(expected_serial)
        self._adi_module = adi_module
        self._iio_module = iio_module
        self._radio_factory = radio_factory
        self._radio: IioRadioDevice | None = None
        self._capture: IioRawSidecarCaptureSession | None = None
        self._original_settings: IioReceiverSettingsReadback | None = None
        self._prepared_plan: PersistentHopPlanV1 | None = None
        self._kernel_buffers_requested: int | None = None
        self._kernel_buffers_readback: int | None = None

    @property
    def uri(self) -> str:
        return self._uri

    @property
    def radio_id(self) -> str:
        return self._require_radio().identity.radio_id

    @property
    def kernel_buffers_readback(self) -> int | None:
        return self._kernel_buffers_readback

    @property
    def kernel_buffers_requested(self) -> int | None:
        return self._kernel_buffers_requested

    def open(self) -> None:
        if self._radio is not None:
            raise RuntimeError("persistent-hop IIO backend is already open")
        radio = (
            self._radio_factory(self._uri, self._expected_serial)
            if self._radio_factory is not None
            else IioRadioDevice(
                self._uri,
                serial=self._expected_serial,
                radio_id=self._expected_serial,
                adi_module=self._adi_module,
                iio_module=self._iio_module,
                expected_metadata_abi=3,
            )
        )
        try:
            radio.open()
        except BaseException:
            radio.close()
            raise
        identity = radio.identity
        if (
            identity.serial == PERSISTENT_HOP_EXCLUDED_SERIAL
            or identity.serial != self._expected_serial
            or identity.uri != self._uri
            or identity.transport is not Transport.IIO_IP
        ):
            radio.close()
            raise PersistentHopClientError(
                "persistent-hop IIO context identity does not match its exact LAN target"
            )
        self._radio = radio

    def context_attributes(self) -> Mapping[str, str]:
        return self._require_radio().iio_context_attributes()

    def prepare_plan(self, plan: PersistentHopPlanV1) -> PersistentHopPlanV1:
        """Bufferlessly compile and verify eight volatile Fast Lock profiles."""

        if self._capture is not None or self._prepared_plan is not None:
            raise RuntimeError("persistent-hop IIO plan was already prepared")
        radio = self._require_radio()
        original = radio.read_receiver_settings_readback()
        self._original_settings = original
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError(
                "refusing to replace Fast Lock slots while a profile is active"
            )
        radio.configure_source_locked_receiver_geometry(
            sample_rate_hz=plan.sample_rate_hz,
            rf_bandwidth_hz=plan.rf_bandwidth_hz,
            channels=(0, 1),
            manual_gain_db=plan.manual_gain_db,
        )
        prepared_profiles = []
        for profile in plan.profiles:
            radio.write_center_frequency_bufferless(profile.lo_hz)
            if round(radio.read_center_frequency()) != profile.lo_hz:
                raise RadioConfigurationError(
                    f"Fast Lock profile {profile.fastlock_profile_index} LO did not read back"
                )
            saved_words = radio.store_rx_fastlock_profile(
                profile.fastlock_profile_index
            )
            if radio.save_rx_fastlock_profile(profile.fastlock_profile_index) != saved_words:
                raise RadioConfigurationError(
                    f"Fast Lock profile {profile.fastlock_profile_index} save readback changed"
                )
            profile_crc32 = zlib.crc32(bytes(saved_words)) & 0xFFFFFFFF
            if not profile_crc32:
                raise RadioConfigurationError(
                    f"Fast Lock profile {profile.fastlock_profile_index} has zero CRC32"
                )
            radio.recall_rx_fastlock_profile(profile.fastlock_profile_index)
            if radio.read_active_rx_fastlock_profile() != profile.fastlock_profile_index:
                raise RadioConfigurationError(
                    f"Fast Lock profile {profile.fastlock_profile_index} recall was not attested"
                )
            prepared_profiles.append(
                dataclasses.replace(profile, profile_crc32=profile_crc32)
            )

        # A conventional LO write exits Fast Lock before OPEN. The provider
        # then owns all recalls and can attest its own initial transition.
        radio.write_center_frequency_bufferless(plan.profiles[0].lo_hz)
        if (
            radio.read_active_rx_fastlock_profile() is not None
            or round(radio.read_center_frequency()) != plan.profiles[0].lo_hz
        ):
            raise RadioConfigurationError("Fast Lock remained active after profile preparation")
        prepared = dataclasses.replace(plan, profiles=tuple(prepared_profiles))
        self._prepared_plan = prepared
        return prepared

    def start(
        self,
        request: bytes,
        *,
        samples_per_block: int,
        kernel_buffers: int,
    ) -> None:
        if self._capture is not None:
            raise RuntimeError("persistent-hop IIO capture is already open")
        plan = self._prepared_plan
        if plan is None:
            raise RuntimeError("persistent-hop IIO plan was not bufferlessly prepared")
        if len(request) != _TANDEM_REQUEST_BYTES + PERSISTENT_HOP_REQUEST_BYTES:
            raise PersistentHopClientError("persistent-hop OPEN request has the wrong size")
        decoded = PersistentHopRequestV1.unpack(request[-PERSISTENT_HOP_REQUEST_BYTES:])
        if (
            decoded != plan.request(session_id=decoded.session_id)
            or samples_per_block != plan.samples_per_block
            or kernel_buffers != plan.kernel_buffers
        ):
            raise PersistentHopClientError(
                "persistent-hop OPEN request differs from the prepared hardware plan"
            )
        module = self._iio_module
        if module is None:
            module = importlib.import_module("iio")
            self._iio_module = module
        capture = self._require_radio().begin_raw_sidecar_metadata_capture(
            samples_per_block,
            kernel_buffers=kernel_buffers,
            request=request,
            status_capacity=PERSISTENT_HOP_STATUS_BYTES,
            metadata_status_reader=lambda buffer, capacity: _read_metadata_status(
                module, buffer, capacity
            ),
            metadata_canceller=lambda buffer: _cancel_metadata_session(module, buffer),
        )
        readback = self._require_radio().read_kernel_buffers_count()
        if readback != kernel_buffers:
            capture.close()
            raise RadioConfigurationError(
                f"persistent-hop kernel buffer readback is {readback}, expected {kernel_buffers}"
            )
        self._kernel_buffers_requested = kernel_buffers
        self._kernel_buffers_readback = readback
        self._capture = capture

    def blocks(self) -> Iterator[PersistentHopWireBlock]:
        capture = self._require_capture()
        while True:
            raw = capture.read_block()
            evidence = PersistentHopEvidenceV1.unpack(raw.sidecar)
            # HOPS and the established ABI-3 prefix independently describe the
            # same refill. Reject disagreement before exposing any IQ.
            stream_generation, *base = _base_block_identity(raw.metadata_header)
            if tuple(base) != (
                evidence.buffer_sequence,
                evidence.block_first_counter,
                evidence.block_end_counter_exclusive,
            ):
                raise PersistentHopClientError(
                    "HOPS counters disagree with the ABI-3 metadata header"
                )
            yield PersistentHopWireBlock(
                evidence=raw.sidecar,
                iq_payload=raw.iq_payload,
                stream_generation=stream_generation,
            )
            if evidence.state in {
                PersistentHopSessionState.COMPLETED,
                PersistentHopSessionState.CANCELLED,
                PersistentHopSessionState.FAILED,
            }:
                return

    def cancel(self) -> None:
        self._require_capture().request_cancel()

    def read_status(self) -> bytes:
        return self._require_capture().read_status()

    def close(self) -> PersistentHopHostLifecycleReceiptV1 | None:
        errors: list[BaseException] = []
        capture, self._capture = self._capture, None
        if capture is not None:
            try:
                capture.close()
            except BaseException as error:
                errors.append(error)
        radio, self._radio = self._radio, None
        original, self._original_settings = self._original_settings, None
        self._prepared_plan = None
        restored: IioReceiverSettingsReadback | None = None
        fastlock_inactive = False
        if radio is not None:
            if original is not None:
                try:
                    restored = radio.restore_receiver_settings_readback(original)
                    fastlock_inactive = radio.read_active_rx_fastlock_profile() is None
                    if restored != original or not fastlock_inactive:
                        raise RadioConfigurationError(
                            "persistent-hop host settings restoration was not exact"
                        )
                except BaseException as error:
                    errors.append(error)
            try:
                radio.close()
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]
        if original is None or restored is None:
            return None
        return PersistentHopHostLifecycleReceiptV1(
            original_settings=_receiver_settings_receipt(original),
            restored_settings=_receiver_settings_receipt(restored),
            receive_buffer_closed=capture is None or not capture.is_open,
            fastlock_inactive=fastlock_inactive,
        )

    def _require_radio(self) -> IioRadioDevice:
        if self._radio is None:
            raise RuntimeError("persistent-hop IIO backend is not open")
        return self._radio

    def _require_capture(self) -> IioRawSidecarCaptureSession:
        if self._capture is None:
            raise RuntimeError("persistent-hop IIO capture is not open")
        return self._capture


def iio_persistent_hop_client(
    uri: str,
    *,
    expected_serial: str,
    adi_module: ModuleType | Any | None = None,
    iio_module: ModuleType | Any | None = None,
) -> PersistentHopClient:
    """Build the production client while preserving the exact serial/IP gates."""

    exact_uri = require_physical_lan_uri(uri)
    exact_serial = require_allowed_serial(expected_serial)
    return PersistentHopClient(
        exact_uri,
        expected_serial=exact_serial,
        backend_factory=lambda selected_uri: IioPersistentHopBackend(
            selected_uri,
            expected_serial=exact_serial,
            adi_module=adi_module,
            iio_module=iio_module,
        ),
    )


def _base_block_identity(metadata_header: bytes) -> tuple[int, int, int, int]:
    # These three fields are frozen in the existing ABI-3/V6 prefix.
    if len(metadata_header) < 44:
        raise PersistentHopClientError("ABI-3 metadata header is too short")
    import struct

    stream_generation = struct.unpack_from("<Q", metadata_header, 16)[0]
    if not stream_generation:
        raise PersistentHopClientError("ABI-3 metadata stream generation is zero")
    buffer_sequence = struct.unpack_from("<Q", metadata_header, 24)[0]
    first_counter = struct.unpack_from("<Q", metadata_header, 32)[0]
    samples_per_channel = struct.unpack_from("<I", metadata_header, 40)[0]
    return (
        stream_generation,
        buffer_sequence,
        first_counter,
        first_counter + samples_per_channel,
    )


def _read_metadata_status(module: Any, buffer: Any, capacity: int) -> bytes:
    public_reader = getattr(buffer, "metadata_status_raw", None)
    if callable(public_reader):
        result = public_reader(capacity)
        if not isinstance(result, (bytes, bytearray, memoryview)):
            raise RadioConfigurationError("pylibiio returned a non-byte metadata status")
        return bytes(result)

    reader = getattr(module, "_buffer_get_metadata_status", None)
    handle = getattr(buffer, "_buffer", None)
    if not callable(reader) or handle is None:
        raise RadioConfigurationError(
            "installed pylibiio cannot return raw metadata status bytes"
        )
    storage = ctypes.create_string_buffer(capacity)
    status_bytes = int(reader(handle, storage, capacity))
    if status_bytes != capacity:
        raise RadioConfigurationError(
            f"IIO server returned {status_bytes} status bytes, expected {capacity}"
        )
    return storage.raw


def _cancel_metadata_session(module: Any, buffer: Any) -> None:
    public_canceller = getattr(buffer, "cancel_metadata_session", None)
    if callable(public_canceller):
        public_canceller()
        return
    canceller = getattr(module, "_buffer_cancel_metadata_session", None)
    handle = getattr(buffer, "_buffer", None)
    if not callable(canceller) or handle is None:
        raise RadioConfigurationError(
            "installed pylibiio lacks persistent-hop in-band cancellation"
        )
    result = canceller(handle)
    if isinstance(result, int) and result < 0:
        raise RadioConfigurationError(
            f"IIO persistent-hop in-band cancellation failed: {result}"
        )


def _receiver_settings_receipt(
    settings: IioReceiverSettingsReadback,
) -> PersistentHopReceiverSettingsV1:
    return PersistentHopReceiverSettingsV1(
        center_frequency_hz=settings.center_frequency_hz,
        sample_rate_hz=settings.sample_rate_hz,
        bandwidth_hz=settings.bandwidth_hz,
        channels=settings.channels,
        gain_modes=tuple(mode.value for mode in settings.gain_modes),
        gain_db=settings.gain_db,
    )
