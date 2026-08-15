"""Bounded direct-USB I/O around the standalone protocol-v3 parser.

The transport deliberately owns only the vendor-specific bulk interface. Radio
configuration remains on a separately serial-attested IIO context. ``usb1`` is
loaded lazily so importing the base package never requires hardware libraries.
"""

from __future__ import annotations

import contextlib
import importlib
import math
import time
from dataclasses import dataclass
from types import ModuleType
from typing import Any, Protocol

import numpy as np
import numpy.typing as npt

from pluto_plus.direct_radio.samples import ci16_dual_rx
from pluto_plus.direct_radio.usb import (
    CAPABILITIES_BYTES,
    HEADER_PREFIX_BYTES_V3,
    CapabilityFlags,
    DirectRxFrame,
    GadgetCapabilitiesV1,
    MetadataFeatures,
    RadioMetadataV3,
    RxFrameParser,
    pack_start_request_v3,
)

PLUTO_VENDOR_ID = 0x0456
PLUTO_PRODUCT_ID = 0xB673
USB_VENDOR_INTERFACE_IN = 0xC1
USB_VENDOR_INTERFACE_OUT = 0x41
USB_CLASS_VENDOR_SPECIFIC = 0xFF
USB_TRANSFER_TYPE_BULK = 2
USB_DIRECTION_IN = 0x80

COMMAND_STOP = 0x11
COMMAND_GET_CAPABILITIES = 0x12
COMMAND_START_RX = 0x13
COMMAND_TARGET_RX = 0

CONTROL_TIMEOUT_MS = 1_000
DEFAULT_BULK_TIMEOUT_MS = 10_000
DEFAULT_BULK_CHUNK_BYTES = 1024 * 1024
ORPHAN_DRAIN_TIMEOUT_MS = 50
MAX_ORPHAN_TRANSFERS = 17
MAX_ORPHAN_BYTES = 8 * 1024 * 1024
REQUIRED_V3_FEATURES = MetadataFeatures(0xF7)


class DirectUsbTransportError(RuntimeError):
    """A selected direct-USB interface failed a bounded operation."""


class DirectUsbNotFoundError(DirectUsbTransportError):
    """No unique direct-USB gadget matched the requested durable identity."""


class UsbReadTimeout(DirectUsbTransportError):
    """A bulk read reached its finite deadline."""


@dataclass(frozen=True, slots=True)
class DirectUsbIdentity:
    serial: str
    bus: int
    address: int
    port_path: tuple[int, ...]
    interface: int
    bulk_in_endpoint: int
    bulk_out_endpoint: int


class UsbConnection(Protocol):
    @property
    def identity(self) -> DirectUsbIdentity: ...

    def control_read(self, command: int, length: int, timeout_ms: int) -> bytes: ...

    def control_write(self, command: int, payload: bytes, timeout_ms: int) -> None: ...

    def bulk_read(self, length: int, timeout_ms: int) -> bytes: ...

    def clear_halt(self) -> None: ...

    def close(self) -> None: ...


class UsbBackend(Protocol):
    def open(
        self, *, serial: str | None, port_path: tuple[int, ...] | None
    ) -> UsbConnection: ...


@dataclass(frozen=True, slots=True)
class DirectUsbCapture:
    utc_ns: int
    samples: npt.NDArray[np.complex64]
    metadata: RadioMetadataV3


class DirectUsbTransport:
    """One serial/path-pinned finite direct-USB capture transport."""

    def __init__(
        self,
        *,
        serial: str | None = None,
        port_path: tuple[int, ...] | None = None,
        backend: UsbBackend | None = None,
        bulk_timeout_ms: int = DEFAULT_BULK_TIMEOUT_MS,
        bulk_chunk_bytes: int = DEFAULT_BULK_CHUNK_BYTES,
    ) -> None:
        if not serial and not port_path:
            raise ValueError("direct USB requires a serial or physical port path")
        if serial is not None and not serial.strip():
            raise ValueError("direct USB serial cannot be blank")
        if port_path is not None and (not port_path or any(item <= 0 for item in port_path)):
            raise ValueError("direct USB physical port path is invalid")
        if bulk_timeout_ms <= 0 or bulk_chunk_bytes <= 0:
            raise ValueError("direct USB read bounds must be positive")
        self.requested_serial = serial
        self.requested_port_path = port_path
        self._backend = backend or LibusbBackend()
        self.bulk_timeout_ms = bulk_timeout_ms
        self.bulk_chunk_bytes = bulk_chunk_bytes
        self._connection: UsbConnection | None = None
        self._capabilities: GadgetCapabilitiesV1 | None = None

    @property
    def identity(self) -> DirectUsbIdentity:
        if self._connection is None:
            raise DirectUsbTransportError("direct-USB transport is not open")
        return self._connection.identity

    @property
    def capabilities(self) -> GadgetCapabilitiesV1:
        if self._capabilities is None:
            raise DirectUsbTransportError("direct-USB capabilities are unavailable")
        return self._capabilities

    def open(self) -> None:
        if self._connection is not None:
            raise DirectUsbTransportError("direct-USB transport is already open")
        connection = self._backend.open(
            serial=self.requested_serial, port_path=self.requested_port_path
        )
        try:
            capabilities = GadgetCapabilitiesV1.unpack(
                connection.control_read(
                    COMMAND_GET_CAPABILITIES, CAPABILITIES_BYTES, CONTROL_TIMEOUT_MS
                )
            )
            if not capabilities.protocol_min <= 3 <= capabilities.protocol_max:
                raise DirectUsbTransportError("direct-USB gadget does not support protocol v3")
            if capabilities.supported_features & REQUIRED_V3_FEATURES != REQUIRED_V3_FEATURES:
                raise DirectUsbTransportError(
                    "direct-USB gadget lacks required protocol-v3 metadata features"
                )
            if not capabilities.capability_flags & CapabilityFlags.FINITE_RX:
                raise DirectUsbTransportError("direct-USB gadget does not support finite RX")
            self._stop(connection)
            self._drain_orphaned_data(connection, capabilities)
        except BaseException:
            connection.close()
            raise
        self._connection = connection
        self._capabilities = capabilities
        self.requested_serial = connection.identity.serial
        self.requested_port_path = connection.identity.port_path

    def close(self) -> None:
        connection, self._connection = self._connection, None
        self._capabilities = None
        if connection is not None:
            try:
                self._stop(connection)
            finally:
                connection.close()

    def capture(self, sample_count: int) -> DirectUsbCapture:
        if sample_count <= 0:
            raise ValueError("direct-USB sample count must be positive")
        connection = self._require_connection()
        capabilities = self.capabilities
        if sample_count > capabilities.max_samples_per_channel:
            raise DirectUsbTransportError(
                f"direct-USB gadget permits at most "
                f"{capabilities.max_samples_per_channel} samples per frame"
            )
        interval = max(1, math.ceil(sample_count / 256))
        capacity = math.ceil(sample_count / interval)
        request = pack_start_request_v3(
            requested_features=REQUIRED_V3_FEATURES,
            enabled_scan_mask=0x0F,
            samples_per_channel=sample_count,
            frame_count=1,
            gain_observation_interval_samples=interval,
            gain_observation_capacity=capacity,
        )
        maximum_header = HEADER_PREFIX_BYTES_V3 + capacity * 32 + 4
        maximum_frame = maximum_header + sample_count * 8
        parser = RxFrameParser()
        frames: list[DirectRxFrame] = []
        before = time.time_ns()
        deadline = time.monotonic() + self.bulk_timeout_ms / 1_000
        connection.control_write(COMMAND_START_RX, request, CONTROL_TIMEOUT_MS)
        try:
            received = 0
            while not frames:
                if received >= maximum_frame:
                    raise DirectUsbTransportError(
                        "direct-USB gadget filled the frame bound without a complete frame"
                    )
                remaining_ms = math.ceil((deadline - time.monotonic()) * 1_000)
                if remaining_ms <= 0:
                    raise UsbReadTimeout("direct-USB frame timed out")
                chunk = connection.bulk_read(
                    min(self.bulk_chunk_bytes, maximum_frame - received), remaining_ms
                )
                if not chunk:
                    raise DirectUsbTransportError("direct-USB gadget returned an empty read")
                received += len(chunk)
                if received > maximum_frame:
                    raise DirectUsbTransportError("direct-USB gadget exceeded the frame bound")
                frames.extend(parser.feed(chunk))
            if len(frames) != 1:
                raise DirectUsbTransportError("direct-USB gadget returned multiple finite frames")
            parser.finish()
            frame = frames[0]
            if frame.metadata.samples_per_channel != sample_count:
                raise DirectUsbTransportError(
                    "direct-USB frame does not match the requested sample count"
                )
            samples = ci16_dual_rx(frame.iq_payload)
            if samples.shape != (2, sample_count):
                raise DirectUsbTransportError(
                    f"direct-USB sample shape is {samples.shape}, expected (2, {sample_count})"
                )
            return DirectUsbCapture(
                utc_ns=(before + time.time_ns()) // 2,
                samples=samples,
                metadata=frame.metadata,
            )
        finally:
            self._stop(connection)

    @staticmethod
    def _stop(connection: UsbConnection) -> None:
        connection.control_write(COMMAND_STOP, b"", CONTROL_TIMEOUT_MS)

    @staticmethod
    def _drain_orphaned_data(
        connection: UsbConnection, capabilities: GadgetCapabilitiesV1
    ) -> None:
        limit = min(MAX_ORPHAN_TRANSFERS, capabilities.max_finite_frames + 1)
        maximum = min(MAX_ORPHAN_BYTES, capabilities.max_samples_per_channel * 8 + 65_535)
        try:
            for _ in range(limit):
                try:
                    connection.bulk_read(maximum, ORPHAN_DRAIN_TIMEOUT_MS)
                except UsbReadTimeout:
                    return
        finally:
            connection.clear_halt()
        raise DirectUsbTransportError(
            f"direct-USB bulk endpoint remained non-empty after {limit} bounded drains"
        )

    def _require_connection(self) -> UsbConnection:
        if self._connection is None:
            raise DirectUsbTransportError("direct-USB transport is not open")
        return self._connection


class LibusbBackend:
    """Lazy ``libusb1`` discovery with exact durable-identity matching."""

    def __init__(self, module: ModuleType | Any | None = None) -> None:
        self._module = module

    def open(
        self, *, serial: str | None, port_path: tuple[int, ...] | None
    ) -> UsbConnection:
        module = self._module
        if module is None:
            try:
                module = importlib.import_module("usb1")
            except ImportError as error:
                raise ImportError(
                    "direct USB requires the 'hardware' extra with libusb1"
                ) from error
        context = module.USBContext()
        context.open()
        matches: list[tuple[Any, str, tuple[int, ...], int, int, int]] = []
        selected: list[_LibusbConnection] = []
        try:
            for device in context.getDeviceIterator(skip_on_error=True):
                if (
                    int(device.getVendorID()) != PLUTO_VENDOR_ID
                    or int(device.getProductID()) != PLUTO_PRODUCT_ID
                ):
                    continue
                candidate_path = tuple(int(item) for item in device.getPortNumberList())
                if port_path is not None and candidate_path != port_path:
                    continue
                try:
                    candidate_serial = str(device.getSerialNumber())
                except Exception:
                    continue
                if serial is not None and candidate_serial != serial:
                    continue
                for interface, bulk_in, bulk_out in _candidate_interfaces(device):
                    matches.append(
                        (device, candidate_serial, candidate_path, interface, bulk_in, bulk_out)
                    )
            for device, found_serial, found_path, interface, bulk_in, bulk_out in matches:
                connection = self._claim(
                    module,
                    context,
                    device,
                    found_serial,
                    found_path,
                    interface,
                    bulk_in,
                    bulk_out,
                )
                try:
                    GadgetCapabilitiesV1.unpack(
                        connection.control_read(
                            COMMAND_GET_CAPABILITIES,
                            CAPABILITIES_BYTES,
                            CONTROL_TIMEOUT_MS,
                        )
                    )
                except Exception:
                    connection.close()
                else:
                    selected.append(connection)
            if len(selected) != 1:
                for connection in selected:
                    connection.close()
                raise DirectUsbNotFoundError(
                    "expected exactly one compatible direct-USB interface for "
                    f"serial={serial!r} port_path={port_path!r}; found {len(selected)}"
                )
            selected[0].claim_context_ownership()
            return selected[0]
        except BaseException:
            context.close()
            raise

    @staticmethod
    def _claim(
        module: ModuleType | Any,
        context: Any,
        device: Any,
        serial: str,
        port_path: tuple[int, ...],
        interface: int,
        bulk_in: int,
        bulk_out: int,
    ) -> _LibusbConnection:
        handle = device.open()
        detached = False
        try:
            if bool(handle.kernelDriverActive(interface)):
                handle.detachKernelDriver(interface)
                detached = True
            handle.claimInterface(interface)
        except BaseException:
            if detached:
                with contextlib.suppress(Exception):
                    handle.attachKernelDriver(interface)
            handle.close()
            raise
        identity = DirectUsbIdentity(
            serial=serial,
            bus=int(device.getBusNumber()),
            address=int(device.getDeviceAddress()),
            port_path=port_path,
            interface=interface,
            bulk_in_endpoint=bulk_in,
            bulk_out_endpoint=bulk_out,
        )
        return _LibusbConnection(module, context, handle, identity, detached)


class _LibusbConnection:
    def __init__(
        self,
        module: ModuleType | Any,
        context: Any,
        handle: Any,
        identity: DirectUsbIdentity,
        detached: bool,
    ) -> None:
        self._module = module
        self._context = context
        self._handle = handle
        self._identity = identity
        self._detached = detached
        self._closed = False
        self._owns_context = False

    @property
    def identity(self) -> DirectUsbIdentity:
        return self._identity

    def claim_context_ownership(self) -> None:
        self._owns_context = True

    def control_read(self, command: int, length: int, timeout_ms: int) -> bytes:
        return bytes(
            self._handle.controlRead(
                USB_VENDOR_INTERFACE_IN,
                command,
                COMMAND_TARGET_RX,
                self._identity.interface,
                length,
                timeout=timeout_ms,
            )
        )

    def control_write(self, command: int, payload: bytes, timeout_ms: int) -> None:
        written = int(
            self._handle.controlWrite(
                USB_VENDOR_INTERFACE_OUT,
                command,
                COMMAND_TARGET_RX,
                self._identity.interface,
                payload,
                timeout=timeout_ms,
            )
        )
        if written != len(payload):
            raise DirectUsbTransportError(
                f"short direct-USB control write: {written}/{len(payload)} bytes"
            )

    def bulk_read(self, length: int, timeout_ms: int) -> bytes:
        try:
            return bytes(
                self._handle.bulkRead(
                    self._identity.bulk_in_endpoint, length, timeout=timeout_ms
                )
            )
        except Exception as error:
            timeout_type = getattr(self._module, "USBErrorTimeout", ())
            if isinstance(error, timeout_type):
                raise UsbReadTimeout("direct-USB bulk read timed out") from error
            raise DirectUsbTransportError(f"direct-USB bulk read failed: {error}") from error

    def clear_halt(self) -> None:
        try:
            self._handle.clearHalt(self._identity.bulk_in_endpoint)
        except Exception as error:
            raise DirectUsbTransportError(
                f"could not clear direct-USB endpoint: {error}"
            ) from error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            with contextlib.suppress(Exception):
                self._handle.releaseInterface(self._identity.interface)
            if self._detached:
                with contextlib.suppress(Exception):
                    self._handle.attachKernelDriver(self._identity.interface)
        finally:
            self._handle.close()
            if self._owns_context:
                self._context.close()


def _candidate_interfaces(device: Any) -> list[tuple[int, int, int]]:
    candidates: list[tuple[int, int, int]] = []
    for setting in device.iterSettings():
        if int(setting.getClass()) != USB_CLASS_VENDOR_SPECIFIC:
            continue
        bulk_in: int | None = None
        bulk_out: int | None = None
        for endpoint in setting.iterEndpoints():
            if int(endpoint.getAttributes()) & 0x03 != USB_TRANSFER_TYPE_BULK:
                continue
            address = int(endpoint.getAddress())
            if address & USB_DIRECTION_IN:
                bulk_in = address
            else:
                bulk_out = address
        if bulk_in is not None and bulk_out is not None:
            candidates.append((int(setting.getNumber()), bulk_in, bulk_out))
    return candidates
