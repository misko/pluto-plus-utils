from __future__ import annotations

import dataclasses
import struct
from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.direct_radio.usb import (
    CAPABILITIES_BYTES,
    CAPABILITIES_MAGIC,
    CapabilityFlags,
    GainObservationFlags,
    GainObservationV3,
    MetadataFlags,
    RadioMetadataV3,
    SampleFormat,
)
from pluto_plus.direct_radio.usb_transport import (
    COMMAND_START_RX,
    COMMAND_STOP,
    REQUIRED_V3_FEATURES,
    DirectUsbIdentity,
    DirectUsbTransport,
    LibusbBackend,
    UsbConnection,
    UsbReadTimeout,
)
from pluto_plus.hardware.direct_usb import DirectUsbRadioDevice
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import RadioSettings, Transport


def _capabilities() -> bytes:
    return struct.pack(
        "<IHHHHIIIII",
        CAPABILITIES_MAGIC,
        CAPABILITIES_BYTES,
        1,
        3,
        0,
        int(REQUIRED_V3_FEATURES),
        65_536,
        16,
        int(CapabilityFlags.FINITE_RX),
        0,
    )


def _frame(count: int, *, corrupt: bool = False) -> tuple[bytes, np.ndarray]:
    interval = max(1, -(-count // 256))
    capacity = -(-count // interval)
    components = np.arange(count * 4, dtype="<i2").reshape(count, 4)
    observation = GainObservationV3(
        sample_sequence_before=1_000,
        sample_sequence_after=1_000 + count,
        read_duration_ns=10,
        flags=GainObservationFlags.VALID | GainObservationFlags.SAMPLE_INTERVAL_VALID,
        rx1_gain_index=1,
        rx2_gain_index=2,
        rx1_gain_db=20,
        rx2_gain_db=21,
    )
    metadata = RadioMetadataV3(
        features=REQUIRED_V3_FEATURES,
        flags=(
            MetadataFlags.SAMPLE_SEQUENCE_VALID
            | MetadataFlags.GAIN_OBSERVATIONS_VALID
            | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
        ),
        stream_id=77,
        buffer_sequence=0,
        first_sample_sequence=1_000,
        samples_per_channel=count,
        iq_payload_bytes=count * 8,
        enabled_scan_mask=0x0F,
        sample_format=SampleFormat.CS16_LE_TIME_INTERLEAVED,
        channel_count=2,
        gain_observation_interval_samples=interval,
        gain_observation_capacity=capacity,
        gain_observations=(observation,),
    )
    wire = bytearray(metadata.pack() + components.tobytes())
    if corrupt:
        wire[40] ^= 1
    return bytes(wire), components


class FakeUsbConnection:
    def __init__(self, serial: str = "serial-a", *, corrupt: bool = False) -> None:
        self._identity = DirectUsbIdentity(serial, 1, 2, (3, 4), 5, 0x81, 0x01)
        self.corrupt = corrupt
        self.commands: list[int] = []
        self.chunks: list[bytes] = []
        self.closed = False
        self.halt_cleared = False
        self.components: np.ndarray | None = None

    @property
    def identity(self) -> DirectUsbIdentity:
        return self._identity

    def control_read(self, command: int, length: int, timeout_ms: int) -> bytes:
        assert length == CAPABILITIES_BYTES
        assert timeout_ms > 0
        return _capabilities()

    def control_write(self, command: int, payload: bytes, timeout_ms: int) -> None:
        self.commands.append(command)
        if command == COMMAND_START_RX:
            count = struct.unpack_from("<I", payload, 16)[0]
            frame, self.components = _frame(count, corrupt=self.corrupt)
            pivot = len(frame) // 3
            self.chunks = [frame[:pivot], frame[pivot:]]

    def bulk_read(self, length: int, timeout_ms: int) -> bytes:
        if not self.chunks:
            raise UsbReadTimeout("idle")
        chunk = self.chunks.pop(0)
        assert len(chunk) <= length
        return chunk

    def clear_halt(self) -> None:
        self.halt_cleared = True

    def close(self) -> None:
        self.closed = True


@dataclasses.dataclass
class FakeUsbBackend:
    connection: FakeUsbConnection
    requested: tuple[str | None, tuple[int, ...] | None] | None = None

    def open(
        self, *, serial: str | None, port_path: tuple[int, ...] | None
    ) -> UsbConnection:
        self.requested = (serial, port_path)
        return self.connection


def test_direct_usb_transport_captures_split_attested_frame_and_stops() -> None:
    connection = FakeUsbConnection()
    backend = FakeUsbBackend(connection)
    transport = DirectUsbTransport(serial="serial-a", backend=backend)
    transport.open()
    capture = transport.capture(1_024)
    transport.close()

    assert backend.requested == ("serial-a", None)
    assert connection.halt_cleared
    assert connection.closed
    assert connection.commands == [COMMAND_STOP, COMMAND_START_RX, COMMAND_STOP, COMMAND_STOP]
    assert capture.samples.shape == (2, 1_024)
    assert connection.components is not None
    np.testing.assert_array_equal(capture.samples.real[0], connection.components[:, 0])
    np.testing.assert_array_equal(capture.samples.imag[1], connection.components[:, 3])


def test_direct_usb_transport_fails_closed_and_stops_on_bad_metadata_crc() -> None:
    connection = FakeUsbConnection(corrupt=True)
    transport = DirectUsbTransport(serial="serial-a", backend=FakeUsbBackend(connection))
    transport.open()
    with pytest.raises(ValueError, match="CRC"):
        transport.capture(64)
    transport.close()
    assert connection.commands[-2:] == [COMMAND_STOP, COMMAND_STOP]


def test_direct_usb_radio_pairs_matching_iio_control_and_direct_capture() -> None:
    connection = FakeUsbConnection()
    control = FakeRadioDevice("serial-a")
    device = DirectUsbRadioDevice(
        control,
        DirectUsbTransport(serial="serial-a", backend=FakeUsbBackend(connection)),
    )
    device.open()
    assert device.identity.serial == "serial-a"
    assert device.identity.transport is Transport.DIRECT_USB
    assert device.read_block(256).samples.shape == (2, 256)
    with pytest.raises(ValueError, match="both receiver"):
        device.apply_settings(RadioSettings(channels=(0,)))
    device.close()


def test_direct_usb_radio_rejects_cross_wired_serials() -> None:
    device = DirectUsbRadioDevice(
        FakeRadioDevice("serial-a"),
        DirectUsbTransport(
            serial="serial-b", backend=FakeUsbBackend(FakeUsbConnection("serial-b"))
        ),
    )
    with pytest.raises(RuntimeError, match="does not match"):
        device.open()


class _Endpoint:
    def __init__(self, address: int) -> None:
        self.address = address

    def getAttributes(self) -> int:
        return 2

    def getAddress(self) -> int:
        return self.address


class _Setting:
    def __init__(self, number: int) -> None:
        self.number = number

    def getClass(self) -> int:
        return 0xFF

    def getNumber(self) -> int:
        return self.number

    def iterEndpoints(self) -> list[_Endpoint]:
        return [_Endpoint(0x81), _Endpoint(0x01)]


class _LibusbHandle:
    def __init__(self) -> None:
        self.claimed: list[int] = []
        self.released: list[int] = []
        self.closed = False

    def kernelDriverActive(self, _interface: int) -> bool:
        return False

    def claimInterface(self, interface: int) -> None:
        self.claimed.append(interface)

    def releaseInterface(self, interface: int) -> None:
        self.released.append(interface)

    def controlRead(
        self,
        _request_type: int,
        _command: int,
        _target: int,
        interface: int,
        length: int,
        *,
        timeout: int,
    ) -> bytes:
        assert timeout > 0
        return _capabilities() if interface == 7 else bytes(length)

    def close(self) -> None:
        self.closed = True


class _LibusbDevice:
    def __init__(self) -> None:
        self.handles: list[_LibusbHandle] = []

    def getVendorID(self) -> int:
        return 0x0456

    def getProductID(self) -> int:
        return 0xB673

    def getPortNumberList(self) -> list[int]:
        return [3, 4]

    def getSerialNumber(self) -> str:
        return "serial-a"

    def getBusNumber(self) -> int:
        return 1

    def getDeviceAddress(self) -> int:
        return 2

    def iterSettings(self) -> list[_Setting]:
        return [_Setting(6), _Setting(7)]

    def open(self) -> _LibusbHandle:
        handle = _LibusbHandle()
        self.handles.append(handle)
        return handle


class _LibusbContext:
    def __init__(self, device: _LibusbDevice) -> None:
        self.device = device
        self.opened = False
        self.closed = False

    def open(self) -> None:
        self.opened = True

    def getDeviceIterator(self, *, skip_on_error: bool) -> list[_LibusbDevice]:
        assert skip_on_error
        return [self.device]

    def close(self) -> None:
        self.closed = True


def test_libusb_backend_probes_interfaces_and_owns_only_the_compatible_one() -> None:
    device = _LibusbDevice()
    context = _LibusbContext(device)
    module = SimpleNamespace(USBContext=lambda: context)

    connection = LibusbBackend(module).open(serial="serial-a", port_path=None)
    assert connection.identity.interface == 7
    assert device.handles[0].closed
    assert not device.handles[1].closed
    assert not context.closed

    connection.close()
    assert device.handles[1].closed
    assert context.closed
