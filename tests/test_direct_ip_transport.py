from __future__ import annotations

import dataclasses
import socket
import threading
from collections.abc import Callable

import numpy as np
import pytest

from pluto_plus.direct_radio.ip import (
    IP_CONTROL_BYTES,
    IpControlFlags,
    IpControlMessageV1,
    IpControlType,
    fragment_ip_frame,
)
from pluto_plus.direct_radio.ip_transport import (
    REQUIRED_V3_FEATURES,
    DirectIpTransport,
    DirectIpTransportError,
)
from pluto_plus.direct_radio.usb import (
    GainObservationFlags,
    GainObservationV3,
    MetadataFlags,
    RadioMetadataV3,
    SampleFormat,
)
from pluto_plus.hardware.direct_ip import DirectIpRadioDevice
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import RadioSettings, Transport


def _frame(request: IpControlMessageV1) -> tuple[bytes, np.ndarray]:
    count = request.samples_per_channel
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
        gain_observation_interval_samples=request.gain_observation_interval_samples,
        gain_observation_capacity=request.gain_observation_capacity,
        gain_observations=(observation,),
    )
    return metadata.pack() + components.tobytes(), components


class UdpGadget:
    def __init__(self, *, send_data: bool = True, corrupt_data: bool = False) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.1)
        self.port = int(self.socket.getsockname()[1])
        self.send_data = send_data
        self.corrupt_data = corrupt_data
        self.requests: list[IpControlMessageV1] = []
        self.components: np.ndarray | None = None
        self.errors: list[BaseException] = []
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> UdpGadget:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self._stop.set()
        self.socket.close()
        self.thread.join(timeout=2)

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                try:
                    payload, peer = self.socket.recvfrom(IP_CONTROL_BYTES)
                except TimeoutError:
                    continue
                except OSError:
                    return
                request = IpControlMessageV1.unpack(payload)
                self.requests.append(request)
                if request.message_type is IpControlType.QUERY_CAPABILITIES:
                    response = IpControlMessageV1(
                        message_type=IpControlType.CAPABILITIES,
                        request_id=request.request_id,
                        flags=IpControlFlags.FINITE_RX,
                        protocol_min=1,
                        protocol_max=3,
                        features=REQUIRED_V3_FEATURES,
                        max_samples_per_channel=65_536,
                        max_finite_frames=16,
                    )
                    self.socket.sendto(response.pack(), peer)
                elif request.message_type is IpControlType.START_RX:
                    response = dataclasses.replace(
                        request,
                        message_type=IpControlType.STARTED,
                        stream_id=77,
                    )
                    self.socket.sendto(response.pack(), peer)
                    if self.send_data:
                        frame, self.components = _frame(request)
                        datagrams = fragment_ip_frame(
                            frame,
                            stream_id=77,
                            frame_sequence=0,
                            max_datagram_bytes=request.max_datagram_bytes,
                        )
                        if self.corrupt_data:
                            damaged = bytearray(datagrams[-1])
                            damaged[-1] ^= 1
                            datagrams = (*datagrams[:-1], bytes(damaged))
                        destination = (peer[0], request.data_port)
                        for datagram in datagrams[::-1]:
                            self.socket.sendto(datagram, destination)
                elif request.message_type is IpControlType.STOP_RX:
                    self.socket.sendto(
                        dataclasses.replace(
                            request, message_type=IpControlType.STOPPED
                        ).pack(),
                        peer,
                    )
        except BaseException as error:
            if not self._stop.is_set():
                self.errors.append(error)


def test_direct_ip_transport_captures_attested_dual_rx_frame() -> None:
    with UdpGadget() as gadget:
        transport = DirectIpTransport(
            "127.0.0.1", control_port=gadget.port, timeout_s=1
        )
        transport.open()
        capture = transport.capture(1_024)
        transport.close()

    assert gadget.errors == []
    assert [request.message_type for request in gadget.requests] == [
        IpControlType.QUERY_CAPABILITIES,
        IpControlType.START_RX,
    ]
    assert capture.samples.shape == (2, 1_024)
    assert gadget.components is not None
    np.testing.assert_array_equal(capture.samples.real[0], gadget.components[:, 0])
    np.testing.assert_array_equal(capture.samples.imag[1], gadget.components[:, 3])
    assert capture.metadata.stream_id == 77


@pytest.mark.parametrize(
    ("gadget_factory", "message"),
    [
        (lambda: UdpGadget(send_data=False), "timed out"),
        (lambda: UdpGadget(corrupt_data=True), "CRC"),
    ],
)
def test_direct_ip_transport_fails_closed_on_missing_or_corrupt_data(
    gadget_factory: Callable[[], UdpGadget], message: str
) -> None:
    with gadget_factory() as gadget:
        transport = DirectIpTransport(
            "127.0.0.1", control_port=gadget.port, timeout_s=0.1
        )
        transport.open()
        with pytest.raises(DirectIpTransportError, match=message):
            transport.capture(64)
        transport.close()


def test_direct_ip_radio_pairs_iio_control_with_direct_capture() -> None:
    with UdpGadget() as gadget:
        control = FakeRadioDevice("serial-a")
        device = DirectIpRadioDevice(
            control,
            DirectIpTransport("127.0.0.1", control_port=gadget.port, timeout_s=1),
        )
        device.open()
        assert device.identity.serial == "serial-a"
        assert device.identity.transport is Transport.DIRECT_IP
        assert device.capabilities.supports_direct_capture
        block = device.read_block(256)
        assert block.samples.shape == (2, 256)
        with pytest.raises(ValueError, match="both receiver"):
            device.apply_settings(RadioSettings(channels=(0,)))
        device.close()
