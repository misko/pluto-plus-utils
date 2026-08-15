"""Clean-room direct-IP UDP transport around the strict wire contracts.

This module performs network I/O but no radio configuration. A production radio
adapter pairs it with an independently serial-attested IIO control context. Each
capture is finite, request-ID matched, peer-address checked, bounded by a deadline,
and accepted only after fragment CRC plus protocol-v3 metadata validation.
"""

from __future__ import annotations

import math
import secrets
import socket
import threading
import time
from dataclasses import dataclass

import numpy as np
import numpy.typing as npt

from pluto_plus.direct_radio.ip import (
    DEFAULT_UDP_DATAGRAM_BYTES,
    IP_CONTROL_BYTES,
    IpControlMessageV1,
    IpControlType,
    IpFrameReassembler,
    make_ip_capability_query,
    make_ip_start_request,
    make_ip_stop_request,
)
from pluto_plus.direct_radio.samples import ci16_dual_rx
from pluto_plus.direct_radio.usb import MetadataFeatures, RadioMetadataV3, RxFrameParser

DEFAULT_CONTROL_PORT = 30_432
REQUIRED_V3_FEATURES = MetadataFeatures(0xF7)


class DirectIpTransportError(RuntimeError):
    """A bounded direct-IP operation could not produce an attested frame."""


@dataclass(frozen=True, slots=True)
class DirectIpCapture:
    utc_ns: int
    samples: npt.NDArray[np.complex64]
    metadata: RadioMetadataV3


class DirectIpTransport:
    """One finite-capture direct-IP client with exclusive socket ownership."""

    def __init__(
        self,
        host: str,
        *,
        control_port: int = DEFAULT_CONTROL_PORT,
        timeout_s: float = 5.0,
        maximum_datagram_bytes: int = DEFAULT_UDP_DATAGRAM_BYTES,
    ) -> None:
        if not host.strip():
            raise ValueError("direct-IP host cannot be empty")
        if not 1 <= control_port <= 65_535:
            raise ValueError("direct-IP control port is outside the TCP/UDP range")
        if timeout_s <= 0:
            raise ValueError("direct-IP timeout must be positive")
        self.host = host
        self.control_port = control_port
        self.timeout_s = timeout_s
        self.maximum_datagram_bytes = maximum_datagram_bytes
        self._control: socket.socket | None = None
        self._data: socket.socket | None = None
        self._remote_ip: str | None = None
        self._capabilities: IpControlMessageV1 | None = None
        self._lock = threading.Lock()

    @property
    def capabilities(self) -> IpControlMessageV1:
        if self._capabilities is None:
            raise DirectIpTransportError("direct-IP transport is not open")
        return self._capabilities

    def open(self) -> None:
        with self._lock:
            if self._control is not None or self._data is not None:
                raise DirectIpTransportError("direct-IP transport is already open")
            try:
                resolved = socket.getaddrinfo(
                    self.host,
                    self.control_port,
                    family=socket.AF_INET,
                    type=socket.SOCK_DGRAM,
                )
                if not resolved:
                    raise DirectIpTransportError("direct-IP host did not resolve to IPv4")
                remote = resolved[0][4]
                control = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                data = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                control.connect(remote)
                data.bind(("0.0.0.0", 0))
                self._control = control
                self._data = data
                self._remote_ip = str(remote[0])
                query = make_ip_capability_query(
                    request_id=self._request_id(), transport_capabilities=True
                )
                capabilities = self._exchange(query, IpControlType.CAPABILITIES)
                if capabilities.protocol_max < 3:
                    raise DirectIpTransportError("direct-IP endpoint does not support protocol v3")
                if capabilities.features & REQUIRED_V3_FEATURES != REQUIRED_V3_FEATURES:
                    raise DirectIpTransportError(
                        "direct-IP endpoint lacks required protocol-v3 metadata features"
                    )
                self._capabilities = capabilities
            except BaseException:
                self._close_unlocked()
                raise

    def close(self) -> None:
        with self._lock:
            self._close_unlocked()

    def capture(self, sample_count: int) -> DirectIpCapture:
        if sample_count <= 0:
            raise ValueError("direct-IP sample count must be positive")
        with self._lock:
            capabilities = self.capabilities
            if sample_count > capabilities.max_samples_per_channel:
                raise DirectIpTransportError(
                    f"direct-IP endpoint permits at most "
                    f"{capabilities.max_samples_per_channel} samples per frame"
                )
            data = self._require_data()
            interval = max(1, math.ceil(sample_count / 256))
            observation_capacity = math.ceil(sample_count / interval)
            request = make_ip_start_request(
                request_id=self._request_id(),
                protocol_version=3,
                features=REQUIRED_V3_FEATURES,
                enabled_scan_mask=0x0F,
                samples_per_channel=sample_count,
                frame_count=1,
                data_port=int(data.getsockname()[1]),
                max_datagram_bytes=self.maximum_datagram_bytes,
                gain_observation_interval_samples=interval,
                gain_observation_capacity=observation_capacity,
            )
            started: IpControlMessageV1 | None = None
            before = time.time_ns()
            try:
                started = self._exchange(request, IpControlType.STARTED)
                frame_bytes = self._receive_frame(started.stream_id)
                parsed = RxFrameParser().parse_complete_frame(frame_bytes)
                if (
                    parsed.metadata.stream_id != started.stream_id
                    or parsed.metadata.samples_per_channel != sample_count
                ):
                    raise DirectIpTransportError(
                        "direct-IP frame does not match the acknowledged stream or sample count"
                    )
                samples = ci16_dual_rx(parsed.iq_payload)
                if samples.shape != (2, sample_count):
                    raise DirectIpTransportError(
                        f"direct-IP sample shape is {samples.shape}, expected (2, {sample_count})"
                    )
                return DirectIpCapture(
                    utc_ns=(before + time.time_ns()) // 2,
                    samples=samples,
                    metadata=parsed.metadata,
                )
            except BaseException:
                if started is not None:
                    self._stop_best_effort(started.stream_id)
                raise

    def _exchange(
        self, request: IpControlMessageV1, expected: IpControlType
    ) -> IpControlMessageV1:
        control = self._require_control()
        deadline = time.monotonic() + self.timeout_s
        payload = request.pack()
        for _attempt in range(3):
            control.send(payload)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                control.settimeout(remaining)
                try:
                    response_payload = control.recv(IP_CONTROL_BYTES + 1)
                except TimeoutError:
                    break
                if len(response_payload) != IP_CONTROL_BYTES:
                    raise DirectIpTransportError("direct-IP control response has invalid length")
                try:
                    response = IpControlMessageV1.unpack(response_payload)
                except ValueError as error:
                    raise DirectIpTransportError(str(error)) from error
                if response.request_id != request.request_id:
                    continue
                if response.message_type is IpControlType.ERROR:
                    raise DirectIpTransportError(
                        f"direct-IP endpoint rejected request with status {response.status}"
                    )
                if response.message_type is not expected:
                    raise DirectIpTransportError(
                        f"direct-IP response is {response.message_type.name}, "
                        f"expected {expected.name}"
                    )
                return response
        raise DirectIpTransportError(f"direct-IP {request.message_type.name} timed out")

    def _receive_frame(self, stream_id: int) -> bytes:
        data = self._require_data()
        remote_ip = self._remote_ip
        deadline = time.monotonic() + self.timeout_s
        reassembler = IpFrameReassembler(
            frame_timeout_seconds=self.timeout_s,
            max_pending_frames=4,
            max_pending_bytes=32 * 1024 * 1024,
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DirectIpTransportError("direct-IP data frame timed out")
            data.settimeout(remaining)
            try:
                datagram, peer = data.recvfrom(self.maximum_datagram_bytes + 1)
            except TimeoutError as error:
                raise DirectIpTransportError("direct-IP data frame timed out") from error
            if peer[0] != remote_ip:
                continue
            if len(datagram) > self.maximum_datagram_bytes:
                raise DirectIpTransportError("direct-IP datagram exceeds negotiated maximum")
            try:
                frames = reassembler.feed(datagram, peer=peer[0])
            except ValueError as error:
                raise DirectIpTransportError(str(error)) from error
            for frame in frames:
                if frame.stream_id != stream_id:
                    raise DirectIpTransportError("direct-IP data belongs to another stream")
                return frame.frame

    def _stop_best_effort(self, stream_id: int) -> None:
        try:
            request = make_ip_stop_request(request_id=self._request_id(), stream_id=stream_id)
            self._exchange(request, IpControlType.STOPPED)
        except (OSError, ValueError, DirectIpTransportError):
            pass

    def _request_id(self) -> int:
        return secrets.randbits(64) or 1

    def _require_control(self) -> socket.socket:
        if self._control is None:
            raise DirectIpTransportError("direct-IP control socket is not open")
        return self._control

    def _require_data(self) -> socket.socket:
        if self._data is None:
            raise DirectIpTransportError("direct-IP data socket is not open")
        return self._data

    def _close_unlocked(self) -> None:
        control, data = self._control, self._data
        self._control = self._data = None
        self._remote_ip = None
        self._capabilities = None
        if control is not None:
            control.close()
        if data is not None:
            data.close()
