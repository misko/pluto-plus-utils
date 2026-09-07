"""Native libiio transport for FPGA Starlink PSS acquisition and tracking results.

The FPGA keeps 60 MS/s receive samples on the radio.  The two IIO devices
transport only a 26-word fine-timing packet or losslessly chunked 20,000-bin
coarse phase maps.  Parsing is intentionally independent from pylibiio so the
wire ABI can be tested with golden byte strings.
"""

from __future__ import annotations

import importlib
import struct
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

from pluto_plus.errors import RadioConfigurationError

PSS_TRACK_DEVICE = "starlink-pss-track"
PSS_MAP_DEVICE = "starlink-pss-map"
PSS_TRACK_ID = 0x50535354
PSS_TRACK_VERSIONS = {15: 0x00010002, 30: 0x00010003, 60: 0x00010003}
PSS_TRACK_GEOMETRY = {15: 0x003D8242, 30: 0x0BCA0884, 60: 0x0F8C1108}
PSS_TRACK_CAPABILITIES = {15: 0x3D, 30: 0x1D, 60: 0x1D}
PSS_PACKET_MAGIC = 0x31535350
PSS_PACKET_HEADER = 0x1A010001
PSS_RESULT_WORDS = 26
PSS_PACKET_BYTES = PSS_RESULT_WORDS * 4

PSS_MAP_ID = 0x50534D41
PSS_MAP_VERSIONS = {15: 0x00010001, 30: 0x00010002, 60: 0x00010004}
PSS_MAP_CAPABILITIES = {15: 0x3F, 30: 0x7F, 60: 0xFF}
PSS_MAP_TILE_GEOMETRY = 0x00401002
PSS_MAP_PHASE_BINS = 20_000
PSS_MAP_CHUNK_MAGIC = 0x4B4E4843
PSS_MAP_CHUNK_BINS = 100
PSS_MAP_CHUNKS = PSS_MAP_PHASE_BINS // PSS_MAP_CHUNK_BINS
PSS_MAP_METADATA_WORDS = 9
PSS_MAP_CHUNK_WORDS = PSS_MAP_METADATA_WORDS + PSS_MAP_CHUNK_BINS // 2
PSS_MAP_CHUNK_BYTES = PSS_MAP_CHUNK_WORDS * 4


def _signed_16(value: int) -> int:
    return value - (1 << 16) if value & (1 << 15) else value


def read_ci16_coefficients(path: Path, *, rate_msps: int) -> tuple[tuple[int, int], ...]:
    """Read the FPGA's strict one-packed-CI16-word-per-line coefficient format."""

    if rate_msps not in PSS_TRACK_VERSIONS:
        raise ValueError("PSS tracker rate must be 15, 30, or 60 MS/s")
    expected = 66 * (rate_msps // 15)
    coefficients: list[tuple[int, int]] = []
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        word = raw.strip()
        if len(word) != 8 or any(
            character not in "0123456789abcdefABCDEF" for character in word
        ):
            raise ValueError(
                f"PSS coefficient line {line_number} is not one packed CI16 word"
            )
        packed = int(word, 16)
        coefficients.append(
            (_signed_16(packed & 0xFFFF), _signed_16(packed >> 16))
        )
    if len(coefficients) != expected:
        raise ValueError(
            f"{rate_msps} MS/s coefficient file has {len(coefficients)} words, "
            f"expected {expected}"
        )
    return tuple(coefficients)


def _s48(low: int, high: int) -> int:
    value = low | ((high & 0xFFFF) << 32)
    return value - (1 << 48) if value & (1 << 47) else value


def _u64(low: int, high: int) -> int:
    return low | (high << 32)


@dataclass(frozen=True, slots=True)
class PssFinePacket:
    """One exact, self-contained fine-timing result from the FPGA."""

    words: tuple[int, ...]
    request_id: int
    center_index: int
    center_timestamp: int
    lag: int
    winner_timestamp: int
    coefficient_generation: int
    correlation_real: int
    correlation_imag: int
    sample_energy: int
    coefficient_energy: int
    saturation_events: int

    @classmethod
    def decode(cls, payload: bytes, *, rate_msps: int) -> Self:
        if rate_msps not in PSS_TRACK_VERSIONS:
            raise ValueError("PSS tracker rate must be 15, 30, or 60 MS/s")
        if len(payload) != PSS_PACKET_BYTES:
            raise ValueError(f"fine packet is {len(payload)} bytes, expected 104")
        words = struct.unpack("<26I", payload)
        lag = struct.unpack("<i", payload[28:32])[0]
        center_index = _u64(words[3], words[4])
        center_timestamp = _u64(words[5], words[6])
        winner_timestamp = _u64(words[8], words[9])
        maximum_lag = 30 * (rate_msps // 15)
        if words[0] != PSS_PACKET_MAGIC or words[1] != PSS_PACKET_HEADER:
            raise ValueError("fine packet envelope does not match PSS ABI 1")
        if words[2] == 0 or words[10] == 0:
            raise ValueError("fine packet request and coefficient generations must be nonzero")
        if center_index != center_timestamp:
            raise ValueError("fine packet center index/timestamp disagree")
        if not -maximum_lag <= lag <= maximum_lag:
            raise ValueError("fine packet winning lag is outside the qualified aperture")
        if winner_timestamp != center_timestamp + lag:
            raise ValueError("fine packet winner timestamp is inconsistent")
        if words[19]:
            raise ValueError("fine packet reports arithmetic saturation")
        sample_energy = _s48(words[15], words[16])
        coefficient_energy = _s48(words[17], words[18])
        if sample_energy <= 0 or coefficient_energy <= 0:
            raise ValueError("fine packet energy must be positive")
        return cls(
            tuple(words),
            words[2],
            center_index,
            center_timestamp,
            lag,
            winner_timestamp,
            words[10],
            _s48(words[11], words[12]),
            _s48(words[13], words[14]),
            sample_energy,
            coefficient_energy,
            words[19],
        )


@dataclass(frozen=True, slots=True)
class PssMapChunk:
    abi_version: int
    generation: int
    chunk_index: int
    chunk_count: int
    start_index: int
    first_bin: int
    bins: tuple[int, ...]

    @classmethod
    def decode(cls, payload: bytes) -> Self:
        if len(payload) != PSS_MAP_CHUNK_BYTES:
            raise ValueError(
                f"phase-map chunk is {len(payload)} bytes, expected {PSS_MAP_CHUNK_BYTES}"
            )
        metadata = struct.unpack_from("<9I", payload)
        bins = struct.unpack_from("<100H", payload, PSS_MAP_METADATA_WORDS * 4)
        start_index = _u64(metadata[5], metadata[6])
        if metadata[0] != PSS_MAP_CHUNK_MAGIC:
            raise ValueError("phase-map chunk magic is invalid")
        if metadata[1] not in PSS_MAP_VERSIONS.values():
            raise ValueError("phase-map chunk ABI is unsupported")
        if metadata[2] == 0:
            raise ValueError("phase-map generation must be nonzero")
        if metadata[4] != PSS_MAP_CHUNKS or metadata[3] >= metadata[4]:
            raise ValueError("phase-map chunk geometry is invalid")
        if metadata[7] != metadata[3] * PSS_MAP_CHUNK_BINS or metadata[8] != len(bins):
            raise ValueError("phase-map chunk bin range is inconsistent")
        return cls(
            abi_version=metadata[1],
            generation=metadata[2],
            chunk_index=metadata[3],
            chunk_count=metadata[4],
            start_index=start_index,
            first_bin=metadata[7],
            bins=tuple(bins),
        )


@dataclass(frozen=True, slots=True)
class PssPhaseMap:
    abi_version: int
    generation: int
    start_index: int
    bins: tuple[int, ...]


class PssMapReassembler:
    """Strictly reassemble one map; partial or interleaved generations fail closed."""

    def __init__(self) -> None:
        self._chunks: list[PssMapChunk] = []

    def reset(self) -> None:
        self._chunks.clear()

    def add(self, chunk: PssMapChunk) -> PssPhaseMap | None:
        if chunk.chunk_index == 0:
            self.reset()
        if chunk.chunk_index != len(self._chunks):
            self.reset()
            raise ValueError("phase-map chunks are missing, duplicated, or out of order")
        if self._chunks:
            first = self._chunks[0]
            if (
                chunk.abi_version != first.abi_version
                or chunk.generation != first.generation
                or chunk.start_index != first.start_index
                or chunk.chunk_count != first.chunk_count
            ):
                self.reset()
                raise ValueError("phase-map generation changed during reassembly")
        self._chunks.append(chunk)
        if len(self._chunks) != chunk.chunk_count:
            return None
        first = self._chunks[0]
        bins = tuple(value for item in self._chunks for value in item.bins)
        self.reset()
        if len(bins) != PSS_MAP_PHASE_BINS:
            raise ValueError("reassembled phase map has the wrong bin count")
        return PssPhaseMap(first.abi_version, first.generation, first.start_index, bins)


def _attr_value(device: Any, name: str) -> str:
    try:
        return str(device.attrs[name].value).strip()
    except (AttributeError, KeyError) as error:
        raise RadioConfigurationError(
            f"{device.name} lacks required IIO attribute {name}"
        ) from error


def _read_int_attr(device: Any, name: str) -> int:
    raw = _attr_value(device, name)
    try:
        value = int(raw, 0)
    except ValueError as error:
        raise RadioConfigurationError(
            f"{device.name} attribute {name} is not an integer"
        ) from error
    if value < 0:
        raise RadioConfigurationError(f"{device.name} attribute {name} is negative")
    return value


def _write_attr(device: Any, name: str, value: int | str) -> None:
    try:
        device.attrs[name].value = str(value)
    except (AttributeError, KeyError) as error:
        raise RadioConfigurationError(
            f"{device.name} lacks writable IIO attribute {name}"
        ) from error


def _find_scan_channel(device: Any, expected_repeat: int) -> Any:
    candidates = [channel for channel in device.channels if getattr(channel, "scan_element", False)]
    for channel in candidates:
        data_format = getattr(channel, "data_format", None)
        if getattr(data_format, "repeat", None) == expected_repeat:
            return channel
    # pylibiio 0.25 does not expose repeat on every build. Names are stable.
    names = {
        PSS_RESULT_WORDS: "packet_words",
        PSS_MAP_CHUNK_WORDS: "chunk_words",
    }
    wanted = names[expected_repeat]
    for channel in candidates:
        if wanted in {getattr(channel, "id", None), getattr(channel, "name", None)}:
            return channel
    raise RadioConfigurationError(
        f"{device.name} lacks the required repeat={expected_repeat} scan channel"
    )


def _disable_scan_channels(device: Any) -> None:
    for channel in device.channels:
        if getattr(channel, "scan_element", False):
            channel.enabled = False


def _split_scans(payload: bytes, scan_bytes: int) -> tuple[bytes, ...]:
    if not payload or len(payload) % scan_bytes:
        raise RadioConfigurationError(
            f"IIO refill returned {len(payload)} bytes, not whole {scan_bytes}-byte scans"
        )
    return tuple(
        payload[offset : offset + scan_bytes]
        for offset in range(0, len(payload), scan_bytes)
    )


def _close_iio_buffer(iio_module: Any, buffer: Any) -> None:
    """Cancel and destroy modern or legacy pylibiio buffers exactly once."""

    first_error: BaseException | None = None
    cancel = getattr(buffer, "cancel", None)
    if callable(cancel):
        try:
            cancel()
        except BaseException as error:
            first_error = error
    try:
        closer = getattr(buffer, "close", None) or getattr(buffer, "destroy", None)
        if callable(closer):
            closer()
        else:
            native = getattr(buffer, "_buffer", None)
            destroy = getattr(iio_module, "_buffer_destroy", None)
            if native is None or not callable(destroy):
                raise RadioConfigurationError(
                    "pylibiio buffer exposes no deterministic destroy operation"
                )
            buffer._buffer = None
            destroy(native)
    except BaseException as error:
        if first_error is None:
            first_error = error
    if first_error is not None:
        raise first_error


def _close_iio_context(iio_module: Any, context: Any) -> None:
    """Destroy modern or legacy pylibiio contexts exactly once."""

    closer = getattr(context, "close", None) or getattr(context, "destroy", None)
    if callable(closer):
        closer()
        return
    native = getattr(context, "_context", None)
    destroy = getattr(iio_module, "_destroy", None)
    if native is None or not callable(destroy):
        raise RadioConfigurationError(
            "pylibiio context exposes no deterministic close operation"
        )
    context._context = None
    destroy(native)


class PssIioClient:
    """Capability-discovered, network-safe IIO client for the two PSS devices."""

    def __init__(self, context: Any, iio_module: Any) -> None:
        self.context = context
        self._iio = iio_module
        self.tracker = self._find_device(PSS_TRACK_DEVICE)
        self.phase_map = self._find_device(PSS_MAP_DEVICE)
        self.rate_msps = self._require_contracts()
        self._fine_buffer: Any | None = None
        self._map_buffer: Any | None = None
        self._expected_request: int | None = None
        self._remaining_results: int | None = None
        self._closed = False

    @classmethod
    def connect(cls, uri: str, *, iio_module: Any | None = None) -> Self:
        module = iio_module or importlib.import_module("iio")
        context = module.Context(uri)
        try:
            return cls(context, module)
        except BaseException:
            _close_iio_context(module, context)
            raise

    def _find_device(self, name: str) -> Any:
        find_device = getattr(self.context, "find_device", None)
        device = find_device(name) if callable(find_device) else None
        if device is None:
            raise RadioConfigurationError(f"IIO context lacks required device {name}")
        return device

    def _require_contracts(self) -> int:
        tracker_id = _read_int_attr(self.tracker, "fpga_identity")
        map_id = _read_int_attr(self.phase_map, "fpga_identity")
        rate = _read_int_attr(self.tracker, "rate_msps")
        map_rate = _read_int_attr(self.phase_map, "input_rate_msps")
        if tracker_id != PSS_TRACK_ID or map_id != PSS_MAP_ID:
            raise RadioConfigurationError("PSS IIO FPGA identity mismatch")
        if rate not in PSS_TRACK_VERSIONS or map_rate != rate:
            raise RadioConfigurationError("PSS tracker/map sample rates disagree")
        expected = (
            (self.tracker, {
                "abi_version": PSS_TRACK_VERSIONS[rate],
                "geometry": PSS_TRACK_GEOMETRY[rate],
                "capabilities": PSS_TRACK_CAPABILITIES[rate],
            }),
            (self.phase_map, {
                "abi_version": PSS_MAP_VERSIONS[rate],
                "tile_geometry": PSS_MAP_TILE_GEOMETRY,
                "capabilities": PSS_MAP_CAPABILITIES[rate],
                "phase_bins": PSS_MAP_PHASE_BINS,
                "reassembly_chunks": PSS_MAP_CHUNKS,
            }),
        )
        for device, attributes in expected:
            for name, value in attributes.items():
                if _read_int_attr(device, name) != value:
                    raise RadioConfigurationError(
                        f"{device.name} attribute {name} does not match the supported ABI"
                    )
            if _read_int_attr(device, "fault_flags"):
                raise RadioConfigurationError(f"{device.name} entered IIO with a latched fault")
        return rate

    def load_coefficients(self, coefficients: Sequence[tuple[int, int]], generation: int) -> None:
        expected = 66 * (self.rate_msps // 15)
        if len(coefficients) != expected or not 1 <= generation <= 0xFFFFFFFF:
            raise ValueError(f"{self.rate_msps} MS/s requires {expected} CI16 coefficients")
        words = []
        for i_value, q_value in coefficients:
            if not -32768 <= i_value <= 32767 or not -32768 <= q_value <= 32767:
                raise ValueError("PSS coefficient is outside signed CI16")
            words.append((i_value & 0xFFFF) | ((q_value & 0xFFFF) << 16))
        _write_attr(self.tracker, "coefficient_generation", generation)
        _write_attr(self.tracker, "coefficient_words", ",".join(f"0x{word:08x}" for word in words))
        _write_attr(self.tracker, "coefficient_commit", 1)
        if _read_int_attr(self.tracker, "active_coefficient_generation") != generation:
            raise RadioConfigurationError("PSS coefficient commit did not become active")

    def load_coefficient_file(self, path: Path, *, generation: int) -> None:
        self.load_coefficients(
            read_ci16_coefficients(path, rate_msps=self.rate_msps), generation
        )

    def open_fine(
        self,
        *,
        first_center: int,
        period_q32_32: int,
        request_base: int,
        count: int,
        queue_target: int = 7,
        refill_results: int = 16,
    ) -> None:
        if self._fine_buffer is not None:
            raise RadioConfigurationError("PSS fine stream is already open")
        if min(first_center, period_q32_32, request_base, refill_results) <= 0:
            raise ValueError("PSS fine schedule values must be positive")
        if not 0 <= count <= 0xFFFFFFFF or not 1 <= queue_target <= 7:
            raise ValueError("PSS fine schedule count or queue target is invalid")
        _disable_scan_channels(self.tracker)
        _find_scan_channel(self.tracker, PSS_RESULT_WORDS).enabled = True
        _write_attr(self.tracker, "schedule_first_center", first_center)
        _write_attr(self.tracker, "schedule_period_q32_32", period_q32_32)
        _write_attr(self.tracker, "schedule_request_base", request_base)
        _write_attr(self.tracker, "schedule_count", count)
        _write_attr(self.tracker, "schedule_queue_target", queue_target)
        actual_refill = min(refill_results, count) if count else refill_results
        self._fine_buffer = self._iio.Buffer(self.tracker, actual_refill, False)
        try:
            _write_attr(self.tracker, "schedule_enable", 1)
            self._expected_request = request_base
            self._remaining_results = count or None
        except BaseException:
            self.close_fine()
            raise

    def read_fine(self) -> tuple[PssFinePacket, ...]:
        if self._fine_buffer is None:
            raise RadioConfigurationError("PSS fine stream is not open")
        self._fine_buffer.refill()
        scans = _split_scans(bytes(self._fine_buffer.read()), PSS_PACKET_BYTES)
        packets = tuple(PssFinePacket.decode(scan, rate_msps=self.rate_msps) for scan in scans)
        active_generation = _read_int_attr(self.tracker, "active_coefficient_generation")
        for packet in packets:
            if packet.coefficient_generation != active_generation:
                raise RadioConfigurationError("PSS fine packet coefficient generation changed")
            if self._expected_request is None or packet.request_id != self._expected_request:
                raise RadioConfigurationError("PSS fine packet request sequence is discontinuous")
            self._expected_request = (self._expected_request + 1) & 0xFFFFFFFF
            if self._expected_request == 0 and (
                self._remaining_results is None or self._remaining_results > 1
            ):
                raise RadioConfigurationError("PSS fine request sequence would wrap through zero")
            if self._remaining_results is not None:
                self._remaining_results -= 1
        if _read_int_attr(self.tracker, "fault_flags"):
            raise RadioConfigurationError("PSS fine driver latched a stream fault")
        return packets

    def open_maps(self, *, refill_chunks: int = 400) -> None:
        if self._map_buffer is not None:
            raise RadioConfigurationError("PSS phase-map stream is already open")
        if refill_chunks < PSS_MAP_CHUNKS:
            raise ValueError(f"phase-map refill must hold at least {PSS_MAP_CHUNKS} chunks")
        _disable_scan_channels(self.phase_map)
        _find_scan_channel(self.phase_map, PSS_MAP_CHUNK_WORDS).enabled = True
        self._map_buffer = self._iio.Buffer(self.phase_map, refill_chunks, False)
        try:
            _write_attr(self.phase_map, "acquisition_enable", 1)
        except BaseException:
            self.close_maps()
            raise

    def read_map_chunks(self) -> tuple[PssMapChunk, ...]:
        if self._map_buffer is None:
            raise RadioConfigurationError("PSS phase-map stream is not open")
        self._map_buffer.refill()
        scans = _split_scans(bytes(self._map_buffer.read()), PSS_MAP_CHUNK_BYTES)
        chunks = tuple(PssMapChunk.decode(scan) for scan in scans)
        if _read_int_attr(self.phase_map, "fault_flags"):
            raise RadioConfigurationError("PSS phase-map driver latched a stream fault")
        return chunks

    def read_maps(self, reassembler: PssMapReassembler) -> tuple[PssPhaseMap, ...]:
        maps: list[PssPhaseMap] = []
        for chunk in self.read_map_chunks():
            completed = reassembler.add(chunk)
            if completed is not None:
                maps.append(completed)
        return tuple(maps)

    def close_fine(self) -> None:
        buffer = self._fine_buffer
        if buffer is None:
            return
        self._fine_buffer = None
        try:
            _write_attr(self.tracker, "schedule_enable", 0)
        finally:
            self._expected_request = None
            self._remaining_results = None
            _close_iio_buffer(self._iio, buffer)

    def close_maps(self) -> None:
        buffer = self._map_buffer
        if buffer is None:
            return
        self._map_buffer = None
        try:
            _write_attr(self.phase_map, "acquisition_enable", 0)
        finally:
            _close_iio_buffer(self._iio, buffer)

    def close(self) -> None:
        if self._closed:
            return
        first_error: BaseException | None = None
        for close_resource in (self.close_fine, self.close_maps):
            try:
                close_resource()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        self._closed = True
        try:
            _close_iio_context(self._iio, self.context)
        except BaseException as error:
            if first_error is None:
                first_error = error
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def reassemble_maps(chunks: Iterable[PssMapChunk]) -> tuple[PssPhaseMap, ...]:
    reassembler = PssMapReassembler()
    maps: list[PssPhaseMap] = []
    for chunk in chunks:
        completed = reassembler.add(chunk)
        if completed is not None:
            maps.append(completed)
    if reassembler._chunks:
        raise ValueError("phase-map stream ended with an incomplete map")
    return tuple(maps)
