from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.pss_iio import (
    PSS_MAP_CHUNK_BINS,
    PSS_MAP_CHUNK_MAGIC,
    PSS_MAP_CHUNKS,
    PSS_MAP_VERSIONS,
    PSS_PACKET_HEADER,
    PSS_PACKET_MAGIC,
    PssFinePacket,
    PssIioClient,
    PssMapChunk,
    PssMapReassembler,
    reassemble_maps,
)


def _fine_packet(*, rate: int = 60, lag: int = -1, request: int = 3) -> bytes:
    center = 0x123456789A
    words = [0] * 26
    words[0] = PSS_PACKET_MAGIC
    words[1] = PSS_PACKET_HEADER
    words[2] = request
    words[3:7] = [center & 0xFFFFFFFF, center >> 32] * 2
    words[7] = lag & 0xFFFFFFFF
    winner = center + lag
    words[8:10] = [winner & 0xFFFFFFFF, winner >> 32]
    words[10] = 7
    words[11:19] = [2, 0, 3, 0, 100, 0, 200, 0]
    return struct.pack("<26I", *words)


def _map_chunk(index: int, *, generation: int = 5, start: int = 1234) -> bytes:
    metadata = (
        PSS_MAP_CHUNK_MAGIC,
        PSS_MAP_VERSIONS[60],
        generation,
        index,
        PSS_MAP_CHUNKS,
        start & 0xFFFFFFFF,
        start >> 32,
        index * PSS_MAP_CHUNK_BINS,
        PSS_MAP_CHUNK_BINS,
    )
    bins = tuple((index + offset) & 0xFFFF for offset in range(PSS_MAP_CHUNK_BINS))
    return struct.pack("<9I100H", *metadata, *bins)


def test_fine_packet_decodes_exact_timing_fields() -> None:
    packet = PssFinePacket.decode(_fine_packet(lag=-17), rate_msps=60)
    assert packet.request_id == 3
    assert packet.lag == -17
    assert packet.winner_timestamp == packet.center_timestamp - 17
    assert packet.sample_energy == 100


@pytest.mark.parametrize("offset", (0, 4, 16, 28, 32, 76))
def test_fine_packet_rejects_each_critical_envelope_mutation(offset: int) -> None:
    payload = bytearray(_fine_packet())
    payload[offset] ^= 0xFF
    with pytest.raises(ValueError):
        PssFinePacket.decode(bytes(payload), rate_msps=60)


def test_map_reassembler_produces_exact_20000_bin_map() -> None:
    chunks = [PssMapChunk.decode(_map_chunk(index)) for index in range(PSS_MAP_CHUNKS)]
    maps = reassemble_maps(chunks)
    assert len(maps) == 1
    assert maps[0].generation == 5
    assert maps[0].start_index == 1234
    assert len(maps[0].bins) == 20_000
    assert maps[0].bins[10_000] == 100


def test_map_reassembler_rejects_missing_chunk_and_recovers_at_next_zero() -> None:
    reassembler = PssMapReassembler()
    assert reassembler.add(PssMapChunk.decode(_map_chunk(0))) is None
    with pytest.raises(ValueError, match="missing"):
        reassembler.add(PssMapChunk.decode(_map_chunk(2)))
    assert reassembler.add(PssMapChunk.decode(_map_chunk(0, generation=6))) is None


class _Attr:
    def __init__(self, value: int) -> None:
        self.value = str(value)


class _Channel:
    def __init__(self, name: str, repeat: int) -> None:
        self.id = name
        self.name = name
        self.scan_element = True
        self.enabled = False
        self.data_format = SimpleNamespace(repeat=repeat)


class _Device:
    def __init__(self, name: str, attrs: dict[str, int], channels: list[_Channel]) -> None:
        self.name = name
        self.attrs = {key: _Attr(value) for key, value in attrs.items()}
        self.channels = channels


class _Context:
    def __init__(self, tracker: _Device, phase_map: _Device) -> None:
        self.devices = {tracker.name: tracker, phase_map.name: phase_map}
        self.closed = False

    def find_device(self, name: str) -> _Device | None:
        return self.devices.get(name)

    def close(self) -> None:
        self.closed = True


class _Buffer:
    payloads: dict[str, bytes] = {}

    def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
        self.device = device
        self.count = count
        self.cancelled = False

    def refill(self) -> None:
        pass

    def read(self) -> bytes:
        return self.payloads[self.device.name]

    def cancel(self) -> None:
        self.cancelled = True


def _client() -> tuple[PssIioClient, _Device, _Device]:
    tracker = _Device(
        "starlink-pss-track",
        {
            "fpga_identity": 0x50535354,
            "abi_version": 0x10003,
            "rate_msps": 60,
            "geometry": 0x0F8C1108,
            "capabilities": 0x1D,
            "fault_flags": 0,
            "active_coefficient_generation": 7,
            "schedule_first_center": 0,
            "schedule_period_q32_32": 0,
            "schedule_request_base": 0,
            "schedule_count": 0,
            "schedule_queue_target": 7,
            "schedule_enable": 0,
            "coefficient_generation": 0,
            "coefficient_words": 0,
            "coefficient_commit": 0,
        },
        [_Channel("packet_words", 26), _Channel("timestamp", 1)],
    )
    phase_map = _Device(
        "starlink-pss-map",
        {
            "fpga_identity": 0x50534D41,
            "abi_version": 0x10004,
            "input_rate_msps": 60,
            "tile_geometry": 0x00401002,
            "capabilities": 0xFF,
            "phase_bins": 20_000,
            "reassembly_chunks": 200,
            "fault_flags": 0,
            "acquisition_enable": 0,
        },
        [_Channel("chunk_metadata", 9), _Channel("phase_bins", 100)],
    )
    context = _Context(tracker, phase_map)
    return PssIioClient(context, SimpleNamespace(Buffer=_Buffer)), tracker, phase_map


def test_client_discovers_contract_and_reads_both_native_iio_streams() -> None:
    client, tracker, phase_map = _client()
    _Buffer.payloads = {
        tracker.name: _fine_packet(),
        phase_map.name: _map_chunk(0),
    }
    client.open_fine(
        first_center=1_000_000,
        period_q32_32=80_000 << 32,
        request_base=3,
        count=1,
    )
    assert client.read_fine()[0].request_id == 3
    client.open_maps()
    assert client.read_map_chunks()[0].chunk_index == 0
    client.close()
    assert tracker.attrs["schedule_enable"].value == "0"
    assert phase_map.attrs["acquisition_enable"].value == "0"


def test_client_fails_closed_on_tracker_map_rate_disagreement() -> None:
    client, _, phase_map = _client()
    client.close()
    phase_map.attrs["input_rate_msps"].value = "30"
    context = _Context(client.tracker, phase_map)
    with pytest.raises(RadioConfigurationError, match="rates disagree"):
        PssIioClient(context, SimpleNamespace(Buffer=_Buffer))
