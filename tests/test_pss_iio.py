from __future__ import annotations

import struct
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.pss_iio import (
    PSS_MAP_CAPABILITIES,
    PSS_MAP_CHUNK_BINS,
    PSS_MAP_CHUNK_MAGIC,
    PSS_MAP_CHUNK_WORDS,
    PSS_MAP_CHUNKS,
    PSS_MAP_SCAN_BYTES,
    PSS_MAP_SCAN_WORDS,
    PSS_MAP_SHARED_XFFT_CAPABILITIES,
    PSS_MAP_SHARED_XFFT_VERSION,
    PSS_MAP_VERSIONS,
    PSS_PACKET_HEADER,
    PSS_PACKET_MAGIC,
    PSS_TRACK_CAPABILITIES,
    PSS_TRACK_GEOMETRY,
    PSS_TRACK_SCAN_BYTES,
    PSS_TRACK_SCAN_WORDS,
    PSS_TRACK_VERSIONS,
    PssAcquisitionHealth,
    PssAcquisitionHealthError,
    PssFinePacket,
    PssGracefulCloseError,
    PssIioClient,
    PssMapChunk,
    PssMapReassembler,
    PssPhaseMap,
    analyze_phase_maps,
    read_ci16_coefficients,
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


def _fine_scan(**kwargs: int) -> bytes:
    payload = _fine_packet(**kwargs)
    return payload + bytes(PSS_TRACK_SCAN_BYTES - len(payload))


def _map_scan(index: int, *, generation: int = 5, start: int = 1234) -> bytes:
    payload = _map_chunk(index, generation=generation, start=start)
    return payload + bytes(PSS_MAP_SCAN_BYTES - len(payload))


def test_transport_scan_strides_are_power_of_two_envelopes() -> None:
    assert PSS_TRACK_SCAN_WORDS == 32
    assert PSS_MAP_SCAN_WORDS == 64
    assert PSS_MAP_CHUNK_WORDS == 59
    assert PSS_TRACK_SCAN_BYTES & (PSS_TRACK_SCAN_BYTES - 1) == 0
    assert PSS_MAP_SCAN_BYTES & (PSS_MAP_SCAN_BYTES - 1) == 0


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


@pytest.mark.parametrize("generation", (5, 6))
def test_map_reassembler_reports_duplicate_or_replacement_zero(generation: int) -> None:
    reassembler = PssMapReassembler()
    assert reassembler.add(PssMapChunk.decode(_map_chunk(0))) is None
    with pytest.raises(ValueError, match="incomplete generation 5"):
        reassembler.add(PssMapChunk.decode(_map_chunk(0, generation=generation)))
    # The offending restart is not admitted. Recovery requires an explicit retry.
    assert reassembler.add(PssMapChunk.decode(_map_chunk(0, generation=7))) is None


def test_whole_map_helper_does_not_hide_an_abandoned_generation() -> None:
    chunks = [PssMapChunk.decode(_map_chunk(0))] + [
        PssMapChunk.decode(_map_chunk(index, generation=6))
        for index in range(PSS_MAP_CHUNKS)
    ]
    with pytest.raises(ValueError, match="incomplete generation 5"):
        reassemble_maps(chunks)


def test_whole_map_helper_rejects_terminal_partial_generation() -> None:
    with pytest.raises(ValueError, match="ended with an incomplete map"):
        reassemble_maps([PssMapChunk.decode(_map_chunk(0))])


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
        self.attrs: dict[str, str] = {}
        self.closed = False
        self.close_count = 0
        self.timeouts: list[int] = []

    def find_device(self, name: str) -> _Device | None:
        return self.devices.get(name)

    def close(self) -> None:
        self.closed = True
        self.close_count += 1

    def set_timeout(self, milliseconds: int) -> None:
        self.timeouts.append(milliseconds)


class _Buffer:
    payloads: dict[str, bytes] = {}

    def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
        self.device = device
        self.count = count
        self.cancelled = False
        self.closed = False
        self.close_count = 0

    def refill(self) -> None:
        pass

    def read(self) -> bytes:
        return self.payloads[self.device.name]

    def cancel(self) -> None:
        self.cancelled = True

    def close(self) -> None:
        self.closed = True
        self.close_count += 1


def _client(*, rate: int = 60, shared_xfft: bool = False) -> tuple[PssIioClient, _Device, _Device]:
    tracker = _Device(
        "starlink-pss-track",
        {
            "fpga_identity": 0x50535354,
            "abi_version": PSS_TRACK_VERSIONS[rate],
            "rate_msps": rate,
            "geometry": PSS_TRACK_GEOMETRY[rate],
            "capabilities": PSS_TRACK_CAPABILITIES[rate],
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
        [_Channel("packet_words", PSS_TRACK_SCAN_WORDS)],
    )
    phase_map = _Device(
        "starlink-pss-map",
        {
            "fpga_identity": 0x50534D41,
            "abi_version": PSS_MAP_SHARED_XFFT_VERSION if shared_xfft else PSS_MAP_VERSIONS[rate],
            "input_rate_msps": rate,
            "tile_geometry": 0x00401002,
            "capabilities": (
                PSS_MAP_SHARED_XFFT_CAPABILITIES if shared_xfft else PSS_MAP_CAPABILITIES[rate]
            ),
            "phase_bins": 20_000,
            "reassembly_chunks": 200,
            "fault_flags": 0,
            "acquisition_enable": 0,
            "acquisition_flush": 0,
            "maps_delivered": 0,
        },
        [_Channel("chunk_words", PSS_MAP_SCAN_WORDS)],
    )
    context = _Context(tracker, phase_map)
    client = PssIioClient(
        context, SimpleNamespace(Buffer=_Buffer), experimental_shared_xfft=shared_xfft
    )
    return client, tracker, phase_map


def test_client_discovers_contract_and_reads_both_native_iio_streams() -> None:
    client, tracker, phase_map = _client()
    _Buffer.payloads = {
        tracker.name: _fine_scan(),
        phase_map.name: _map_scan(0),
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


def test_client_rejects_nonzero_fine_transport_padding() -> None:
    client, tracker, _ = _client()
    payload = bytearray(_fine_scan())
    payload[-1] = 1
    _Buffer.payloads = {tracker.name: bytes(payload)}
    client.open_fine(
        first_center=1_000_000,
        period_q32_32=80_000 << 32,
        request_base=3,
        count=1,
    )
    with pytest.raises(RadioConfigurationError, match="padding"):
        client.read_fine()
    client.close()


def test_client_rejects_nonzero_map_transport_padding() -> None:
    client, _, phase_map = _client()
    payload = bytearray(_map_scan(0))
    payload[-1] = 1
    _Buffer.payloads = {phase_map.name: bytes(payload)}
    client.open_maps()
    with pytest.raises(RadioConfigurationError, match="padding"):
        client.read_map_chunks()
    client.close()


def test_phase_map_analysis_matches_qualified_drift_and_source_units() -> None:
    maps = []
    for tile in range(3):
        bins = [100] * 20_000
        bins[1_200 + tile * 12] = 300
        maps.append(
            PssPhaseMap(
                abi_version=PSS_MAP_VERSIONS[60],
                generation=10 + tile,
                start_index=5_000_000 + tile * 1_280_000,
                bins=tuple(bins),
            )
        )

    estimate = analyze_phase_maps(maps, rate_msps=60)

    assert estimate.phase_bin == 1_200
    assert estimate.drift_bins_per_64_frames == 12
    assert estimate.combined_score == 900
    assert estimate.combined_median == 300.0
    assert estimate.median_absolute_deviation == 0.0
    assert estimate.peak_to_median == 3.0
    assert estimate.robust_z == float("inf")
    assert estimate.candidate_start_index_canonical == 5_001_200
    assert estimate.candidate_start_index_source_center == 20_004_800
    assert estimate.estimated_frame_period_canonical_samples == 20_000.1875
    assert estimate.estimated_frame_period_source_samples == 80_000.75
    assert maps[0].canonical_start_index == 5_000_000
    assert maps[0].source_start_index(rate_msps=60) == 20_000_000


def test_phase_map_analysis_uses_deterministic_tie_order() -> None:
    flat = tuple([100] * 20_000)
    maps = tuple(
        PssPhaseMap(PSS_MAP_VERSIONS[30], 20 + tile, tile * 1_280_000, flat) for tile in range(3)
    )

    estimate = analyze_phase_maps(maps, rate_msps=30)

    assert estimate.phase_bin == 0
    assert estimate.drift_bins_per_64_frames == -12
    assert estimate.peak_to_median == 1.0
    assert estimate.robust_z == 0.0


@pytest.mark.parametrize("mutation", ("count", "generation", "start", "abi", "drift"))
def test_phase_map_analysis_rejects_invalid_window(mutation: str) -> None:
    bins = tuple([1] * 20_000)
    maps = [
        PssPhaseMap(PSS_MAP_VERSIONS[60], 1 + tile, tile * 1_280_000, bins) for tile in range(3)
    ]
    drift = (-12, -8, -4, 0, 4, 8, 12)
    if mutation == "count":
        maps.pop()
    elif mutation == "generation":
        maps[1] = PssPhaseMap(PSS_MAP_VERSIONS[60], 4, 1_280_000, bins)
    elif mutation == "start":
        maps[1] = PssPhaseMap(PSS_MAP_VERSIONS[60], 2, 1_280_001, bins)
    elif mutation == "abi":
        maps[1] = PssPhaseMap(PSS_MAP_VERSIONS[30], 2, 1_280_000, bins)
    else:
        drift = (-12, -12)

    with pytest.raises(ValueError):
        analyze_phase_maps(maps, rate_msps=60, drift_bins=drift)


def test_client_fails_closed_on_tracker_map_rate_disagreement() -> None:
    client, _, phase_map = _client()
    client.close()
    phase_map.attrs["input_rate_msps"].value = "30"
    context = _Context(client.tracker, phase_map)
    with pytest.raises(RadioConfigurationError, match="rates disagree"):
        PssIioClient(context, SimpleNamespace(Buffer=_Buffer))


def test_coefficient_file_decodes_packed_signed_ci16(tmp_path) -> None:
    coefficient_path = tmp_path / "coefficients.mem"
    words = ["f97effc1", *("00010002" for _ in range(263))]
    coefficient_path.write_text("\n".join(words) + "\n", encoding="ascii")
    coefficients = read_ci16_coefficients(coefficient_path, rate_msps=60)
    assert coefficients[0] == (-1666, -63)
    assert coefficients[-1] == (1, 2)

    client, tracker, _ = _client()
    client.load_coefficient_file(coefficient_path, generation=7)
    staged = tracker.attrs["coefficient_words"].value.split(",")
    assert staged[0] == "0xffc1f97e"
    assert staged[-1] == "0x00020001"
    client.close()


def test_coefficient_file_rejects_bad_word_or_rate_count(tmp_path) -> None:
    coefficient_path = tmp_path / "coefficients.mem"
    coefficient_path.write_text("xyz\n", encoding="ascii")
    with pytest.raises(ValueError, match="line 1"):
        read_ci16_coefficients(coefficient_path, rate_msps=60)
    coefficient_path.write_text("00000000\n", encoding="ascii")
    with pytest.raises(ValueError, match="expected 264"):
        read_ci16_coefficients(coefficient_path, rate_msps=60)


def test_legacy_pylibiio_resources_are_destroyed_exactly_once() -> None:
    client, _, _ = _client()
    context = client.context
    context.close = None  # type: ignore[method-assign]
    context._context = object()
    destroyed_contexts: list[object] = []
    destroyed_buffers: list[object] = []

    class LegacyBuffer(_Buffer):
        close = None

        def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
            super().__init__(device, count, cyclic)
            self._buffer = object()

    module = SimpleNamespace(
        Buffer=LegacyBuffer,
        _destroy=destroyed_contexts.append,
        _buffer_destroy=destroyed_buffers.append,
    )
    client._iio = module
    client.open_fine(
        first_center=1_000_000,
        period_q32_32=80_000 << 32,
        request_base=3,
        count=1,
    )
    client.open_maps()
    client.close()
    client.close()
    assert len(destroyed_buffers) == 2
    assert len(destroyed_contexts) == 1
    assert context._context is None


def test_connect_destroys_legacy_context_when_contract_discovery_fails() -> None:
    native = object()
    destroyed: list[object] = []

    class MissingContext:
        def __init__(self, uri: str) -> None:
            self.uri = uri
            self._context = native

        def find_device(self, name: str) -> None:
            return None

    module = SimpleNamespace(Context=MissingContext, _destroy=destroyed.append)
    with pytest.raises(RadioConfigurationError, match="lacks required device"):
        PssIioClient.connect("usb:5.1.5", iio_module=module)
    assert destroyed == [native]


def test_connect_binds_expected_serial_and_closes_mismatch() -> None:
    client, tracker, phase_map = _client()
    context = client.context
    client.close()
    context.closed = False
    context.attrs = {"hw_serial": "SERIAL_A"}
    module = SimpleNamespace(Context=lambda uri: context, Buffer=_Buffer)

    connected = PssIioClient.connect("ip:192.0.2.1", expected_serial="SERIAL_A", iio_module=module)
    connected.close()
    assert context.closed

    mismatch_context = _Context(tracker, phase_map)
    mismatch_context.attrs = {"hw_serial": "SERIAL_B"}
    mismatch_module = SimpleNamespace(Context=lambda uri: mismatch_context, Buffer=_Buffer)
    with pytest.raises(RadioConfigurationError, match="serial does not match"):
        PssIioClient.connect("ip:192.0.2.1", expected_serial="SERIAL_A", iio_module=mismatch_module)
    assert mismatch_context.closed


def test_map_stream_cannot_restart_in_same_client_or_driver_epoch() -> None:
    client, _, phase_map = _client()
    client.open_maps()
    client.close_maps()
    with pytest.raises(RadioConfigurationError, match="one continuous session"):
        client.open_maps()
    client.close()

    second, _, second_map = _client()
    second_map.attrs["maps_delivered"].value = "1"
    with pytest.raises(RadioConfigurationError, match="one continuous session"):
        second.open_maps()
    second.close()


def test_legacy_buffer_is_destroyed_even_when_cancel_fails() -> None:
    client, _, _ = _client()
    destroyed_buffers: list[object] = []

    class FailingCancelBuffer(_Buffer):
        close = None

        def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
            super().__init__(device, count, cyclic)
            self._buffer = object()

        def cancel(self) -> None:
            raise RuntimeError("cancel failed")

    client._iio = SimpleNamespace(
        Buffer=FailingCancelBuffer,
        _buffer_destroy=destroyed_buffers.append,
    )
    client.open_maps()
    with pytest.raises(RuntimeError, match="cancel failed"):
        client.close_maps()
    assert len(destroyed_buffers) == 1


def _chunk_with_abi(abi: int, *, index: int = 0) -> bytes:
    payload = bytearray(_map_chunk(index))
    struct.pack_into("<I", payload, 4, abi)
    return bytes(payload)


@pytest.mark.parametrize("rate", (15, 30, 60))
def test_legacy_contract_defaults_remain_exact(rate: int) -> None:
    client, _, _ = _client(rate=rate)
    assert client.map_abi_version == PSS_MAP_VERSIONS[rate]
    assert not client.experimental_shared_xfft
    client.close()


def test_shared_map_decode_requires_opt_in_and_reassembles_unchanged_geometry() -> None:
    payload = _chunk_with_abi(PSS_MAP_SHARED_XFFT_VERSION)
    with pytest.raises(ValueError, match="ABI is unsupported"):
        PssMapChunk.decode(payload)
    chunks = [
        PssMapChunk.decode(
            _chunk_with_abi(PSS_MAP_SHARED_XFFT_VERSION, index=index),
            allow_experimental_shared_xfft=True,
        )
        for index in range(PSS_MAP_CHUNKS)
    ]
    maps = reassemble_maps(chunks)
    assert len(maps) == 1 and maps[0].abi_version == PSS_MAP_SHARED_XFFT_VERSION
    assert maps[0].bins == reassemble_maps(
        PssMapChunk.decode(_map_chunk(index)) for index in range(PSS_MAP_CHUNKS)
    )[0].bins
    with pytest.raises(ValueError, match="ABI is unsupported"):
        PssMapChunk.decode(_chunk_with_abi(0x10006), allow_experimental_shared_xfft=True)


def test_shared_contract_is_exact_and_not_admitted_by_default() -> None:
    client, _, phase_map = _client(rate=15, shared_xfft=True)
    assert client.map_abi_version == PSS_MAP_SHARED_XFFT_VERSION
    with pytest.raises(RadioConfigurationError, match="abi_version"):
        PssIioClient(client.context, client._iio)
    phase_map.attrs["capabilities"].value = str(PSS_MAP_CAPABILITIES[15])
    with pytest.raises(RadioConfigurationError, match="capabilities"):
        PssIioClient(client.context, client._iio, experimental_shared_xfft=True)
    phase_map.attrs["capabilities"].value = str(PSS_MAP_SHARED_XFFT_CAPABILITIES)
    phase_map.attrs["fault_flags"].value = "64"
    with pytest.raises(RadioConfigurationError, match="latched fault"):
        PssIioClient(client.context, client._iio, experimental_shared_xfft=True)
    client.close()


@pytest.mark.parametrize("rate", (30, 60))
def test_shared_contract_rejects_unqualified_source_rates(rate: int) -> None:
    with pytest.raises(RadioConfigurationError, match="only supports 15"):
        _client(rate=rate, shared_xfft=True)


@pytest.mark.parametrize("shared,wrong_abi", ((True, 0x10001), (True, 0x10004), (False, 0x10002)))
def test_map_stream_is_bound_to_attested_context(shared: bool, wrong_abi: int) -> None:
    client, _, _ = _client(rate=15, shared_xfft=shared)
    payload = _chunk_with_abi(wrong_abi)
    _Buffer.payloads["starlink-pss-map"] = payload + bytes(PSS_MAP_SCAN_BYTES - len(payload))
    client.open_maps()
    with pytest.raises(RadioConfigurationError, match="differs from its attested context"):
        client.read_map_chunks()
    client.close()


def test_shared_stream_returns_only_exact_abi_and_preserves_fault_gate() -> None:
    client, _, phase_map = _client(rate=15, shared_xfft=True)
    payload = _chunk_with_abi(PSS_MAP_SHARED_XFFT_VERSION)
    _Buffer.payloads["starlink-pss-map"] = payload + bytes(PSS_MAP_SCAN_BYTES - len(payload))
    client.open_maps()
    assert client.read_map_chunks()[0].abi_version == PSS_MAP_SHARED_XFFT_VERSION
    phase_map.attrs["fault_flags"].value = "64"
    with pytest.raises(RadioConfigurationError, match="latched a stream fault"):
        client.read_map_chunks()
    client.close()


@pytest.mark.parametrize("serial", (None, "", " "))
def test_shared_connect_requires_serial_before_opening_context(serial: str | None) -> None:
    with pytest.raises(ValueError, match="exact expected serial"):
        PssIioClient.connect(
            "ip:192.0.2.1", expected_serial=serial,
            experimental_shared_xfft=True, iio_module=SimpleNamespace(),
        )


def test_shared_connect_attests_serial_and_closes_failed_contract() -> None:
    client, _, phase_map = _client(rate=15, shared_xfft=True)
    context = client.context
    context.attrs = {"hw_serial": "CANARY"}
    module = SimpleNamespace(Context=lambda uri: context, Buffer=_Buffer)
    connected = PssIioClient.connect(
        "ip:192.0.2.1", expected_serial="CANARY", experimental_shared_xfft=True,
        iio_module=module,
    )
    assert connected.map_abi_version == PSS_MAP_SHARED_XFFT_VERSION
    connected.close()
    context.closed = False
    phase_map.attrs["tile_geometry"].value = "0"
    with pytest.raises(RadioConfigurationError, match="tile_geometry"):
        PssIioClient.connect(
            "ip:192.0.2.1", expected_serial="CANARY", experimental_shared_xfft=True,
            iio_module=module,
        )
    assert context.closed


def test_shared_map_analysis_retains_the_same_numerical_algorithm_and_units() -> None:
    bins = [100] * 20_000
    bins[1234] = 1000
    shared = tuple(
        PssPhaseMap(PSS_MAP_SHARED_XFFT_VERSION, 10 + tile, tile * 1_280_000, tuple(bins))
        for tile in range(3)
    )
    legacy = tuple(replace(item, abi_version=PSS_MAP_VERSIONS[15]) for item in shared)
    estimate = analyze_phase_maps(shared, rate_msps=15, experimental_shared_xfft=True)
    assert estimate == analyze_phase_maps(legacy, rate_msps=15)
    assert estimate.candidate_start_index_source_center == 1234
    with pytest.raises(ValueError, match="ABI does not match"):
        analyze_phase_maps(shared, rate_msps=15)
    with pytest.raises(ValueError, match="ABI does not match"):
        analyze_phase_maps(legacy, rate_msps=15, experimental_shared_xfft=True)
    with pytest.raises(ValueError, match="only supports 15"):
        analyze_phase_maps(shared, rate_msps=60, experimental_shared_xfft=True)


def _health_line(*, abi: int = 0x10004, generation: int = 8,
                 changes: dict[int, int] | None = None) -> str:
    rate, mode = {
        0x10001: (15, 0), 0x10002: (30, 1), 0x10003: (60, 1),
        0x10004: (60, 2), 0x10005: (15, 0),
    }[abi]
    words = [0] * 46
    words[:5] = [abi, rate, generation, 0x101, 0x101]
    words[34] = mode
    for index, value in (changes or {}).items():
        words[index] = value
    return "PSMH 1 46 " + " ".join(f"{word:08x}" for word in words) + "\n"


class _HealthAttr:
    def __init__(self, *lines: str) -> None:
        self.lines = iter(lines)

    @property
    def value(self) -> str:
        return next(self.lines)


def _install_health(phase_map: _Device, *lines: str) -> None:
    phase_map.attrs["acquisition_health"] = _HealthAttr(*lines)  # type: ignore[assignment]


@pytest.mark.parametrize("abi", (0x10001, 0x10002, 0x10003, 0x10004, 0x10005))
def test_health_golden_abi_contracts_preserve_raw_and_distinct_telemetry(abi: int) -> None:
    raw = _health_line(abi=abi)
    receipt = PssAcquisitionHealth.decode(raw)
    receipt.require_fault_free()
    assert receipt.raw == raw and len(receipt.words) == 46
    assert receipt.abi_version == abi and receipt.generation == 8
    assert receipt.declared_rate_msps == (15 if abi in (0x10001, 0x10005)
                                        else 30 if abi == 0x10002 else 60)
    expected = None if abi in (0x10001, 0x10005) else 0
    assert receipt.ddc_accepted_observation == receipt.ddc_emitted_observation == expected
    assert not receipt.acquisition_enabled


@pytest.mark.parametrize("mutation", (
    lambda raw: raw.replace("PSMH", "PIL1"),
    lambda raw: raw.replace("PSMH 1", "PSMH 2"),
    lambda raw: raw.replace("1 46", "1 45"),
    lambda raw: raw.replace("00010004", "0001000A"),
    lambda raw: raw.replace("00010004", "0010004"),
    lambda raw: raw + "00000000",
    lambda raw: raw[:-10],
    lambda raw: raw + "\N{SNOWMAN}",
    lambda raw: raw + " " * 2048,
))
def test_health_rejects_malformed_wire(mutation) -> None:
    with pytest.raises(ValueError):
        PssAcquisitionHealth.decode(mutation(_health_line()))


@pytest.mark.parametrize("changes", (
    {0: 0x10006}, {1: 15}, {2: 0}, {3: 0x200}, {4: 0x200},
    {5: 8}, {6: 128}, {10: 4}, {24: 0x4000}, {34: 1},
    {45: 0x04000000}, {45: 0x00000400}, {44: 2 << 16 | 3},
    {45: 2 << 16 | 3}, {10: 1}, {10: 2}, {10: 3, 11: 1, 12: 1},
))
def test_health_rejects_reserved_and_inconsistent_fields(changes: dict[int, int]) -> None:
    with pytest.raises(ValueError):
        PssAcquisitionHealth.decode(_health_line(changes=changes))


def test_health_ddc_modes_never_manufacture_atomic_or_missing_high_words() -> None:
    with pytest.raises(ValueError, match="unavailable nonzero"):
        PssAcquisitionHealth.decode(_health_line(abi=0x10005, changes={35: 1}))
    for high in (36, 38):
        with pytest.raises(ValueError, match="unavailable nonzero"):
            PssAcquisitionHealth.decode(_health_line(abi=0x10002, changes={high: 1}))
    # Live low32 reads may straddle a wrap; they are not comparable 64-bit totals.
    low = PssAcquisitionHealth.decode(_health_line(abi=0x10002, changes={35: 1, 37: 100}))
    assert low.ddc_telemetry_mode == 1 and low.ddc_accepted_observation == 1
    assert low.ddc_emitted_observation == 100
    full = PssAcquisitionHealth.decode(_health_line(changes={35: 2, 36: 3, 37: 4, 38: 5}))
    assert full.ddc_telemetry_mode == 2
    assert full.ddc_accepted_observation == (3 << 32) + 2
    assert full.ddc_emitted_observation == (5 << 32) + 4


@pytest.mark.parametrize("index", (6, 9, *range(17, 31), 31, 32, 33, 39, 40))
def test_health_preserves_every_fault_for_diagnostics_but_refuses_qualification(index: int) -> None:
    receipt = PssAcquisitionHealth.decode(_health_line(changes={index: 1}))
    assert receipt.words[index] == 1
    with pytest.raises(ValueError, match="fault"):
        receipt.require_fault_free()


@pytest.mark.parametrize("changes", ({3: 0}, {4: 0}, {24: 1 << 13}))
def test_health_requires_live_epoch_and_rejects_upstream_clipping(changes: dict[int, int]) -> None:
    with pytest.raises(ValueError):
        PssAcquisitionHealth.decode(_health_line(changes=changes)).require_fault_free()


def test_health_shared_fault_and_nonfatal_denominator_are_not_conflated() -> None:
    noisy = PssAcquisitionHealth.decode(_health_line(changes={24: 1 << 11, 43: 123}))
    noisy.require_fault_free()
    with pytest.raises(ValueError, match="fault"):
        PssAcquisitionHealth.decode(
            _health_line(abi=0x10005, changes={24: 1 << 14})
        ).require_fault_free()


@pytest.mark.parametrize("abi,mask", ((0x10001, 0x17ff), (0x10002, 0x37ff),
                                    (0x10003, 0x37ff), (0x10004, 0x37ff),
                                    (0x10005, 0x57ff)))
def test_health_every_defined_fatal_bit_is_gated(abi: int, mask: int) -> None:
    for bit in range(15):
        if mask & (1 << bit):
            with pytest.raises(ValueError, match="fault"):
                PssAcquisitionHealth.decode(
                    _health_line(abi=abi, changes={24: 1 << bit})
                ).require_fault_free()


def test_health_helper_binds_fresh_receipts_and_retains_late_fault_evidence() -> None:
    client, _, phase_map = _client()
    fault = _health_line(generation=9, changes={24: 1 << 13})
    _install_health(phase_map, _health_line(), fault, _health_line(generation=9),
                    _health_line(generation=10, changes={6: 1}))
    assert client.read_acquisition_health(timeout_ms=37).generation == 8
    assert client.context.timeouts == [37]
    with pytest.raises(PssAcquisitionHealthError, match="hardware fault") as caught:
        client.read_acquisition_health()
    assert caught.value.raw == fault and caught.value.receipt.words[24] == 1 << 13
    with pytest.raises(PssAcquisitionHealthError, match="stale or reset"):
        client.read_acquisition_health()
    diagnostic = client.read_acquisition_health(require_fault_free=False)
    assert diagnostic.words[6] == 1
    client.close()


def test_health_helper_refuses_missing_or_mismatched_evidence_without_legacy_fallback() -> None:
    client, _, phase_map = _client()
    assert phase_map.attrs["fault_flags"].value == "0"
    with pytest.raises(PssAcquisitionHealthError, match="unavailable") as caught:
        client.read_acquisition_health()
    assert caught.value.raw is None and caught.value.receipt is None
    _install_health(phase_map, _health_line(abi=0x10003), "broken")
    with pytest.raises(PssAcquisitionHealthError, match="admitted context"):
        client.read_acquisition_health()
    with pytest.raises(PssAcquisitionHealthError) as caught:
        client.read_acquisition_health()
    assert caught.value.raw == "broken" and caught.value.receipt is None
    client.close()


@pytest.mark.parametrize("timeout", (0, -1, 60001, True, 1.5))
def test_health_helper_requires_bounded_context_timeout(timeout) -> None:
    client, _, _ = _client()
    with pytest.raises(ValueError, match="timeout"):
        client.read_acquisition_health(timeout_ms=timeout)
    assert client.context.timeouts == []
    client.close()


@pytest.mark.parametrize("legacy", (False, True))
def test_graceful_close_destroys_both_streams_once_without_native_cancel(legacy: bool) -> None:
    client, tracker, phase_map = _client()
    destroyed: list[object] = []
    if legacy:
        class LegacyBuffer(_Buffer):
            close = None

            def __init__(self, device: _Device, count: int, cyclic: bool) -> None:
                super().__init__(device, count, cyclic)
                self._buffer = object()

        client.context.close = None
        client.context._context = object()
        client._iio = SimpleNamespace(Buffer=LegacyBuffer, _buffer_destroy=destroyed.append,
                                      _destroy=destroyed.append)
    client.open_maps()
    client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                     request_base=3, count=1)
    _Buffer.payloads[tracker.name] = _fine_scan()
    client.read_fine()
    buffers = [client._fine_buffer, client._map_buffer]
    _install_health(phase_map, _health_line(changes={5: 7, 3: 3, 4: 3}),
                    _health_line(generation=9))
    receipt = client.close_gracefully(readers_joined=True)
    assert not receipt.errors and not receipt.native_cancel_used
    assert receipt.reader_join_asserted and receipt.health_after.generation == 9
    assert receipt.health_before_raw == receipt.health_before.raw
    assert receipt.health_after_raw == receipt.health_after.raw
    assert tracker.attrs["schedule_enable"].value == "0"
    assert phase_map.attrs["acquisition_enable"].value == "0"
    assert all(not buffer.cancelled for buffer in buffers)
    assert client.close_gracefully(readers_joined=True) is receipt
    client.close()
    if legacy:
        assert len(destroyed) == 3 and client.context._context is None
        assert all(buffer._buffer is None for buffer in buffers)
    else:
        assert all(buffer.close_count == 1 for buffer in buffers)
        assert client.context.close_count == 1


@pytest.mark.parametrize("failure", ("missing_health", "malformed_health", "late_fault",
                                     "incomplete_fine", "active_map", "tracker_fault",
                                     "disable", "destroy", "context_close"))
def test_graceful_close_preserves_failed_evidence_and_still_tears_down(failure: str) -> None:
    client, tracker, phase_map = _client()
    client.open_maps()
    buffer = client._map_buffer
    if failure == "incomplete_fine":
        client.open_fine(first_center=1_000_000, period_q32_32=80_000 << 32,
                         request_base=3, count=1)
    fine = client._fine_buffer
    late_changes = {24: 1 << 13} if failure == "late_fault" else (
        {5: 1} if failure == "active_map" else {}
    )
    if failure != "missing_health":
        _install_health(phase_map, _health_line(),
                        "broken" if failure == "malformed_health" else
                        _health_line(generation=9, changes=late_changes))
    if failure == "tracker_fault":
        tracker.attrs["fault_flags"].value = "1"
    if failure == "disable":
        phase_map.attrs["acquisition_enable"] = _HealthAttr("1")
    if failure == "destroy":
        def failing_close() -> None:
            buffer.close_count += 1
            raise OSError("destroy failed")
        buffer.close = failing_close
    if failure == "context_close":
        def failing_context_close() -> None:
            client.context.close_count += 1
            raise OSError("context close failed")
        client.context.close = failing_context_close
    with pytest.raises(PssGracefulCloseError) as caught:
        client.close_gracefully(readers_joined=True)
    receipt = caught.value.receipt
    assert receipt.errors and not receipt.native_cancel_used
    if failure == "late_fault":
        assert receipt.health_after.words[24] == 1 << 13
        assert receipt.health_after_raw == receipt.health_after.raw
    if failure == "malformed_health":
        assert receipt.health_after is None and receipt.health_after_raw == "broken"
    if failure == "incomplete_fine":
        assert any("incomplete" in error for error in receipt.errors)
        assert fine.close_count == 1 and not fine.cancelled
    assert buffer.close_count == 1 and not buffer.cancelled
    assert client.context.close_count == 1
    assert client._fine_buffer is None and client._map_buffer is None
    with pytest.raises(PssGracefulCloseError) as second:
        client.close_gracefully(readers_joined=True)
    assert second.value.receipt is receipt and buffer.close_count == 1


def test_graceful_close_refuses_inflight_read_then_allows_joined_reader_teardown() -> None:
    client, _, phase_map = _client()
    client.open_maps()
    buffer = client._map_buffer
    entered, release = threading.Event(), threading.Event()
    result: list[object] = []

    def blocked_refill() -> None:
        entered.set()
        assert release.wait(2)

    def reader() -> None:
        try:
            result.append(client.read_map_chunks())
        except BaseException as error:
            result.append(error)

    buffer.refill = blocked_refill
    _Buffer.payloads[phase_map.name] = _map_scan(0)
    worker = threading.Thread(target=reader)
    worker.start()
    try:
        assert entered.wait(2)
        with pytest.raises(RadioConfigurationError, match="in-flight"):
            client.close_gracefully(readers_joined=True)
        assert not buffer.closed and not buffer.cancelled
    finally:
        release.set()
        worker.join(2)
    assert not worker.is_alive() and not isinstance(result[0], BaseException)
    _install_health(phase_map, _health_line(), _health_line(generation=9))
    client.close_gracefully(readers_joined=True)
    assert buffer.close_count == 1 and not buffer.cancelled


def test_graceful_close_requires_join_assertion_and_timeout_before_touching_resources() -> None:
    client, _, phase_map = _client()
    client.open_maps()
    buffer = client._map_buffer
    for value in (False, 1):
        with pytest.raises(ValueError, match="join"):
            client.close_gracefully(readers_joined=value)
    setter = client.context.set_timeout
    client.context.set_timeout = None
    with pytest.raises(RadioConfigurationError, match="bounded"):
        client.close_gracefully(readers_joined=True)
    assert not buffer.closed and not buffer.cancelled
    assert not client._graceful_closing
    client.context.set_timeout = setter
    _install_health(phase_map, _health_line(), _health_line(generation=9))
    client.close_gracefully(readers_joined=True)


def test_graceful_close_blocks_new_public_operations_and_legacy_close_is_not_a_receipt() -> None:
    client, _, phase_map = _client()
    client.open_maps()
    buffer = client._map_buffer
    original_close = buffer.close

    def checked_close() -> None:
        with pytest.raises(RadioConfigurationError, match="closing gracefully"):
            client.read_map_chunks()
        with pytest.raises(RadioConfigurationError, match="closing gracefully"):
            client.close()
        original_close()

    buffer.close = checked_close
    _install_health(phase_map, _health_line(), _health_line(generation=9))
    client.close_gracefully(readers_joined=True)
    legacy, _, _ = _client()
    legacy.close()
    with pytest.raises(RadioConfigurationError, match="without a graceful receipt"):
        legacy.close_gracefully(readers_joined=True)
