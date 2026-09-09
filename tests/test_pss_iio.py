from __future__ import annotations

import struct
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
    PssFinePacket,
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
        self.closed = False

    def refill(self) -> None:
        pass

    def read(self) -> bytes:
        return self.payloads[self.device.name]

    def cancel(self) -> None:
        self.cancelled = True

    def close(self) -> None:
        self.closed = True


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
