"""Version-three durations must not reinterpret fixed-dwell recordings."""

import dataclasses

import pytest
from test_adaptive_scan_client import ScriptedSocket, setup
from test_adaptive_scan_qualification import _setup, _stream

from pluto_plus.adaptive_scan import AdaptiveScanProtocolError, ScanCapabilities, ScanSetup
from pluto_plus.adaptive_scan_client import AdaptiveScanClient, AdaptiveScanTransportError
from pluto_plus.adaptive_scan_qualification import AdaptiveScanAccumulator


@pytest.mark.parametrize("dwell", [120, 240, 360])
@pytest.mark.parametrize("rate", [2_500_000, 10_000_000])
def test_v3_roundtrip_and_old_versions_stay_fixed(dwell, rate):
    value = dataclasses.replace(
        setup(), protocol_version=3, dwell_ms=dwell, source_rate_hz=rate, rx_mask=3
    )
    assert ScanSetup.unpack(value.pack()) == value
    if dwell == 360:
        for version in (1, 2):
            with pytest.raises(AdaptiveScanProtocolError, match="20..240"):
                dataclasses.replace(value, protocol_version=version).pack()
    with pytest.raises(AdaptiveScanProtocolError):
        dataclasses.replace(value, source_rate_hz=15_000_000).pack()


def test_v3_capabilities_require_explicit_endpoint():
    caps = ScanCapabilities(
        protocol_version=3, rate_mask=0x11, rx_mask=3, minimum_dwell_ms=120, maximum_dwell_ms=360
    )
    sock = ScriptedSocket(b"96\n" + caps.pack())
    client = AdaptiveScanClient("radio", connector=lambda *args: sock)
    assert client.variable_dwell_capabilities() == caps
    assert bytes(sock.sent) == b"SCANCAPS3 96\n"
    sock = ScriptedSocket(b"-38\n")
    with pytest.raises(AdaptiveScanTransportError):
        AdaptiveScanClient("radio", connector=lambda *args: sock).variable_dwell_capabilities()


def test_mixed_duration_accounting_uses_actual_intervals():
    config = dataclasses.replace(_setup(2_500_000, 360, 3), protocol_version=3)
    records, terminal = _stream(config, visits=2, delivered=2, transition_samples=2500)
    short_samples = 2_500_000 * 120 // 1000
    first = dataclasses.replace(
        records[0],
        protocol_version=3,
        valid_end=records[0].valid_start + short_samples,
        iq_bytes=short_samples * 8,
    )
    second = dataclasses.replace(records[1], protocol_version=3)
    total_bytes = first.iq_bytes + second.iq_bytes
    terminal = dataclasses.replace(terminal, iq_bytes=total_bytes)
    acc = AdaptiveScanAccumulator(config)
    for r in (first, second):
        acc.observe(r, r.iq_bytes)
    result = acc.finish(terminal)
    assert result.planned_valid_samples == 2_500_000 * 480 // 1000
    assert result.delivered_valid_samples == result.planned_valid_samples
