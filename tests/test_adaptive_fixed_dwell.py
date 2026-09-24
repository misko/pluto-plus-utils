"""Version-four fixed dwells remain immutable for the whole scan."""

import dataclasses

import pytest
from test_adaptive_scan_client import ScriptedSocket, setup
from test_adaptive_scan_qualification import _setup, _stream

from pluto_plus.adaptive_scan import (
    FIXED_DWELL_VERSION,
    AdaptiveScanProtocolError,
    ScanCapabilities,
    ScanSetup,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanClient, AdaptiveScanTransportError
from pluto_plus.adaptive_scan_qualification import (
    AdaptiveScanAccumulator,
    AdaptiveScanQualificationError,
)


@pytest.mark.parametrize("dwell", [120, 240, 360])
def test_v4_roundtrip_and_old_versions_stay_unchanged(dwell):
    value = dataclasses.replace(
        setup(),
        protocol_version=FIXED_DWELL_VERSION,
        dwell_ms=dwell,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_000_000,
        rx_mask=3,
    )
    assert ScanSetup.unpack(value.pack()) == value
    if dwell == 360:
        for version in (1, 2):
            with pytest.raises(AdaptiveScanProtocolError, match="20..240"):
                dataclasses.replace(value, protocol_version=version).pack()
    with pytest.raises(AdaptiveScanProtocolError):
        dataclasses.replace(value, source_rate_hz=10_000_000).pack()
    with pytest.raises(AdaptiveScanProtocolError, match="dual RX"):
        dataclasses.replace(value, rx_mask=1).pack()


def test_v4_capabilities_require_explicit_endpoint():
    caps = ScanCapabilities(
        protocol_version=FIXED_DWELL_VERSION,
        rate_mask=0x10,
        rx_mask=3,
        minimum_dwell_ms=120,
        maximum_dwell_ms=360,
    )
    sock = ScriptedSocket(b"96\n" + caps.pack())
    client = AdaptiveScanClient("radio", connector=lambda *args: sock)
    assert client.fixed_dwell_capabilities() == caps
    assert bytes(sock.sent) == b"SCANCAPS4 96\n"
    sock = ScriptedSocket(b"-38\n")
    with pytest.raises(AdaptiveScanTransportError):
        AdaptiveScanClient("radio", connector=lambda *args: sock).fixed_dwell_capabilities()


def test_v4_rejects_a_short_complete_visit():
    config = dataclasses.replace(
        _setup(2_500_000, 360, 3), protocol_version=FIXED_DWELL_VERSION
    )
    records, _ = _stream(config, visits=1, delivered=1, transition_samples=2_500)
    short_samples = 2_500_000 * 120 // 1_000
    short = dataclasses.replace(
        records[0],
        protocol_version=FIXED_DWELL_VERSION,
        valid_end=records[0].valid_start + short_samples,
        iq_bytes=short_samples * 8,
    )
    with pytest.raises(AdaptiveScanQualificationError, match="disagrees with dwell"):
        AdaptiveScanAccumulator(config).observe(short, short.iq_bytes)
