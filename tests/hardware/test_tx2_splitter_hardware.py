"""Opt-in RF proof of TX2 -> attenuator -> tee -> RX0/RX1 on each radio."""

from __future__ import annotations

import os
import time
from typing import Any

import numpy as np
import pytest

from pluto_plus.hardware.iio import _mute_transmit
from pluto_plus.tx2_loopback import analyze_tx2_splitter

pytestmark = pytest.mark.hardware

SAMPLE_RATE_HZ = 3_000_000
RF_BANDWIDTH_HZ = 1_500_000
TONE_HZ = 100_000
SAMPLES = 65_536
AUTHORIZED_SERIALS = {
    "1040007c4a94000211000b009186843ef2",
    "104000b29905000e17000800065934759d",
}


def _targets() -> tuple[tuple[str, float, float], ...]:
    serials = tuple(
        item.strip()
        for item in os.environ.get("PLUTO_TX2_LOOPBACK_SERIALS", "").split(",")
        if item.strip()
    )
    attenuation = os.environ.get("PLUTO_TX2_LOOPBACK_ATTENUATION_DB", "").strip()
    gain = os.environ.get("PLUTO_TX2_LOOPBACK_TX_GAIN_DB", "-50").strip()
    if not serials or not attenuation:
        pytest.skip(
            "set PLUTO_TX2_LOOPBACK_SERIALS and PLUTO_TX2_LOOPBACK_ATTENUATION_DB "
            "to opt into TX2 RF transmission"
        )
    if len(serials) != len(set(serials)) or not set(serials) <= AUTHORIZED_SERIALS:
        pytest.fail("TX2 loopback serial list is duplicate or outside the authorized pair")
    try:
        attenuation_db = float(attenuation)
        tx_gain_db = float(gain)
    except ValueError:
        pytest.fail("TX2 attenuation and gain must be numeric")
    if not 0 <= attenuation_db <= 120 or not -80 <= tx_gain_db <= -10:
        pytest.fail("TX2 attenuation/gain is outside the bounded hardware-test range")
    if attenuation_db - tx_gain_db < 30:
        pytest.fail("TX2 loopback must provide at least 30 dB effective attenuation")
    return tuple((serial, attenuation_db, tx_gain_db) for serial in serials)


def _usb_uri(serial: str) -> str:
    import iio

    matches = [
        uri
        for uri, description in iio.scan_contexts().items()
        if uri.startswith("usb:") and f"serial={serial}" in description
    ]
    if len(matches) != 1:
        pytest.fail(f"expected one USB IIO context for {serial}, got {matches}")
    return matches[0]


def _snapshot(sdr: Any) -> dict[str, Any]:
    names = (
        "rx_enabled_channels",
        "sample_rate",
        "rx_rf_bandwidth",
        "tx_rf_bandwidth",
        "rx_lo",
        "tx_lo",
        "rx_buffer_size",
        "gain_control_mode_chan0",
        "gain_control_mode_chan1",
        "rx_hardwaregain_chan0",
        "rx_hardwaregain_chan1",
    )
    return {name: getattr(sdr, name) for name in names}


def _restore(sdr: Any, snapshot: dict[str, Any]) -> None:
    sdr.rx_destroy_buffer()
    for name, value in snapshot.items():
        setattr(sdr, name, value)


def test_each_selected_radio_tx2_reaches_both_splitter_receivers() -> None:
    """Transmit only through physical TX2 and prove both tee legs independently."""

    targets = _targets()
    import adi

    for serial, attenuation_db, tx_gain_db in targets:
        sdr = adi.ad9361(uri=_usb_uri(serial))
        snapshot: dict[str, Any] | None = None
        paired_tx = False
        try:
            assert sdr._ctx.attrs.get("hw_serial") == serial
            # A 2R2T image is mandatory: chan1 is physical TX2, and both tee
            # outputs must be visible simultaneously as RX0/RX1.
            phy_tx2 = sdr._ctrl.find_channel("voltage1", True)
            phy_rx2 = sdr._ctrl.find_channel("voltage1", False)
            if (
                phy_tx2 is None
                or "hardwaregain" not in phy_tx2.attrs
                or phy_rx2 is None
                or not {"hardwaregain", "gain_control_mode"} <= set(phy_rx2.attrs)
            ):
                pytest.fail(f"{serial} does not expose the required 2R2T PHY controls")
            paired_tx = True
            assert float(sdr.tx_hardwaregain_chan0) <= -80.0
            assert float(sdr.tx_hardwaregain_chan1) <= -80.0
            snapshot = _snapshot(sdr)
            _mute_transmit(sdr)
            sdr.rx_enabled_channels = [0, 1]
            sdr.sample_rate = SAMPLE_RATE_HZ
            sdr.rx_rf_bandwidth = RF_BANDWIDTH_HZ
            sdr.tx_rf_bandwidth = RF_BANDWIDTH_HZ
            sdr.rx_buffer_size = SAMPLES
            sdr.gain_control_mode_chan0 = "manual"
            sdr.gain_control_mode_chan1 = "manual"
            sdr.rx_hardwaregain_chan0 = 30
            sdr.rx_hardwaregain_chan1 = 30
            frequency_hz = int(os.environ.get("PLUTO_TX2_LOOPBACK_LO_HZ", "915000000"))
            sdr.rx_lo = frequency_hz
            sdr.tx_lo = frequency_hz
            assert int(sdr.rx_lo) == frequency_hz and int(sdr.tx_lo) == frequency_hz

            sdr._ctrl.attrs["calib_mode"].value = "tx_quad"
            assert float(sdr.tx_hardwaregain_chan0) <= -80.0
            sdr.tx_hardwaregain_chan1 = tx_gain_db
            # Match the proven tandem qualification sequence: calibrate while
            # muted, apply the bounded TX2 attenuation with DDS still off, then
            # enable the waveform. TX1 remains at -80 dB throughout.
            sdr.dds_single_tone(TONE_HZ, 0.25, channel=1)
            time.sleep(0.25)
            signal = np.asarray(sdr.rx())[:, 1024:]
            result = analyze_tx2_splitter(
                signal,
                sample_rate_hz=SAMPLE_RATE_HZ,
                expected_tone_hz=TONE_HZ,
            )
            assert tuple(metric.channel for metric in result.receivers) == ("RX0", "RX1")
            assert attenuation_db - tx_gain_db >= 30
        finally:
            try:
                _mute_transmit(sdr)
                assert float(sdr.tx_hardwaregain_chan0) <= -80.0
                if paired_tx:
                    assert float(sdr.tx_hardwaregain_chan1) <= -80.0
            finally:
                if snapshot is not None:
                    _restore(sdr, snapshot)
                sdr.rx_destroy_buffer()
                sdr._ctx.close()
