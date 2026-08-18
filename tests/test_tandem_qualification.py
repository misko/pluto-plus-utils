from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

import pluto_plus.tandem_qualification as qualification
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.tandem import TandemGainTable, TandemMode, TandemSessionRequestV1


def _local(path: Path, serial: str = "SERIAL_A") -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=17,
        product="PlutoSDR+ with timestamp support",
        serial=serial,
        speed_mbps=480,
        interface_count=6,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )


def test_tandem_request_is_exact_and_capacity_bounded() -> None:
    request = TandemSessionRequestV1(mode=TandemMode.AUTO)

    assert len(request.pack(65_536)) == 104
    with pytest.raises(ValueError, match="event capacity"):
        TandemSessionRequestV1(
            mode=TandemMode.AUTO,
            event_capacity=1,
            cooldown_periods=1,
        ).pack(65_536)


def test_auto_stimulus_stays_within_normalized_dds_bounds() -> None:
    assert 0 < qualification.TONE_SCALE < qualification.AUTO_TONE_SCALE <= 1


def test_qualification_plan_is_exact_local_and_safety_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "3-11"
    target.mkdir()
    monkeypatch.setattr(
        qualification,
        "scan_local_usb_plutos",
        lambda: (_local(target),),
    )

    plan = qualification.prepare_tandem_qualification(
        "SERIAL_A",
        target,
        physical_attenuation_db=20,
        strong_tx_gain_db=-10,
        weak_tx_gain_db=-60,
    )

    assert plan.effective_attenuation_db == 30
    assert plan.expected_firmware == "v0.39-plutoplus-spf-libiio-metadata-v6-36-gab79b"
    assert plan.expected_metadata_abi == 2
    assert plan.frequencies_hz == (915_000_000, 2_450_000_000, 5_800_000_000)
    assert plan.confirmation_phrase == "QUALIFY TANDEM SERIAL_A 20DB"

    with pytest.raises(qualification.TandemQualificationError, match="unsafe loopback"):
        qualification.prepare_tandem_qualification(
            "SERIAL_A",
            target,
            physical_attenuation_db=20,
            strong_tx_gain_db=0,
            weak_tx_gain_db=-60,
        )
    with pytest.raises(qualification.TandemQualificationError, match="exactly one"):
        qualification.prepare_tandem_qualification(
            "SERIAL_B",
            target,
            physical_attenuation_db=30,
            strong_tx_gain_db=0,
            weak_tx_gain_db=-60,
        )


@pytest.mark.parametrize(
    ("frequency_hz", "expected"),
    [
        (915_000_000, TandemGainTable.MHZ_200_1300),
        (2_450_000_000, TandemGainTable.MHZ_1300_4000),
        (5_800_000_000, TandemGainTable.MHZ_4000_6000),
    ],
)
def test_three_band_matrix_selects_each_gain_table(
    frequency_hz: int, expected: TandemGainTable
) -> None:
    assert qualification._expected_gain_table(frequency_hz) is expected


def test_gain_table_mapping_rejects_unqualified_frequency() -> None:
    with pytest.raises(
        qualification.TandemQualificationError, match="outside the qualified gain tables"
    ):
        qualification._expected_gain_table(100_000_000)


def test_tone_analysis_requires_coherent_signal_on_both_receivers() -> None:
    rng = np.random.default_rng(7)
    sample_index = np.arange(16_384)
    carrier = np.exp(
        2j * np.pi * qualification.TONE_HZ * sample_index / qualification.SAMPLE_RATE_HZ
    )
    noise = rng.normal(0, 0.5, (2, sample_index.size)) + 1j * rng.normal(
        0, 0.5, (2, sample_index.size)
    )
    signal = np.vstack((256 * carrier, 220 * np.exp(0.3j) * carrier)) + noise

    diagnostics = qualification._analyze_tone(signal, 2_450_000_000)

    assert diagnostics["frequency_hz"] == 2_450_000_000
    assert diagnostics["cross_channel_coherence"] > 0.99
    assert [row["channel"] for row in diagnostics["rx_channels"]] == ["RX1", "RX2"]
    assert all(row["tone_snr_db"] > 30 for row in diagnostics["rx_channels"])

    signal[1] = 0
    with pytest.raises(qualification.TandemQualificationError, match="outside qualification"):
        qualification._analyze_tone(signal, 2_450_000_000)
