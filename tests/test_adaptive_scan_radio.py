from __future__ import annotations

import zlib

import pytest

from pluto_plus import adaptive_scan_radio
from pluto_plus.adaptive_scan import ScanSetup, ScanTarget
from pluto_plus.adaptive_scan_radio import (
    prepare_adaptive_scan_radio,
    restore_adaptive_scan_radio,
)
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import IioReceiverSettingsReadback
from pluto_plus.models import GainMode, RadioIdentity, Transport
from pluto_plus.setup_profiles import AD9361_1R1T_TARGET_PROFILE

ORIGINAL = IioReceiverSettingsReadback(
    915_000_000.0,
    2_500_000.0,
    2_500_000.0,
    (0, 1),
    (GainMode.MANUAL, GainMode.MANUAL),
    (40.0, 41.0),
)


def _setup() -> ScanSetup:
    return ScanSetup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=15_000_000,
        analog_bandwidth_hz=8_000_000,
        duration_ms=2_000,
        dwell_ms=240,
        transition_budget_ms=10,
        maximum_revisit_ms=1_000,
        feedback_age_ms=1_000,
        application_delay_ms=1_000,
        decay_ms=5_000,
        maximum_boost=3,
        maximum_queue_bytes=200_000_000,
        maximum_queue_age_ms=5_000,
        maximum_queue_visits=50,
        analysis_digest=bytes(range(1, 33)),
        targets=(
            ScanTarget(10, 2, 2_400_000_000, 1, 0),
            ScanTarget(11, 5, 2_500_000_000, 2, 0),
        ),
    )


class Radio:
    def __init__(self, uri: str, serial: str, *, bad_recall: bool = False) -> None:
        self.identity = RadioIdentity(
            radio_id=serial,
            serial=serial,
            uri=uri,
            transport=Transport.IIO_IP,
        )
        self.bad_recall = bad_recall
        self.opened = False
        self.closed = False
        self.restored = False
        self.settings = ORIGINAL
        self.frequency = round(ORIGINAL.center_frequency_hz)
        self.cached_frequency = self.frequency
        self.active = None
        self.profiles = {}
        self.profile_frequencies = {}
        self.kernel_buffers = 4

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def iio_context_attributes(self):
        return {"hw_serial": self.identity.serial, "iio,adaptive-scan": "1"}

    def read_receiver_settings_readback(self):
        return self.settings

    def restore_receiver_settings_readback(self, snapshot):
        self.settings = snapshot
        self.frequency = round(snapshot.center_frequency_hz)
        self.cached_frequency = self.frequency
        self.active = None
        self.restored = True
        return snapshot

    def configure_adaptive_scan_rx0_geometry(
        self, *, sample_rate_hz, rf_bandwidth_hz, manual_gain_db
    ):
        self.settings = IioReceiverSettingsReadback(
            float(self.frequency),
            float(sample_rate_hz),
            float(rf_bandwidth_hz),
            (0,),
            (GainMode.MANUAL,),
            (manual_gain_db,),
        )
        return self.settings

    def read_kernel_buffers_count(self):
        return self.kernel_buffers

    def configure_kernel_buffers(self, count):
        self.kernel_buffers = count
        return count

    def write_center_frequency_bufferless(self, center_frequency_hz):
        requested = round(center_frequency_hz)
        # Model clk_set_rate() suppressing a write at the cached ordinary
        # rate even when Fast Lock has changed the live synthesizer.
        if requested != self.cached_frequency:
            self.frequency = requested
            self.cached_frequency = requested
            self.active = None

    def read_center_frequency(self):
        return float(self.frequency)

    def store_rx_fastlock_profile(self, profile):
        words = tuple((self.frequency // 1_000_000 + profile + index) & 0xFF for index in range(16))
        self.profiles[profile] = words
        self.profile_frequencies[profile] = self.frequency
        return words

    def save_rx_fastlock_profile(self, profile):
        return self.profiles[profile]

    def load_rx_fastlock_profile(self, profile, values):
        self.profiles[profile] = values

    def recall_rx_fastlock_profile(self, profile):
        self.active = None if self.bad_recall else profile
        if not self.bad_recall:
            self.frequency = self.profile_frequencies[profile]
            words = self.profiles[profile]
            self.profiles[profile] = (*words[:-1], (words[-1] + 2) & 0xFF)

    def read_active_rx_fastlock_profile(self):
        return self.active


def test_prepare_binds_profiles_and_restore_is_exact() -> None:
    radios = []

    def factory(uri, serial):
        radio = Radio(uri, serial)
        radios.append(radio)
        return radio

    preparation = prepare_adaptive_scan_radio(
        "ip:192.168.1.18", "SERIAL_A", _setup(), radio_factory=factory
    )
    assert radios[0].closed and not radios[0].restored
    assert preparation.configured.channels == (0,)
    assert preparation.original_kernel_buffers == 4
    assert preparation.configured_kernel_buffers == 16
    assert [target.profile_crc32 for target in preparation.setup.targets] == [
        zlib.crc32(bytes(words)) & 0xFFFF_FFFF for words in preparation.profile_words
    ]

    restoration = restore_adaptive_scan_radio(preparation, radio_factory=factory)
    assert restoration.expected == restoration.observed == ORIGINAL
    assert restoration.expected_kernel_buffers == restoration.observed_kernel_buffers == 4
    assert restoration.fastlock_inactive
    assert radios[1].closed and radios[1].restored and radios[1].kernel_buffers == 4


def test_prepare_failure_restores_and_closes() -> None:
    radio = Radio("ip:192.168.1.18", "SERIAL_A", bad_recall=True)
    with pytest.raises(RadioConfigurationError, match="recall"):
        prepare_adaptive_scan_radio(
            "ip:192.168.1.18",
            "SERIAL_A",
            _setup(),
            radio_factory=lambda _uri, _serial: radio,
        )
    assert radio.restored and radio.closed and radio.settings == ORIGINAL


def test_production_factory_selects_exact_rx0_layout_before_open(monkeypatch) -> None:
    class Device:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs
            self.layout = None

        def configure_rx_layout(self, expectation):
            self.layout = expectation

    monkeypatch.setattr(adaptive_scan_radio, "IioRadioDevice", Device)
    radio = adaptive_scan_radio._default_factory("ip:192.168.1.15", "SERIAL_A")

    assert radio.layout == AD9361_1R1T_TARGET_PROFILE.rx_layout_expectation
    assert radio.kwargs["expected_metadata_abi"] == 3
    assert radio.kwargs["require_idle_tandem_owner"] is True
