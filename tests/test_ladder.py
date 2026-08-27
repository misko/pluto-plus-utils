from __future__ import annotations

from typing import Literal

import numpy as np
import pytest

from pluto_plus.hardware.base import SampleBlock
from pluto_plus.ladder import parse_rate_ladder, run_iio_ladder
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport


class FakeLadderRadio:
    def __init__(self, *, fail_rate: int | None = None) -> None:
        self._identity = RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Pluto+ Test",
            firmware_version="v6",
        )
        self._capabilities = RadioCapabilities(
            receiver_channels=(0, 1),
            minimum_sample_rate_hz=520_833,
            maximum_sample_rate_hz=30_720_000,
        )
        self.settings = RadioSettings()
        self.original = self.settings
        self.fail_rate = fail_rate
        self.opened = False
        self.closed = False
        self.applied: list[RadioSettings] = []
        self.kernel_buffers: int | None = None
        self._kernel_buffer_configuration_basis: Literal["setter_accepted", "readback"] = "readback"

    @property
    def identity(self) -> RadioIdentity:
        return self._identity

    @property
    def capabilities(self) -> RadioCapabilities:
        return self._capabilities

    @property
    def kernel_buffer_configuration_basis(self) -> Literal["setter_accepted", "readback"]:
        return self._kernel_buffer_configuration_basis

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def read_settings(self) -> RadioSettings:
        return self.settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        self.applied.append(settings)
        self.settings = settings
        return settings

    def configure_kernel_buffers(self, count: int) -> None:
        self.kernel_buffers = count

    def read_block(self, sample_count: int) -> SampleBlock:
        if self.fail_rate == round(self.settings.sample_rate_hz):
            raise OSError("injected refill failure")
        return SampleBlock(
            utc_ns=1,
            samples=np.ones((2, sample_count), dtype=np.complex64),
        )


class AdvancingClock:
    def __init__(self, step_ns: int = 100_000_000) -> None:
        self.value = 0
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.value += self.step_ns
        return self.value


def test_rate_ladder_parser_accepts_decimal_suffixes_and_rejects_ambiguity() -> None:
    assert parse_rate_ladder("520833,1M,1.5M,30.72M") == (
        520_833,
        1_000_000,
        1_500_000,
        30_720_000,
    )
    for invalid in ("", "1M,1M", "2M,1M", "1.5", "one"):
        with pytest.raises(ValueError):
            parse_rate_ladder(invalid)


def test_ladder_measures_paired_wire_payload_and_restores_original_settings() -> None:
    radio = FakeLadderRadio()
    report = run_iio_ladder(
        uri="ip:192.168.1.15",
        serial="SERIAL_A",
        rates_hz=(1_000_000, 2_000_000),
        samples_per_channel=16_384,
        frames=2,
        warmup_frames=1,
        radio_factory=lambda _uri, _serial: radio,
        clock_ns=AdvancingClock(),
    )

    assert radio.opened and radio.closed
    assert radio.settings == radio.original
    assert radio.applied[-1] == radio.original
    assert report.serial == "SERIAL_A"
    assert report.wire_bytes_per_sample_period == 8
    assert report.kernel_buffers == 8
    assert report.kernel_buffer_configuration_basis == "readback"
    assert radio.kernel_buffers == 8
    assert report.original_settings_restored
    assert len(report.cells) == 2
    assert report.failures == ()
    first = report.cells[0]
    assert first.wire_bytes == 2 * 16_384 * 8
    assert first.offered_payload_mbps == 8.0
    assert first.achieved_payload_mbps > 0
    assert first.transferred_mb_per_minute == pytest.approx(first.achieved_payload_mbps * 60)


def test_ladder_records_a_failed_rung_and_still_restores() -> None:
    radio = FakeLadderRadio(fail_rate=2_000_000)
    report = run_iio_ladder(
        uri="usb:",
        serial="SERIAL_A",
        rates_hz=(1_000_000, 2_000_000),
        samples_per_channel=16_384,
        frames=1,
        warmup_frames=0,
        radio_factory=lambda _uri, _serial: radio,
        clock_ns=AdvancingClock(),
    )

    assert [cell.sample_rate_hz for cell in report.cells] == [1_000_000]
    assert report.failures[0].sample_rate_hz == 2_000_000
    assert report.failures[0].error_type == "OSError"
    assert radio.settings == radio.original
    assert radio.closed


def test_ladder_rejects_out_of_range_rates_without_skipping_other_cells() -> None:
    radio = FakeLadderRadio()
    report = run_iio_ladder(
        uri="usb:",
        serial="SERIAL_A",
        rates_hz=(100_000, 1_000_000),
        samples_per_channel=16_384,
        frames=1,
        warmup_frames=0,
        radio_factory=lambda _uri, _serial: radio,
        clock_ns=AdvancingClock(),
    )

    assert [cell.sample_rate_hz for cell in report.cells] == [1_000_000]
    assert report.failures[0].sample_rate_hz == 100_000
    assert "below device minimum" in report.failures[0].message
