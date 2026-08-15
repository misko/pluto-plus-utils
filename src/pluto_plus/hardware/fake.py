"""Deterministic fake Pluto+ for offline development and end-to-end tests."""

from __future__ import annotations

import threading
import time
from collections.abc import Mapping

import numpy as np

from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport


class FakeRadioDevice:
    def __init__(
        self,
        serial: str = "fake-001",
        *,
        settings: RadioSettings | None = None,
        realtime: bool = False,
        tone_offset_hz: float = 125_000,
        seed: int = 0,
        firmware_capable: bool = False,
    ) -> None:
        self._identity = RadioIdentity(
            radio_id=serial,
            serial=serial,
            uri=f"fake:{serial}",
            transport=Transport.FAKE,
            model="Synthetic Pluto+",
            firmware_version="fake-v1",
            usb_path=(
                f"/sys/bus/usb/devices/{serial}" if firmware_capable else None
            ),
        )
        self._capabilities = RadioCapabilities(
            supports_live_tuning=True,
            supports_volatile_firmware=firmware_capable,
            supports_persistent_firmware=firmware_capable,
            minimum_sample_rate_hz=100_000,
            maximum_sample_rate_hz=61_440_000,
        )
        self._settings = settings or RadioSettings()
        self._realtime = realtime
        self._tone_offset_hz = tone_offset_hz
        self._rng = np.random.default_rng(seed)
        self._sample_cursor = 0
        self._open = False
        self._lock = threading.Lock()
        self.apply_count = 0

    @property
    def identity(self) -> RadioIdentity:
        return self._identity

    @property
    def capabilities(self) -> RadioCapabilities:
        return self._capabilities

    def open(self) -> None:
        with self._lock:
            if self._open:
                raise RuntimeError("fake radio is already open")
            self._open = True

    def close(self) -> None:
        with self._lock:
            self._open = False

    def read_settings(self) -> RadioSettings:
        with self._lock:
            self._require_open()
            return self._settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        with self._lock:
            self._require_open()
            self._settings = settings
            self.apply_count += 1
            return self._settings

    def read_block(self, sample_count: int) -> SampleBlock:
        if sample_count <= 0:
            raise ValueError("sample_count must be positive")
        with self._lock:
            self._require_open()
            settings = self._settings
            start = self._sample_cursor
            self._sample_cursor += sample_count
        if self._realtime:
            time.sleep(sample_count / settings.sample_rate_hz)
        axis = (np.arange(sample_count, dtype=np.float64) + start) / settings.sample_rate_hz
        channels = []
        for index, _channel in enumerate(settings.channels):
            phase = index * 0.37
            tone = 8_000 * np.exp(2j * np.pi * self._tone_offset_hz * axis + 1j * phase)
            noise = self._rng.normal(0, 250, sample_count) + 1j * self._rng.normal(
                0, 250, sample_count
            )
            channels.append((tone + noise).astype(np.complex64))
        return SampleBlock(utc_ns=time.time_ns(), samples=np.stack(channels))

    def diagnostic_facts(self) -> Mapping[str, object]:
        return {
            "phy_model": None,
            "buffer_metadata": None,
            "rx_scan_channels": (),
            "uboot": None,
            "boot_provenance": None,
        }

    def _require_open(self) -> None:
        if not self._open:
            raise RuntimeError("fake radio is not open")
