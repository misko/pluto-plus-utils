"""Narrow hardware port owned by the radio controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings

DEFAULT_RESTORE_LO_SEARCH_HZ = 16


@dataclass(frozen=True, slots=True)
class SampleBlock:
    utc_ns: int
    samples: np.ndarray

    def __post_init__(self) -> None:
        if self.utc_ns <= 0:
            raise ValueError("utc_ns must be positive")
        if self.samples.ndim != 2 or not self.samples.shape[0] or not self.samples.shape[1]:
            raise ValueError("samples must have receiver and sample dimensions")
        if not np.iscomplexobj(self.samples):
            raise ValueError("samples must be complex")


@dataclass(frozen=True, slots=True)
class SettingsRestorationAttempt:
    """One bounded RX-LO request and its independent settings readback."""

    requested_center_frequency_hz: int
    readback: RadioSettings | None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SettingsRestoration:
    """Evidence that a prior hardware settings snapshot was exactly restored."""

    snapshot: RadioSettings
    restored: RadioSettings
    attempts: tuple[SettingsRestorationAttempt, ...]


class SettingsRestorationError(RadioConfigurationError):
    """A bounded exact restoration attempt failed closed."""

    def __init__(self, message: str, attempts: tuple[SettingsRestorationAttempt, ...]) -> None:
        super().__init__(message)
        self.attempts = attempts


class RadioDevice(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    @property
    def capabilities(self) -> RadioCapabilities: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_settings(self) -> RadioSettings: ...

    def apply_settings(self, settings: RadioSettings) -> RadioSettings: ...

    def read_block(self, sample_count: int) -> SampleBlock: ...


def restore_settings_exact(
    device: RadioDevice,
    snapshot: RadioSettings,
    *,
    maximum_lo_offset_hz: int = DEFAULT_RESTORE_LO_SEARCH_HZ,
) -> SettingsRestoration:
    """Restore an exact readback despite a non-idempotent AD9361 RX-LO mapping.

    AD9361/pyadi LO quantization can expose a value which cannot be reproduced by
    requesting that same value. Restoration therefore searches a tightly bounded,
    deterministic set of nearby integer requests. Every attempt independently
    reads all settings back; only the RX-LO request may vary, and success still
    requires an exact match to the complete original snapshot.
    """

    if not isinstance(maximum_lo_offset_hz, int) or isinstance(maximum_lo_offset_hz, bool):
        raise ValueError("maximum_lo_offset_hz must be a non-negative integer")
    if maximum_lo_offset_hz < 0:
        raise ValueError("maximum_lo_offset_hz must be a non-negative integer")
    if maximum_lo_offset_hz > 1024:
        raise ValueError("maximum_lo_offset_hz cannot exceed 1024 Hz")

    requested_center = round(snapshot.center_frequency_hz)
    offsets = [0]
    for delta in range(1, maximum_lo_offset_hz + 1):
        offsets.extend((delta, -delta))

    attempts: list[SettingsRestorationAttempt] = []
    for offset in offsets:
        candidate_center = requested_center + offset
        if candidate_center <= 0:
            continue
        candidate = snapshot.model_copy(update={"center_frequency_hz": float(candidate_center)})
        try:
            device.apply_settings(candidate)
            actual = device.read_settings()
        except Exception as error:
            attempt = SettingsRestorationAttempt(
                requested_center_frequency_hz=candidate_center,
                readback=None,
                error=f"{type(error).__name__}: {error}",
            )
            attempts.append(attempt)
            raise SettingsRestorationError(
                "exact settings restoration failed during apply/readback",
                tuple(attempts),
            ) from error

        attempts.append(
            SettingsRestorationAttempt(
                requested_center_frequency_hz=candidate_center,
                readback=actual,
            )
        )
        if _settings_without_center(actual) != _settings_without_center(snapshot):
            raise SettingsRestorationError(
                "exact settings restoration changed a non-LO field",
                tuple(attempts),
            )
        if actual == snapshot:
            return SettingsRestoration(
                snapshot=snapshot,
                restored=actual,
                attempts=tuple(attempts),
            )

    summary = ", ".join(
        f"{attempt.requested_center_frequency_hz}->"
        f"{None if attempt.readback is None else attempt.readback.center_frequency_hz:g}"
        for attempt in attempts
    )
    raise SettingsRestorationError(
        "exact settings restoration could not reproduce RX LO "
        f"{snapshot.center_frequency_hz:g} Hz within +/-{maximum_lo_offset_hz} Hz "
        f"({summary})",
        tuple(attempts),
    )


def _settings_without_center(settings: RadioSettings) -> tuple[object, ...]:
    return (
        settings.sample_rate_hz,
        settings.bandwidth_hz,
        settings.gain_mode,
        settings.gain_db,
        settings.channels,
    )
