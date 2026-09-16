"""Exact-radio preparation and restoration for feature-request #103."""

from __future__ import annotations

import dataclasses
import zlib
from collections.abc import Callable, Mapping
from typing import Protocol

from .adaptive_scan import ScanSetup
from .errors import RadioConfigurationError
from .hardware.iio import (
    IioRadioDevice,
    IioReceiverSettingsReadback,
    _receiver_settings_restored,
)
from .models import RadioIdentity, Transport
from .persistent_hop import require_physical_lan_uri


class AdaptiveScanRadio(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def iio_context_attributes(self) -> Mapping[str, str]: ...

    def read_receiver_settings_readback(self) -> IioReceiverSettingsReadback: ...

    def restore_receiver_settings_readback(
        self, snapshot: IioReceiverSettingsReadback
    ) -> IioReceiverSettingsReadback: ...

    def configure_adaptive_scan_rx0_geometry(
        self, *, sample_rate_hz: int, rf_bandwidth_hz: int, manual_gain_db: float
    ) -> IioReceiverSettingsReadback: ...

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None: ...

    def read_center_frequency(self) -> float: ...

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]: ...

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]: ...

    def recall_rx_fastlock_profile(self, profile: int) -> None: ...

    def read_active_rx_fastlock_profile(self) -> int | None: ...


RadioFactory = Callable[[str, str], AdaptiveScanRadio]


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanRadioPreparation:
    uri: str
    serial: str
    original: IioReceiverSettingsReadback
    configured: IioReceiverSettingsReadback
    setup: ScanSetup
    profile_words: tuple[tuple[int, ...], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanRadioRestoration:
    expected: IioReceiverSettingsReadback
    observed: IioReceiverSettingsReadback
    fastlock_inactive: bool


def _default_factory(uri: str, serial: str) -> AdaptiveScanRadio:
    return IioRadioDevice(
        uri,
        serial=serial,
        radio_id=serial,
        expected_metadata_abi=3,
        require_idle_tandem_owner=True,
    )


def _attest_identity(radio: AdaptiveScanRadio, uri: str, serial: str) -> None:
    identity = radio.identity
    if (
        identity.serial != serial
        or identity.uri != uri
        or identity.transport is not Transport.IIO_IP
    ):
        raise RadioConfigurationError("adaptive scan radio identity or route changed")
    attributes = radio.iio_context_attributes()
    if attributes.get("hw_serial") != serial or attributes.get("iio,adaptive-scan") != "1":
        raise RadioConfigurationError("adaptive scan capability/serial attestation failed")


def prepare_adaptive_scan_radio(
    uri: str,
    serial: str,
    setup: ScanSetup,
    *,
    manual_gain_db: float = 40.0,
    radio_factory: RadioFactory = _default_factory,
) -> AdaptiveScanRadioPreparation:
    """Program exact RX0 geometry and volatile profiles, restoring on failure."""

    selected_uri = require_physical_lan_uri(uri)
    setup.validate()
    radio = radio_factory(selected_uri, serial)
    original: IioReceiverSettingsReadback | None = None
    failure: BaseException | None = None
    result: AdaptiveScanRadioPreparation | None = None
    try:
        radio.open()
        _attest_identity(radio, selected_uri, serial)
        original = radio.read_receiver_settings_readback()
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError("adaptive scan preparation found active Fast Lock")
        configured = radio.configure_adaptive_scan_rx0_geometry(
            sample_rate_hz=setup.source_rate_hz,
            rf_bandwidth_hz=setup.analog_bandwidth_hz,
            manual_gain_db=manual_gain_db,
        )
        words: list[tuple[int, ...]] = []
        for target in setup.targets:
            radio.write_center_frequency_bufferless(target.frequency_hz)
            if round(radio.read_center_frequency()) != target.frequency_hz:
                raise RadioConfigurationError("adaptive scan LO did not read back exactly")
            stored = radio.store_rx_fastlock_profile(target.profile)
            if radio.save_rx_fastlock_profile(target.profile) != stored:
                raise RadioConfigurationError("adaptive scan Fast Lock save changed")
            radio.recall_rx_fastlock_profile(target.profile)
            if radio.read_active_rx_fastlock_profile() != target.profile:
                raise RadioConfigurationError("adaptive scan Fast Lock recall was not attested")
            words.append(stored)

        radio.write_center_frequency_bufferless(setup.targets[0].frequency_hz)
        if (
            radio.read_active_rx_fastlock_profile() is not None
            or round(radio.read_center_frequency()) != setup.targets[0].frequency_hz
        ):
            raise RadioConfigurationError("adaptive scan preparation did not exit Fast Lock")
        final_words = tuple(
            radio.save_rx_fastlock_profile(target.profile) for target in setup.targets
        )
        if any(
            radio.save_rx_fastlock_profile(target.profile) != saved
            for target, saved in zip(setup.targets, final_words, strict=True)
        ):
            raise RadioConfigurationError("adaptive scan final Fast Lock readback changed")
        targets = tuple(
            dataclasses.replace(target, profile_crc32=zlib.crc32(bytes(saved)) & 0xFFFF_FFFF)
            for target, saved in zip(setup.targets, final_words, strict=True)
        )
        if any(not target.profile_crc32 for target in targets):
            raise RadioConfigurationError("adaptive scan Fast Lock CRC32 is zero")
        prepared = dataclasses.replace(setup, targets=targets)
        prepared.validate()
        result = AdaptiveScanRadioPreparation(
            uri=selected_uri,
            serial=serial,
            original=original,
            configured=configured,
            setup=prepared,
            profile_words=final_words,
        )
    except BaseException as error:
        failure = error
        if original is not None:
            try:
                radio.restore_receiver_settings_readback(original)
            except BaseException as cleanup:
                error.add_note(f"adaptive scan preparation restoration failed: {cleanup!r}")
    finally:
        try:
            radio.close()
        except BaseException as cleanup:
            if failure is not None:
                failure.add_note(f"adaptive scan preparation close failed: {cleanup!r}")
            else:
                raise
    if failure is not None:
        raise failure
    if result is None:
        raise RuntimeError("adaptive scan preparation produced no result")
    return result


def restore_adaptive_scan_radio(
    preparation: AdaptiveScanRadioPreparation,
    *,
    radio_factory: RadioFactory = _default_factory,
) -> AdaptiveScanRadioRestoration:
    """Restore the exact pre-session host state over the same serial/IP route."""

    radio = radio_factory(preparation.uri, preparation.serial)
    radio.open()
    try:
        _attest_identity(radio, preparation.uri, preparation.serial)
        observed = radio.restore_receiver_settings_readback(preparation.original)
        inactive = radio.read_active_rx_fastlock_profile() is None
        if not _receiver_settings_restored(preparation.original, observed) or not inactive:
            raise RadioConfigurationError("adaptive scan host restoration was not exact")
        return AdaptiveScanRadioRestoration(preparation.original, observed, inactive)
    finally:
        radio.close()
