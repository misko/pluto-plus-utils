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
from .setup_profiles import AD9361_1R1T_TARGET_PROFILE, AD9361_2R2T_TARGET_PROFILE

ADAPTIVE_SCAN_KERNEL_BUFFERS = 16


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

    def configure_adaptive_scan_geometry(
        self,
        *,
        sample_rate_hz: int,
        rf_bandwidth_hz: int,
        manual_gain_db: float,
        rx_mask: int,
    ) -> IioReceiverSettingsReadback: ...

    def read_kernel_buffers_count(self) -> int: ...

    def configure_kernel_buffers(self, count: int) -> int: ...

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None: ...

    def read_center_frequency(self) -> float: ...

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]: ...

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]: ...

    def load_rx_fastlock_profile(self, profile: int, values: tuple[int, ...]) -> None: ...

    def recall_rx_fastlock_profile(self, profile: int) -> None: ...

    def read_active_rx_fastlock_profile(self) -> int | None: ...


RadioFactory = Callable[[str, str], AdaptiveScanRadio]


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanRadioPreparation:
    uri: str
    serial: str
    original: IioReceiverSettingsReadback
    configured: IioReceiverSettingsReadback
    original_kernel_buffers: int
    configured_kernel_buffers: int
    setup: ScanSetup
    profile_words: tuple[tuple[int, ...], ...]


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanRadioRestoration:
    expected: IioReceiverSettingsReadback
    observed: IioReceiverSettingsReadback
    expected_kernel_buffers: int
    observed_kernel_buffers: int
    fastlock_inactive: bool


def _default_factory(uri: str, serial: str, rx_mask: int = 1) -> AdaptiveScanRadio:
    radio = IioRadioDevice(
        uri,
        serial=serial,
        radio_id=serial,
        expected_metadata_abi=3,
        require_idle_tandem_owner=True,
    )
    if rx_mask == 1:
        # A 2R2T Pluto+ may expose the second complex stream while a single-RX
        # scan deliberately selects only its first physical receiver.
        radio.configure_rx_layout(
            AD9361_1R1T_TARGET_PROFILE.rx_layout_expectation.model_copy(
                update={"allow_additional_scan_channels": True}
            )
        )
    elif rx_mask == 3:
        radio.configure_rx_layout(AD9361_2R2T_TARGET_PROFILE.rx_layout_expectation)
    else:
        raise ValueError("adaptive scan RX mask must select RX1 or RX1+RX2")
    return radio


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
    radio_factory: RadioFactory | None = None,
) -> AdaptiveScanRadioPreparation:
    """Program exact manual-gain RX geometry and volatile profiles."""

    selected_uri = require_physical_lan_uri(uri)
    setup.validate()
    radio = (
        _default_factory(selected_uri, serial, setup.rx_mask)
        if radio_factory is None
        else radio_factory(selected_uri, serial)
    )
    original: IioReceiverSettingsReadback | None = None
    original_kernel_buffers: int | None = None
    failure: BaseException | None = None
    result: AdaptiveScanRadioPreparation | None = None
    try:
        radio.open()
        _attest_identity(radio, selected_uri, serial)
        original = radio.read_receiver_settings_readback()
        original_kernel_buffers = radio.read_kernel_buffers_count()
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError("adaptive scan preparation found active Fast Lock")
        configured = radio.configure_adaptive_scan_geometry(
            sample_rate_hz=setup.source_rate_hz,
            rf_bandwidth_hz=setup.analog_bandwidth_hz,
            manual_gain_db=manual_gain_db,
            rx_mask=setup.rx_mask,
        )
        if configured.sample_rate_hz != setup.source_rate_hz:
            raise RadioConfigurationError(
                "adaptive scan rate did not read back exactly: "
                f"requested={setup.source_rate_hz} observed={configured.sample_rate_hz}"
            )
        configured_kernel_buffers = radio.configure_kernel_buffers(
            ADAPTIVE_SCAN_KERNEL_BUFFERS
        )
        words: list[tuple[int, ...]] = []
        for target in setup.targets:
            radio.write_center_frequency_bufferless(target.frequency_hz)
            observed_frequency = round(radio.read_center_frequency())
            if observed_frequency != target.frequency_hz:
                raise RadioConfigurationError(
                    "adaptive scan LO did not read back exactly: "
                    f"requested={target.frequency_hz} observed={observed_frequency}"
                )
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
        final_words = tuple(words)
        # Ordinary LO tuning for a subsequent target can overwrite the
        # currently selected hardware profile. Reload the saved immutable
        # bytes after all frequency compilation, then prove every slot.
        for target, saved in zip(setup.targets, final_words, strict=True):
            radio.load_rx_fastlock_profile(target.profile, saved)
            if radio.save_rx_fastlock_profile(target.profile) != saved:
                raise RadioConfigurationError("adaptive scan Fast Lock reload changed")
        for target in setup.targets:
            radio.recall_rx_fastlock_profile(target.profile)
            # The ordinary IIO LO getter is backed by the clock framework's
            # cached rate, which Fast Lock deliberately bypasses. RC8 validates
            # the live RFPLL registers in-kernel before accepting scan setup.
            if radio.read_active_rx_fastlock_profile() != target.profile:
                raise RadioConfigurationError("adaptive scan reloaded profile recall failed")
        # A recall may adapt the profile's ALC byte. Put the originally
        # attested bytes back after the recall test so OPENM's pre-recall CRC
        # check sees exactly the words whose CRC is carried in the setup.
        for target, saved in zip(setup.targets, final_words, strict=True):
            radio.load_rx_fastlock_profile(target.profile, saved)
            if radio.save_rx_fastlock_profile(target.profile) != saved:
                raise RadioConfigurationError("adaptive scan final Fast Lock reload changed")
        # The clock framework can suppress an ordinary write when its cached
        # rate already equals target 0, even though Fast Lock has since changed
        # the live RFPLL. Force a distinct cached-rate transition first so the
        # driver's normal set-rate path always exits Fast Lock.
        radio.write_center_frequency_bufferless(setup.targets[-1].frequency_hz)
        radio.write_center_frequency_bufferless(setup.targets[0].frequency_hz)
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError("adaptive scan reload validation did not exit Fast Lock")
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
            original_kernel_buffers=original_kernel_buffers,
            configured_kernel_buffers=configured_kernel_buffers,
            setup=prepared,
            profile_words=final_words,
        )
    except BaseException as error:
        failure = error
        if original is not None:
            try:
                radio.restore_receiver_settings_readback(original)
                if original_kernel_buffers is not None:
                    radio.configure_kernel_buffers(original_kernel_buffers)
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
    radio_factory: RadioFactory | None = None,
) -> AdaptiveScanRadioRestoration:
    """Restore the exact pre-session host state over the same serial/IP route."""

    radio = (
        _default_factory(preparation.uri, preparation.serial, preparation.setup.rx_mask)
        if radio_factory is None
        else radio_factory(preparation.uri, preparation.serial)
    )
    radio.open()
    try:
        _attest_identity(radio, preparation.uri, preparation.serial)
        observed = radio.restore_receiver_settings_readback(preparation.original)
        restored_kernel_buffers = radio.configure_kernel_buffers(
            preparation.original_kernel_buffers
        )
        inactive = radio.read_active_rx_fastlock_profile() is None
        if (
            not _receiver_settings_restored(preparation.original, observed)
            or restored_kernel_buffers != preparation.original_kernel_buffers
            or not inactive
        ):
            raise RadioConfigurationError("adaptive scan host restoration was not exact")
        return AdaptiveScanRadioRestoration(
            expected=preparation.original,
            observed=observed,
            expected_kernel_buffers=preparation.original_kernel_buffers,
            observed_kernel_buffers=restored_kernel_buffers,
            fastlock_inactive=inactive,
        )
    finally:
        radio.close()
