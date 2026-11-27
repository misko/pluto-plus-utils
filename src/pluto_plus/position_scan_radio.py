"""Prepare 24 immutable RX images and own one negotiated v6 session."""

from __future__ import annotations

import dataclasses
import zlib
from collections.abc import Callable, Iterator

from .adaptive_scan_client import AdaptiveScanVisit
from .adaptive_scan_radio import (
    ADAPTIVE_SCAN_KERNEL_BUFFERS,
    AdaptiveScanRadioPreparation,
    AdaptiveScanRadioRestoration,
    RadioFactory,
    _attest_identity,
    _default_factory,
    restore_adaptive_scan_radio,
)
from .continuous_scan_radio import ContinuousRadioReceipt
from .errors import RadioConfigurationError
from .models import GainMode
from .persistent_hop import require_physical_lan_uri
from .position_scan import (
    PositionClient,
    PositionControl,
    PositionSession,
    PositionSetup,
    PositionStatus,
)


def prepare_position_scan_radio(
    uri: str,
    serial: str,
    setup: PositionSetup,
    *,
    manual_gain_db: float = 40.0,
    radio_factory: RadioFactory | None = None,
) -> AdaptiveScanRadioPreparation:
    """Compile all profiles before streaming; kernel owns subsequent slot reuse."""
    setup.validate()
    selected = require_physical_lan_uri(uri)
    radio = (
        _default_factory(selected, serial, 3)
        if radio_factory is None
        else radio_factory(selected, serial)
    )
    original = None
    buffers = None
    try:
        radio.open()
        _attest_identity(radio, selected, serial)
        original = radio.read_receiver_settings_readback()
        buffers = radio.read_kernel_buffers_count()
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError("v6 preparation found active Fast Lock")
        configured = radio.configure_adaptive_scan_geometry(
            sample_rate_hz=setup.source_rate_hz,
            rf_bandwidth_hz=setup.analog_bandwidth_hz,
            manual_gain_db=manual_gain_db,
            rx_mask=setup.rx_mask,
        )
        if configured.sample_rate_hz != setup.source_rate_hz or configured.gain_modes != (
            GainMode.MANUAL,
        ) * len(configured.channels):
            raise RadioConfigurationError("v6 geometry did not read back exactly")
        configured_buffers = radio.configure_kernel_buffers(ADAPTIVE_SCAN_KERNEL_BUFFERS)
        targets = []
        words = []
        for target in setup.targets:
            radio.write_center_frequency_bufferless(target.frequency_hz)
            # Clock-framework getters round differently from the profile
            # decoder. The kernel separately enforces its tighter 2 Hz bound.
            if abs(round(radio.read_center_frequency()) - target.frequency_hz) > 4:
                raise RadioConfigurationError("v6 LO did not read back exactly")
            saved = radio.store_rx_fastlock_profile(target.profile)
            if len(saved) != 16 or radio.save_rx_fastlock_profile(target.profile) != saved:
                raise RadioConfigurationError("v6 profile save changed")
            radio.recall_rx_fastlock_profile(target.profile)
            if radio.read_active_rx_fastlock_profile() != target.profile:
                raise RadioConfigurationError("v6 calibration recall was not attested")
            image = bytes(saved)
            crc = zlib.crc32(image) & 0xFFFF_FFFF
            if not crc:
                raise RadioConfigurationError("v6 profile CRC is zero")
            targets.append(dataclasses.replace(target, profile_image=image, profile_crc32=crc))
            words.append(saved)
        radio.write_center_frequency_bufferless(setup.targets[-1].frequency_hz)
        radio.write_center_frequency_bufferless(setup.targets[0].frequency_hz)
        if radio.read_active_rx_fastlock_profile() is not None:
            raise RadioConfigurationError("v6 preparation did not exit Fast Lock")
        for target in targets[:8]:
            saved = tuple(target.profile_image)
            radio.load_rx_fastlock_profile(target.profile, saved)
            if radio.save_rx_fastlock_profile(target.profile) != saved:
                raise RadioConfigurationError("v6 initial slot reload changed")
        prepared = dataclasses.replace(setup, targets=tuple(targets))
        prepared.pack()
        return AdaptiveScanRadioPreparation(
            selected,
            serial,
            original,
            configured,
            buffers,
            configured_buffers,
            prepared,
            tuple(words),
        )
    except BaseException as failure:
        if original is not None:
            try:
                radio.restore_receiver_settings_readback(original)
                if buffers is not None:
                    radio.configure_kernel_buffers(buffers)
            except BaseException as cleanup:
                failure.add_note(f"v6 preparation restoration failed: {cleanup!r}")
        raise
    finally:
        radio.close()


class PositionRadioOwner:
    def __init__(
        self,
        client: PositionClient,
        preparation: AdaptiveScanRadioPreparation,
        session: PositionSession,
        *,
        radio_factory: RadioFactory | None = None,
    ) -> None:
        self.client = client
        self.preparation = preparation
        self.session = session
        self.radio_factory = radio_factory
        self._request = 0
        self._closed = False
        self.restoration: AdaptiveScanRadioRestoration | None = None

    def visits(self) -> Iterator[AdaptiveScanVisit]:
        yield from self.session.visits()

    def stop(self, *, forced: bool = False) -> PositionStatus:
        self._request += 1
        return self.session.request_stop(self._request, forced=forced)

    def abort_read(self) -> None:
        self.session.abort_read()

    def close(self) -> ContinuousRadioReceipt:
        if not self._closed:
            failure = None
            try:
                self.session.close()
            except BaseException as error:
                failure = error
            try:
                self.restoration = restore_adaptive_scan_radio(
                    self.preparation, radio_factory=self.radio_factory
                )
            except BaseException as cleanup:
                if failure is not None:
                    failure.add_note(f"v6 restoration failed: {cleanup!r}")
                else:
                    failure = cleanup
            self._closed = True
            if failure is not None:
                raise failure
        if self.restoration is None:
            raise RuntimeError("v6 restoration has not completed")
        return ContinuousRadioReceipt(self.preparation, self.session.terminal, self.restoration)

    @classmethod
    def start(
        cls,
        uri: str,
        serial: str,
        setup: PositionSetup,
        *,
        gain_db: float = 40.0,
        radio_factory: RadioFactory | None = None,
        client_factory: Callable[[str], PositionClient] = PositionClient,
        before_start_hook: Callable[[AdaptiveScanRadioPreparation], None] | None = None,
        samples_per_block: int = 100_000,
    ) -> PositionRadioOwner:
        selected = require_physical_lan_uri(uri)
        client = client_factory(selected.removeprefix("ip:"))
        client.capabilities()
        setup.validate()
        preparation = prepare_position_scan_radio(
            selected,
            serial,
            setup,
            manual_gain_db=gain_db,
            radio_factory=radio_factory,
        )
        try:
            if before_start_hook is not None:
                before_start_hook(preparation)
            session = client.start(preparation.setup, samples_per_block=samples_per_block)
        except BaseException as failure:
            try:
                restore_adaptive_scan_radio(preparation, radio_factory=radio_factory)
            except BaseException as cleanup:
                failure.add_note(f"v6 START restoration failed: {cleanup!r}")
            raise
        return cls(client, preparation, session, radio_factory=radio_factory)

    def status(self) -> PositionStatus:
        self._request += 1
        return self.client.control(
            self.session.device,
            PositionControl(
                self._request,
                self.session.setup.session,
                self.session.setup.generation,
            ),
        )
