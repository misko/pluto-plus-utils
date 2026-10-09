"""Persistent v5 prepare/start/drain/restore ownership, separate from campaigns."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from .adaptive_scan_client import AdaptiveScanVisit
from .adaptive_scan_radio import (
    AdaptiveScanRadioPreparation,
    AdaptiveScanRadioRestoration,
    RadioFactory,
    prepare_adaptive_scan_radio,
    restore_adaptive_scan_radio,
)
from .continuous_scan import ContinuousClient, ContinuousSession, ContinuousSetup, ContinuousStatus
from .persistent_hop import require_physical_lan_uri


@dataclass(frozen=True, slots=True)
class ContinuousRadioReceipt:
    preparation: AdaptiveScanRadioPreparation
    terminal: object
    restoration: AdaptiveScanRadioRestoration


class ContinuousRadioOwner:
    """Explicit owner: STOP acknowledgment is distinct from drain and restoration.

    A consumer must drain visits after graceful STOP to obtain its terminal.
    Closing early cancels the data connection and still restores host settings;
    that path cannot claim a graceful complete stream. No campaign is restarted.
    """

    def __init__(
        self,
        client: ContinuousClient,
        preparation: AdaptiveScanRadioPreparation,
        session: ContinuousSession,
        *,
        radio_factory: RadioFactory | None = None,
    ):
        self.client = client
        self.preparation = preparation
        self.session = session
        self.radio_factory = radio_factory
        self.restoration: AdaptiveScanRadioRestoration | None = None
        self._closed = False
        self._request = 0

    @classmethod
    def start(
        cls,
        uri: str,
        serial: str,
        setup: ContinuousSetup,
        *,
        gain_db: float = 40.0,
        radio_factory: RadioFactory | None = None,
        client_factory: Callable[[str], ContinuousClient] = ContinuousClient,
        before_start_hook: Callable[[AdaptiveScanRadioPreparation], None] | None = None,
        samples_per_block: int = 100_000,
    ) -> ContinuousRadioOwner:
        selected = require_physical_lan_uri(uri)
        client = client_factory(selected.removeprefix("ip:"))
        client.capabilities()  # Fail unsupported firmware before any radio mutation.
        preparation = prepare_adaptive_scan_radio(
            selected, serial, setup, manual_gain_db=gain_db, radio_factory=radio_factory
        )
        try:
            if not isinstance(preparation.setup, ContinuousSetup):
                raise ValueError("continuous radio preparation lost its v5 setup")
            if before_start_hook is not None:
                before_start_hook(preparation)
            session = client.start(preparation.setup, samples_per_block=samples_per_block)
        except BaseException as failure:
            try:
                restore_adaptive_scan_radio(preparation, radio_factory=radio_factory)
            except BaseException as cleanup:
                failure.add_note(f"continuous START restoration failed: {cleanup!r}")
            raise
        return cls(client, preparation, session, radio_factory=radio_factory)

    def visits(self) -> Iterator[AdaptiveScanVisit]:
        yield from self.session.visits()

    def status(self) -> ContinuousStatus:
        from .continuous_scan import ContinuousControl

        self._request += 1
        return self.client.control(
            self.session.device,
            ContinuousControl(
                self._request, self.session.setup.session, self.session.setup.generation
            ),
        )

    def stop(self, *, forced: bool = False) -> ContinuousStatus:
        self._request += 1
        return self.session.request_stop(self._request, forced=forced)

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
                    failure.add_note(f"continuous host restoration failed: {cleanup!r}")
                else:
                    failure = cleanup
            self._closed = True
            if failure is not None:
                raise failure
        if self.restoration is None:
            raise RuntimeError("continuous host restoration has not completed")
        return ContinuousRadioReceipt(self.preparation, self.session.terminal, self.restoration)

    def abort_read(self) -> None:
        self.session.abort_read()
