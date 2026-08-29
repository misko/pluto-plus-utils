from __future__ import annotations

import stat
from pathlib import Path

import pytest

from pluto_plus.catalog import Catalog
from pluto_plus.controller import RadioController
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import Transport
from pluto_plus.radio_lock import (
    RadioLockError,
    acquire_radio_lock,
    radio_lock_path,
)


class UsbFakeRadio(FakeRadioDevice):
    def __init__(self, serial: str) -> None:
        super().__init__(serial)
        self._identity = self._identity.model_copy(  # noqa: SLF001
            update={"uri": "usb:3.29.5", "transport": Transport.IIO_USB}
        )


def test_per_serial_lock_is_private_non_sensitive_and_nonblocking(tmp_path: Path) -> None:
    root = (tmp_path / "locks").absolute()

    with acquire_radio_lock("SECRET-SERIAL", root=root):
        path = radio_lock_path("SECRET-SERIAL", root=root)
        assert "SECRET-SERIAL" not in path.name
        assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        with (
            pytest.raises(RadioLockError, match="already owned"),
            acquire_radio_lock("SECRET-SERIAL", root=root),
        ):
            pytest.fail("duplicate lock unexpectedly acquired")

    with acquire_radio_lock("SECRET-SERIAL", root=root):
        pass


def test_usb_controller_holds_the_same_lock_for_capture_lifetime(tmp_path: Path) -> None:
    root = (tmp_path / "locks").absolute()
    controller = RadioController(
        UsbFakeRadio("SERIAL_A"),
        tmp_path / "captures",
        Catalog(tmp_path / "catalog.sqlite3"),
        radio_lock_root=root,
    )
    try:
        with (
            pytest.raises(RadioLockError, match="already owned"),
            acquire_radio_lock("SERIAL_A", root=root),
        ):
            pytest.fail("survey lock unexpectedly overlapped managed capture")
    finally:
        controller.close()

    with acquire_radio_lock("SERIAL_A", root=root):
        pass
