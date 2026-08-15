"""Production radio discovery without importing native IIO libraries eagerly."""

from __future__ import annotations

from pathlib import Path

from pluto_plus.hardware.iio import IioRadioDevice, discover_usb_serials


def discover_devices(
    usb_root: Path = Path("/sys/bus/usb/devices"),
) -> tuple[IioRadioDevice, ...]:
    """Return serial-pinned USB adapters for every unambiguous runtime Pluto+."""

    return tuple(
        IioRadioDevice("usb:", serial=serial, radio_id=serial)
        for serial in discover_usb_serials(usb_root)
    )
