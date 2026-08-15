from __future__ import annotations

from pluto_plus.hardware.discovery import discover_devices


def test_discovery_builds_serial_pinned_devices(tmp_path) -> None:
    for index, serial in enumerate(("SERIAL_B", "SERIAL_A"), start=1):
        device = tmp_path / f"1-{index}"
        device.mkdir()
        (device / "idVendor").write_text("0456\n")
        (device / "idProduct").write_text("b673\n")
        (device / "serial").write_text(serial + "\n")

    devices = discover_devices(tmp_path)

    assert [device.identity.radio_id for device in devices] == ["SERIAL_A", "SERIAL_B"]
    assert [device.identity.serial for device in devices] == ["SERIAL_A", "SERIAL_B"]
