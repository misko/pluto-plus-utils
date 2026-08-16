from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pluto_plus.inventory import (
    LocalUsbPluto,
    build_radio_inventory,
    scan_local_usb_plutos,
)
from pluto_plus.models import (
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    RadioSnapshot,
    RadioState,
    Transport,
)


def _attribute(device: Path, name: str, value: str) -> None:
    (device / name).write_text(value + "\n")


def _usb_device(
    root: Path,
    name: str,
    *,
    serial: str,
    product: str,
    bus: int,
    device_number: int,
) -> Path:
    device = root / name
    device.mkdir(parents=True)
    for key, value in {
        "idVendor": "0456",
        "idProduct": "b673",
        "serial": serial,
        "product": product,
        "busnum": str(bus),
        "devnum": str(device_number),
        "speed": "480",
        "bNumInterfaces": "7" if "+" in product else "6",
    }.items():
        _attribute(device, key, value)
    return device


def _class_device(root: Path, name: str, target: Path, *, device_link: bool) -> None:
    root.mkdir(parents=True, exist_ok=True)
    if device_link:
        entry = root / name
        entry.mkdir()
        (entry / "device").symlink_to(target, target_is_directory=True)
    else:
        (root / name).symlink_to(target, target_is_directory=True)


def _snapshot(
    serial: str,
    *,
    uri: str,
    transport: Transport,
    managed: bool,
    firmware: str,
) -> RadioSnapshot:
    return RadioSnapshot(
        identity=RadioIdentity(
            radio_id=serial,
            serial=serial,
            uri=uri,
            transport=transport,
            model="Analog Devices PlutoSDR Rev.C",
            firmware_version=firmware,
        ),
        capabilities=RadioCapabilities(),
        managed=managed,
        state=RadioState.READY if managed else RadioState.OFFLINE,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
    )


def test_sysfs_scan_correlates_network_terminal_storage_and_blank_serial(
    tmp_path: Path,
) -> None:
    usb_root = tmp_path / "usb"
    net_root = tmp_path / "net"
    tty_root = tmp_path / "tty"
    block_root = tmp_path / "block"
    plus = _usb_device(
        usb_root,
        "3-8",
        serial="SERIAL_PLUS",
        product="PlutoSDR+ with timestamp support",
        bus=3,
        device_number=11,
    )
    network_function = plus / "3-8:1.0"
    terminal_function = plus / "3-8:1.3"
    storage_partition = plus / "3-8:1.2" / "host" / "block" / "sdb" / "sdb1"
    network_function.mkdir()
    terminal_function.mkdir()
    storage_partition.mkdir(parents=True)
    (storage_partition / "partition").write_text("1\n")
    _class_device(net_root, "enx001", network_function, device_link=True)
    _class_device(tty_root, "ttyACM0", terminal_function, device_link=True)
    _class_device(block_root, "sdb1", storage_partition, device_link=False)
    _usb_device(
        usb_root,
        "5-1",
        serial="",
        product="PlutoSDR (ADALM-PLUTO)",
        bus=5,
        device_number=4,
    )
    unrelated = usb_root / "not-pluto"
    unrelated.mkdir()
    _attribute(unrelated, "idVendor", "1234")
    _attribute(unrelated, "idProduct", "5678")

    devices = scan_local_usb_plutos(
        usb_root,
        net_root=net_root,
        tty_root=tty_root,
        block_root=block_root,
        ipv4_reader=lambda name: ("192.168.2.10",) if name == "enx001" else (),
    )

    assert len(devices) == 2
    assert devices[0].serial == "SERIAL_PLUS"
    assert devices[0].usb_path.endswith("/3-8")
    assert devices[0].host_network_interfaces[0].name == "enx001"
    assert devices[0].host_network_interfaces[0].ipv4_addresses == ("192.168.2.10",)
    assert devices[0].terminal_devices == ("/dev/ttyACM0",)
    assert devices[0].storage_devices == ("/dev/sdb1",)
    assert devices[1].serial is None


def test_inventory_merges_unique_usb_and_network_identity_and_keeps_ambiguous() -> None:
    local = LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-8",
        bus_number=3,
        device_number=11,
        product="PlutoSDR+ with timestamp support",
        serial="SERIAL_PLUS",
        speed_mbps=480,
        interface_count=7,
        terminal_devices=("/dev/ttyACM0",),
    )
    blank = local.model_copy(
        update={
            "usb_path": "/sys/bus/usb/devices/5-1",
            "product": "PlutoSDR (ADALM-PLUTO)",
            "serial": None,
        }
    )
    snapshots = (
        _snapshot(
            "SERIAL_PLUS",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            managed=True,
            firmware="v5",
        ),
        _snapshot(
            "NETWORK_ONLY",
            uri="ip:192.168.1.165",
            transport=Transport.IIO_IP,
            managed=False,
            firmware="v4",
        ),
    )

    report = build_radio_inventory(
        snapshots,
        (local, blank),
        now=datetime(2026, 8, 16, tzinfo=UTC),
    )
    by_id = {record.inventory_id: record for record in report.records}
    merged = by_id["SERIAL_PLUS"]
    assert merged.classification == "confirmed_pluto_plus"
    assert merged.sources == ("usb", "daemon_managed", "network")
    assert merged.radio_ip == "192.168.1.15"
    assert merged.firmware_version == "v5"
    assert by_id["NETWORK_ONLY"].sources == ("daemon_discovered", "network")
    assert by_id["NETWORK_ONLY"].radio_ip == "192.168.1.165"
    assert by_id["usb:5-1"].classification == "pluto_class_ambiguous"
    assert "blank" in by_id["usb:5-1"].notes[0]


def test_duplicate_usb_serials_are_never_collapsed_into_daemon_identity() -> None:
    first = LocalUsbPluto(
        usb_path="/sys/bus/usb/devices/3-8",
        product="PlutoSDR+",
        serial="DUPLICATE",
        bus_number=3,
        device_number=8,
        speed_mbps=480,
        interface_count=7,
    )
    second = first.model_copy(
        update={"usb_path": "/sys/bus/usb/devices/5-2", "bus_number": 5}
    )
    report = build_radio_inventory(
        (
            _snapshot(
                "DUPLICATE",
                uri="ip:192.168.1.15",
                transport=Transport.IIO_IP,
                managed=True,
                firmware="v5",
            ),
        ),
        (first, second),
    )

    assert len(report.records) == 3
    assert len({record.inventory_id for record in report.records}) == 3
    usb_records = [record for record in report.records if record.usb_path]
    assert all("duplicate USB serial" in record.notes[0] for record in usb_records)
    assert all("daemon_managed" not in record.sources for record in usb_records)
