from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from pluto_plus.inventory import (
    LocalUsbPluto,
    build_radio_inventory,
    local_ipv4_discovery_networks,
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
    udev_root: Path,
    name: str,
    *,
    serial: str,
    product: str,
    bus: int,
    device_number: int,
) -> Path:
    device = root / name
    device.mkdir(parents=True)
    minor = bus * 100 + device_number
    (device / "uevent").write_text(
        f"MAJOR=189\nMINOR={minor}\nDEVTYPE=usb_device\nPRODUCT=456/b673/515\n"
        f"BUSNUM={bus:03d}\nDEVNUM={device_number:03d}\n"
    )
    udev_root.mkdir(parents=True, exist_ok=True)
    interfaces = ":0202ff:0a0000:080650:020201:020000:"
    if "+" in product:
        interfaces += "ff0000:"
    encoded_product = product.replace(" ", "\\x20")
    properties = [
        f"E:ID_MODEL_ENC={encoded_product}",
        f"E:ID_USB_INTERFACES={interfaces}",
    ]
    if serial:
        properties.append(f"E:ID_SERIAL_SHORT={serial}")
    (udev_root / f"c189:{minor}").write_text("\n".join(properties) + "\n")
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
    udev_root = tmp_path / "udev"
    plus = _usb_device(
        usb_root,
        udev_root,
        "3-8",
        serial="SERIAL_PLUS",
        product="PlutoSDR+ with timestamp support",
        bus=3,
        device_number=11,
    )
    _attribute(plus, "speed", "480")
    _attribute(plus, "version", " 2.00")
    _attribute(plus, "bMaxPower", "500mA")
    (plus / "power").mkdir()
    _attribute(plus / "power", "runtime_status", "active")
    _attribute(plus / "power", "control", "on")
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
        udev_root,
        "5-1",
        serial="",
        product="PlutoSDR (ADALM-PLUTO)",
        bus=5,
        device_number=4,
    )
    unrelated = usb_root / "not-pluto"
    unrelated.mkdir()
    _attribute(unrelated, "uevent", "PRODUCT=1234/5678/1")

    devices = scan_local_usb_plutos(
        usb_root,
        net_root=net_root,
        tty_root=tty_root,
        block_root=block_root,
        udev_data_root=udev_root,
        ipv4_reader=lambda name: ("192.168.2.10",) if name == "enx001" else (),
        kernel_log_reader=lambda: (
            "usb 3-8: device descriptor read/64, error -71\n"
            "usb usb3-port8: attempt power cycle\n"
            "usb 3-8: USB disconnect, device number 10\n"
            "usb 3-7: unrelated error -71\n"
        ),
    )

    assert len(devices) == 2
    assert devices[0].serial == "SERIAL_PLUS"
    assert devices[0].usb_path.endswith("/3-8")
    assert devices[0].host_network_interfaces[0].name == "enx001"
    assert devices[0].host_network_interfaces[0].ipv4_addresses == ("192.168.2.10",)
    assert devices[0].terminal_devices == ("/dev/ttyACM0",)
    assert devices[0].storage_devices == ("/dev/sdb1",)
    assert devices[0].speed_mbps == 480
    assert devices[0].usb_spec_version == "2.00"
    assert devices[0].advertised_max_power_ma == 500
    assert devices[0].runtime_power_status == "active"
    assert devices[0].runtime_power_control == "on"
    assert devices[0].direct_to_root_hub is True
    assert devices[0].intermediate_hub_count == 0
    assert devices[0].link_faults is not None
    assert devices[0].link_faults.error_count == 1
    assert devices[0].link_faults.disconnect_count == 1
    assert devices[0].link_faults.port_power_cycle_count == 1
    assert devices[1].serial is None


def test_sysfs_scan_reports_intermediate_hub_and_nearest_pci_controller(
    tmp_path: Path,
) -> None:
    usb_root = tmp_path / "usb"
    usb_root.mkdir()
    udev_root = tmp_path / "udev"
    controller = tmp_path / "devices" / "pci0000:00" / "0000:00:1d.0"
    hub = controller / "usb5" / "5-2"
    physical = _usb_device(
        hub,
        udev_root,
        "5-2.4",
        serial="SERIAL_HUBBED",
        product="PlutoSDR+ with timestamp support",
        bus=5,
        device_number=9,
    )
    controller.mkdir(parents=True, exist_ok=True)
    _attribute(controller, "vendor", "0x1b21")
    _attribute(controller, "device", "0x2426")
    (usb_root / "5-2.4").symlink_to(physical, target_is_directory=True)

    (device,) = scan_local_usb_plutos(
        usb_root,
        udev_data_root=udev_root,
        kernel_log_reader=lambda: "",
    )

    assert device.direct_to_root_hub is False
    assert device.intermediate_hub_count == 1
    assert device.resolved_parent_path == str(physical)
    assert device.root_controller_pci_address == "0000:00:1d.0"
    assert device.root_controller_vendor_id == "1b21"
    assert device.root_controller_device_id == "2426"


def test_sysfs_scan_rejects_stale_zero_address_usb_device(tmp_path: Path) -> None:
    usb_root = tmp_path / "usb"
    udev_root = tmp_path / "udev"
    _usb_device(
        usb_root,
        udev_root,
        "5-1",
        serial="",
        product="PlutoSDR (ADALM-PLUTO)",
        bus=5,
        device_number=0,
    )

    assert scan_local_usb_plutos(usb_root, udev_data_root=udev_root) == ()


def test_automatic_networks_are_private_local_and_never_broader_than_24(
    tmp_path: Path,
) -> None:
    net_root = tmp_path / "net"
    for name in ("lo", "eth0", "eth1", "tailscale0", "public0", "invalid0"):
        (net_root / name).mkdir(parents=True)
    values = {
        "eth0": ("192.168.1.142", "255.255.0.0"),
        "eth1": ("192.168.2.130", "255.255.255.128"),
        "tailscale0": ("100.105.69.63", "255.255.255.255"),
        "public0": ("8.8.8.8", "255.255.255.0"),
        "invalid0": ("not-an-address", "255.255.255.0"),
    }

    networks = local_ipv4_discovery_networks(
        net_root,
        interface_reader=lambda name: values.get(name),
        exclude_interfaces=("eth1",),
    )

    assert networks == (
        "100.105.69.63/32",
        "192.168.1.0/24",
    )


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
    second = first.model_copy(update={"usb_path": "/sys/bus/usb/devices/5-2", "bus_number": 5})
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
