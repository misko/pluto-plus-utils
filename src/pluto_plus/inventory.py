"""Read-only correlation of daemon radios with Linux USB device topology."""

from __future__ import annotations

import fcntl
import socket
import struct
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from pluto_plus.models import ApiModel, RadioSnapshot, Transport

PLUTO_USB_VENDOR = "0456"
PLUTO_RUNTIME_PRODUCT = "b673"
_SIOCGIFADDR = 0x8915


class HostNetworkInterface(ApiModel):
    name: str = Field(min_length=1)
    ipv4_addresses: tuple[str, ...] = ()


class LocalUsbPluto(ApiModel):
    usb_path: str
    bus_number: int | None
    device_number: int | None
    product: str
    serial: str | None
    speed_mbps: int | None
    interface_count: int | None
    host_network_interfaces: tuple[HostNetworkInterface, ...] = ()
    terminal_devices: tuple[str, ...] = ()
    storage_devices: tuple[str, ...] = ()

    @property
    def confirmed_plus(self) -> bool:
        return "plutosdr+" in self.product.lower()


class RadioInventoryRecord(ApiModel):
    inventory_id: str
    serial: str | None
    classification: Literal[
        "confirmed_pluto_plus",
        "daemon_attested_pluto",
        "pluto_class_ambiguous",
        "simulated",
    ]
    sources: tuple[str, ...]
    managed: bool
    state: str
    model: str
    firmware_version: str | None
    transport: str | None
    iio_uri: str | None
    radio_ip: str | None
    usb_path: str | None
    usb_bus_device: str | None
    usb_speed_mbps: int | None
    usb_interface_count: int | None
    host_network_interfaces: tuple[HostNetworkInterface, ...] = ()
    terminal_devices: tuple[str, ...] = ()
    storage_devices: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


class RadioInventoryReport(ApiModel):
    generated_at: datetime
    records: tuple[RadioInventoryRecord, ...]


def scan_local_usb_plutos(
    usb_root: Path = Path("/sys/bus/usb/devices"),
    *,
    net_root: Path = Path("/sys/class/net"),
    tty_root: Path = Path("/sys/class/tty"),
    block_root: Path = Path("/sys/class/block"),
    ipv4_reader: Callable[[str], tuple[str, ...]] | None = None,
) -> tuple[LocalUsbPluto, ...]:
    """Inventory every runtime Pluto USB function without opening the radio."""

    if not usb_root.is_dir():
        return ()
    address_reader = ipv4_reader or _interface_ipv4_addresses
    devices: list[LocalUsbPluto] = []
    for candidate in sorted(usb_root.iterdir(), key=lambda item: item.name):
        if _read(candidate / "idVendor").lower() != PLUTO_USB_VENDOR:
            continue
        if _read(candidate / "idProduct").lower() != PLUTO_RUNTIME_PRODUCT:
            continue
        resolved = candidate.resolve()
        network_names = _class_devices_below(net_root, resolved, device_link=True)
        terminals = tuple(
            f"/dev/{name}"
            for name in _class_devices_below(tty_root, resolved, device_link=True)
            if name.startswith("ttyACM")
        )
        block_names = _class_devices_below(block_root, resolved, device_link=False)
        partitions = tuple(
            name for name in block_names if (block_root / name / "partition").exists()
        )
        storage_names = partitions or tuple(
            name for name in block_names if not (block_root / name / "partition").exists()
        )
        interfaces = tuple(
            HostNetworkInterface(name=name, ipv4_addresses=address_reader(name))
            for name in network_names
        )
        raw_serial = _read(candidate / "serial")
        devices.append(
            LocalUsbPluto(
                usb_path=str(candidate),
                bus_number=_integer(candidate / "busnum"),
                device_number=_integer(candidate / "devnum"),
                product=_read(candidate / "product") or "ADI Pluto runtime device",
                serial=raw_serial or None,
                speed_mbps=_numeric_integer(candidate / "speed"),
                interface_count=_integer(candidate / "bNumInterfaces"),
                host_network_interfaces=interfaces,
                terminal_devices=terminals,
                storage_devices=tuple(f"/dev/{name}" for name in storage_names),
            )
        )
    return tuple(devices)


def build_radio_inventory(
    snapshots: Iterable[RadioSnapshot],
    local_devices: Iterable[LocalUsbPluto],
    *,
    now: datetime | None = None,
) -> RadioInventoryReport:
    """Merge only unambiguous serial matches; retain every ambiguous device."""

    radio_snapshots = tuple(snapshots)
    local = tuple(local_devices)
    snapshots_by_serial = {item.identity.serial: item for item in radio_snapshots}
    local_serial_counts: dict[str, int] = {}
    for device in local:
        if device.serial:
            local_serial_counts[device.serial] = local_serial_counts.get(device.serial, 0) + 1

    consumed_serials: set[str] = set()
    records: list[RadioInventoryRecord] = []
    for device in local:
        snapshot = (
            snapshots_by_serial.get(device.serial)
            if device.serial and local_serial_counts[device.serial] == 1
            else None
        )
        if snapshot is not None and device.serial is not None:
            consumed_serials.add(device.serial)
        records.append(_record(device=device, snapshot=snapshot, duplicate_serial=(
            device.serial is not None and local_serial_counts[device.serial] > 1
        )))
    for snapshot in radio_snapshots:
        if snapshot.identity.serial not in consumed_serials:
            records.append(_record(device=None, snapshot=snapshot, duplicate_serial=False))
    records.sort(key=_record_sort_key)
    generated = now or datetime.now(UTC)
    if generated.tzinfo is None:
        raise ValueError("inventory timestamp must be timezone-aware")
    return RadioInventoryReport(
        generated_at=generated.astimezone(UTC),
        records=tuple(records),
    )


def _record(
    *,
    device: LocalUsbPluto | None,
    snapshot: RadioSnapshot | None,
    duplicate_serial: bool,
) -> RadioInventoryRecord:
    identity = None if snapshot is None else snapshot.identity
    serial = device.serial if device is not None else identity.serial if identity else None
    sources: list[str] = []
    if device is not None:
        sources.append("usb")
    if snapshot is not None:
        sources.append("daemon_managed" if snapshot.managed else "daemon_discovered")
        if identity is not None and identity.transport in {
            Transport.IIO_IP,
            Transport.DIRECT_IP,
        }:
            sources.append("network")
    notes: list[str] = []
    if device is not None and device.serial is None:
        notes.append("USB serial descriptor is blank; identity correlation is unsafe")
    if duplicate_serial:
        notes.append("duplicate USB serial; daemon correlation refused")
    if snapshot is None and device is not None:
        notes.append("not present in daemon inventory")
    if identity is not None and identity.transport is Transport.FAKE:
        classification: str = "simulated"
    elif device is not None and device.confirmed_plus:
        classification = "confirmed_pluto_plus"
    elif snapshot is not None:
        classification = "daemon_attested_pluto"
    else:
        classification = "pluto_class_ambiguous"
    uri = None if identity is None else identity.uri
    bus_device = None
    if device is not None and device.bus_number is not None and device.device_number is not None:
        bus_device = f"{device.bus_number:03d}:{device.device_number:03d}"
    return RadioInventoryRecord(
        inventory_id=(
            (f"usb:{Path(device.usb_path).name}" if duplicate_serial and device else None)
            or serial
            or (f"usb:{Path(device.usb_path).name}" if device is not None else "unknown")
        ),
        serial=serial,
        classification=classification,  # type: ignore[arg-type]
        sources=tuple(sources),
        managed=False if snapshot is None else snapshot.managed,
        state=("attached" if snapshot is None else str(snapshot.state)),
        model=(
            identity.model
            if identity is not None
            else device.product if device is not None else "Unknown Pluto"
        ),
        firmware_version=None if identity is None else identity.firmware_version,
        transport=None if identity is None else str(identity.transport),
        iio_uri=uri,
        radio_ip=_radio_ip(uri),
        usb_path=None if device is None else device.usb_path,
        usb_bus_device=bus_device,
        usb_speed_mbps=None if device is None else device.speed_mbps,
        usb_interface_count=None if device is None else device.interface_count,
        host_network_interfaces=(
            () if device is None else device.host_network_interfaces
        ),
        terminal_devices=() if device is None else device.terminal_devices,
        storage_devices=() if device is None else device.storage_devices,
        notes=tuple(notes),
    )


def _record_sort_key(record: RadioInventoryRecord) -> tuple[int, str, str]:
    return (
        0 if record.usb_path is not None else 1,
        record.serial or "~",
        record.usb_path or record.iio_uri or "",
    )


def _radio_ip(uri: str | None) -> str | None:
    if uri is None:
        return None
    for prefix in ("ip:", "direct-ip:"):
        if uri.startswith(prefix):
            return uri.removeprefix(prefix).split(",", maxsplit=1)[0]
    return None


def _class_devices_below(
    root: Path, device_root: Path, *, device_link: bool
) -> tuple[str, ...]:
    if not root.is_dir():
        return ()
    names: list[str] = []
    for entry in root.iterdir():
        try:
            target = (
                (entry / "device").resolve(strict=True)
                if device_link
                else entry.resolve(strict=True)
            )
            target.relative_to(device_root)
        except (OSError, ValueError):
            continue
        names.append(entry.name)
    return tuple(sorted(names))


def _interface_ipv4_addresses(interface: str) -> tuple[str, ...]:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            request = struct.pack("256s", interface[:15].encode())
            response = fcntl.ioctl(channel.fileno(), _SIOCGIFADDR, request)
        return (socket.inet_ntoa(response[20:24]),)
    except OSError:
        return ()


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except (OSError, UnicodeError):
        return ""


def _integer(path: Path) -> int | None:
    value = _read(path)
    try:
        return int(value)
    except ValueError:
        return None


def _numeric_integer(path: Path) -> int | None:
    value = _read(path)
    try:
        return round(float(value))
    except ValueError:
        return None
