"""Read-only correlation of daemon radios with Linux USB device topology."""

from __future__ import annotations

import fcntl
import ipaddress
import os
import re
import socket
import stat
import struct
import subprocess
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import Field

from pluto_plus.models import ApiModel, RadioSnapshot, Transport

PLUTO_USB_VENDOR = "0456"
PLUTO_RUNTIME_PRODUCT = "b673"
_SIOCGIFADDR = 0x8915
_SIOCGIFNETMASK = 0x891B
_MAX_AUTOMATIC_PREFIX_LENGTH = 24


class HostNetworkInterface(ApiModel):
    name: str = Field(min_length=1)
    ipv4_addresses: tuple[str, ...] = ()


class UsbLinkFaultSummary(ApiModel):
    """Bounded, port-scoped kernel observations; never electrical telemetry."""

    observation_window: str
    error_count: int = Field(ge=0)
    disconnect_count: int = Field(ge=0)
    port_power_cycle_count: int = Field(ge=0)
    recent_messages: tuple[str, ...] = ()


class LocalUsbPluto(ApiModel):
    usb_path: str
    bus_number: int | None
    device_number: int | None
    product: str
    serial: str | None
    speed_mbps: float | None
    interface_count: int | None
    usb_spec_version: str | None = None
    advertised_max_power_ma: int | None = None
    runtime_power_status: str | None = None
    runtime_power_control: str | None = None
    resolved_parent_path: str | None = None
    direct_to_root_hub: bool | None = None
    intermediate_hub_count: int | None = None
    root_controller_pci_address: str | None = None
    root_controller_vendor_id: str | None = None
    root_controller_device_id: str | None = None
    link_faults: UsbLinkFaultSummary | None = None
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
        "network_attested_pluto",
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
    usb_speed_mbps: float | None
    usb_interface_count: int | None
    usb_spec_version: str | None = None
    usb_advertised_max_power_ma: int | None = None
    usb_runtime_power_status: str | None = None
    usb_runtime_power_control: str | None = None
    usb_resolved_parent_path: str | None = None
    usb_direct_to_root_hub: bool | None = None
    usb_intermediate_hub_count: int | None = None
    usb_root_controller_pci_address: str | None = None
    usb_root_controller_vendor_id: str | None = None
    usb_root_controller_device_id: str | None = None
    usb_link_faults: UsbLinkFaultSummary | None = None
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
    udev_data_root: Path = Path("/run/udev/data"),
    ipv4_reader: Callable[[str], tuple[str, ...]] | None = None,
    kernel_log_reader: Callable[[], str | None] | None = None,
) -> tuple[LocalUsbPluto, ...]:
    """Inventory runtime Plutos from cached topology without opening the radio.

    USB strings come from udev. Small cached link/power attributes are read in
    disposable, tightly time-bounded child processes so a sick USB device cannot
    block inventory inside the kernel. No USB control transfer or IIOD connection
    is initiated.
    """

    if not usb_root.is_dir():
        return ()
    address_reader = ipv4_reader or _interface_ipv4_addresses
    log_text = (kernel_log_reader or _recent_kernel_usb_log)()
    devices: list[LocalUsbPluto] = []
    for candidate in sorted(usb_root.iterdir(), key=lambda item: item.name):
        try:
            resolved = candidate.resolve(strict=True)
            initial_device = os.stat(resolved, follow_symlinks=False)
        except OSError:
            continue
        if not stat.S_ISDIR(initial_device.st_mode):
            continue
        device_identity = _inode_identity(initial_device)
        if not _device_alias_is_bound(candidate, resolved, device_identity):
            continue
        event = _key_value_lines(_read(candidate / "uevent"))
        if event.get("DEVTYPE") != "usb_device":
            continue
        product_parts = event.get("PRODUCT", "").split("/")
        if len(product_parts) != 3:
            continue
        try:
            vendor_id = f"{int(product_parts[0], 16):04x}"
            product_id = f"{int(product_parts[1], 16):04x}"
        except ValueError:
            continue
        if vendor_id != PLUTO_USB_VENDOR or product_id != PLUTO_RUNTIME_PRODUCT:
            continue
        device_number = _optional_decimal(event.get("DEVNUM"))
        # USB address zero is reserved for enumeration and is never a usable
        # userspace device.  A failed xHCI teardown can leave a cached sysfs and
        # udev record behind with DEVNUM=000; admitting it creates a phantom
        # radio and can also retain stale tty/block correlations indefinitely.
        if device_number is None or device_number <= 0:
            continue
        properties = _udev_properties(
            udev_data_root,
            event.get("MAJOR"),
            event.get("MINOR"),
        )
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
        interface_count = _physical_usb_interface_count(
            candidate,
            resolved,
            device_identity,
        )
        interfaces = tuple(
            HostNetworkInterface(name=name, ipv4_addresses=address_reader(name))
            for name in network_names
        )
        raw_serial = properties.get("ID_SERIAL_SHORT", "").strip()
        product_name = _decode_udev_text(properties.get("ID_MODEL_ENC", ""))
        resolved_path = str(resolved)
        controller_path = _nearest_pci_controller(resolved)
        speed = _optional_float(_bounded_sysfs_read(candidate / "speed"))
        usb_version = _normalized_optional(_bounded_sysfs_read(candidate / "version"))
        advertised_power = _parse_milliamps(_bounded_sysfs_read(candidate / "bMaxPower"))
        runtime_power_status = _normalized_optional(
            _bounded_sysfs_read(candidate / "power" / "runtime_status")
        )
        runtime_power_control = _normalized_optional(
            _bounded_sysfs_read(candidate / "power" / "control")
        )
        root_controller_vendor_id = (
            None
            if controller_path is None
            else _normalized_hex_id(_read(controller_path / "vendor"))
        )
        root_controller_device_id = (
            None
            if controller_path is None
            else _normalized_hex_id(_read(controller_path / "device"))
        )
        if (
            not _device_alias_is_bound(candidate, resolved, device_identity)
            or _key_value_lines(_read(candidate / "uevent")) != event
            or _udev_properties(
                udev_data_root,
                event.get("MAJOR"),
                event.get("MINOR"),
            )
            != properties
        ):
            continue
        port_name = candidate.name
        devices.append(
            LocalUsbPluto(
                usb_path=str(candidate),
                bus_number=_optional_decimal(event.get("BUSNUM")),
                device_number=device_number,
                product=(
                    product_name
                    or (
                        "PlutoSDR+ runtime device"
                        if interface_count is not None and interface_count >= 7
                        else "ADI Pluto runtime device"
                    )
                ),
                serial=raw_serial or None,
                speed_mbps=speed,
                interface_count=interface_count,
                usb_spec_version=usb_version,
                advertised_max_power_ma=advertised_power,
                runtime_power_status=runtime_power_status,
                runtime_power_control=runtime_power_control,
                resolved_parent_path=resolved_path,
                direct_to_root_hub=_direct_to_root_hub(port_name),
                intermediate_hub_count=_intermediate_hub_count(port_name),
                root_controller_pci_address=(
                    None if controller_path is None else controller_path.name
                ),
                root_controller_vendor_id=root_controller_vendor_id,
                root_controller_device_id=root_controller_device_id,
                link_faults=_usb_link_fault_summary(log_text, port_name),
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
    snapshot_origin: Literal["daemon", "standalone"] = "daemon",
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
        records.append(
            _record(
                device=device,
                snapshot=snapshot,
                duplicate_serial=(
                    device.serial is not None and local_serial_counts[device.serial] > 1
                ),
                snapshot_origin=snapshot_origin,
            )
        )
    for snapshot in radio_snapshots:
        if snapshot.identity.serial not in consumed_serials:
            records.append(
                _record(
                    device=None,
                    snapshot=snapshot,
                    duplicate_serial=False,
                    snapshot_origin=snapshot_origin,
                )
            )
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
    snapshot_origin: Literal["daemon", "standalone"],
) -> RadioInventoryRecord:
    identity = None if snapshot is None else snapshot.identity
    serial = device.serial if device is not None else identity.serial if identity else None
    sources: list[str] = []
    if device is not None:
        sources.append("usb")
    if snapshot is not None:
        sources.append(
            "standalone_discovered"
            if snapshot_origin == "standalone"
            else "daemon_managed"
            if snapshot.managed
            else "daemon_discovered"
        )
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
        notes.append(
            "local USB topology only; radio was not opened"
            if snapshot_origin == "standalone"
            else "not present in daemon inventory"
        )
    if snapshot is not None and snapshot_origin == "standalone":
        notes.append("read-only standalone network discovery; not opened for control")
    if identity is not None and identity.transport is Transport.FAKE:
        classification: str = "simulated"
    elif device is not None and device.confirmed_plus:
        classification = "confirmed_pluto_plus"
    elif snapshot is not None and snapshot_origin == "standalone":
        classification = "network_attested_pluto"
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
        state=(
            "attached"
            if snapshot is None
            else "discovered"
            if snapshot_origin == "standalone"
            else str(snapshot.state)
        ),
        model=(
            identity.model
            if identity is not None
            else device.product
            if device is not None
            else "Unknown Pluto"
        ),
        firmware_version=None if identity is None else identity.firmware_version,
        transport=None if identity is None else str(identity.transport),
        iio_uri=uri,
        radio_ip=_radio_ip(uri),
        usb_path=None if device is None else device.usb_path,
        usb_bus_device=bus_device,
        usb_speed_mbps=None if device is None else device.speed_mbps,
        usb_interface_count=None if device is None else device.interface_count,
        usb_spec_version=None if device is None else device.usb_spec_version,
        usb_advertised_max_power_ma=(None if device is None else device.advertised_max_power_ma),
        usb_runtime_power_status=None if device is None else device.runtime_power_status,
        usb_runtime_power_control=None if device is None else device.runtime_power_control,
        usb_resolved_parent_path=None if device is None else device.resolved_parent_path,
        usb_direct_to_root_hub=None if device is None else device.direct_to_root_hub,
        usb_intermediate_hub_count=(None if device is None else device.intermediate_hub_count),
        usb_root_controller_pci_address=(
            None if device is None else device.root_controller_pci_address
        ),
        usb_root_controller_vendor_id=(
            None if device is None else device.root_controller_vendor_id
        ),
        usb_root_controller_device_id=(
            None if device is None else device.root_controller_device_id
        ),
        usb_link_faults=None if device is None else device.link_faults,
        host_network_interfaces=(() if device is None else device.host_network_interfaces),
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


def _class_devices_below(root: Path, device_root: Path, *, device_link: bool) -> tuple[str, ...]:
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


def local_ipv4_discovery_networks(
    net_root: Path = Path("/sys/class/net"),
    *,
    interface_reader: Callable[[str], tuple[str, str] | None] | None = None,
    exclude_interfaces: Iterable[str] = (),
) -> tuple[str, ...]:
    """Return bounded private/link-local IPv4 networks attached to this host.

    Automatic discovery never scans a range broader than the /24 containing the
    host address. Operators can use an explicit ``--network-cidr`` when a larger
    or otherwise non-local range is intentional.
    """

    if not net_root.is_dir():
        return ()
    reader = interface_reader or _interface_ipv4_address_and_mask
    excluded = set(exclude_interfaces)
    networks: set[ipaddress.IPv4Network] = set()
    shared = ipaddress.ip_network("100.64.0.0/10")
    for entry in sorted(net_root.iterdir(), key=lambda item: item.name):
        if entry.name == "lo" or entry.name in excluded:
            continue
        address_and_mask = reader(entry.name)
        if address_and_mask is None:
            continue
        address_text, mask_text = address_and_mask
        try:
            interface = ipaddress.IPv4Interface(f"{address_text}/{mask_text}")
        except ValueError:
            continue
        address = interface.ip
        if not (address.is_private or address.is_link_local or address in shared):
            continue
        prefix_length = max(
            interface.network.prefixlen,
            _MAX_AUTOMATIC_PREFIX_LENGTH,
        )
        networks.add(ipaddress.IPv4Network((int(address), prefix_length), strict=False))
    return tuple(
        str(network) for network in sorted(networks, key=lambda item: int(item.network_address))
    )


def _interface_ipv4_address_and_mask(interface: str) -> tuple[str, str] | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as channel:
            request = struct.pack("256s", interface[:15].encode())
            address = fcntl.ioctl(channel.fileno(), _SIOCGIFADDR, request)
            mask = fcntl.ioctl(channel.fileno(), _SIOCGIFNETMASK, request)
        return socket.inet_ntoa(address[20:24]), socket.inet_ntoa(mask[20:24])
    except OSError:
        return None


def _read(path: Path) -> str:
    try:
        return path.read_text().strip()
    except (OSError, UnicodeError):
        return ""


def _key_value_lines(value: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in value.splitlines():
        key, separator, field_value = line.partition("=")
        if separator and key:
            fields[key] = field_value
    return fields


def _udev_properties(
    data_root: Path,
    major: str | None,
    minor: str | None,
) -> dict[str, str]:
    if major is None or minor is None or not major.isdecimal() or not minor.isdecimal():
        return {}
    fields: dict[str, str] = {}
    for line in _read(data_root / f"c{major}:{minor}").splitlines():
        if not line.startswith("E:"):
            continue
        key, separator, value = line[2:].partition("=")
        if separator and key:
            fields[key] = value
    return fields


def _decode_udev_text(value: str) -> str:
    decoded = re.sub(
        r"\\x([0-9A-Fa-f]{2})",
        lambda match: bytes((int(match.group(1), 16),)).decode("utf-8", errors="replace"),
        value,
    )
    return decoded.replace("_", " ").strip()


def _optional_decimal(value: str | None) -> int | None:
    if value is None or not value.isdecimal():
        return None
    return int(value, 10)


def _optional_float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None


def _normalized_optional(value: str) -> str | None:
    normalized = value.strip()
    return normalized or None


def _parse_milliamps(value: str) -> int | None:
    match = re.fullmatch(r"\s*(\d+)\s*mA\s*", value, flags=re.IGNORECASE)
    return None if match is None else int(match.group(1), 10)


def _bounded_sysfs_read(path: Path) -> str:
    """Read one cached attribute without allowing a wedged device to hang us."""

    try:
        completed = subprocess.run(
            ("cat", "--", str(path)),
            check=False,
            capture_output=True,
            text=True,
            timeout=0.25,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if completed.returncode != 0 or len(completed.stdout) > 256:
        return ""
    return completed.stdout.strip()


def _physical_usb_interface_count(
    device: Path,
    resolved_device: Path,
    expected_device_identity: tuple[int, int],
) -> int | None:
    """Return the descriptor count only when this device exposes every interface.

    ``ID_USB_INTERFACES`` is a set of interface class signatures, not an
    interface-instance list. In particular, udev collapses the two CDC-data
    Pluto+ functions into one ``0a0000`` token. Bind the count to the selected
    physical device instead: the active configuration's descriptor count and
    its kernel-created interface nodes must agree. A disappearing, unconfigured,
    or internally inconsistent device is reported with an unknown count so
    callers which require a canonical function set fail closed.
    """

    try:
        device_fd = os.open(
            resolved_device,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
        )
    except OSError:
        return None
    try:
        device_identity = _directory_identity(device_fd)
        if (
            device_identity is None
            or device_identity != expected_device_identity
            or not _device_alias_is_bound(device, resolved_device, expected_device_identity)
        ):
            return None
        descriptor_count = _optional_decimal(
            _bounded_dirfd_attribute_read(device_fd, "bNumInterfaces")
        )
        configuration = _optional_decimal(
            _bounded_dirfd_attribute_read(device_fd, "bConfigurationValue")
        )
        if (
            descriptor_count is None
            or descriptor_count <= 0
            or configuration is None
            or configuration <= 0
        ):
            return None
        interface_pattern = re.compile(rf"{re.escape(resolved_device.name)}:{configuration}\.(\d+)")
        try:
            names = os.listdir(device_fd)
        except OSError:
            return None
        interface_identities: dict[str, tuple[int, int]] = {}
        interface_numbers: set[int] = set()
        for name in names:
            match = interface_pattern.fullmatch(name)
            if match is None:
                continue
            identity = _direct_child_directory_identity(
                device_fd,
                name,
                expected_device_identity,
            )
            if identity is None:
                return None
            interface_identities[name] = identity
            interface_numbers.add(int(match.group(1), 10))
        if len(interface_numbers) != descriptor_count:
            return None
        if not _directory_entries_still_match(device_fd, interface_pattern, interface_identities):
            return None
        if (
            _optional_decimal(_bounded_dirfd_attribute_read(device_fd, "bNumInterfaces"))
            != descriptor_count
            or _optional_decimal(_bounded_dirfd_attribute_read(device_fd, "bConfigurationValue"))
            != configuration
        ):
            return None
        if not _device_alias_is_bound(device, resolved_device, expected_device_identity):
            return None
        return descriptor_count
    finally:
        os.close(device_fd)


def _bounded_dirfd_attribute_read(directory_fd: int, name: str) -> str:
    """Read one no-follow attribute bound to an already-open device directory."""

    try:
        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            return ""
        attribute_fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=directory_fd,
        )
    except OSError:
        return ""
    try:
        opened = os.fstat(attribute_fd)
        if not stat.S_ISREG(opened.st_mode) or _inode_identity(before) != _inode_identity(opened):
            return ""
        try:
            completed = subprocess.run(
                ("cat",),
                check=False,
                stdin=attribute_fd,
                capture_output=True,
                text=True,
                timeout=0.25,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        try:
            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return ""
        if _inode_identity(after) != _inode_identity(opened):
            return ""
        if completed.returncode != 0 or len(completed.stdout) > 256:
            return ""
        return completed.stdout.strip()
    finally:
        os.close(attribute_fd)


def _directory_identity(directory_fd: int) -> tuple[int, int] | None:
    try:
        observed = os.fstat(directory_fd)
    except OSError:
        return None
    if not stat.S_ISDIR(observed.st_mode):
        return None
    return _inode_identity(observed)


def _device_alias_is_bound(
    device: Path,
    resolved_device: Path,
    expected_identity: tuple[int, int],
) -> bool:
    try:
        alias = os.stat(device, follow_symlinks=True)
        resolved = os.stat(resolved_device, follow_symlinks=False)
    except OSError:
        return False
    return (
        stat.S_ISDIR(alias.st_mode)
        and stat.S_ISDIR(resolved.st_mode)
        and _inode_identity(alias) == expected_identity
        and _inode_identity(resolved) == expected_identity
    )


def _direct_child_directory_identity(
    parent_fd: int,
    name: str,
    parent_identity: tuple[int, int],
) -> tuple[int, int] | None:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(before.st_mode):
            return None
        child_fd = os.open(
            name,
            os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
    except OSError:
        return None
    try:
        opened = os.fstat(child_fd)
        owning_parent = os.stat("..", dir_fd=child_fd, follow_symlinks=False)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return None
    finally:
        os.close(child_fd)
    identity = _inode_identity(opened)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or _inode_identity(before) != identity
        or _inode_identity(after) != identity
        or _inode_identity(owning_parent) != parent_identity
    ):
        return None
    return identity


def _directory_entries_still_match(
    directory_fd: int,
    interface_pattern: re.Pattern[str],
    expected: dict[str, tuple[int, int]],
) -> bool:
    try:
        current_names = {
            name for name in os.listdir(directory_fd) if interface_pattern.fullmatch(name)
        }
        if current_names != set(expected):
            return False
        for name, identity in expected.items():
            observed = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if not stat.S_ISDIR(observed.st_mode) or _inode_identity(observed) != identity:
                return False
    except OSError:
        return False
    return True


def _inode_identity(observed: os.stat_result) -> tuple[int, int]:
    return observed.st_dev, observed.st_ino


def _direct_to_root_hub(port_name: str) -> bool | None:
    if not re.fullmatch(r"\d+-\d+(?:\.\d+)*", port_name):
        return None
    return "." not in port_name


def _intermediate_hub_count(port_name: str) -> int | None:
    direct = _direct_to_root_hub(port_name)
    return None if direct is None else port_name.count(".")


_PCI_ADDRESS = re.compile(r"^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7]$")


def _nearest_pci_controller(device_path: Path) -> Path | None:
    for parent in device_path.parents:
        if _PCI_ADDRESS.fullmatch(parent.name):
            return parent
    return None


def _normalized_hex_id(value: str) -> str | None:
    normalized = value.strip().lower().removeprefix("0x")
    if not re.fullmatch(r"[0-9a-f]{4}", normalized):
        return None
    return normalized


_KERNEL_LOG_WINDOW = "current boot, last 1000 kernel messages"
_USB_ERROR_TERMS = re.compile(
    r"(?:error\s+-\d+|device descriptor read|device not accepting address|unable to enumerate)",
    flags=re.IGNORECASE,
)


def _recent_kernel_usb_log() -> str | None:
    try:
        completed = subprocess.run(
            ("journalctl", "--dmesg", "--boot", "-n", "1000", "--no-pager", "-o", "cat"),
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout[-1_000_000:]


def _usb_link_fault_summary(log_text: str | None, port_name: str) -> UsbLinkFaultSummary | None:
    if log_text is None:
        return None
    # Kernel messages name a device as "usb 5-1:" and a root-hub port as
    # "usb usb5-port1:". The latter is safely attributable only for a direct
    # child. Intermediate-hub port messages are intentionally not guessed.
    device_pattern = re.compile(rf"\busb\s+{re.escape(port_name)}(?::|\s)", re.IGNORECASE)
    root_port_pattern: re.Pattern[str] | None = None
    direct_match = re.fullmatch(r"(\d+)-(\d+)", port_name)
    if direct_match is not None:
        root_port_pattern = re.compile(
            rf"\busb\s+usb{direct_match.group(1)}-port{direct_match.group(2)}(?::|\s)",
            re.IGNORECASE,
        )
    scoped = [
        line.strip()
        for line in log_text.splitlines()
        if device_pattern.search(line)
        or (root_port_pattern is not None and root_port_pattern.search(line))
    ]
    interesting = [
        line
        for line in scoped
        if _USB_ERROR_TERMS.search(line)
        or "disconnect" in line.lower()
        or "power cycle" in line.lower()
    ]
    if not interesting:
        return UsbLinkFaultSummary(
            observation_window=_KERNEL_LOG_WINDOW,
            error_count=0,
            disconnect_count=0,
            port_power_cycle_count=0,
        )
    return UsbLinkFaultSummary(
        observation_window=_KERNEL_LOG_WINDOW,
        error_count=sum(bool(_USB_ERROR_TERMS.search(line)) for line in interesting),
        disconnect_count=sum("disconnect" in line.lower() for line in interesting),
        port_power_cycle_count=sum("power cycle" in line.lower() for line in interesting),
        recent_messages=tuple(interesting[-8:]),
    )
