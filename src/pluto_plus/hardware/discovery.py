"""Production radio discovery without importing native IIO libraries eagerly."""

from __future__ import annotations

import ipaddress
import socket
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from pluto_plus.hardware.iio import IioRadioDevice, discover_usb_serials

IIO_NETWORK_PORT = 30_431
MAX_NETWORK_DISCOVERY_HOSTS = 4_096
MAX_IIO_CONTEXT_XML_BYTES = 2 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class NetworkIioObservation:
    """Read-only, serial-attested network Pluto inventory record."""

    host: str
    serial: str
    model: str
    firmware_version: str | None

    def device(self) -> IioRadioDevice:
        """Promote this observation to an exact-serial managed adapter."""

        return IioRadioDevice(f"ip:{self.host}", serial=self.serial, radio_id=self.serial)


def discover_devices(
    usb_root: Path = Path("/sys/bus/usb/devices"),
) -> tuple[IioRadioDevice, ...]:
    """Return serial-pinned USB adapters for every unambiguous runtime Pluto+."""

    return tuple(
        IioRadioDevice("usb:", serial=serial, radio_id=serial)
        for serial in discover_usb_serials(usb_root)
    )


def discover_network_iio(
    networks: Iterable[str],
    *,
    port_probe: Callable[[str], bool] | None = None,
    inspect_context: Callable[[str], Mapping[str, object]] | None = None,
    max_hosts: int = MAX_NETWORK_DISCOVERY_HOSTS,
    workers: int = 64,
) -> tuple[NetworkIioObservation, ...]:
    """Inventory Pluto-compatible libiio contexts within bounded IPv4 CIDRs.

    Port discovery is concurrent and read-only. Only hosts that answer on the
    standard libiio network port are inspected, and each accepted observation
    must expose a stable serial, Pluto model, firmware version, AD9361 PHY, and
    the paired-RX buffer device. No radio attributes or buffers are written.
    """

    if max_hosts < 1:
        raise ValueError("network discovery max_hosts must be positive")
    if workers < 1 or workers > 256:
        raise ValueError("network discovery workers must be between 1 and 256")
    candidates: set[str] = set()
    for specification in networks:
        try:
            network = ipaddress.ip_network(specification, strict=False)
        except ValueError as error:
            raise ValueError(f"invalid network discovery CIDR {specification!r}") from error
        if not isinstance(network, ipaddress.IPv4Network):
            raise ValueError("network libiio discovery currently supports IPv4 CIDRs only")
        candidates.update(str(address) for address in network.hosts())
        if len(candidates) > max_hosts:
            raise ValueError(f"network discovery exceeds the {max_hosts}-host safety bound")
    probe = port_probe or _iio_port_open
    inspector = inspect_context or _inspect_iio_context
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="iio-discovery") as pool:
        open_hosts = [
            host
            for host, available in zip(
                sorted(candidates, key=ipaddress.ip_address),
                pool.map(probe, sorted(candidates, key=ipaddress.ip_address)),
                strict=True,
            )
            if available
        ]
    observations: list[NetworkIioObservation] = []
    for host in open_hosts:
        try:
            facts = inspector(host)
        except (OSError, RuntimeError, ValueError):
            continue
        observation = _observation_from_facts(host, facts)
        if observation is not None:
            observations.append(observation)
    serial_hosts: dict[str, list[str]] = {}
    for observation in observations:
        serial_hosts.setdefault(observation.serial, []).append(observation.host)
    duplicates = {serial: hosts for serial, hosts in serial_hosts.items() if len(hosts) > 1}
    if duplicates:
        raise ValueError(f"duplicate network IIO serials are ambiguous: {duplicates}")
    return tuple(sorted(observations, key=lambda item: item.serial))


def _iio_port_open(host: str, *, timeout_s: float = 0.12) -> bool:
    try:
        with socket.create_connection((host, IIO_NETWORK_PORT), timeout=timeout_s):
            return True
    except OSError:
        return False


def _inspect_iio_context(host: str) -> Mapping[str, object]:
    """Read the public IIOD context description without loading native libiio."""

    with socket.create_connection((host, IIO_NETWORK_PORT), timeout=1.0) as channel:
        channel.settimeout(2.0)
        stream = channel.makefile("rb")
        channel.sendall(b"PRINT\r\n")
        header = stream.readline(32)
        if not header.endswith(b"\n"):
            raise ValueError("invalid IIOD PRINT length header")
        try:
            size = int(header.strip())
        except ValueError as error:
            raise ValueError("invalid IIOD PRINT length") from error
        if size < 1 or size > MAX_IIO_CONTEXT_XML_BYTES:
            raise ValueError("IIOD context XML exceeds the safety bound")
        payload = stream.read(size)
        if len(payload) != size:
            raise OSError("truncated IIOD context XML")
    return _facts_from_context_xml(payload)


def _facts_from_context_xml(payload: bytes) -> Mapping[str, object]:
    """Extract only bounded inventory facts from an IIOD PRINT response."""

    if b"<!ENTITY" in payload.upper():
        raise ValueError("IIOD context XML contains unsupported entities")
    try:
        root = ElementTree.fromstring(payload)
    except ElementTree.ParseError as error:
        raise ValueError("invalid IIOD context XML") from error
    if root.tag != "context":
        raise ValueError("IIOD response root is not a context")
    facts: dict[str, object] = {}
    for attribute in root.findall("context-attribute"):
        name = attribute.get("name")
        value = attribute.get("value")
        if name is not None and value is not None:
            facts[name] = value
    facts["device_names"] = tuple(
        name for device in root.findall("device") if (name := device.get("name")) is not None
    )
    for device in root.findall("device"):
        name = device.get("name")
        if not name:
            continue
        scan_channels = tuple(
            channel_id
            for channel in device.findall("channel")
            if channel.get("type") == "input"
            and channel.find("scan-element") is not None
            and (channel_id := channel.get("id")) is not None
        )
        if scan_channels:
            facts[f"{name},scan_channels"] = scan_channels
    return facts


def _observation_from_facts(host: str, facts: Mapping[str, object]) -> NetworkIioObservation | None:
    serial = str(facts.get("hw_serial") or "").strip()
    model = str(facts.get("hw_model") or "").strip()
    firmware = str(facts.get("fw_version") or "").strip() or None
    phy_model = str(facts.get("ad9361-phy,model") or "").strip()
    raw_device_names = facts.get("device_names", ())
    device_names = (
        {str(value) for value in raw_device_names}
        if isinstance(raw_device_names, (tuple, list, set, frozenset))
        else set()
    )
    if (
        not serial
        or "plutosdr" not in model.lower()
        or phy_model not in {"ad9361", "ad9363a", "ad9364"}
        or not {"ad9361-phy", "cf-ad9361-lpc"} <= device_names
    ):
        return None
    return NetworkIioObservation(
        host=host,
        serial=serial,
        model=model,
        firmware_version=firmware,
    )
