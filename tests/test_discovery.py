from __future__ import annotations

import pytest

from pluto_plus.hardware.discovery import (
    _facts_from_context_xml,
    discover_devices,
    discover_network_iio,
)


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


def test_network_discovery_attests_and_sorts_read_only_pluto_contexts() -> None:
    open_hosts = {"192.0.2.2", "192.0.2.4", "192.0.2.5"}
    facts = {
        "192.0.2.2": {
            "hw_serial": "SERIAL_B",
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "fw_version": "v2",
            "ad9361-phy,model": "ad9361",
            "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        },
        "192.0.2.4": {
            "hw_serial": "SERIAL_A",
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "fw_version": "v1",
            "ad9361-phy,model": "ad9361",
            "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        },
        # A service on the libiio port is not enough: reject non-Pluto contexts.
        "192.0.2.5": {
            "hw_serial": "NOT_A_PLUTO",
            "hw_model": "Industrial sensor",
            "device_names": ("adc",),
        },
    }

    observations = discover_network_iio(
        ["192.0.2.0/29", "192.0.2.4/30"],
        port_probe=lambda host: host in open_hosts,
        inspect_context=lambda host: facts[host],
    )

    assert [(item.serial, item.host) for item in observations] == [
        ("SERIAL_A", "192.0.2.4"),
        ("SERIAL_B", "192.0.2.2"),
    ]
    promoted = observations[0].device()
    assert promoted.identity.radio_id == "SERIAL_A"
    assert promoted.identity.uri == "ip:192.0.2.4"


def test_network_context_xml_inventory_needs_no_native_libiio() -> None:
    facts = _facts_from_context_xml(
        b"""<?xml version="1.0"?>
        <context name="local">
          <context-attribute name="hw_serial" value="SERIAL_A" />
          <context-attribute name="hw_model" value="Analog Devices PlutoSDR Rev.C" />
          <context-attribute name="fw_version" value="v5" />
          <context-attribute name="ad9361-phy,model" value="ad9361" />
          <device id="iio:device0" name="ad9361-phy" />
          <device id="iio:device1" name="cf-ad9361-lpc" />
        </context>"""
    )

    assert facts == {
        "hw_serial": "SERIAL_A",
        "hw_model": "Analog Devices PlutoSDR Rev.C",
        "fw_version": "v5",
        "ad9361-phy,model": "ad9361",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
    }


@pytest.mark.parametrize(
    "payload",
    [
        b"<not-context />",
        b"<context>",
        b'<!DOCTYPE context [<!ENTITY x "unsafe">]><context>&x;</context>',
    ],
)
def test_network_context_xml_rejects_malformed_or_entity_input(payload: bytes) -> None:
    with pytest.raises(ValueError):
        _facts_from_context_xml(payload)


def test_network_discovery_is_bounded_and_rejects_duplicate_serials() -> None:
    with pytest.raises(ValueError, match="safety bound"):
        discover_network_iio(["192.0.2.0/24"], max_hosts=16)

    duplicate_facts = {
        "hw_serial": "DUPLICATE",
        "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
        "fw_version": "v1",
        "ad9361-phy,model": "ad9361",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
    }
    with pytest.raises(ValueError, match="duplicate network IIO serials"):
        discover_network_iio(
            ["192.0.2.0/30"],
            port_probe=lambda _host: True,
            inspect_context=lambda _host: duplicate_facts,
        )


@pytest.mark.parametrize("network", ["not-a-network", "2001:db8::/126"])
def test_network_discovery_rejects_invalid_or_ipv6_ranges(network: str) -> None:
    with pytest.raises(ValueError):
        discover_network_iio([network])
