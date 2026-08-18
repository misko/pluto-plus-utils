from __future__ import annotations

from pathlib import Path

import pytest

import pluto_plus.tandem_qualification as qualification
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1


def _local(path: Path, serial: str = "SERIAL_A") -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=17,
        product="PlutoSDR+ with timestamp support",
        serial=serial,
        speed_mbps=480,
        interface_count=6,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )


def test_tandem_request_is_exact_and_capacity_bounded() -> None:
    request = TandemSessionRequestV1(mode=TandemMode.AUTO)

    assert len(request.pack(65_536)) == 104
    with pytest.raises(ValueError, match="event capacity"):
        TandemSessionRequestV1(
            mode=TandemMode.AUTO,
            event_capacity=1,
            cooldown_periods=1,
        ).pack(65_536)


def test_qualification_plan_is_exact_local_and_safety_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "3-11"
    target.mkdir()
    monkeypatch.setattr(
        qualification,
        "scan_local_usb_plutos",
        lambda: (_local(target),),
    )

    plan = qualification.prepare_tandem_qualification(
        "SERIAL_A",
        target,
        physical_attenuation_db=20,
        strong_tx_gain_db=-10,
        weak_tx_gain_db=-60,
    )

    assert plan.effective_attenuation_db == 30
    assert plan.expected_firmware == "v0.39-plutoplus-spf-libiio-metadata-v6-36-gab79b"
    assert plan.expected_metadata_abi == 2
    assert plan.confirmation_phrase == "QUALIFY TANDEM SERIAL_A 20DB"

    with pytest.raises(qualification.TandemQualificationError, match="unsafe loopback"):
        qualification.prepare_tandem_qualification(
            "SERIAL_A",
            target,
            physical_attenuation_db=20,
            strong_tx_gain_db=0,
            weak_tx_gain_db=-60,
        )
    with pytest.raises(qualification.TandemQualificationError, match="exactly one"):
        qualification.prepare_tandem_qualification(
            "SERIAL_B",
            target,
            physical_attenuation_db=30,
            strong_tx_gain_db=0,
            weak_tx_gain_db=-60,
        )
