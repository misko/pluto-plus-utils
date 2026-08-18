from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Sequence
from dataclasses import asdict
from pathlib import Path

import pytest

import pluto_plus.bootstrap_firmware as bootstrap
import pluto_plus.volatile_firmware as volatile
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.local_reboot import LocalRebootAttestation, LocalRebootCapabilities


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _dfu() -> bytes:
    suffix = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            DFU_PRODUCT_ID.to_bytes(2, "little"),
            DFU_VENDOR_ID.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD",
            b"\x10",
        )
    )
    partial = _fit() + suffix
    crc = 0xFFFFFFFF
    for byte in partial:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return partial + crc.to_bytes(4, "little")


def _radio(path: Path) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=7,
        product="PlutoSDR+",
        serial="SERIAL_A",
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
    )


def _facts(firmware: str) -> dict[str, object]:
    return {
        "hw_serial": "SERIAL_A",
        "hw_model": "Analog Devices PlutoSDR Rev.C",
        "fw_version": firmware,
        "ad9361-phy,model": "ad9361",
        "iio,buffer-metadata": "2",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc", "tandem-agc"),
    }


@pytest.fixture
def ram_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]]:
    usb_root = tmp_path / "usb"
    target = usb_root / "3-7"
    target.mkdir(parents=True)
    image = tmp_path / "candidate.dfu"
    image.write_bytes(_dfu())
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.168.1.15 ssh-ed25519 AAAATEST\n")
    known_hosts.chmod(0o600)
    fit = _fit()
    policy = bootstrap.TANDEM_V6_LATCH_CLEAR_RAM_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "fit_body_sha256": hashlib.sha256(fit).hexdigest(),
            "fit_body_size": len(fit),
            "device_firmware": "candidate-v1",
        }
    )
    profile_id = policy.profile_id
    monkeypatch.setitem(
        volatile.STANDALONE_FLASH_PROFILES,
        profile_id,
        bootstrap.StandaloneFlashProfile(policy, 2, True, persistent_allowed=False),
    )
    monkeypatch.setattr(volatile, "_USB_ROOT", usb_root)
    radios = (_radio(target),)
    plan = volatile.prepare_ram_boot_plan(
        image,
        target,
        profile_id=profile_id,
        transition_host="192.168.1.15",
        known_hosts_file=known_hosts,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("stable-v6"),
        usb_access_checker=lambda path: True,
    )
    return plan, known_hosts, target, radios


def test_plan_is_exact_profile_path_serial_and_explicitly_volatile(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, target, _ = ram_plan

    assert plan.usb_sysfs_path == str(target)
    assert plan.serial == "SERIAL_A"
    assert plan.transition_route_mode == "lan"
    assert plan.confirmation_phrase == "RAM BOOT SERIAL_A"
    assert plan.expected_firmware == "candidate-v1"
    assert plan.fit_size == len(_fit())


def test_ram_only_profile_is_rejected_by_persistent_flash(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target, radios = ram_plan
    monkeypatch.setattr(bootstrap, "_USB_ROOT", target.parent)
    monkeypatch.setattr(bootstrap, "scan_local_usb_plutos", lambda: radios)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="RAM-only"):
        bootstrap.prepare_usb_flash_plan(
            Path(plan.image_path),
            target,
            mutation_profile_id=plan.profile_id,
        )


class RecordingTransition:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    def enter_ram(self, plan: volatile.VolatileFirmwarePlan) -> None:
        self.calls.append(plan.serial)
        if self.fail:
            raise TimeoutError("radio disconnected during RAM transition")


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_s: float) -> str:
        assert timeout_s > 0
        command = tuple(argv)
        self.commands.append(command)
        return "dfu-util 0.11"


class RecordingSshTransport:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def run(
        self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15
    ) -> str:
        self.commands.append(command)
        return ""


class FixedAttestationRadio:
    def __init__(self, attestation: LocalRebootAttestation) -> None:
        self.attestation = attestation
        self.muted: list[str] = []

    def attest(self, serial: str) -> LocalRebootAttestation:
        assert serial == self.attestation.serial
        return self.attestation

    def ensure_tx_safe(self, serial: str) -> None:
        self.muted.append(serial)


def test_ssh_transition_accepts_equivalent_rev_c_models_from_iiod_and_device_tree(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, _, _ = ram_plan
    transport = RecordingSshTransport()
    transition = volatile.SshRamBootTransition(transport)  # type: ignore[arg-type]
    radio = FixedAttestationRadio(
        LocalRebootAttestation(
            serial=plan.serial,
            firmware=plan.before_firmware,
            boot_id="boot-a",
            capabilities=LocalRebootCapabilities(
                board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
                phy_model=plan.before_phy,
                rx_scan_channels=("voltage0", "voltage1"),
                tandem_agc=False,
            ),
        )
    )
    transition._radio = radio  # type: ignore[assignment]

    transition.enter_ram(plan)

    assert radio.muted == [plan.serial]
    assert len(transport.commands) == 1
    assert "/usr/sbin/device_reboot ram" in transport.commands[0]


def test_execute_uses_only_exact_path_firmware_alt_and_attests_return(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, known_hosts, _, radios = ram_plan
    facts = iter((_facts("stable-v6"), _facts("candidate-v1")))
    products = iter(("b674", "b673"))
    transition = RecordingTransition()
    runner = RecordingRunner()
    muted: list[str] = []
    monkeypatch.setattr(volatile, "mute_returned_radio", muted.append)

    result = volatile.execute_ram_boot_plan(
        plan,
        confirmation=plan.confirmation_phrase,
        known_hosts_file=known_hosts,
        transition=transition,
        receipt_directory=tmp_path / "receipts",
        command_runner=runner,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: next(facts),
        usb_access_checker=lambda path: True,
        usb_product_reader=lambda path: next(products),
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "success"
    assert transition.calls == ["SERIAL_A"]
    assert runner.commands[0] == ("dfu-util", "--version")
    assert runner.commands[1][:7] == (
        "dfu-util",
        "-p",
        "3-7",
        "-d",
        "0456:b674",
        "-a",
        "firmware.dfu",
    )
    assert runner.commands[1][-2:] == ("-D", plan.image_path)
    assert runner.commands[2][-1] == "-e"
    assert muted == ["SERIAL_A"]
    assert stat.S_IMODE(Path(result.receipt_path).stat().st_mode) == 0o600
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert receipt["outcome"] == "success"
    assert "volatile_dfu_downloaded" in receipt["phases"]


def test_transition_uncertainty_is_receipted_and_never_retryable(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, known_hosts, _, radios = ram_plan

    result = volatile.execute_ram_boot_plan(
        plan,
        confirmation=plan.confirmation_phrase,
        known_hosts_file=known_hosts,
        transition=RecordingTransition(fail=True),
        receipt_directory=tmp_path / "receipts",
        command_runner=RecordingRunner(),
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("stable-v6"),
        usb_access_checker=lambda path: True,
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "unknown"
    assert result.retryable is False
    assert "Do not retry" in (result.remediation or "")
    durable = json.loads(Path(result.receipt_path).read_text())
    assert durable["phases"][-1] == "ram_transition_dispatch_attempted"


def test_execute_refuses_unwritable_raw_usb_before_transition_or_receipt(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, known_hosts, _, radios = ram_plan
    blocked = plan.__class__(**(asdict(plan) | {"raw_usb_write_access": False}))
    transition = RecordingTransition()
    receipt_directory = tmp_path / "receipts"

    with pytest.raises(volatile.VolatileFirmwareError, match="not writable"):
        volatile.execute_ram_boot_plan(
            blocked,
            confirmation=blocked.confirmation_phrase,
            known_hosts_file=known_hosts,
            transition=transition,
            receipt_directory=receipt_directory,
            command_runner=RecordingRunner(),
            scanner=lambda: radios,
            iiod_inspector=lambda interface: _facts("stable-v6"),
            usb_access_checker=lambda path: False,
        )

    assert transition.calls == []
    assert not receipt_directory.exists()
