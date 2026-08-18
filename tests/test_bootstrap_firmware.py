from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import pluto_plus.bootstrap_firmware as bootstrap
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto


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


def _local(path: Path, *, serial: str | None = None) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=17,
        product="PlutoSDR+ with timestamp support",
        serial=serial,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )


@pytest.fixture
def planned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[bootstrap.BootstrapPlan, bytes, Path]:
    usb_root = tmp_path / "usb"
    target = usb_root / "3-11"
    target.mkdir(parents=True)
    image = tmp_path / "canonical.dfu"
    image.write_bytes(_dfu())
    policy = bootstrap.BOOTSTRAP_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "device_firmware": "v5",
        }
    )
    monkeypatch.setattr(bootstrap, "_USB_ROOT", usb_root)
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_POLICY", policy)
    monkeypatch.setattr(bootstrap, "scan_local_usb_plutos", lambda: (_local(target),))
    monkeypatch.setattr(bootstrap, "_attest_partition", lambda target, part: Path("/dev/sdb"))
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "",
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9363A)",
            "fw_version": "v0.32-dirty",
            "ad9361-phy,model": "ad9363a",
        },
    )
    plan, frm = bootstrap.prepare_bootstrap_plan(image, target)
    return plan, frm, target


def test_prepare_is_canonical_path_bound_and_read_only(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
) -> None:
    plan, frm, target = planned

    assert plan.usb_sysfs_path == str(target)
    assert plan.confirmation_phrase == "BOOTSTRAP 3-11"
    assert plan.partition == "/dev/sdb1"
    assert plan.block_device == "/dev/sdb"
    assert plan.before_firmware == "v0.32-dirty"
    assert hashlib.sha256(frm).hexdigest() == plan.frm_sha256


def test_prepare_rejects_an_image_outside_immutable_policy(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "BOOTSTRAP_POLICY",
        bootstrap.BOOTSTRAP_POLICY.model_copy(update={"asset_sha256": "0" * 64}),
    )

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="canonical qualified DFU"):
        bootstrap.prepare_bootstrap_plan(Path(plan.image_path), target)


def test_prepare_refuses_to_bypass_normal_serial_flow(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "scan_local_usb_plutos",
        lambda: (_local(target, serial="SERIAL_A"),),
    )

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="firmware flash"):
        bootstrap.prepare_bootstrap_plan(Path(plan.image_path), target)


def test_normal_flash_requires_matching_stable_usb_and_iiod_serial(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "scan_local_usb_plutos",
        lambda: (_local(target, serial="SERIAL_A"),),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_A",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v0.37",
            "ad9361-phy,model": "ad9361",
        },
    )

    normal, _ = bootstrap.prepare_usb_flash_plan(Path(plan.image_path), target)

    assert normal.operation == "flash"
    assert normal.target_serial == "SERIAL_A"
    assert normal.confirmation_phrase == "FLASH SERIAL_A"

    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_B",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v0.37",
            "ad9361-phy,model": "ad9361",
        },
    )
    with pytest.raises(bootstrap.BootstrapFirmwareError, match="serials do not match"):
        bootstrap.prepare_usb_flash_plan(Path(plan.image_path), target)


def test_execute_requires_exact_confirmation_before_operations(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path], tmp_path: Path
) -> None:
    plan, frm, _ = planned

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="confirmation"):
        bootstrap.execute_bootstrap_plan(
            plan,
            frm,
            confirmation="BOOTSTRAP wrong",
            receipt_directory=tmp_path / "receipts",
        )

    assert not (tmp_path / "receipts").exists()


def test_execute_writes_only_pluto_frm_and_attests_return(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, target = planned
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "info.html").write_text("Pluto")
    commands: list[tuple[str, ...]] = []

    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_mount_partition", lambda partition: mountpoint)
    monkeypatch.setattr(bootstrap, "_run", lambda argv, timeout_s: commands.append(tuple(argv)))
    monkeypatch.setattr(bootstrap, "_wait_for_path", lambda path, present, timeout_s: None)
    monkeypatch.setattr(
        bootstrap,
        "_one_local_target",
        lambda path: _local(target, serial="SERIAL_NEW"),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_NEW",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
    )

    assert result.outcome == "success"
    assert result.returned_serial == "SERIAL_NEW"
    assert (mountpoint / "pluto.frm").read_bytes() == frm
    assert sorted(path.name for path in mountpoint.iterdir()) == ["info.html", "pluto.frm"]
    assert commands == [
        ("sync", "-f", str(mountpoint / "pluto.frm")),
        ("udisksctl", "unmount", "--block-device", "/dev/sdb1"),
        ("udisksctl", "power-off", "--block-device", "/dev/sdb"),
    ]
    receipt_path = Path(result.receipt_path)
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(receipt_path.read_text())["outcome"] == "success"


def test_failure_after_write_is_unknown_and_durably_receipted(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "info.html").write_text("Pluto")
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_mount_partition", lambda partition: mountpoint)

    def fail_sync(argv: tuple[str, ...], *, timeout_s: float) -> None:
        del timeout_s
        if argv[0] == "sync":
            raise bootstrap.BootstrapFirmwareError("sync failed")

    monkeypatch.setattr(bootstrap, "_run", fail_sync)

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
    )

    assert result.outcome == "unknown"
    assert "sync failed" in (result.error or "")
    assert json.loads(Path(result.receipt_path).read_text())["outcome"] == "unknown"


class FakeSshTransport:
    def __init__(self, plan: bootstrap.BootstrapPlan, *, updater_output: str = "Done\n") -> None:
        self.plan = plan
        self.updater_output = updater_output
        self.calls: list[tuple[str, bytes | None]] = []

    def upload_frm(self, data: bytes, *, timeout_s: float = 120) -> None:
        del timeout_s
        self.calls.append(("upload_frm", data))

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        del timeout_s
        self.calls.append((command, stdin))
        if command == bootstrap._REMOTE_ATTEST_COMMAND:
            return (
                "serial=\n"
                f"model={self.plan.before_model}\n"
                f"firmware={self.plan.before_firmware}\n"
                "updater=/sbin/update_frm.sh\n"
            )
        if command == bootstrap._REMOTE_STAGE_HASH_COMMAND:
            return f"{self.plan.frm_sha256}  /tmp/pluto-plus-utils/pluto.frm\n"
        if command == bootstrap._REMOTE_UPDATE_COMMAND:
            return self.updater_output
        if command.startswith("head -c "):
            return f"{self.plan.fit_sha256}  -\n"
        return ""


def test_bound_ssh_force_flash_verifies_stage_mtd3_and_return(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, target = planned
    transport = FakeSshTransport(plan)
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_wait_for_path", lambda path, present, timeout_s: None)
    monkeypatch.setattr(
        bootstrap,
        "_one_local_target",
        lambda path: _local(target, serial="SERIAL_NEW"),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_NEW",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    result = bootstrap.execute_usb_flash_plan_ssh(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        transport=transport,
    )

    assert result.outcome == "success"
    assert "mtd3_fit_verified" in result.phases
    stage = next(call for call in transport.calls if call[0] == "upload_frm")
    assert stage[1] == frm
    assert transport.calls[-1][0] == bootstrap._REMOTE_REBOOT_COMMAND


def test_bound_ssh_ambiguous_updater_result_is_unknown(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    transport = FakeSshTransport(plan, updater_output="Failed\nDone\n")
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial: (plan, frm),
    )

    result = bootstrap.execute_usb_flash_plan_ssh(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        transport=transport,
    )

    assert result.outcome == "unknown"
    assert "unambiguous Done" in (result.error or "")


def test_force_flash_can_verify_v5_when_hardware_serial_remains_blank(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(bootstrap, "_one_local_target", lambda path: _local(target))
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    serial, firmware, phy = bootstrap._attest_return(plan)

    assert serial is None
    assert firmware == plan.expected_firmware
    assert phy == "ad9363a"


def test_return_attestation_retries_transient_iiod_startup(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _ = planned
    attempts = 0

    def attest(current: bootstrap.BootstrapPlan) -> tuple[None, str, str]:
        nonlocal attempts
        assert current == plan
        attempts += 1
        if attempts == 1:
            raise bootstrap.BootstrapFirmwareError("IIOD timed out")
        return None, plan.expected_firmware, "ad9363a"

    monkeypatch.setattr(bootstrap, "_attest_return", attest)
    monkeypatch.setattr(bootstrap.time, "sleep", lambda duration: None)

    result = bootstrap._attest_return_when_ready(plan, timeout_s=1)

    assert result == (None, plan.expected_firmware, "ad9363a")
    assert attempts == 2
