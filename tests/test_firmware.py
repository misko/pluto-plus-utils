from __future__ import annotations

import binascii
import json
from collections.abc import Sequence
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
    FirmwareAuthorizationError,
    FirmwareError,
    FirmwareExecutionError,
    FirmwareIdentityError,
    FirmwareImageError,
    FirmwareManager,
    FirmwareMode,
    LocalMassStorageFilesystem,
    MassStorageQspiUpdater,
    RadioFirmwareIdentity,
    SysfsRadioFirmwareIdentityProbe,
    UpdaterBlockDevice,
    generate_frm,
    validate_dfu,
    validate_frm,
)


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _raw_dfu_crc(data: bytes) -> int:
    # Independent spelling of the DFU CRC accumulator used by dfu-util.
    accumulator = 0xFFFFFFFF
    for byte in data:
        accumulator ^= byte
        for _ in range(8):
            accumulator = (
                (accumulator >> 1) ^ 0xEDB88320
                if accumulator & 1
                else accumulator >> 1
            )
    return accumulator


def _dfu(
    *,
    body: bytes | None = None,
    vendor: int = DFU_VENDOR_ID,
    product: int = DFU_PRODUCT_ID,
) -> bytes:
    suffix_without_crc = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            product.to_bytes(2, "little"),
            vendor.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD",
            b"\x10",
        )
    )
    partial = (body or _fit()) + suffix_without_crc
    return partial + _raw_dfu_crc(partial).to_bytes(4, "little")


class FakeExecutor:
    def __init__(self, *, uid: int = 0, failure: BaseException | None = None) -> None:
        self.uid = uid
        self.failure = failure
        self.calls: list[tuple[str, RadioFirmwareIdentity, Path, str | None]] = []

    def effective_uid(self) -> int:
        return self.uid

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        self.calls.append(("ram", radio, image, None))
        if self.failure:
            raise self.failure

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        self.calls.append(("qspi", radio, image, target_name))
        if self.failure:
            raise self.failure


class MutableClock:
    def __init__(self) -> None:
        self.value = datetime(2026, 8, 15, 12, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.value


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.value += duration


class FakeCommandRunner:
    def __init__(self, *, fail_on: str | None = None) -> None:
        self.fail_on = fail_on
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_s: float) -> None:
        del timeout_s
        command = tuple(argv)
        self.calls.append(command)
        if command[0] == self.fail_on:
            raise RuntimeError(f"{self.fail_on} failed")


class FakeMassStorageFilesystem:
    def __init__(self, source: Path, *, info: bool = True, fail_copy: bool = False) -> None:
        self.source = source
        self.source_data = generate_frm(_dfu())
        self.info = info
        self.fail_copy = fail_copy
        self.prepared: list[Path] = []
        self.writes: list[tuple[Path, bytes]] = []

    def read_bytes(self, path: Path) -> bytes:
        assert path == self.source
        return self.source_data

    def prepare_private_mountpoint(self, path: Path) -> None:
        self.prepared.append(path)

    def is_file(self, path: Path) -> bool:
        return self.info and path.name == "info.html"

    def write_fat_atomic(self, path: Path, data: bytes) -> None:
        if self.fail_copy:
            raise OSError("copy failed")
        self.writes.append((path, data))


class SequenceEnumerator:
    def __init__(self, states: list[list[UpdaterBlockDevice]]) -> None:
        self.states = states
        self.index = 0

    def __call__(self) -> list[UpdaterBlockDevice]:
        state = self.states[min(self.index, len(self.states) - 1)]
        self.index += 1
        return state


@pytest.fixture
def radio() -> RadioFirmwareIdentity:
    return RadioFirmwareIdentity(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/1-2.3",
        observed_firmware="v0.37",
    )


def _manager(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    *,
    executor: FakeExecutor | None = None,
    clock: MutableClock | None = None,
    probe: object | None = None,
) -> tuple[FirmwareManager, FakeExecutor, MutableClock]:
    fake_executor = executor or FakeExecutor()
    fake_clock = clock or MutableClock()
    identity_probe = probe if callable(probe) else lambda _serial: radio
    return (
        FirmwareManager(
            staging_directory=tmp_path / "stage",
            receipt_directory=tmp_path / "receipts",
            identity_probe=identity_probe,
            executor=fake_executor,
            clock=fake_clock,
            confirmation_ttl=timedelta(minutes=2),
        ),
        fake_executor,
        fake_clock,
    )


def _image(tmp_path: Path, *, name: str = "release.dfu") -> Path:
    path = tmp_path / name
    path.write_bytes(_dfu())
    return path


def test_dfu_and_generated_frm_validate_strictly() -> None:
    dfu = _dfu()
    assert validate_dfu(dfu) == _fit()
    frm = generate_frm(dfu)
    assert validate_frm(frm) == _fit()
    assert frm.endswith(b"\n")


@pytest.mark.parametrize(
    "bad_image, message",
    [
        (b"not firmware", "too short"),
        (_dfu(body=b"x" * 96), "FIT header"),
        (_dfu(vendor=0xFFFF), "expected 0456:b673"),
        (_dfu(product=0xFFFF), "expected 0456:b673"),
        (_dfu()[:-1] + bytes([_dfu()[-1] ^ 1]), "CRC mismatch"),
    ],
)
def test_malformed_dfu_is_rejected(bad_image: bytes, message: str) -> None:
    with pytest.raises(FirmwareImageError, match=message):
        validate_dfu(bad_image)


def test_malformed_frm_is_rejected() -> None:
    good = generate_frm(_dfu())
    with pytest.raises(FirmwareImageError, match="newline"):
        validate_frm(good[:-1] + b"x")
    with pytest.raises(FirmwareImageError, match="MD5 trailer mismatch"):
        validate_frm(good[:-34] + b"X" + good[-33:])


@pytest.mark.parametrize("name", ["boot.frm", "bundle.zip"])
def test_known_bootloader_bearing_inputs_are_refused(
    tmp_path: Path, radio: RadioFirmwareIdentity, name: str
) -> None:
    source = tmp_path / name
    source.write_bytes(_dfu())
    manager, _, _ = _manager(tmp_path, radio)
    with pytest.raises(FirmwareImageError, match="forbidden"):
        manager.create_plan(radio, source, FirmwareMode.PERSISTENT_QSPI)


def test_plan_is_immutable_and_stages_content_addressed_image(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    manager, _, _ = _manager(tmp_path, radio)
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.PERSISTENT_QSPI)
    assert Path(planned.plan.staged_path).name == "pluto.frm"
    assert validate_frm(Path(planned.plan.staged_path).read_bytes()) == _fit()
    with pytest.raises(FrozenInstanceError):
        planned.plan.image_size = 1  # type: ignore[misc]


def test_identity_drift_is_refused_before_token_consumption(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    current = {"identity": radio}
    manager, executor, _ = _manager(
        tmp_path, radio, probe=lambda _serial: current["identity"]
    )
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    current["identity"] = replace(radio, observed_firmware="unexpected")
    with pytest.raises(FirmwareIdentityError, match="changed"):
        manager.execute(planned.plan, planned.confirmation_token)
    assert executor.calls == []


def test_staged_hash_drift_is_refused(tmp_path: Path, radio: RadioFirmwareIdentity) -> None:
    manager, executor, _ = _manager(tmp_path, radio)
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    Path(planned.plan.staged_path).write_bytes(b"tampered")
    with pytest.raises(FirmwareImageError, match="hash or size changed"):
        manager.execute(planned.plan, planned.confirmation_token)
    assert executor.calls == []


def test_confirmation_is_bound_to_the_complete_immutable_plan(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    manager, executor, _ = _manager(tmp_path, radio)
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    forged = replace(planned.plan, source_name="different.dfu")
    with pytest.raises(FirmwareAuthorizationError, match="another plan"):
        manager.execute(forged, planned.confirmation_token)
    assert executor.calls == []


def test_expired_wrong_and_reused_confirmations_are_refused(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    manager, executor, clock = _manager(tmp_path, radio)
    first = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    with pytest.raises(FirmwareAuthorizationError, match="invalid"):
        manager.execute(first.plan, "wrong")
    receipt = manager.execute(first.plan, first.confirmation_token)
    assert receipt.success
    with pytest.raises(FirmwareAuthorizationError, match="already used"):
        manager.execute(first.plan, first.confirmation_token)

    second = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    clock.value += timedelta(minutes=3)
    with pytest.raises(FirmwareAuthorizationError, match="plan has expired"):
        manager.execute(second.plan, second.confirmation_token)
    assert len(executor.calls) == 1


def test_non_root_is_refused(tmp_path: Path, radio: RadioFirmwareIdentity) -> None:
    manager, executor, _ = _manager(tmp_path, radio, executor=FakeExecutor(uid=1000))
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    with pytest.raises(FirmwareAuthorizationError, match="require root"):
        manager.execute(planned.plan, planned.confirmation_token)
    assert executor.calls == []


def test_command_failure_consumes_token_and_writes_failure_receipt(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    manager, executor, _ = _manager(
        tmp_path, radio, executor=FakeExecutor(failure=RuntimeError("dfu-util failed"))
    )
    planned = manager.create_plan(radio, _image(tmp_path), FirmwareMode.VOLATILE_DFU)
    with pytest.raises(FirmwareExecutionError, match="dfu-util failed") as caught:
        manager.execute(planned.plan, planned.confirmation_token)
    assert not caught.value.receipt.success
    receipt_files = list((tmp_path / "receipts").glob("*.json"))
    assert len(receipt_files) == 1
    assert json.loads(receipt_files[0].read_text())["success"] is False
    with pytest.raises(FirmwareAuthorizationError, match="already used"):
        manager.execute(planned.plan, planned.confirmation_token)
    assert len(executor.calls) == 1


@pytest.mark.parametrize(
    ("mode", "expected_call", "expected_name"),
    [
        (FirmwareMode.VOLATILE_DFU, "ram", "firmware.dfu"),
        (FirmwareMode.PERSISTENT_QSPI, "qspi", "pluto.frm"),
    ],
)
def test_successful_fake_operations_create_durable_receipts(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    mode: FirmwareMode,
    expected_call: str,
    expected_name: str,
) -> None:
    manager, executor, _ = _manager(tmp_path, radio)
    planned = manager.create_plan(radio, _image(tmp_path), mode)
    receipt = manager.execute(planned.plan, planned.confirmation_token)
    assert receipt.success and receipt.error is None
    assert executor.calls == [
        (
            expected_call,
            radio,
            Path(planned.plan.staged_path),
            "pluto.frm" if mode is FirmwareMode.PERSISTENT_QSPI else None,
        )
    ]
    assert Path(planned.plan.staged_path).name == expected_name
    payload = json.loads((tmp_path / "receipts" / f"{receipt.receipt_id}.json").read_text())
    assert payload["radio"]["serial"] == "SERIAL_A"
    assert payload["radio"]["usb_sysfs_path"] == radio.usb_sysfs_path
    assert payload["image_sha256"] == planned.plan.image_sha256
    assert payload["mode"] == mode.value
    assert payload["success"] is True


def test_expected_post_update_firmware_is_re_attested(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    current = {"identity": radio}
    manager, executor, _ = _manager(
        tmp_path, radio, probe=lambda _serial: current["identity"]
    )
    planned = manager.create_plan(
        radio,
        _image(tmp_path),
        FirmwareMode.VOLATILE_DFU,
        expected_firmware="v0.99",
    )

    with pytest.raises(FirmwareExecutionError, match="expected 'v0.99'") as caught:
        manager.execute(planned.plan, planned.confirmation_token)

    assert executor.calls[0][0] == "ram"
    assert not caught.value.receipt.success


def test_crc_fixture_is_independent_of_binascii_helper() -> None:
    data = _dfu()[:-4]
    assert _raw_dfu_crc(data) == (binascii.crc32(data) ^ 0xFFFFFFFF)


def _block(serial: str = "SERIAL_A", suffix: str = "a") -> UpdaterBlockDevice:
    return UpdaterBlockDevice(
        device=Path(f"/dev/sd{suffix}"),
        partition=Path(f"/dev/sd{suffix}1"),
        id_serial_short=serial,
    )


def _updater(
    tmp_path: Path,
    states: list[list[UpdaterBlockDevice]],
    *,
    fail_on: str | None = None,
    info: bool = True,
    fail_copy: bool = False,
    timeout: float = 2,
) -> tuple[
    MassStorageQspiUpdater,
    FakeCommandRunner,
    FakeMassStorageFilesystem,
    FakeMonotonic,
]:
    source = tmp_path / "staged" / "pluto.frm"
    commands = FakeCommandRunner(fail_on=fail_on)
    filesystem = FakeMassStorageFilesystem(source, info=info, fail_copy=fail_copy)
    clock = FakeMonotonic()
    updater = MassStorageQspiUpdater(
        enumerate_devices=SequenceEnumerator(states),
        command_runner=commands,
        filesystem=filesystem,
        mountpoint=Path("/run/pluto-plus/firmware-SERIAL_A"),
        monotonic=clock,
        sleep=clock.sleep,
        reenumeration_timeout_s=timeout,
        poll_interval_s=1,
    )
    return updater, commands, filesystem, clock


def test_mass_storage_qspi_success_is_serial_scoped(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    selected = _block()
    other = _block("SERIAL_B", "b")
    updater, commands, filesystem, _ = _updater(
        tmp_path, [[other, selected], [other], [other, selected]]
    )
    updater.install(
        radio,
        tmp_path / "staged" / "pluto.frm",
        target_name="pluto.frm",
    )
    assert filesystem.writes == [
        (
            Path("/run/pluto-plus/firmware-SERIAL_A/pluto.frm"),
            filesystem.source_data,
        )
    ]
    assert commands.calls == [
        (
            "mount",
            "-o",
            "rw,nodev,nosuid,noexec",
            "/dev/sda1",
            "/run/pluto-plus/firmware-SERIAL_A",
        ),
        ("sync", "-f", "/run/pluto-plus/firmware-SERIAL_A/pluto.frm"),
        ("umount", "/run/pluto-plus/firmware-SERIAL_A"),
        ("eject", "/dev/sda"),
    ]


@pytest.mark.parametrize("states, count", [([[]], 0), ([[_block(), _block(suffix="b")]], 2)])
def test_mass_storage_qspi_refuses_zero_or_duplicate_serial_matches(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    states: list[list[UpdaterBlockDevice]],
    count: int,
) -> None:
    updater, commands, filesystem, _ = _updater(tmp_path, states)
    with pytest.raises(FirmwareError, match=f"found {count}"):
        updater.install(radio, filesystem.source, target_name="pluto.frm")
    assert commands.calls == []


def test_mass_storage_qspi_refuses_every_other_target(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    updater, commands, filesystem, _ = _updater(tmp_path, [[_block()]])
    with pytest.raises(FirmwareError, match="only pluto.frm"):
        updater.install(radio, filesystem.source, target_name="boot.frm")
    assert commands.calls == []


def test_mass_storage_qspi_revalidates_source_before_hardware(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    updater, commands, filesystem, _ = _updater(tmp_path, [[_block()]])
    filesystem.source_data = b"not a frm"
    with pytest.raises(FirmwareImageError, match="too short"):
        updater.install(radio, filesystem.source, target_name="pluto.frm")
    assert commands.calls == []


@pytest.mark.parametrize(
    ("fail_on", "message"),
    [
        ("mount", "operation failed: mount failed"),
        ("sync", "operation failed: sync failed"),
        ("umount", "unmount failed: umount failed"),
        ("eject", "eject failed"),
    ],
)
def test_mass_storage_qspi_command_failures_fail_closed(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    fail_on: str,
    message: str,
) -> None:
    updater, commands, filesystem, _ = _updater(
        tmp_path, [[_block()], [], [_block()]], fail_on=fail_on
    )
    with pytest.raises(FirmwareError, match=message):
        updater.install(radio, filesystem.source, target_name="pluto.frm")
    if fail_on in {"mount", "sync", "umount"}:
        assert any(call[0] == "umount" for call in commands.calls)
    if fail_on != "eject":
        assert not any(call[0] == "eject" for call in commands.calls)


@pytest.mark.parametrize(
    ("info", "fail_copy", "message"),
    [
        (False, False, "no info.html"),
        (True, True, "copy failed"),
    ],
)
def test_mass_storage_qspi_volume_or_copy_failure_always_unmounts(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    info: bool,
    fail_copy: bool,
    message: str,
) -> None:
    updater, commands, filesystem, _ = _updater(
        tmp_path, [[_block()]], info=info, fail_copy=fail_copy
    )
    with pytest.raises(FirmwareError, match=message):
        updater.install(radio, filesystem.source, target_name="pluto.frm")
    assert commands.calls[-1][0] == "umount"
    assert not any(call[0] == "eject" for call in commands.calls)


def test_mass_storage_qspi_requires_disappearance(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    updater, _, filesystem, _ = _updater(tmp_path, [[_block()]], timeout=2)
    with pytest.raises(FirmwareError, match="did not disappear"):
        updater.install(radio, filesystem.source, target_name="pluto.frm")


def test_mass_storage_qspi_requires_reappearance(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    updater, _, filesystem, _ = _updater(tmp_path, [[_block()], []], timeout=2)
    with pytest.raises(FirmwareError, match="did not reappear"):
        updater.install(radio, filesystem.source, target_name="pluto.frm")


def test_mass_storage_qspi_refuses_duplicates_during_reenumeration(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    updater, _, filesystem, _ = _updater(
        tmp_path, [[_block()], [], [_block(), _block(suffix="b")]]
    )
    with pytest.raises(FirmwareError, match="duplicate updater identities"):
        updater.install(radio, filesystem.source, target_name="pluto.frm")


def test_local_mass_storage_filesystem_uses_same_volume_replace(tmp_path: Path) -> None:
    filesystem = LocalMassStorageFilesystem()
    mountpoint = tmp_path / "private-mount"
    filesystem.prepare_private_mountpoint(mountpoint)
    target = mountpoint / "pluto.frm"
    filesystem.write_fat_atomic(target, b"new firmware")
    assert target.read_bytes() == b"new firmware"
    assert list(mountpoint.iterdir()) == [target]


def test_sysfs_identity_probe_requires_one_exact_runtime_serial() -> None:
    root = Path("/sys/bus/usb/devices")
    pluto = root / "1-2.3"
    other = root / "1-2.4"
    values = {
        pluto / "idVendor": "0456\n",
        pluto / "idProduct": "b673\n",
        pluto / "serial": "SERIAL_A\n",
        other / "idVendor": "ffff\n",
        other / "idProduct": "b673\n",
        other / "serial": "SERIAL_A\n",
    }
    observed_calls: list[tuple[str, str]] = []

    def observed(serial: str, path: str) -> str:
        observed_calls.append((serial, path))
        return "v0.38\n"

    probe = SysfsRadioFirmwareIdentityProbe(
        enumerate_devices=lambda: [other, pluto],
        text_reader=values.__getitem__,
        observed_firmware_reader=observed,
    )
    identity = probe("SERIAL_A")
    assert identity == RadioFirmwareIdentity("SERIAL_A", str(pluto), "v0.38")
    assert observed_calls == [("SERIAL_A", str(pluto))]


def test_sysfs_identity_probe_fails_closed_on_missing_duplicate_or_empty_firmware() -> None:
    root = Path("/sys/bus/usb/devices")
    first, second = root / "1-1", root / "1-2"
    values = {
        path / attribute: value
        for path in (first, second)
        for attribute, value in (
            ("idVendor", "0456"),
            ("idProduct", "b673"),
            ("serial", "SERIAL_A"),
        )
    }
    missing = SysfsRadioFirmwareIdentityProbe(
        enumerate_devices=lambda: [],
        text_reader=values.__getitem__,
        observed_firmware_reader=lambda _serial, _path: "v0.38",
    )
    with pytest.raises(FirmwareIdentityError, match="found 0"):
        missing("SERIAL_A")
    duplicate = SysfsRadioFirmwareIdentityProbe(
        enumerate_devices=lambda: [first, second],
        text_reader=values.__getitem__,
        observed_firmware_reader=lambda _serial, _path: "v0.38",
    )
    with pytest.raises(FirmwareIdentityError, match="found 2"):
        duplicate("SERIAL_A")
    empty = SysfsRadioFirmwareIdentityProbe(
        enumerate_devices=lambda: [first],
        text_reader=values.__getitem__,
        observed_firmware_reader=lambda _serial, _path: " ",
    )
    with pytest.raises(FirmwareIdentityError, match="empty"):
        empty("SERIAL_A")
