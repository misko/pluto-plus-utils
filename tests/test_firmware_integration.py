from __future__ import annotations

import binascii
from pathlib import Path

from fastapi.testclient import TestClient

from pluto_plus.api import API_PREFIX, create_app
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
    FirmwareManager,
    RadioFirmwareIdentity,
)
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.service import PlutoService


def _dfu() -> bytes:
    fit = bytearray(96)
    fit[:4] = FIT_MAGIC
    fit[4:8] = len(fit).to_bytes(4, "big")
    fit[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    suffix = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            DFU_PRODUCT_ID.to_bytes(2, "little"),
            DFU_VENDOR_ID.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD\x10",
        )
    )
    partial = bytes(fit) + suffix
    crc = binascii.crc32(partial) ^ 0xFFFFFFFF
    return partial + crc.to_bytes(4, "little")


class FakePrivilegedExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def effective_uid(self) -> int:
        return 0

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        self.calls.append(("volatile", radio.serial, image.name))

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        self.calls.append(("persistent", radio.serial, target_name))


def test_unconfigured_firmware_surface_fails_closed(tmp_path: Path) -> None:
    service = PlutoService(tmp_path / "state", (FakeRadioDevice(),))
    with TestClient(create_app(service)) as client:
        status = client.get(f"{API_PREFIX}/firmware")
        assert status.status_code == 200
        assert status.json()["available"] is False

        upload = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "candidate.dfu"},
            content=_dfu(),
        )
        assert upload.status_code == 503
        assert upload.json()["error"]["code"] == "firmware_unavailable"


def test_api_firmware_plan_execute_reopens_and_receipts(tmp_path: Path) -> None:
    radio = FakeRadioDevice(firmware_capable=True)
    executor = FakePrivilegedExecutor()
    identity = RadioFirmwareIdentity(
        serial="fake-001",
        usb_sysfs_path="/sys/bus/usb/devices/fake-001",
        observed_firmware="fake-v1",
    )

    def probe(serial: str) -> RadioFirmwareIdentity:
        if serial != identity.serial:
            raise RuntimeError(f"unexpected serial: {serial}")
        return identity

    manager = FirmwareManager(
        staging_directory=tmp_path / "firmware-stage",
        receipt_directory=tmp_path / "firmware-receipts",
        identity_probe=probe,
        executor=executor,
    )
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        firmware_manager=manager,
    )

    with TestClient(create_app(service)) as client:
        uploaded = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "candidate.dfu"},
            content=_dfu(),
        )
        assert uploaded.status_code == 201
        image_id = uploaded.json()["image_id"]

        canonical = client.post(
            f"{API_PREFIX}/radios/fake-001/doctor/firmware-plans",
            json={"image_id": image_id, "mode": "volatile_dfu"},
        )
        assert canonical.status_code == 422
        assert canonical.json()["error"]["code"] == "firmware_validation_failed"
        assert "selected canonical release" in canonical.json()["error"]["message"]

        planned = client.post(
            f"{API_PREFIX}/radios/fake-001/firmware/plans",
            json={
                "image_id": image_id,
                "mode": "volatile_dfu",
                "expected_firmware_version": "fake-v1",
            },
        )
        assert planned.status_code == 201
        plan = planned.json()
        assert plan["plan"]["radio"]["serial"] == "fake-001"
        assert plan["plan"]["image_sha256"] == image_id

        executed = client.post(
            f"{API_PREFIX}/firmware/executions",
            json={
                "plan_id": plan["plan"]["plan_id"],
                "confirmation_token": plan["confirmation_token"],
            },
        )
        assert executed.status_code == 201
        assert executed.json()["success"] is True
        assert executor.calls == [("volatile", "fake-001", "firmware.dfu")]

        snapshot = client.get(f"{API_PREFIX}/radios/fake-001").json()
        assert snapshot["state"] == "ready"
        assert snapshot["revision"] == 1
        receipts = client.get(f"{API_PREFIX}/firmware/receipts").json()
        assert [item["receipt_id"] for item in receipts] == [executed.json()["receipt_id"]]
