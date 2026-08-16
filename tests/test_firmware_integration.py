from __future__ import annotations

import binascii
from pathlib import Path

from fastapi.testclient import TestClient

from pluto_plus.admin import AdminMutationPolicy
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

_ADMIN_TOKEN = "test-admin-token-with-at-least-32-characters"
_ADMIN_ORIGIN = "http://testserver"


def _admin_policy() -> AdminMutationPolicy:
    return AdminMutationPolicy(
        token=_ADMIN_TOKEN,
        allowed_origins={_ADMIN_ORIGIN},
    )


def _admin_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {_ADMIN_TOKEN}",
        "Origin": _ADMIN_ORIGIN,
    }


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
    with TestClient(create_app(service, admin_policy=_admin_policy())) as client:
        status = client.get(f"{API_PREFIX}/firmware")
        assert status.status_code == 200
        assert status.json()["available"] is False

        upload = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "candidate.dfu"},
            content=_dfu(),
            headers=_admin_headers(),
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

    with TestClient(create_app(service, admin_policy=_admin_policy())) as client:
        uploaded = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "candidate.dfu"},
            content=_dfu(),
            headers=_admin_headers(),
        )
        assert uploaded.status_code == 201
        image_id = uploaded.json()["image_id"]

        canonical = client.post(
            f"{API_PREFIX}/radios/fake-001/doctor/firmware-plans",
            json={"image_id": image_id, "mode": "volatile_dfu"},
            headers=_admin_headers(),
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
            headers=_admin_headers(),
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
            headers=_admin_headers(),
        )
        assert executed.status_code == 201
        assert executed.json()["success"] is True
        assert executor.calls == [("volatile", "fake-001", "firmware.dfu")]

        snapshot = client.get(f"{API_PREFIX}/radios/fake-001").json()
        assert snapshot["state"] == "ready"
        assert snapshot["revision"] == 1
        denied_receipts = client.get(f"{API_PREFIX}/firmware/receipts")
        assert denied_receipts.status_code == 403
        receipts = client.get(
            f"{API_PREFIX}/firmware/receipts", headers=_admin_headers()
        ).json()
        assert [item["receipt_id"] for item in receipts] == [executed.json()["receipt_id"]]


def test_configured_firmware_helper_is_not_exposed_without_admin_policy(
    tmp_path: Path,
) -> None:
    radio = FakeRadioDevice(firmware_capable=True)
    executor = FakePrivilegedExecutor()
    identity = RadioFirmwareIdentity(
        serial="fake-001",
        usb_sysfs_path="/sys/bus/usb/devices/fake-001",
        observed_firmware="fake-v1",
    )
    manager = FirmwareManager(
        staging_directory=tmp_path / "firmware-stage",
        receipt_directory=tmp_path / "firmware-receipts",
        identity_probe=lambda _serial: identity,
        executor=executor,
    )
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        firmware_manager=manager,
    )

    with TestClient(create_app(service)) as client:
        status = client.get(f"{API_PREFIX}/firmware")
        assert status.status_code == 200
        assert status.json()["helper_available"] is True
        assert status.json()["admin_authentication_configured"] is False
        assert status.json()["available"] is False

        refused = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "candidate.dfu"},
            content=_dfu(),
        )
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "admin_authentication_unavailable"
    assert executor.calls == []


def test_firmware_mutation_rejects_bad_bearer_and_browser_origin(tmp_path: Path) -> None:
    radio = FakeRadioDevice(firmware_capable=True)
    executor = FakePrivilegedExecutor()
    identity = RadioFirmwareIdentity(
        serial="fake-001",
        usb_sysfs_path="/sys/bus/usb/devices/fake-001",
        observed_firmware="fake-v1",
    )
    manager = FirmwareManager(
        staging_directory=tmp_path / "firmware-stage",
        receipt_directory=tmp_path / "firmware-receipts",
        identity_probe=lambda _serial: identity,
        executor=executor,
    )
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        firmware_manager=manager,
    )

    with TestClient(create_app(service, admin_policy=_admin_policy())) as client:
        for headers in (
            {"Origin": _ADMIN_ORIGIN},
            {
                "Authorization": f"Bearer {_ADMIN_TOKEN}",
                "Origin": "http://attacker.invalid",
            },
            {
                "Authorization": f"Bearer {_ADMIN_TOKEN}",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            },
        ):
            refused = client.post(
                f"{API_PREFIX}/firmware/images",
                params={"filename": "candidate.dfu"},
                content=_dfu(),
                headers=headers,
            )
            assert refused.status_code == 403
            assert refused.json()["error"]["code"] == "admin_authentication_failed"
    assert executor.calls == []
