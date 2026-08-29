from __future__ import annotations

import binascii
import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import pluto_plus.service as service_module
from pluto_plus.admin import AdminMutationPolicy
from pluto_plus.api import API_PREFIX, create_app
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
    FirmwareAuthorizationError,
    FirmwareExecutionError,
    FirmwareExecutorFailure,
    FirmwareManager,
    FirmwareTransport,
    RadioFirmwareIdentity,
)
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import RadioCapabilities, RadioIdentity, Transport
from pluto_plus.service import PlutoService

TOKEN = "test-admin-token-with-at-least-32-characters"
ORIGIN = "http://testserver"


class NetworkFakeRadio(FakeRadioDevice):
    def __init__(self, serial: str, host: str, firmware: str) -> None:
        super().__init__(serial)
        self._identity = RadioIdentity(
            radio_id=serial,
            serial=serial,
            uri=f"ip:{host}",
            transport=Transport.IIO_IP,
            model="PlutoSDR Rev.C",
            firmware_version=firmware,
        )
        self._capabilities = RadioCapabilities(supports_persistent_firmware=False)


@dataclass(frozen=True)
class Evidence:
    attempt_id: str = "attempt-safe-reference"
    completed_phases: tuple[str, ...] = ("frm_staged", "mtd_verified")
    failure_phase: str = "post_reboot_attestation"
    outcome: str = "uncertain"
    reconciliation_required: bool = True


class UncertainExecution(RuntimeError):
    def __init__(self) -> None:
        super().__init__("radio did not return through the pinned SSH identity")
        self.evidence = Evidence()


class FakeIpExecutor:
    def __init__(self, identity: RadioFirmwareIdentity) -> None:
        self.identity = identity
        self.flash_calls = 0
        self.reconcile_calls = 0

    def authorize_execution(self) -> None:
        return

    def identity_probe(self, serial: str) -> RadioFirmwareIdentity:
        assert serial == self.identity.serial
        return self.identity

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        raise AssertionError("SSH transport must never dispatch DFU")

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        self.flash_calls += 1
        raise UncertainExecution()

    def reconcile_persistent_qspi(
        self, radio: RadioFirmwareIdentity, **kwargs: object
    ) -> tuple[str, ...]:
        self.reconcile_calls += 1
        self.identity = RadioFirmwareIdentity(
            serial=radio.serial,
            usb_sysfs_path=None,
            observed_firmware="canonical-v1",
            endpoint=radio.endpoint,
            host_key_fingerprint=radio.host_key_fingerprint,
        )
        return ("reconciled_qspi_fit_verified",)


class VerifiedRotatedKeyExecutor(FakeIpExecutor):
    def __init__(self, identity: RadioFirmwareIdentity) -> None:
        super().__init__(identity)
        self.last_evidence = None
        self.key_reconciliation_required = False

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        from pluto_plus.firmware import validate_frm

        self.flash_calls += 1
        data = image.read_bytes()
        fit = validate_frm(data)
        phases = (
            "local_validation",
            "remote_preflight",
            "tx_safe_before_update",
            "remote_stage_verified",
            "update_frm_completed",
            "qspi_fit_verified",
            "remote_stage_cleaned",
            "sync_completed",
            "reset_dispatched",
            "post_reset_attestation",
            "tx_safe_after_reset",
            "ssh_reenrollment_required",
        )
        self.last_evidence = SimpleNamespace(
            attempt_id="verified-attempt",
            finished_at="finished",
            outcome="unknown",
            frm_sha256=hashlib.sha256(data).hexdigest(),
            frm_size=len(data),
            fit_sha256=hashlib.sha256(fit).hexdigest(),
            fit_size=len(fit),
            qspi=SimpleNamespace(
                fit_sha256=hashlib.sha256(fit).hexdigest(), fit_size=len(fit)
            ),
            after=SimpleNamespace(
                serial=radio.serial,
                endpoint=radio.endpoint,
                active_firmware="canonical-v1",
            ),
            completed_phases=phases,
            key_reconciliation_required=True,
        )
        self.key_reconciliation_required = True
        raise FirmwareExecutorFailure(
            "pinned SSH host key changed after reset",
            outcome="unknown",
            completed_phases=phases,
            failure_phase="ssh_reenrollment_required",
            reconciliation_required=True,
            evidence_reference="verified-attempt",
        )

    def reconcile_persistent_qspi(
        self, radio: RadioFirmwareIdentity, **kwargs: object
    ) -> tuple[str, ...]:
        phases = super().reconcile_persistent_qspi(radio, **kwargs)
        self.key_reconciliation_required = False
        return phases


def _dfu() -> tuple[bytes, bytes]:
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
    return partial + (binascii.crc32(partial) ^ 0xFFFFFFFF).to_bytes(4, "little"), bytes(fit)


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}


def test_ssh_only_canonical_plan_confirmation_unknown_and_reconcile(
    tmp_path: Path, monkeypatch
) -> None:
    image, fit = _dfu()
    policy = service_module.PERSISTENT_UPGRADE_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image).hexdigest(),
            "fit_body_sha256": hashlib.sha256(fit).hexdigest(),
            "fit_body_size": len(fit),
            "device_firmware": "canonical-v1",
        }
    )
    monkeypatch.setattr(service_module, "PERSISTENT_UPGRADE_POLICY", policy)
    serial = "ip-radio-1"
    radio = NetworkFakeRadio(serial, "192.168.2.15", "old-v1")
    identity = RadioFirmwareIdentity(
        serial=serial,
        usb_sysfs_path=None,
        observed_firmware="old-v1",
        endpoint="192.168.2.15",
        host_key_fingerprint="SHA256:dGVzdA==",
    )
    executor = FakeIpExecutor(identity)
    manager = FirmwareManager(
        staging_directory=tmp_path / "stage",
        receipt_directory=tmp_path / "receipts",
        identity_probe=executor.identity_probe,
        executor=executor,
        transport=FirmwareTransport.SSH_FRM,
    )
    service = PlutoService(
        tmp_path / "state",
        (radio, NetworkFakeRadio("unenrolled", "192.168.2.21", "old-v1")),
        ip_firmware_managers={serial: manager},
    )
    policy_auth = AdminMutationPolicy(token=TOKEN, allowed_origins={ORIGIN})
    with TestClient(create_app(service, admin_policy=policy_auth)) as client:
        status = client.get(f"{API_PREFIX}/firmware").json()
        assert status["available"] is True
        assert status["transports"]["usb"]["available"] is False
        assert status["transports"]["ssh_frm"]["enrolled_radio_ids"] == [serial]
        doctor = client.get(f"{API_PREFIX}/radios/{serial}/doctor").json()
        helper_finding = next(
            item for item in doctor["findings"] if item["code"] == "firmware.helper"
        )
        assert helper_finding["status"] == "pass"

        uploaded = client.post(
            f"{API_PREFIX}/firmware/images",
            params={"filename": "canonical.dfu"},
            content=image,
            headers=_headers(),
        )
        assert uploaded.status_code == 201
        image_id = uploaded.json()["image_id"]
        assert client.get(f"{API_PREFIX}/firmware/images").status_code == 200

        unenrolled = client.post(
            f"{API_PREFIX}/radios/unenrolled/doctor/firmware-plans",
            json={
                "image_id": image_id,
                "mode": "persistent_qspi",
                "transport": "ssh_frm",
            },
            headers=_headers(),
        )
        assert unenrolled.status_code == 503
        assert unenrolled.json()["error"]["code"] == "firmware_unavailable"

        plan_response = client.post(
            f"{API_PREFIX}/radios/{serial}/doctor/firmware-plans",
            json={
                "image_id": image_id,
                "mode": "persistent_qspi",
                "transport": "ssh_frm",
            },
            headers=_headers(),
        )
        assert plan_response.status_code == 201, plan_response.text
        planned = plan_response.json()
        assert planned["plan"]["transport"] == "ssh_frm"
        assert planned["plan"]["transport_summary"]["endpoint"] == "192.168.2.15"
        assert "private_key" not in plan_response.text

        noncanonical_route = client.post(
            f"{API_PREFIX}/radios/{serial}/firmware/plans",
            json={
                "image_id": image_id,
                "mode": "persistent_qspi",
                "transport": "ssh_frm",
            },
            headers=_headers(),
        )
        assert noncanonical_route.status_code == 422
        assert noncanonical_route.json()["error"]["code"] == (
            "ssh_firmware_requires_canonical_route"
        )

        denied = client.post(
            f"{API_PREFIX}/firmware/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
            },
            headers=_headers(),
        )
        assert denied.status_code == 403
        assert executor.flash_calls == 0

        # A denied confirmation does not consume the one-time plan token.
        failed = client.post(
            f"{API_PREFIX}/firmware/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
                "operator_confirmation": f"FLASH {serial}",
            },
            headers=_headers(),
        )
        assert failed.status_code == 500
        receipt = failed.json()["receipt"]
        assert receipt["outcome"] == "unknown"
        assert receipt["reconciliation_required"] is True
        assert receipt["evidence_reference"] == "attempt-safe-reference"
        assert "mtd_verified" in receipt["completed_phases"]
        blocked_doctor = client.get(f"{API_PREFIX}/radios/{serial}/doctor").json()
        blocked_helper = next(
            item
            for item in blocked_doctor["findings"]
            if item["code"] == "firmware.helper"
        )
        assert blocked_helper["status"] == "warn"

        reconciled = client.post(
            f"{API_PREFIX}/firmware/receipts/{receipt['receipt_id']}/reconcile",
            json={},
            headers=_headers(),
        )
        assert reconciled.status_code == 200, reconciled.text
        assert reconciled.json()["outcome"] == "success"
        healthy_doctor = client.get(f"{API_PREFIX}/radios/{serial}/doctor").json()
        healthy_helper = next(
            item
            for item in healthy_doctor["findings"]
            if item["code"] == "firmware.helper"
        )
        assert healthy_helper["status"] == "pass"
        assert executor.flash_calls == 1
        assert executor.reconcile_calls == 1


def test_ssh_mutation_rejects_remote_plaintext_before_auth(tmp_path: Path) -> None:
    service = PlutoService(tmp_path / "state", (NetworkFakeRadio("r1", "192.168.2.15", "v1"),))
    policy = AdminMutationPolicy(token=TOKEN, allowed_origins={"http://gauss:8765"})
    with TestClient(
        create_app(service, admin_policy=policy),
        base_url="http://gauss:8765",
        client=("192.0.2.20", 50000),
    ) as client:
        response = client.post(
            f"{API_PREFIX}/radios/r1/firmware/plans",
            json={"image_id": "none", "mode": "persistent_qspi", "transport": "ssh_frm"},
            headers={"Authorization": f"Bearer {TOKEN}", "Origin": "http://gauss:8765"},
        )
        assert response.status_code == 426
        assert response.json()["error"]["code"] == "admin_secure_transport_required"


def test_rotated_key_remains_unknown_and_blocks_preissued_plan_without_auto_trust(
    tmp_path: Path,
) -> None:
    image, _fit = _dfu()
    source = tmp_path / "canonical.dfu"
    source.write_bytes(image)
    identity = RadioFirmwareIdentity(
        serial="SERIAL_A",
        usb_sysfs_path=None,
        observed_firmware="old-v1",
        endpoint="192.168.2.15",
        host_key_fingerprint="SHA256:dGVzdA==",
    )
    executor = VerifiedRotatedKeyExecutor(identity)
    manager = FirmwareManager(
        staging_directory=tmp_path / "stage",
        receipt_directory=tmp_path / "receipts",
        identity_probe=executor.identity_probe,
        executor=executor,
        transport=FirmwareTransport.SSH_FRM,
    )
    planned = manager.create_plan(
        identity,
        source,
        service_module.FirmwareMode.PERSISTENT_QSPI,
        expected_firmware="canonical-v1",
    )
    preissued = manager.create_plan(
        identity,
        source,
        service_module.FirmwareMode.PERSISTENT_QSPI,
        expected_firmware="canonical-v1",
    )
    with pytest.raises(FirmwareExecutionError) as caught:
        manager.execute(
            planned.plan,
            planned.confirmation_token,
            operator_confirmation="FLASH SERIAL_A",
        )
    receipt = caught.value.receipt

    assert receipt.success is False
    assert receipt.outcome == "unknown"
    assert receipt.reconciliation_required is True
    assert receipt.evidence_reference == "verified-attempt"
    assert manager.key_reconciliation_required is True
    with pytest.raises(FirmwareAuthorizationError, match="unresolved durable receipts"):
        manager.execute(
            preissued.plan,
            preissued.confirmation_token,
            operator_confirmation="FLASH SERIAL_A",
        )
    assert executor.flash_calls == 1

    restarted_executor = VerifiedRotatedKeyExecutor(identity)
    restarted = FirmwareManager(
        staging_directory=tmp_path / "stage",
        receipt_directory=tmp_path / "receipts",
        identity_probe=restarted_executor.identity_probe,
        executor=restarted_executor,
        transport=FirmwareTransport.SSH_FRM,
    )
    assert restarted.key_reconciliation_required is True
    with pytest.raises(FirmwareAuthorizationError, match="unresolved durable receipts"):
        restarted.create_plan(
            identity,
            source,
            service_module.FirmwareMode.PERSISTENT_QSPI,
            expected_firmware="canonical-v1",
        )

    real_reconcile = executor.reconcile_persistent_qspi

    def failed_reconcile(
        radio: RadioFirmwareIdentity, **kwargs: object
    ) -> tuple[str, ...]:
        del radio, kwargs
        raise RuntimeError("pinned host identity is still unavailable")

    executor.reconcile_persistent_qspi = failed_reconcile  # type: ignore[method-assign]
    failed_reconciliation = manager.reconcile(receipt.receipt_id)
    assert failed_reconciliation.success is False
    assert failed_reconciliation.reconciliation_of == receipt.receipt_id
    assert manager.key_reconciliation_required is True

    executor.reconcile_persistent_qspi = real_reconcile  # type: ignore[method-assign]
    successful_reconciliation = manager.reconcile(
        failed_reconciliation.receipt_id
    )
    assert successful_reconciliation.success is True
    assert successful_reconciliation.reconciliation_of == receipt.receipt_id
    assert manager.key_reconciliation_required is False
    resolved_restart_executor = VerifiedRotatedKeyExecutor(executor.identity)
    resolved_restart = FirmwareManager(
        staging_directory=tmp_path / "stage",
        receipt_directory=tmp_path / "receipts",
        identity_probe=resolved_restart_executor.identity_probe,
        executor=resolved_restart_executor,
        transport=FirmwareTransport.SSH_FRM,
    )
    assert resolved_restart.key_reconciliation_required is False
