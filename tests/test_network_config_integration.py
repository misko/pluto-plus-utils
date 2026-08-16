from __future__ import annotations

import hashlib
from pathlib import Path

from fastapi.testclient import TestClient

from pluto_plus.admin import AdminMutationPolicy
from pluto_plus.api import API_PREFIX, create_app
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import RadioCapabilities, RadioIdentity, Transport
from pluto_plus.network_config import (
    NetworkConfigExecutionResult,
    NetworkConfigIdentity,
    NetworkConfigManager,
    NetworkConfigObservation,
    NetworkConfigPlan,
    persistent_environment_sha256,
)
from pluto_plus.service import PlutoService

TOKEN = "network-config-admin-token-with-32-bytes"
ORIGIN = "http://testserver"
SERIAL = "NETWORK_RADIO_A"


class NetworkRadio(FakeRadioDevice):
    def __init__(self) -> None:
        super().__init__(SERIAL)
        self._identity = RadioIdentity(
            radio_id=SERIAL,
            serial=SERIAL,
            uri="ip:192.168.1.165",
            transport=Transport.IIO_IP,
            model="PlutoSDR Rev.C",
            firmware_version="canonical-v1",
        )
        self._capabilities = RadioCapabilities()


class Backend:
    def __init__(self, identity: NetworkConfigIdentity) -> None:
        self.values = {
            "ipaddr": "192.168.2.1",
            "ipaddr_host": "192.168.2.10",
            "netmask": "255.255.255.0",
            "ipaddr_eth": "",
            "netmask_eth": "255.255.255.0",
        }
        self.identity = identity
        self.apply_calls = 0

    def inspect_network_config(self, serial: str) -> NetworkConfigObservation:
        assert serial == SERIAL
        return NetworkConfigObservation(
            identity=self.identity,
            config_txt_sha256="a" * 64,
            environment_sha256=persistent_environment_sha256(self.values),
            config_txt_redacted=(
                "[NETWORK]\r\nipaddr = 192.168.2.1\r\n"
                "[WLAN]\r\npwd_wlan = <redacted>\r\n"
            ),
            hostname="pluto",
            usb_radio_address=self.values["ipaddr"],
            usb_host_address=self.values["ipaddr_host"],
            usb_netmask=self.values["netmask"],
            ethernet_address=self.values["ipaddr_eth"] or None,
            ethernet_netmask=self.values["netmask_eth"],
        )

    def apply_network_config(
        self, plan: NetworkConfigPlan
    ) -> NetworkConfigExecutionResult:
        self.apply_calls += 1
        self.values.update(plan.changes)
        backup = b"complete persistent environment\n"
        return NetworkConfigExecutionResult(
            observation=self.inspect_network_config(SERIAL),
            backup_path="/root/.pluto-plus-network-config/backup.env",
            backup_sha256=hashlib.sha256(backup).hexdigest(),
            backup_content=backup,
            completed_phases=(
                "identity_attested",
                "environment_revalidated",
                "backup_persisted",
                "environment_written",
                "persistent_readback_verified",
            ),
        )


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {TOKEN}", "Origin": ORIGIN}


def _service(tmp_path: Path) -> tuple[PlutoService, Backend]:
    identity = NetworkConfigIdentity(
        serial=SERIAL,
        endpoint="192.168.1.165",
        host_key_fingerprint="SHA256:" + "A" * 43,
    )
    backend = Backend(identity)
    manager = NetworkConfigManager(
        identity=identity,
        backend=backend,
        receipt_directory=tmp_path / "network-receipts",
    )
    return (
        PlutoService(
            tmp_path / "state",
            (NetworkRadio(),),
            network_config_managers={SERIAL: manager},
        ),
        backend,
    )


def test_authenticated_read_plan_execute_and_receipt_flow(tmp_path: Path) -> None:
    service, backend = _service(tmp_path)
    policy = AdminMutationPolicy(token=TOKEN, allowed_origins={ORIGIN})
    with TestClient(create_app(service, admin_policy=policy)) as client:
        status = client.get(f"{API_PREFIX}/network-config")
        assert status.status_code == 200
        assert status.json()["available"] is True
        assert status.json()["enrolled_radio_ids"] == [SERIAL]

        denied = client.get(f"{API_PREFIX}/radios/{SERIAL}/config")
        assert denied.status_code == 403
        observed = client.get(
            f"{API_PREFIX}/radios/{SERIAL}/config", headers=_headers()
        )
        assert observed.status_code == 200
        assert observed.json()["ethernet_address"] is None
        assert "<redacted>" in observed.json()["config_txt_redacted"]

        planned = client.post(
            f"{API_PREFIX}/radios/{SERIAL}/config/plans",
            json={
                "interface": "ethernet",
                "mode": "static",
                "address": "192.168.1.165",
                "netmask": "255.255.255.0",
                "host_address": None,
            },
            headers=_headers(),
        )
        assert planned.status_code == 201, planned.text
        document = planned.json()
        assert document["plan"]["confirmation"] == (
            f"SET STATIC IP {SERIAL} 192.168.1.165"
        )
        assert document["plan"]["changes_items"] == [
            ["ipaddr_eth", "192.168.1.165"]
        ]

        denied_execution = client.post(
            f"{API_PREFIX}/network-config/executions",
            json={
                "plan_id": document["plan"]["plan_id"],
                "confirmation_token": document["confirmation_token"],
                "operator_confirmation": SERIAL,
            },
            headers=_headers(),
        )
        assert denied_execution.status_code == 403
        assert backend.apply_calls == 0

        executed = client.post(
            f"{API_PREFIX}/network-config/executions",
            json={
                "plan_id": document["plan"]["plan_id"],
                "confirmation_token": document["confirmation_token"],
                "operator_confirmation": document["plan"]["confirmation"],
            },
            headers=_headers(),
        )
        assert executed.status_code == 201, executed.text
        receipt = executed.json()
        assert receipt["outcome"] == "persisted_restart_required"
        assert receipt["restart_required"] is True
        assert receipt["endpoint_after_restart"] == "192.168.1.165"
        assert backend.apply_calls == 1
        assert service.get_radio(SERIAL).state == "ready"

        denied_receipts = client.get(f"{API_PREFIX}/network-config/receipts")
        assert denied_receipts.status_code == 403
        receipts = client.get(
            f"{API_PREFIX}/network-config/receipts", headers=_headers()
        )
        assert receipts.status_code == 200
        assert receipts.json()[0]["receipt_id"] == receipt["receipt_id"]


def test_surface_fails_closed_without_enrollment_auth_or_secure_transport(
    tmp_path: Path,
) -> None:
    unconfigured = PlutoService(tmp_path / "unconfigured", (NetworkRadio(),))
    with TestClient(create_app(unconfigured)) as client:
        assert client.get(f"{API_PREFIX}/network-config").json()["available"] is False
        response = client.get(f"{API_PREFIX}/radios/{SERIAL}/config")
        assert response.status_code == 503

    service, _ = _service(tmp_path / "remote")
    policy = AdminMutationPolicy(token=TOKEN, allowed_origins={"http://gauss:8765"})
    with TestClient(
        create_app(service, admin_policy=policy),
        base_url="http://gauss:8765",
        client=("192.0.2.20", 50000),
    ) as client:
        status = client.get(f"{API_PREFIX}/network-config").json()
        assert status["secure_transport"] is False
        assert status["available"] is False
        response = client.post(
            f"{API_PREFIX}/radios/{SERIAL}/config/plans",
            json={
                "interface": "ethernet",
                "mode": "dhcp",
                "address": None,
                "netmask": None,
                "host_address": None,
            },
            headers={
                "Authorization": f"Bearer {TOKEN}",
                "Origin": "http://gauss:8765",
            },
        )
        assert response.status_code == 426
        assert response.json()["error"]["code"] == "admin_secure_transport_required"
