from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from pluto_plus.admin import AdminMutationPolicy
from pluto_plus.api import API_PREFIX, create_app
from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT
from pluto_plus.errors import RadioSetupRequiredError
from pluto_plus.hardware.fake import FakeRadioDevice
from pluto_plus.models import RadioIdentity, Transport
from pluto_plus.service import PlutoService
from pluto_plus.setup import (
    CanonicalSetupManager,
    SetupExecutionResult,
    SetupExecutorFailure,
    SetupIdentity,
    SetupObservation,
    SetupPlan,
    SetupUnavailableError,
)
from pluto_plus.setup_profiles import (
    AD9361_1R1T_CLEAR_ATTR_PROFILE,
    AD9363A_1R1T_CLEAR_ATTR_PROFILE,
    SetupTarget,
)

ADMIN_TOKEN = "setup-admin-token-is-at-least-32-bytes"
ALLOWED_ORIGIN = "http://127.0.0.1"
AUTH_HEADERS = {
    "Authorization": f"Bearer {ADMIN_TOKEN}",
    "Origin": ALLOWED_ORIGIN,
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


class RepairableFakeRadio(FakeRadioDevice):
    """A fake whose passive doctor facts change only after setup execution."""

    def __init__(self) -> None:
        super().__init__(serial="SERIAL_A", firmware_capable=True)
        self._identity = RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
            firmware_version=CANONICAL_POLICY.device_firmware,
            usb_path="/sys/bus/usb/devices/3-8",
        )
        self.open_count = 0
        self.close_count = 0
        self._canonical = False

    def open(self) -> None:
        super().open()
        self.open_count += 1

    def close(self) -> None:
        super().close()
        self.close_count += 1

    def diagnostic_facts(self) -> Mapping[str, object]:
        return {
            "phy_model": "ad9361" if self._canonical else "ad9363a",
            "buffer_metadata": True,
            "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
            "rx_lo_5g8_accepted": self._canonical,
            "rx_lo_5g8_readback_hz": 5_800_000_000 if self._canonical else None,
            "rx_lo_restored": self._canonical,
            "uboot": CANONICAL_UBOOT
            if self._canonical
            else {
                "attr_name": "compatible",
                "attr_val": "ad9361",
                "compatible": "ad9361",
                "mode": "1r1t",
            },
            # The fixture starts from an independently cold-attested canonical QSPI
            # image. Setup execution proves the environment survived a reboot; it
            # does not try to infer firmware persistence from that soft reboot.
            "boot_provenance": "qspi_cold_boot_verified",
            "usb_path": self.identity.usb_path,
        }

    def mark_canonical(self) -> None:
        self._canonical = True


class LegacyRadioAdapter:
    """Model an existing third-party adapter predating RX-layout selection."""

    def __init__(self, delegate: RepairableFakeRadio) -> None:
        self._delegate = delegate

    def __getattr__(self, name: str) -> Any:
        if name == "configure_rx_layout":
            raise AttributeError(name)
        return getattr(self._delegate, name)


class StartupDegradedRepairableRadio(RepairableFakeRadio):
    def __init__(self) -> None:
        super().__init__()
        self._facts_available = False

    def open(self) -> None:
        super().open()
        self._facts_available = True
        if not self._canonical:
            raise RadioSetupRequiredError(
                "radio requires canonical AD9361/2R2T setup "
                "(phy_model=ad9363a, rx_scan_channels=('voltage0', 'voltage1'))"
            )

    def close(self) -> None:
        super().close()
        self._facts_available = False

    def diagnostic_facts(self) -> Mapping[str, object]:
        return super().diagnostic_facts() if self._facts_available else {}


class SetupBackend:
    def __init__(self, radio: RepairableFakeRadio, *, fail: bool = False) -> None:
        self.radio = radio
        self.fail = fail
        self.inspect_count = 0
        self.executed: list[SetupPlan] = []

    @staticmethod
    def identity() -> SetupIdentity:
        return SetupIdentity(
            serial="SERIAL_A",
            usb_sysfs_path="/sys/bus/usb/devices/3-8",
            observed_firmware=CANONICAL_POLICY.device_firmware,
        )

    def observation(self) -> SetupObservation:
        canonical = self.radio._canonical
        return SetupObservation(
            identity=self.identity(),
            board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
            live_phy_model="ad9361" if canonical else "ad9363a",
            uboot=(
                dict(CANONICAL_UBOOT)
                if canonical
                else {
                    "attr_name": "compatible",
                    "attr_val": "ad9361",
                    "compatible": "ad9361",
                    "mode": "1r1t",
                }
            ),
            environment_sha256=("3" if canonical else "1") * 64,
            versions_sha256="2" * 64,
            qspi_firmware_sha256=CANONICAL_POLICY.fit_body_sha256,
            boot_provenance=("qspi_reboot_verified" if canonical else "qspi_image_verified"),
            rx_scan_channels=(
                ("voltage0", "voltage1", "voltage2", "voltage3")
                if canonical
                else ("voltage0", "voltage1")
            ),
            tx_safe=True,
            rx_lo_5g8_accepted=canonical,
            rx_lo_5g8_readback_hz=5_800_000_000 if canonical else None,
            rx_lo_restored=canonical,
        )

    def inspect(self, identity: SetupIdentity) -> SetupObservation:
        self.inspect_count += 1
        assert identity == self.identity()
        return self.observation()

    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        self.executed.append(plan)
        if self.fail:
            raise SetupExecutorFailure(
                "SSH host-key verification failed after reboot",
                backup_path="setup-backups/SERIAL_A-before.txt",
                backup_sha256="4" * 64,
                failure_phase="post_reboot_attestation",
                completed_phases=(
                    "preflight",
                    "backup",
                    "mutation_dispatched",
                    "reboot_observed",
                ),
            )
        self.radio.mark_canonical()
        return SetupExecutionResult(
            observation=self.observation(),
            backup_path="setup-backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
        )


class NativeSetupBackend(SetupBackend):
    def __init__(self, radio: RepairableFakeRadio) -> None:
        super().__init__(radio)
        self.native = False

    def observation(self) -> SetupObservation:
        if not self.native:
            return super().observation()
        return SetupObservation(
            identity=self.identity(),
            board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
            live_phy_model="ad9363a",
            uboot=AD9363A_1R1T_CLEAR_ATTR_PROFILE.uboot,
            environment_sha256="5" * 64,
            versions_sha256="2" * 64,
            qspi_firmware_sha256=CANONICAL_POLICY.fit_body_sha256,
            boot_provenance="qspi_reboot_verified",
            rx_scan_channels=("voltage0", "voltage1"),
            tx_safe=True,
            rx_lo_5g8_accepted=False,
            rx_lo_5g8_readback_hz=None,
            rx_lo_restored=True,
        )

    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        assert plan.target is SetupTarget.AD9363A_1R1T
        self.executed.append(plan)
        self.native = True
        self.radio._settings = self.radio._settings.model_copy(update={"channels": (0,)})
        return SetupExecutionResult(
            observation=self.observation(),
            backup_path="setup-backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
        )


class UncertainNativeSetupBackend(NativeSetupBackend):
    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        assert plan.target is SetupTarget.AD9363A_1R1T
        self.executed.append(plan)
        self.native = True
        self.radio._settings = self.radio._settings.model_copy(  # noqa: SLF001
            update={"channels": (0,)}
        )
        after = self.observation()
        raise SetupExecutorFailure(
            "post-reboot response was lost",
            backup_path="setup-backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
            after=after,
            failure_phase="post_reboot_attestation",
            completed_phases=(
                "preflight",
                "backup",
                "mutation_dispatched",
                "reboot_observed",
            ),
        )


class Ad9361SingleSetupBackend(SetupBackend):
    def __init__(self, radio: RepairableFakeRadio) -> None:
        super().__init__(radio)
        self.single = False

    def observation(self) -> SetupObservation:
        if not self.single:
            return super().observation()
        return SetupObservation(
            identity=self.identity(),
            board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
            live_phy_model="ad9361",
            uboot=AD9361_1R1T_CLEAR_ATTR_PROFILE.uboot,
            environment_sha256="6" * 64,
            versions_sha256="2" * 64,
            qspi_firmware_sha256=CANONICAL_POLICY.fit_body_sha256,
            boot_provenance="qspi_reboot_verified",
            rx_scan_channels=("voltage0", "voltage1"),
            tx_safe=True,
            rx_lo_5g8_accepted=True,
            rx_lo_5g8_readback_hz=5_800_000_000,
            rx_lo_restored=True,
        )

    def provision(self, plan: SetupPlan) -> SetupExecutionResult:
        assert plan.target is SetupTarget.AD9361_1R1T
        self.executed.append(plan)
        self.single = True
        self.radio._settings = self.radio._settings.model_copy(update={"channels": (0,)})
        return SetupExecutionResult(
            observation=self.observation(),
            backup_path="setup-backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
        )


class UnavailableSetupBackend:
    """Models SSH transport/host-key refusal without exposing stale facts."""

    def __init__(self) -> None:
        self.inspect_count = 0
        self.provision_count = 0

    def inspect(self, _identity: SetupIdentity) -> SetupObservation:
        self.inspect_count += 1
        raise SetupUnavailableError("SSH host-key verification failed")

    def provision(self, _plan: SetupPlan) -> SetupExecutionResult:
        self.provision_count += 1
        raise AssertionError("an unavailable inspector must never reach mutation")


def _manager(tmp_path: Path, backend: SetupBackend) -> CanonicalSetupManager:
    return CanonicalSetupManager(
        receipt_directory=tmp_path / "setup-receipts",
        inspector=backend.inspect,
        executor=backend,
    )


def _policy() -> AdminMutationPolicy:
    return AdminMutationPolicy(
        token=ADMIN_TOKEN,
        allowed_origins=frozenset({ALLOWED_ORIGIN}),
    )


def _client(service: PlutoService, policy: AdminMutationPolicy | None) -> TestClient:
    return TestClient(
        create_app(service, admin_policy=policy),
        base_url=ALLOWED_ORIGIN,
    )


def _service(
    tmp_path: Path,
    *,
    with_setup: bool = True,
    fail: bool = False,
) -> tuple[PlutoService, RepairableFakeRadio, SetupBackend]:
    radio = RepairableFakeRadio()
    backend = SetupBackend(radio, fail=fail)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend) if with_setup else None,
    )
    return service, radio, backend


def _post_plan(client: TestClient, headers: dict[str, str] | None = None) -> Any:
    return client.post(
        f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
        json={},
        headers=headers,
    )


def _post_plan_without_body(
    client: TestClient,
    headers: dict[str, str] | None = None,
) -> Any:
    return client.post(
        f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
        headers=headers,
    )


def test_setup_surface_fails_closed_without_manager_or_admin_policy(tmp_path: Path) -> None:
    missing_manager, _radio, backend = _service(tmp_path / "no-manager", with_setup=False)
    with _client(missing_manager, _policy()) as client:
        status = client.get(f"{API_PREFIX}/setup")
        assert status.status_code == 200
        assert status.json()["available"] is False
        refused = _post_plan(client, AUTH_HEADERS)
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "setup_unavailable"
    assert backend.executed == []

    missing_policy, _radio, backend = _service(tmp_path / "no-policy")
    with _client(missing_policy, None) as client:
        status = client.get(f"{API_PREFIX}/setup")
        assert status.status_code == 200
        assert status.json()["available"] is False
        refused = _post_plan(client)
        assert refused.status_code == 503
        assert refused.json()["error"]["code"] == "admin_authentication_unavailable"
    assert backend.executed == []


def test_setup_mutations_require_bearer_and_exact_browser_origin(tmp_path: Path) -> None:
    service, _radio, backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        status = client.get(f"{API_PREFIX}/setup")
        assert status.status_code == 200
        assert status.json()["available"] is True

        missing = _post_plan(client, {"Origin": ALLOWED_ORIGIN})
        assert missing.status_code == 403
        assert missing.json()["error"]["code"] == "admin_authentication_failed"

        bad_token = _post_plan(
            client,
            {**AUTH_HEADERS, "Authorization": "Bearer " + "x" * 32},
        )
        assert bad_token.status_code == 403

        wrong_origin = _post_plan(
            client,
            {**AUTH_HEADERS, "Origin": "http://attacker.invalid"},
        )
        assert wrong_origin.status_code == 403

        browser_without_origin = _post_plan(
            client,
            {
                "Authorization": f"Bearer {ADMIN_TOKEN}",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            },
        )
        assert browser_without_origin.status_code == 403
    assert backend.executed == []


def test_setup_api_plan_execute_receipt_and_fresh_doctor(tmp_path: Path) -> None:
    service, radio, backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        before = client.get(f"{API_PREFIX}/radios/SERIAL_A/doctor").json()
        before_findings = {item["code"]: item for item in before["findings"]}
        assert before_findings["rf.phy_model"]["status"] == "pass"
        assert before_findings["setup.uboot_2r2t"]["status"] == "fail"

        planned = _post_plan(client, AUTH_HEADERS)
        assert planned.status_code == 201
        document = planned.json()
        assert document["plan"]["identity"] == {
            "serial": "SERIAL_A",
            "usb_sysfs_path": "/sys/bus/usb/devices/3-8",
            "observed_firmware": CANONICAL_POLICY.device_firmware,
        }
        assert document["plan"]["environment_sha256"] == "1" * 64
        assert dict(document["plan"]["changes_items"]) == {
            "attr_name": None,
            "attr_val": None,
            "mode": "2r2t",
        }
        assert "compatible" not in dict(document["plan"]["changes_items"])

        wrong_token = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": document["plan"]["plan_id"],
                "confirmation_token": "wrong",
            },
            headers=AUTH_HEADERS,
        )
        assert wrong_token.status_code == 403
        assert wrong_token.json()["error"]["code"] == "setup_authorization_failed"
        assert backend.executed == []

        executed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": document["plan"]["plan_id"],
                "confirmation_token": document["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )
        assert executed.status_code == 201
        receipt = executed.json()
        assert receipt["success"] is True
        assert receipt["backup_sha256"] == "4" * 64
        assert len(backend.executed) == 1

        # The controller must be quiesced for the reboot and reopened afterward;
        # setup success cannot be inferred solely from the helper response.
        assert radio.close_count == 1
        assert radio.open_count == 2
        assert client.get(f"{API_PREFIX}/radios/SERIAL_A").json()["state"] == "ready"

        after = client.get(f"{API_PREFIX}/radios/SERIAL_A/doctor").json()
        after_findings = {item["code"]: item for item in after["findings"]}
        assert after_findings["rf.phy_model"]["status"] == "pass"
        assert after_findings["setup.uboot_2r2t"]["status"] == "pass"
        assert after_findings["rf.dual_rx_scan"]["status"] == "pass"

        unauthorized_receipts = client.get(f"{API_PREFIX}/setup/receipts")
        assert unauthorized_receipts.status_code == 403
        receipts = client.get(
            f"{API_PREFIX}/setup/receipts",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert receipts.status_code == 200
        assert [item["receipt_id"] for item in receipts.json()] == [receipt["receipt_id"]]


def test_setup_api_without_body_retains_legacy_default_target(tmp_path: Path) -> None:
    service, _radio, backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        planned = _post_plan_without_body(client, AUTH_HEADERS)

        assert planned.status_code == 201
        assert planned.json()["plan"]["target"] == "ad9361-2r2t"
    assert backend.executed == []


def test_setup_api_selects_native_target_and_recovers_without_paired_rx(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    radio.mark_canonical()
    backend = NativeSetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        status = client.get(f"{API_PREFIX}/setup").json()
        targets = {item["target"]: item for item in status["targets"]}
        assert status["default_target"] == "ad9361-2r2t"
        assert set(targets) == {"ad9361-2r2t", "ad9361-1r1t", "ad9363a-1r1t"}
        assert targets["ad9363a-1r1t"]["configuration"]["receiver_layout"] == ("single_stream")
        assert targets["ad9363a-1r1t"]["operating_policy"]["support_tier"] == ("development")
        assert targets["ad9363a-1r1t"]["operating_policy"]["intended_physical_rfic"] is None

        planned = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        )
        assert planned.status_code == 201
        document = planned.json()
        assert document["plan"]["target"] == "ad9363a-1r1t"
        assert dict(document["plan"]["changes_items"]) == {
            "compatible": "ad9363a",
            "mode": "1r1t",
        }

        executed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": document["plan"]["plan_id"],
                "confirmation_token": document["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )
        assert executed.status_code == 201
        assert executed.json()["target"] == "ad9363a-1r1t"
        assert service.get_radio("SERIAL_A").actual_settings.channels == (0,)
        assert service.get_radio("SERIAL_A").state.value == "ready"
        assert len(backend.executed) == 1


def test_setup_api_rejects_unknown_target_before_planning(tmp_path: Path) -> None:
    service, _radio, backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        refused = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9369-super-mode"},
            headers=AUTH_HEADERS,
        )

        assert refused.status_code == 422
    assert backend.executed == []


def test_enrolled_runtime_target_rejects_mismatched_setup_plan(tmp_path: Path) -> None:
    radio = RepairableFakeRadio()
    radio.mark_canonical()
    backend = NativeSetupBackend(radio)
    service = PlutoService(tmp_path / "state", (radio,))
    service.enroll_setup_manager(
        "SERIAL_A",
        _manager(tmp_path, backend),
        SetupTarget.AD9363A_1R1T,
    )

    with _client(service, _policy()) as client:
        status = client.get(f"{API_PREFIX}/setup").json()
        assert status["configured_radio_id"] == "SERIAL_A"
        assert status["configured_target"] == "ad9363a-1r1t"

        refused = _post_plan(client, AUTH_HEADERS)
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "setup_precondition_failed"

        accepted = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        )
        assert accepted.status_code == 201
    assert backend.executed == []


def test_single_stream_plan_is_rejected_before_direct_capture_mutation(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    radio._capabilities = radio.capabilities.model_copy(  # noqa: SLF001
        update={"supports_direct_capture": True}
    )
    backend = NativeSetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        refused = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        )

        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "setup_precondition_failed"
    assert backend.inspect_count == 0
    assert backend.executed == []


def test_single_stream_plan_requires_layout_aware_adapter_before_mutation(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    backend = NativeSetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (LegacyRadioAdapter(radio),),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        refused = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        )

        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "setup_precondition_failed"
    assert backend.inspect_count == 0
    assert backend.executed == []


def test_setup_api_keeps_ad9361_driver_independent_from_paired_rx_recovery(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    radio.mark_canonical()
    backend = Ad9361SingleSetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        planned = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9361-1r1t"},
            headers=AUTH_HEADERS,
        ).json()
        assert planned["plan"]["target"] == "ad9361-1r1t"
        assert dict(planned["plan"]["changes_items"]) == {"mode": "1r1t"}

        executed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )

        assert executed.status_code == 201
        assert executed.json()["target"] == "ad9361-1r1t"
        assert service.get_radio("SERIAL_A").actual_settings.channels == (0,)


def test_setup_required_radio_does_not_hide_healthy_radios_and_can_be_repaired(
    tmp_path: Path,
) -> None:
    radio = StartupDegradedRepairableRadio()
    backend = SetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (radio, FakeRadioDevice("healthy")),
        setup_manager=_manager(tmp_path, backend),
    )
    try:
        snapshots = {item.identity.radio_id: item for item in service.list_radios()}
        assert snapshots["healthy"].state.value == "ready"
        assert snapshots["SERIAL_A"].state.value == "error"
        assert "RadioSetupRequiredError" in (snapshots["SERIAL_A"].last_error or "")

        report = service.doctor("SERIAL_A")
        findings = {item.code: item for item in report.findings}
        assert findings["rf.phy_model"].status.value == "pass"
        assert findings["rf.dual_rx_scan"].status.value == "fail"

        planned = service.create_canonical_setup_plan("SERIAL_A")
        receipt = service.execute_setup_plan(
            planned.plan.plan_id, planned.confirmation_token
        )
        assert receipt.success is True
        assert service.get_radio("SERIAL_A").state.value == "ready"
    finally:
        service.close()


def test_setup_execution_failure_is_receipted_and_controller_recovers(tmp_path: Path) -> None:
    service, radio, backend = _service(tmp_path, fail=True)
    with _client(service, _policy()) as client:
        planned = _post_plan(client, AUTH_HEADERS).json()
        failed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )
        assert failed.status_code == 500
        assert failed.json()["error"]["code"] == "setup_execution_failed"
        failure_receipt = failed.json()["receipt"]
        assert failure_receipt["success"] is False
        assert failure_receipt["outcome"] == "unknown"
        assert failure_receipt["failure_phase"] == "post_reboot_attestation"
        completed = failure_receipt["completed_phases"]
        required_phases = [
            "preflight",
            "backup",
            "mutation_dispatched",
            "reboot_observed",
        ]
        assert all(phase in completed for phase in required_phases)
        assert [completed.index(phase) for phase in required_phases] == sorted(
            completed.index(phase) for phase in required_phases
        )
        assert failure_receipt["backup_path"] == "setup-backups/SERIAL_A-before.txt"
        assert failure_receipt["backup_sha256"] == "4" * 64
        assert failure_receipt["reconciliation_required"] is True
        assert radio.close_count == 1
        assert radio.open_count == 2
        assert client.get(f"{API_PREFIX}/radios/SERIAL_A").json()["state"] == "ready"

        receipts = client.get(
            f"{API_PREFIX}/setup/receipts",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        ).json()
        assert len(receipts) == 1
        assert receipts[0]["success"] is False
        assert receipts[0]["outcome"] == "unknown"
        assert receipts[0]["failure_phase"] == "post_reboot_attestation"
        assert receipts[0]["backup_path"] == "setup-backups/SERIAL_A-before.txt"
        assert receipts[0]["backup_sha256"] == "4" * 64
        assert "host-key verification failed" in receipts[0]["error"]
        assert len(backend.executed) == 1

        opens_before_reconcile = radio.open_count
        closes_before_reconcile = radio.close_count
        reconciled = client.post(
            f"{API_PREFIX}/setup/receipts/{failure_receipt['receipt_id']}/reconcile",
            json={},
            headers=AUTH_HEADERS,
        )
        assert reconciled.status_code == 201
        reconciliation = reconciled.json()
        assert reconciliation["reconciliation_of"] == failure_receipt["receipt_id"]
        assert reconciliation["outcome"] == "reconciled_not_canonical"
        # Reconciliation is an authenticated fresh inspection, never a retry.
        assert len(backend.executed) == 1
        assert radio.open_count == opens_before_reconcile
        assert radio.close_count == closes_before_reconcile


def test_failed_single_stream_transition_remains_setup_repairable(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    backend = SetupBackend(radio, fail=True)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        planned = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        ).json()
        failed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )

        assert failed.status_code == 500
        snapshot = client.get(f"{API_PREFIX}/radios/SERIAL_A").json()
        assert snapshot["state"] == "error"
        assert "RadioSetupRequiredError" in snapshot["last_error"]

        retry = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        )

        assert retry.status_code == 201
        assert retry.json()["plan"]["target"] == "ad9363a-1r1t"
    assert backend.inspect_count >= 3
    assert len(backend.executed) == 1


def test_native_target_is_preserved_through_uncertain_receipt_reconciliation(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    radio.mark_canonical()
    backend = UncertainNativeSetupBackend(radio)
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=_manager(tmp_path, backend),
    )

    with _client(service, _policy()) as client:
        planned = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/doctor/setup-plans",
            json={"target": "ad9363a-1r1t"},
            headers=AUTH_HEADERS,
        ).json()
        failed = client.post(
            f"{API_PREFIX}/setup/executions",
            json={
                "plan_id": planned["plan"]["plan_id"],
                "confirmation_token": planned["confirmation_token"],
            },
            headers=AUTH_HEADERS,
        )

        assert failed.status_code == 500
        failure_receipt = failed.json()["receipt"]
        assert failure_receipt["target"] == "ad9363a-1r1t"
        assert service.get_radio("SERIAL_A").actual_settings.channels == (0,)

        reconciled = client.post(
            f"{API_PREFIX}/setup/receipts/{failure_receipt['receipt_id']}/reconcile",
            json={},
            headers=AUTH_HEADERS,
        )

        assert reconciled.status_code == 201
        assert reconciled.json()["target"] == "ad9363a-1r1t"
        assert reconciled.json()["outcome"] == "reconciled_verified"
        assert len(backend.executed) == 1


def test_setup_plan_is_refused_while_radio_is_busy(tmp_path: Path) -> None:
    service, _radio, backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        started = client.post(
            f"{API_PREFIX}/radios/SERIAL_A/streams",
            json={"block_size": 4096, "fft_size": 256},
        )
        assert started.status_code == 201
        refused = _post_plan(client, AUTH_HEADERS)
        assert refused.status_code == 409
        assert refused.json()["error"]["code"] == "radio_busy"
        assert backend.executed == []
        client.delete(f"{API_PREFIX}/radios/SERIAL_A/streams/current")


def test_non_browser_cli_request_may_omit_origin_but_not_bearer(tmp_path: Path) -> None:
    service, _radio, _backend = _service(tmp_path)
    with _client(service, _policy()) as client:
        planned = _post_plan(
            client,
            {"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert planned.status_code == 201


def test_helper_host_key_failure_makes_doctor_unknown_and_plan_typed_503(
    tmp_path: Path,
) -> None:
    radio = RepairableFakeRadio()
    backend = UnavailableSetupBackend()
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "setup-receipts",
        inspector=backend.inspect,
        executor=backend,
    )
    service = PlutoService(
        tmp_path / "state",
        (radio,),
        setup_manager=manager,
    )

    # These persistent facts are intentionally unavailable from the local IIO
    # context. A rejected SSH host key must never fall back to a prior PASS.
    radio._canonical = False
    original_facts = radio.diagnostic_facts
    radio.diagnostic_facts = lambda: {  # type: ignore[method-assign]
        **original_facts(),
        "uboot": None,
        "boot_provenance": None,
    }

    with _client(service, _policy()) as client:
        doctor = client.get(f"{API_PREFIX}/radios/SERIAL_A/doctor")
        assert doctor.status_code == 200
        findings = {item["code"]: item for item in doctor.json()["findings"]}
        assert findings["setup.uboot_2r2t"]["status"] == "unknown"
        assert findings["firmware.boot_provenance"]["status"] == "unknown"

        planned = _post_plan(client, AUTH_HEADERS)
        assert planned.status_code == 503
        assert planned.json() == {
            "error": {
                "code": "setup_unavailable",
                "message": "SSH host-key verification failed",
            }
        }
    assert backend.inspect_count >= 2
    assert backend.provision_count == 0


def test_setup_mutation_transport_allows_loopback_or_https_only(tmp_path: Path) -> None:
    nonloop_origin = "http://192.0.2.15"
    https_origin = "https://radio.example"
    policy = AdminMutationPolicy(
        token=ADMIN_TOKEN,
        allowed_origins={ALLOWED_ORIGIN, nonloop_origin, https_origin},
    )

    nonloop_service, _radio, nonloop_backend = _service(tmp_path / "nonloop")
    with TestClient(
        create_app(nonloop_service, admin_policy=policy),
        base_url=nonloop_origin,
        client=("192.0.2.20", 50000),
    ) as client:
        status = client.get(f"{API_PREFIX}/setup")
        assert status.status_code == 200
        assert status.json()["available"] is False
        refused = _post_plan(
            client,
            {
                **AUTH_HEADERS,
                "Origin": nonloop_origin,
            },
        )
        assert refused.status_code == 426
        assert refused.json()["error"]["code"] == "admin_secure_transport_required"
    assert nonloop_backend.executed == []

    loopback_service, _radio, _backend = _service(tmp_path / "loopback")
    with TestClient(
        create_app(loopback_service, admin_policy=policy),
        base_url=ALLOWED_ORIGIN,
        client=("127.0.0.1", 50000),
    ) as client:
        allowed = _post_plan(client, AUTH_HEADERS)
        assert allowed.status_code == 201

    https_service, _radio, _backend = _service(tmp_path / "https")
    with TestClient(
        create_app(https_service, admin_policy=policy),
        base_url=https_origin,
        client=("192.0.2.20", 50000),
    ) as client:
        allowed = _post_plan(
            client,
            {
                **AUTH_HEADERS,
                "Origin": https_origin,
            },
        )
        assert allowed.status_code == 201
