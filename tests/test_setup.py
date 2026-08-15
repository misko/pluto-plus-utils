from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT
from pluto_plus.setup import (
    CanonicalSetupManager,
    SetupAuthorizationError,
    SetupExecutionResult,
    SetupIdentity,
    SetupObservation,
    SetupPreconditionError,
)


def _identity() -> SetupIdentity:
    return SetupIdentity(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        observed_firmware=CANONICAL_POLICY.device_firmware,
    )


def _observation(**updates: object) -> SetupObservation:
    values: dict[str, object] = {
        "identity": _identity(),
        "board_model": "Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
        "live_phy_model": "ad9363a",
        "uboot": {
            "attr_name": None,
            "attr_val": None,
            "compatible": None,
            "mode": "2r2t",
        },
        "environment_sha256": "1" * 64,
        "versions_sha256": "2" * 64,
        "qspi_firmware_sha256": CANONICAL_POLICY.fit_body_sha256,
        "boot_provenance": "qspi_image_verified",
        "rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3"),
        "tx_safe": True,
    }
    values.update(updates)
    return SetupObservation.model_validate(values)


class FakeSetupBackend:
    def __init__(self, current: SetupObservation) -> None:
        self.current = current
        self.plans = []

    def inspect(self, identity: SetupIdentity) -> SetupObservation:
        assert identity.serial == self.current.identity.serial
        return self.current

    def provision(self, plan: object) -> SetupExecutionResult:
        self.plans.append(plan)
        self.current = _observation(
            live_phy_model="ad9361",
            uboot=CANONICAL_UBOOT,
            environment_sha256="3" * 64,
            boot_provenance="qspi_reboot_verified",
        )
        return SetupExecutionResult(
            observation=self.current,
            backup_path="backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
        )


def test_setup_plan_is_exact_identity_environment_and_policy_bound(tmp_path: Path) -> None:
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )

    planned = manager.create_plan(_identity())

    assert planned.plan.identity == _identity()
    assert planned.plan.profile_id == CANONICAL_POLICY.profile_id
    assert planned.plan.environment_sha256 == "1" * 64
    assert planned.plan.changes == {
        "attr_name": "compatible",
        "attr_val": "ad9361",
        "compatible": "ad9361",
    }
    assert "mode" not in planned.plan.changes
    assert planned.plan.tx_mute_required is False


def test_setup_plan_explicitly_includes_required_fail_closed_tx_mute(
    tmp_path: Path,
) -> None:
    backend = FakeSetupBackend(_observation(tx_safe=False))
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )

    planned = manager.create_plan(_identity())

    assert planned.plan.tx_mute_required is True


@pytest.mark.parametrize(
    "updates",
    [
        {"board_model": "Analog Devices PlutoSDR Rev.B"},
        {"boot_provenance": "ram"},
        {"qspi_firmware_sha256": "0" * 64},
    ],
)
def test_setup_plan_refuses_unsafe_preconditions(
    tmp_path: Path, updates: dict[str, object]
) -> None:
    backend = FakeSetupBackend(_observation(**updates))
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )
    with pytest.raises(SetupPreconditionError):
        manager.create_plan(_identity())
    assert backend.plans == []


def test_setup_token_is_one_time_and_environment_drift_prevents_mutation(
    tmp_path: Path,
) -> None:
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())
    backend.current = _observation(environment_sha256="9" * 64)

    with pytest.raises(SetupPreconditionError, match="changed"):
        manager.execute(planned.plan, planned.confirmation_token)
    assert backend.plans == []


def test_setup_success_is_verified_and_receipted(tmp_path: Path) -> None:
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())
    receipt = manager.execute(planned.plan, planned.confirmation_token)

    assert receipt.success
    assert receipt.after is not None
    assert receipt.after.uboot == CANONICAL_UBOOT
    assert receipt.after.live_phy_model == "ad9361"
    assert receipt.backup_sha256 == "4" * 64
    assert len(manager.list_receipts()) == 1
    assert next((tmp_path / "receipts").glob("*.json")).is_file()
    with pytest.raises(SetupAuthorizationError, match="already used"):
        manager.execute(planned.plan, planned.confirmation_token)


def test_setup_token_rejects_tampered_plan(tmp_path: Path) -> None:
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
        clock=lambda: datetime(2026, 8, 15, tzinfo=UTC),
        confirmation_ttl=timedelta(minutes=5),
    )
    planned = manager.create_plan(_identity())
    tampered = replace(planned.plan, environment_sha256="a" * 64)
    with pytest.raises(SetupAuthorizationError, match="another plan"):
        manager.execute(tampered, planned.confirmation_token)
