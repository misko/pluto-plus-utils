from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.doctor import (
    CANONICAL_POLICY,
    CANONICAL_UBOOT,
    DDR_RING_V1_RELEASE_PERSISTENT_POLICY,
)
from pluto_plus.setup import (
    CanonicalSetupManager,
    SetupAuthorizationError,
    SetupExecutionResult,
    SetupHostKeyRotation,
    SetupIdentity,
    SetupObservation,
    SetupPreconditionError,
    observation_functionally_qualified,
)
from pluto_plus.setup_profiles import (
    AD9361_1R1T_CLEAR_ATTR_PROFILE,
    AD9363A_1R1T_CLEAR_ATTR_PROFILE,
    DEFAULT_SETUP_TARGET,
    SetupTarget,
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
        self.host_key_rotation: SetupHostKeyRotation | None = None

    def inspect(self, identity: SetupIdentity) -> SetupObservation:
        assert identity.serial == self.current.identity.serial
        return self.current

    def provision(self, plan: object) -> SetupExecutionResult:
        self.plans.append(plan)
        self.current = _observation(
            live_phy_model="ad9363a",
            uboot=CANONICAL_UBOOT,
            environment_sha256="3" * 64,
            boot_provenance="qspi_reboot_verified",
            rx_lo_5g8_accepted=True,
            rx_lo_5g8_readback_hz=5_800_000_000,
            rx_lo_restored=True,
        )
        return SetupExecutionResult(
            observation=self.current,
            backup_path="backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
            host_key_rotation=self.host_key_rotation,
        )


class NativeSetupBackend(FakeSetupBackend):
    def provision(self, plan: object) -> SetupExecutionResult:
        from pluto_plus.setup import SetupPlan

        assert isinstance(plan, SetupPlan)
        assert plan.target is SetupTarget.AD9363A_1R1T
        self.plans.append(plan)
        self.current = _observation(
            live_phy_model="ad9363a",
            uboot=AD9363A_1R1T_CLEAR_ATTR_PROFILE.uboot,
            environment_sha256="3" * 64,
            boot_provenance="qspi_reboot_verified",
            rx_scan_channels=("voltage0", "voltage1"),
            rx_lo_5g8_accepted=False,
            rx_lo_5g8_readback_hz=None,
            rx_lo_restored=True,
        )
        return SetupExecutionResult(
            observation=self.current,
            backup_path="backups/SERIAL_A-before.txt",
            backup_sha256="4" * 64,
        )


class Ad9361SingleSetupBackend(FakeSetupBackend):
    def provision(self, plan: object) -> SetupExecutionResult:
        from pluto_plus.setup import SetupPlan

        assert isinstance(plan, SetupPlan)
        assert plan.target is SetupTarget.AD9361_1R1T
        self.plans.append(plan)
        self.current = _observation(
            live_phy_model="ad9361",
            uboot=AD9361_1R1T_CLEAR_ATTR_PROFILE.uboot,
            environment_sha256="4" * 64,
            boot_provenance="qspi_reboot_verified",
            rx_scan_channels=("voltage0", "voltage1"),
            rx_lo_5g8_accepted=True,
            rx_lo_5g8_readback_hz=5_800_000_000,
            rx_lo_restored=True,
        )
        return SetupExecutionResult(
            observation=self.current,
            backup_path="backups/SERIAL_A-before.txt",
            backup_sha256="5" * 64,
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
    assert planned.plan.changes == {"compatible": "ad9361"}
    assert "mode" not in planned.plan.changes
    assert planned.plan.tx_mute_required is False
    assert planned.plan.target is DEFAULT_SETUP_TARGET


def test_setup_plan_binds_an_explicit_native_single_stream_target(tmp_path: Path) -> None:
    backend = NativeSetupBackend(_observation(uboot=CANONICAL_UBOOT))
    receipt_directory = tmp_path / "receipts"
    manager = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    )

    planned = manager.create_plan(_identity(), SetupTarget.AD9363A_1R1T)

    assert planned.plan.target is SetupTarget.AD9363A_1R1T
    assert planned.plan.profile_id == CANONICAL_POLICY.profile_id
    assert planned.plan.changes == {
        "compatible": "ad9363a",
        "mode": "1r1t",
    }

    receipt = manager.execute(planned.plan, planned.confirmation_token)
    assert receipt.target is SetupTarget.AD9363A_1R1T
    assert receipt.after is not None
    assert receipt.after.live_phy_model == "ad9363a"
    assert receipt.after.rx_scan_channels == ("voltage0", "voltage1")
    assert receipt.after.rx_lo_5g8_accepted is False
    reloaded = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    ).list_receipts()
    assert len(reloaded) == 1
    assert reloaded[0].schema_version == 4
    assert reloaded[0].target is SetupTarget.AD9363A_1R1T


def test_setup_plan_binds_ad9361_driver_independently_of_1r1t_mode(
    tmp_path: Path,
) -> None:
    backend = Ad9361SingleSetupBackend(_observation(uboot=CANONICAL_UBOOT))
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )

    planned = manager.create_plan(_identity(), SetupTarget.AD9361_1R1T)

    assert planned.plan.target is SetupTarget.AD9361_1R1T
    assert planned.plan.changes == {"mode": "1r1t"}
    receipt = manager.execute(planned.plan, planned.confirmation_token)
    assert receipt.after is not None
    assert receipt.after.live_phy_model == "ad9361"
    assert receipt.after.rx_scan_channels == ("voltage0", "voltage1")
    assert receipt.after.rx_lo_5g8_readback_hz == 5_800_000_000


@pytest.mark.parametrize(
    "updates",
    [
        {"live_phy_model": "ad9363a"},
        {"rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3")},
        {"rx_lo_5g8_accepted": False, "rx_lo_5g8_readback_hz": None},
    ],
)
def test_ad9361_1r1t_requires_exact_driver_single_rx_and_5g8_proof(
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "live_phy_model": "ad9361",
        "uboot": AD9361_1R1T_CLEAR_ATTR_PROFILE.uboot,
        "rx_scan_channels": ("voltage0", "voltage1"),
        "rx_lo_5g8_accepted": True,
        "rx_lo_5g8_readback_hz": 5_800_000_000,
        "rx_lo_restored": True,
    }
    values.update(updates)

    assert not observation_functionally_qualified(
        _observation(**values), SetupTarget.AD9361_1R1T
    )


@pytest.mark.parametrize(
    "updates",
    [
        {"live_phy_model": "ad9361"},
        {"rx_scan_channels": ("voltage0", "voltage1", "voltage2", "voltage3")},
        {"tx_safe": False},
    ],
)
def test_native_target_requires_exact_driver_single_rx_geometry_and_safe_tx(
    updates: dict[str, object],
) -> None:
    values: dict[str, object] = {
        "live_phy_model": "ad9363a",
        "uboot": AD9363A_1R1T_CLEAR_ATTR_PROFILE.uboot,
        "rx_scan_channels": ("voltage0", "voltage1"),
        "tx_safe": True,
        "rx_lo_5g8_accepted": False,
        "rx_lo_restored": True,
    }
    values.update(updates)
    observation = _observation(**values)

    assert not observation_functionally_qualified(observation, SetupTarget.AD9363A_1R1T)


def test_native_target_does_not_relabel_legacy_5g8_fields_as_a_generic_probe() -> None:
    observation = _observation(
        live_phy_model="ad9363a",
        uboot=AD9363A_1R1T_CLEAR_ATTR_PROFILE.uboot,
        rx_scan_channels=("voltage0", "voltage1"),
        rx_lo_5g8_accepted=False,
        rx_lo_5g8_readback_hz=None,
        rx_lo_restored=True,
    )

    assert observation_functionally_qualified(observation, SetupTarget.AD9363A_1R1T)
    assert not observation_functionally_qualified(observation)


def test_setup_plan_accepts_only_exact_shipped_persistent_policy(tmp_path: Path) -> None:
    policy = DDR_RING_V1_RELEASE_PERSISTENT_POLICY
    identity = _identity().model_copy(update={"observed_firmware": policy.device_firmware})
    observation = _observation(
        identity=identity,
        qspi_firmware_sha256=policy.fit_body_sha256,
    )
    backend = FakeSetupBackend(observation)
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
        policy=policy,
    )

    planned = manager.create_plan(identity)

    assert manager.firmware_policy is policy
    assert planned.plan.profile_id == policy.profile_id
    assert planned.plan.identity.observed_firmware == policy.device_firmware
    assert planned.plan.changes == {
        "attr_name": "compatible",
        "attr_val": "ad9361",
        "compatible": "ad9361",
    }

    unshipped = policy.model_copy(update={"fit_body_sha256": "f" * 64})
    with pytest.raises(ValueError, match="exact shipped hardware-qualified"):
        CanonicalSetupManager(
            receipt_directory=tmp_path / "unshipped",
            inspector=backend.inspect,
            executor=backend,
            policy=unshipped,
        )


def test_setup_plan_deletes_attr_name_and_attr_val_that_revert_2r2t(
    tmp_path: Path,
) -> None:
    backend = FakeSetupBackend(
        _observation(
            uboot={
                "attr_name": "compatible",
                "attr_val": "ad9361",
                "compatible": "ad9361",
                "mode": "1r1t",
            }
        )
    )
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )

    planned = manager.create_plan(_identity())

    assert planned.plan.changes == {
        "attr_name": None,
        "attr_val": None,
        "mode": "2r2t",
    }


def test_setup_plan_never_changes_a_bounded_2r2t_tuple_when_lo_probe_is_unavailable(
    tmp_path: Path,
) -> None:
    backend = FakeSetupBackend(
        _observation(
            uboot=CANONICAL_UBOOT,
            rx_lo_5g8_accepted=None,
            rx_lo_5g8_readback_hz=None,
            rx_lo_restored=None,
        )
    )
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )

    with pytest.raises(SetupPreconditionError, match="idle RX data plane"):
        manager.create_plan(_identity())

    assert backend.plans == []


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
    assert receipt.after.live_phy_model == "ad9363a"
    assert receipt.backup_sha256 == "4" * 64
    assert len(manager.list_receipts()) == 1
    assert next((tmp_path / "receipts").glob("*.json")).is_file()
    with pytest.raises(SetupAuthorizationError, match="already used"):
        manager.execute(planned.plan, planned.confirmation_token)


def test_setup_receipt_persists_post_reboot_host_key_rotation(tmp_path: Path) -> None:
    backend = FakeSetupBackend(_observation())
    backend.host_key_rotation = SetupHostKeyRotation(
        previous_known_hosts_sha256="5" * 64,
        replacement_known_hosts_sha256="6" * 64,
        previous_fingerprint="SHA256:old",
        replacement_fingerprint="SHA256:new",
        previous_known_hosts_backup="/private/known_hosts.pre-reboot",
    )
    receipt_directory = tmp_path / "receipts"
    manager = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())

    receipt = manager.execute(planned.plan, planned.confirmation_token)
    reloaded = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    ).list_receipts()[0]

    assert receipt.schema_version == 4
    assert receipt.host_key_rotation == backend.host_key_rotation
    assert reloaded.host_key_rotation == backend.host_key_rotation


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


def test_setup_token_is_bound_to_target(tmp_path: Path) -> None:
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=tmp_path / "receipts",
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())
    tampered = replace(planned.plan, target=SetupTarget.AD9363A_1R1T)

    with pytest.raises(SetupAuthorizationError, match="another plan"):
        manager.execute(tampered, planned.confirmation_token)


def test_legacy_setup_receipt_without_target_loads_as_default(tmp_path: Path) -> None:
    receipt_directory = tmp_path / "receipts"
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())
    receipt = manager.execute(planned.plan, planned.confirmation_token)
    receipt_path = receipt_directory / f"{receipt.receipt_id}.json"
    document = json.loads(receipt_path.read_text())
    document.pop("target")
    document["schema_version"] = 3
    receipt_path.write_text(json.dumps(document))

    reloaded = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    ).list_receipts()

    assert len(reloaded) == 1
    assert reloaded[0].schema_version == 3
    assert reloaded[0].target is DEFAULT_SETUP_TARGET


def test_schema4_setup_receipt_without_target_is_rejected(tmp_path: Path) -> None:
    receipt_directory = tmp_path / "receipts"
    backend = FakeSetupBackend(_observation())
    manager = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    )
    planned = manager.create_plan(_identity())
    receipt = manager.execute(planned.plan, planned.confirmation_token)
    receipt_path = receipt_directory / f"{receipt.receipt_id}.json"
    document = json.loads(receipt_path.read_text())
    document.pop("target")
    receipt_path.write_text(json.dumps(document))

    reloaded = CanonicalSetupManager(
        receipt_directory=receipt_directory,
        inspector=backend.inspect,
        executor=backend,
    ).list_receipts()

    assert reloaded == []
