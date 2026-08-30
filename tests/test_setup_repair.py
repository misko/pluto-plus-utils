from __future__ import annotations

from pathlib import Path

import pytest

from pluto_plus.doctor import (
    CANONICAL_POLICY,
    CANONICAL_UBOOT,
    DDR_BURST_V2_RELEASE_PERSISTENT_POLICY,
    DDR_RING_V1_RELEASE_PERSISTENT_POLICY,
    setup_repair_policy_for_firmware,
)
from pluto_plus.setup import (
    CanonicalSetupManager,
    SetupExecutionResult,
    SetupExecutorFailure,
    SetupIdentity,
    SetupObservation,
)
from pluto_plus.setup_helper import SetupHelperError
from pluto_plus.setup_profiles import SET_ATTR_PROFILE
from pluto_plus.setup_repair import probe_and_repair

# The state a radio lands in when attr_val fires the malformed AD9364 branch.
REVERTED_UBOOT = {
    "attr_name": "compatible",
    "attr_val": "ad9361",
    "compatible": "ad9361",
    "mode": "1r1t",
}


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
        "live_phy_model": "ad9361",
        "uboot": dict(REVERTED_UBOOT),
        "environment_sha256": "1" * 64,
        "versions_sha256": "2" * 64,
        "qspi_firmware_sha256": CANONICAL_POLICY.fit_body_sha256,
        "boot_provenance": "qspi_image_verified",
        "rx_scan_channels": ("voltage0", "voltage1"),
        "tx_safe": True,
    }
    values.update(updates)
    return SetupObservation.model_validate(values)


class FakeBackend:
    def __init__(self, current: SetupObservation) -> None:
        self.current = current
        self.provisioned: list[object] = []

    def inspect(self, identity: SetupIdentity) -> SetupObservation:
        return self.current

    def provision(self, plan: object) -> SetupExecutionResult:
        self.provisioned.append(plan)
        self.current = _observation(
            uboot=dict(CANONICAL_UBOOT),
            environment_sha256="3" * 64,
            boot_provenance="qspi_reboot_verified",
            rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
            rx_lo_5g8_accepted=True,
            rx_lo_5g8_readback_hz=5_800_000_000,
            rx_lo_restored=True,
        )
        return SetupExecutionResult(
            observation=self.current,
            backup_path="/private/SERIAL_A-before.json",
            backup_sha256="4" * 64,
        )


def _factory(backend: FakeBackend, tmp_path: Path):
    def build(identity: SetupIdentity) -> CanonicalSetupManager:
        return CanonicalSetupManager(
            receipt_directory=tmp_path / "receipts",
            inspector=backend.inspect,
            executor=backend,
        )

    return build


def _probe(backend: FakeBackend, tmp_path: Path, *, repair: bool = True):
    return probe_and_repair(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        firmware_version=CANONICAL_POLICY.device_firmware,
        manager_factory=_factory(backend, tmp_path),
        repair=repair,
    )


def test_setup_repair_policy_is_selected_only_by_exact_firmware() -> None:
    previous = DDR_BURST_V2_RELEASE_PERSISTENT_POLICY
    policy = DDR_RING_V1_RELEASE_PERSISTENT_POLICY

    assert setup_repair_policy_for_firmware(policy.device_firmware) is policy
    assert setup_repair_policy_for_firmware(previous.device_firmware) is previous
    assert setup_repair_policy_for_firmware(CANONICAL_POLICY.device_firmware) is CANONICAL_POLICY
    with pytest.raises(ValueError, match="no exact shipped setup repair policy"):
        setup_repair_policy_for_firmware("v0.42-plutoplus-spf-ddr-burst-v2-rc3")


def test_probe_repairs_a_reverted_tuple_and_reports_the_deletions(tmp_path: Path) -> None:
    backend = FakeBackend(_observation())

    outcome = _probe(backend, tmp_path)

    assert outcome.status == "pass"
    assert dict(outcome.actual or ()) == CANONICAL_UBOOT
    assert outcome.repair is not None
    assert outcome.repair.attempted and outcome.repair.succeeded
    assert dict(outcome.repair.changes) == {
        "attr_name": None,
        "attr_val": None,
        "mode": "2r2t",
    }
    assert outcome.repair.backup_path == "/private/SERIAL_A-before.json"
    assert len(backend.provisioned) == 1


def test_probe_reports_without_mutating_when_repair_is_disabled(tmp_path: Path) -> None:
    backend = FakeBackend(_observation())

    outcome = _probe(backend, tmp_path, repair=False)

    assert outcome.status == "fail"
    assert dict(outcome.actual or ()) == REVERTED_UBOOT
    assert outcome.repair is None
    assert backend.provisioned == []


def test_probe_passes_and_never_mutates_a_canonical_radio(tmp_path: Path) -> None:
    backend = FakeBackend(
        _observation(
            uboot=dict(CANONICAL_UBOOT),
            rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
            rx_lo_5g8_accepted=True,
            rx_lo_5g8_readback_hz=5_800_000_000,
            rx_lo_restored=True,
        )
    )

    outcome = _probe(backend, tmp_path)

    assert outcome.status == "pass"
    assert outcome.repair is None
    assert backend.provisioned == []


def test_probe_never_passes_canonical_tuple_with_wrong_qspi_hash(tmp_path: Path) -> None:
    backend = FakeBackend(
        _observation(
            uboot=dict(CANONICAL_UBOOT),
            qspi_firmware_sha256="f" * 64,
            boot_provenance="unknown",
        )
    )

    outcome = _probe(backend, tmp_path)

    assert outcome.status == "unknown"
    assert outcome.actual is None
    assert outcome.repair is None
    assert "QSPI firmware hash does not match setup policy" in outcome.summary
    assert backend.provisioned == []


def test_unreachable_radio_degrades_to_unknown_instead_of_raising(tmp_path: Path) -> None:
    def build(identity: SetupIdentity) -> CanonicalSetupManager:
        raise SetupHelperError("ssh: connect to host 192.168.2.1 port 22: No route to host")

    outcome = probe_and_repair(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        firmware_version=CANONICAL_POLICY.device_firmware,
        manager_factory=build,
    )

    assert outcome.status == "unknown"
    assert outcome.actual is None
    assert outcome.repair is None
    assert "No route to host" in outcome.summary


def test_missing_firmware_cannot_bind_an_identity(tmp_path: Path) -> None:
    backend = FakeBackend(_observation())

    outcome = probe_and_repair(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        firmware_version=None,
        manager_factory=_factory(backend, tmp_path),
    )

    assert outcome.status == "unknown"
    assert backend.provisioned == []


def test_repair_failure_is_reported_and_never_claims_success(tmp_path: Path) -> None:
    class FailingBackend(FakeBackend):
        def provision(self, plan: object) -> SetupExecutionResult:
            raise SetupHelperError("transmit path did not reach fail-closed state")

    backend = FailingBackend(_observation())

    outcome = _probe(backend, tmp_path)

    assert outcome.status == "fail"
    assert outcome.repair is not None
    assert outcome.repair.attempted and not outcome.repair.succeeded
    assert outcome.repair.error is not None
    assert dict(outcome.actual or ()) == REVERTED_UBOOT


def test_repair_failure_reports_the_last_rebooted_profile(tmp_path: Path) -> None:
    after = _observation(
        uboot=SET_ATTR_PROFILE.uboot,
        environment_sha256="8" * 64,
        boot_provenance="qspi_reboot_verified",
        rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
        rx_lo_5g8_accepted=False,
        rx_lo_restored=True,
    )

    class FailingAfterRebootBackend(FakeBackend):
        def provision(self, plan: object) -> SetupExecutionResult:
            del plan
            raise SetupExecutorFailure(
                "neither bounded profile accepted 5.8 GHz",
                backup_path="/private/SERIAL_A-before.json",
                backup_sha256="4" * 64,
                after=after,
                completed_phases=("reboot_observed:ad9361-2r2t-set-attr-pair",),
            )

    outcome = _probe(FailingAfterRebootBackend(_observation()), tmp_path)

    assert outcome.status == "fail"
    assert dict(outcome.actual or ()) == SET_ATTR_PROFILE.uboot
    assert outcome.rx_lo_5g8_accepted is False
    assert outcome.repair is not None
    assert outcome.repair.receipt_id is not None
    assert outcome.repair.backup_path == "/private/SERIAL_A-before.json"
