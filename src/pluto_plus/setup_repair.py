"""Credentialed persistent-setup inspection and guarded repair for the local doctor.

The standalone doctor reads USB topology and live IIOD facts, and neither can reach
the persistent U-Boot environment.  Given exact-radio SSH credentials this module
reads the real tuple, and unless repair is disabled it drives the existing guarded
setup transaction -- environment backup, fail-closed TX mute, environment-digest
binding, reboot, re-attestation, and a durable receipt -- to restore the canonical
values.  It never invents a mutation path of its own.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pluto_plus.doctor import CANONICAL_UBOOT
from pluto_plus.setup import (
    CanonicalSetupManager,
    SetupError,
    SetupIdentity,
    SetupPreconditionError,
)
from pluto_plus.setup_helper import (
    BoundSshTransport,
    FixedSshSetupExecutor,
    SetupHelperError,
)

ProbeStatus = Literal["pass", "fail", "unknown"]
ManagerFactory = Callable[[SetupIdentity], CanonicalSetupManager]

_ALREADY_CANONICAL = "radio setup is already canonical"


@dataclass(frozen=True, slots=True)
class SetupCredentials:
    """Exact-radio SSH material needed to reach one radio's persistent environment."""

    host: str
    password: str
    known_hosts_file: Path
    receipt_directory: Path
    state_root: Path
    interface: str | None = None


@dataclass(frozen=True, slots=True)
class SetupRepairRecord:
    """What a repair attempt actually did, for the report and the operator."""

    attempted: bool
    succeeded: bool
    changes: tuple[tuple[str, str | None], ...] = ()
    receipt_id: str | None = None
    backup_path: str | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class SetupProbeOutcome:
    """Persistent-tuple facts, plus any repair performed in the same pass."""

    status: ProbeStatus
    actual: tuple[tuple[str, str | None], ...] | None
    summary: str
    repair: SetupRepairRecord | None = None


def ssh_manager_factory(
    credentials: SetupCredentials,
) -> ManagerFactory:
    """Build the real SSH-backed manager factory for one radio's credentials."""

    def build(identity: SetupIdentity) -> CanonicalSetupManager:
        transport = BoundSshTransport(
            host=credentials.host,
            interface=credentials.interface,
            password=credentials.password,
            known_hosts_file=credentials.known_hosts_file,
        )
        executor = FixedSshSetupExecutor(
            identity=identity,
            transport=transport,
            state_root=credentials.state_root,
        )
        return CanonicalSetupManager(
            receipt_directory=credentials.receipt_directory,
            inspector=executor.inspect,
            executor=executor,
        )

    return build


def probe_and_repair(
    *,
    serial: str,
    usb_sysfs_path: str,
    firmware_version: str | None,
    manager_factory: ManagerFactory,
    repair: bool = True,
) -> SetupProbeOutcome:
    """Read the persistent tuple for one exact radio and optionally restore it.

    Returns an ``unknown`` outcome rather than raising when the radio cannot be
    reached, so a credentialed doctor run degrades to the read-only report instead
    of failing the whole sweep.
    """

    if not firmware_version:
        return SetupProbeOutcome(
            status="unknown",
            actual=None,
            summary="Persistent tuple needs an attested firmware version to bind an identity",
        )
    try:
        identity = SetupIdentity(
            serial=serial,
            usb_sysfs_path=usb_sysfs_path,
            observed_firmware=firmware_version,
        )
        manager = manager_factory(identity)
        observation = manager.inspect(identity)
    except (SetupError, SetupHelperError, OSError, ValueError) as error:
        return SetupProbeOutcome(
            status="unknown",
            actual=None,
            summary=f"Persistent tuple could not be read: {error}",
        )

    actual = tuple((key, observation.uboot.get(key)) for key in CANONICAL_UBOOT)
    if dict(actual) == CANONICAL_UBOOT:
        return SetupProbeOutcome(
            status="pass",
            actual=actual,
            summary="Persistent AD9361/2R2T U-Boot tuple is canonical",
        )
    if not repair:
        return SetupProbeOutcome(
            status="fail",
            actual=actual,
            summary="Persistent AD9361/2R2T U-Boot tuple is not canonical; repair is disabled",
        )
    return _repair(manager, identity, actual)


def _repair(
    manager: CanonicalSetupManager,
    identity: SetupIdentity,
    actual: tuple[tuple[str, str | None], ...],
) -> SetupProbeOutcome:
    try:
        planned = manager.create_plan(identity)
    except SetupPreconditionError as error:
        if str(error) == _ALREADY_CANONICAL:
            return SetupProbeOutcome(
                status="pass",
                actual=actual,
                summary="Persistent AD9361/2R2T U-Boot tuple is canonical",
            )
        return _repair_failed(actual, (), str(error))
    except (SetupError, SetupHelperError, OSError, ValueError) as error:
        return _repair_failed(actual, (), str(error))

    changes = planned.plan.changes_items
    try:
        receipt = manager.execute(planned.plan, planned.confirmation_token)
    except (SetupError, SetupHelperError, OSError, ValueError) as error:
        return _repair_failed(actual, changes, str(error))

    if not receipt.success or receipt.after is None:
        return _repair_failed(actual, changes, receipt.error or receipt.outcome)
    repaired = tuple((key, receipt.after.uboot.get(key)) for key in CANONICAL_UBOOT)
    return SetupProbeOutcome(
        status="pass" if dict(repaired) == CANONICAL_UBOOT else "fail",
        actual=repaired,
        summary=(
            "Persistent AD9361/2R2T U-Boot tuple was repaired and re-attested after reboot"
            if dict(repaired) == CANONICAL_UBOOT
            else "Repair completed but the re-attested tuple is still not canonical"
        ),
        repair=SetupRepairRecord(
            attempted=True,
            succeeded=dict(repaired) == CANONICAL_UBOOT,
            changes=changes,
            receipt_id=receipt.receipt_id,
            backup_path=receipt.backup_path,
        ),
    )


def _repair_failed(
    actual: tuple[tuple[str, str | None], ...],
    changes: tuple[tuple[str, str | None], ...],
    error: str,
) -> SetupProbeOutcome:
    return SetupProbeOutcome(
        status="fail",
        actual=actual,
        summary=f"Persistent AD9361/2R2T U-Boot tuple repair failed: {error}",
        repair=SetupRepairRecord(attempted=True, succeeded=False, changes=changes, error=error),
    )
