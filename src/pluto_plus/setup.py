"""Guarded canonical AD9361/2R2T setup plans and durable receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from pydantic import Field, field_validator

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT
from pluto_plus.models import ApiModel


class SetupError(RuntimeError):
    """Base class for canonical setup failures."""


class SetupUnavailableError(SetupError):
    """No setup helper is configured or reachable."""


class SetupPreconditionError(SetupError):
    """Observed hardware does not satisfy the immutable setup policy."""


class SetupAuthorizationError(SetupError):
    """A confirmation token is invalid, expired, reused, or plan-mismatched."""


class SetupPlanNotFoundError(SetupError):
    """The requested in-memory setup plan is unknown to this daemon."""


class SetupReceiptNotFoundError(SetupError):
    """The requested durable setup receipt is unknown to this daemon."""


class SetupExecutionError(SetupError):
    def __init__(self, message: str, receipt: SetupReceipt) -> None:
        super().__init__(message)
        self.receipt = receipt


class SetupExecutorFailure(SetupError):
    """An executor failed after creating a durable pre-mutation backup."""

    def __init__(
        self,
        message: str,
        *,
        backup_path: str,
        backup_sha256: str,
        after: SetupObservation | None = None,
        failure_phase: str = "environment_write",
        completed_phases: tuple[str, ...] = (),
        reconciliation_required: bool = True,
    ) -> None:
        super().__init__(message)
        self.backup_path = backup_path
        self.backup_sha256 = backup_sha256
        self.after = after
        self.failure_phase = failure_phase
        self.completed_phases = completed_phases
        self.reconciliation_required = reconciliation_required


class SetupIdentity(ApiModel):
    serial: str = Field(min_length=1, max_length=128)
    usb_sysfs_path: str = Field(pattern=r"^/sys/bus/usb/devices/[^/]+$")
    observed_firmware: str = Field(min_length=1, max_length=256)


class SetupObservation(ApiModel):
    identity: SetupIdentity
    board_model: str = Field(min_length=1, max_length=256)
    live_phy_model: str = Field(min_length=1, max_length=64)
    uboot: dict[str, str | None]
    environment_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    versions_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    qspi_firmware_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    boot_provenance: str = Field(min_length=1, max_length=64)
    rx_scan_channels: tuple[str, ...]
    tx_safe: bool

    @field_validator("uboot")
    @classmethod
    def validate_uboot_keys(
        cls, value: dict[str, str | None]
    ) -> dict[str, str | None]:
        if set(value) != set(CANONICAL_UBOOT):
            raise ValueError("U-Boot observation must contain exactly the canonical keys")
        return value


class SetupExecutionResult(ApiModel):
    observation: SetupObservation
    backup_path: str = Field(min_length=1, max_length=1024)
    backup_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    completed_phases: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SetupPlan:
    plan_id: str
    created_at: datetime
    expires_at: datetime
    identity: SetupIdentity
    profile_id: str
    environment_sha256: str
    before: SetupObservation
    changes_items: tuple[tuple[str, str | None], ...]
    tx_mute_required: bool

    @property
    def changes(self) -> dict[str, str | None]:
        return dict(self.changes_items)


@dataclass(frozen=True, slots=True)
class PlannedSetup:
    plan: SetupPlan
    confirmation_token: str


@dataclass(frozen=True, slots=True)
class SetupReceipt:
    schema_version: int
    receipt_id: str
    plan_id: str
    started_at: datetime
    finished_at: datetime
    identity: SetupIdentity
    before: SetupObservation
    after: SetupObservation | None
    changes_items: tuple[tuple[str, str | None], ...]
    backup_path: str | None
    backup_sha256: str | None
    outcome: Literal[
        "verified",
        "failed_before_mutation",
        "unknown",
        "reconciled_verified",
        "reconciled_not_canonical",
    ]
    failure_phase: str | None
    completed_phases: tuple[str, ...]
    reconciliation_required: bool
    reconciliation_of: str | None
    success: bool
    error: str | None

    @property
    def changes(self) -> dict[str, str | None]:
        return dict(self.changes_items)


class SetupExecutor(Protocol):
    def provision(self, plan: SetupPlan) -> SetupExecutionResult: ...


@dataclass(slots=True)
class _TokenRecord:
    digest: bytes
    plan: SetupPlan
    expires_at: datetime
    used: bool = False


class CanonicalSetupManager:
    """Issue and execute short-lived plans for the one canonical setup action."""

    _BOARD_MODEL = "Analog Devices PlutoSDR Rev.C (Z7010/AD9363)"
    _SAFE_BOOT_PROVENANCE = {
        "qspi_image_verified",
        "qspi_reboot_verified",
        "qspi_cold_boot_verified",
    }

    def __init__(
        self,
        *,
        receipt_directory: Path,
        inspector: Callable[[SetupIdentity], SetupObservation],
        executor: SetupExecutor,
        clock: Callable[[], datetime] | None = None,
        confirmation_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if confirmation_ttl <= timedelta(0):
            raise ValueError("confirmation_ttl must be positive")
        self._receipts_directory = receipt_directory
        self._inspect = inspector
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._ttl = confirmation_ttl
        self._tokens: dict[str, _TokenRecord] = {}
        self._receipts: dict[str, SetupReceipt] = {}
        self._lock = threading.Lock()
        self._load_receipts()

    def inspect(self, identity: SetupIdentity) -> SetupObservation:
        observation = self._inspect(identity)
        self._validate_identity(identity, observation)
        return observation

    def create_plan(self, identity: SetupIdentity) -> PlannedSetup:
        before = self.inspect(identity)
        self._validate_preconditions(before)
        changes = tuple(
            (key, expected)
            for key, expected in CANONICAL_UBOOT.items()
            if before.uboot.get(key) != expected
        )
        if not changes:
            raise SetupPreconditionError("radio setup is already canonical")
        now = self._now()
        plan = SetupPlan(
            plan_id=uuid.uuid4().hex,
            created_at=now,
            expires_at=now + self._ttl,
            identity=identity,
            profile_id=CANONICAL_POLICY.profile_id,
            environment_sha256=before.environment_sha256,
            before=before,
            changes_items=changes,
            tx_mute_required=not before.tx_safe,
        )
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._tokens[plan.plan_id] = _TokenRecord(
                digest=hashlib.sha256(token.encode()).digest(),
                plan=plan,
                expires_at=plan.expires_at,
            )
        return PlannedSetup(plan, token)

    def execute(
        self,
        plan: SetupPlan,
        confirmation_token: str,
        *,
        before_mutation: Callable[[], None] | None = None,
        after_mutation: Callable[[], None] | None = None,
    ) -> SetupReceipt:
        now = self._now()
        if now >= plan.expires_at:
            raise SetupAuthorizationError("confirmation token has expired")
        self._authorize(plan, confirmation_token, now, consume=False)
        current = self.inspect(plan.identity)
        if current != plan.before or current.environment_sha256 != plan.environment_sha256:
            raise SetupPreconditionError("radio identity or persistent environment changed")
        self._authorize(plan, confirmation_token, now, consume=True)
        started = self._now()
        result: SetupExecutionResult | None = None
        partial_failure: SetupExecutorFailure | None = None
        error: str | None = None
        outcome: Literal["verified", "failed_before_mutation", "unknown"] = "verified"
        failure_phase: str | None = None
        completed_phases: tuple[str, ...] = ()
        reconciliation_required = False
        mutation_started = False
        try:
            if before_mutation is not None:
                before_mutation()
            mutation_started = True
            result = self._executor.provision(plan)
            self._validate_success(plan.identity, result.observation)
        except SetupExecutorFailure as caught:
            partial_failure = caught
            error = f"{type(caught).__name__}: {caught}"
            outcome = "unknown" if caught.reconciliation_required else "failed_before_mutation"
            failure_phase = caught.failure_phase
            completed_phases = caught.completed_phases
            reconciliation_required = caught.reconciliation_required
        except SetupUnavailableError as caught:
            error = f"{type(caught).__name__}: {caught}"
            outcome = "failed_before_mutation"
            failure_phase = "preflight"
        except BaseException as caught:
            error = f"{type(caught).__name__}: {caught}"
            outcome = "unknown" if mutation_started else "failed_before_mutation"
            failure_phase = "executor" if mutation_started else "controller_quiesce"
            reconciliation_required = mutation_started
        finally:
            if mutation_started and after_mutation is not None:
                try:
                    after_mutation()
                except BaseException as caught:
                    recovery_error = f"{type(caught).__name__}: {caught}"
                    error = (
                        recovery_error
                        if error is None
                        else f"{error}; recovery failed: {recovery_error}"
                    )
        if result is not None:
            completed_phases = result.completed_phases or (
                "preflight",
                "backup",
                "tx_safe",
                "mutation_dispatched",
                "reboot_observed",
                "post_reboot_attestation",
            )
        receipt = SetupReceipt(
            schema_version=2,
            receipt_id=uuid.uuid4().hex,
            plan_id=plan.plan_id,
            started_at=started,
            finished_at=self._now(),
            identity=plan.identity,
            before=plan.before,
            after=(
                result.observation
                if result is not None
                else (None if partial_failure is None else partial_failure.after)
            ),
            changes_items=plan.changes_items,
            backup_path=(
                result.backup_path
                if result is not None
                else (None if partial_failure is None else partial_failure.backup_path)
            ),
            backup_sha256=(
                result.backup_sha256
                if result is not None
                else (None if partial_failure is None else partial_failure.backup_sha256)
            ),
            outcome=outcome,
            failure_phase=failure_phase,
            completed_phases=completed_phases,
            reconciliation_required=reconciliation_required,
            reconciliation_of=None,
            success=error is None,
            error=error,
        )
        self._write_receipt(receipt)
        with self._lock:
            self._receipts[receipt.receipt_id] = receipt
        if error is not None:
            raise SetupExecutionError(error, receipt)
        return receipt

    def list_receipts(self) -> list[SetupReceipt]:
        with self._lock:
            return sorted(
                self._receipts.values(), key=lambda item: item.started_at, reverse=True
            )

    def reconcile(self, receipt_id: str) -> SetupReceipt:
        """Re-attest an uncertain outcome without invoking the mutation executor."""

        with self._lock:
            original = self._receipts.get(receipt_id)
        if original is None:
            raise SetupReceiptNotFoundError(f"unknown setup receipt: {receipt_id}")
        if not original.reconciliation_required:
            raise SetupPreconditionError("setup receipt does not require reconciliation")
        started = self._now()
        observation = self.inspect(original.identity)
        if "reboot_observed" in original.completed_phases:
            observation = observation.model_copy(
                update={"boot_provenance": "qspi_reboot_verified"}
            )
        error: str | None = None
        try:
            self._validate_success(original.identity, observation)
        except SetupPreconditionError as caught:
            error = f"{type(caught).__name__}: {caught}"
        success = error is None
        receipt = SetupReceipt(
            schema_version=2,
            receipt_id=uuid.uuid4().hex,
            plan_id=original.plan_id,
            started_at=started,
            finished_at=self._now(),
            identity=original.identity,
            before=original.before,
            after=observation,
            changes_items=original.changes_items,
            backup_path=original.backup_path,
            backup_sha256=original.backup_sha256,
            outcome=("reconciled_verified" if success else "reconciled_not_canonical"),
            failure_phase=None if success else "read_only_reconciliation",
            completed_phases=(*original.completed_phases, "read_only_reconciliation"),
            reconciliation_required=False,
            reconciliation_of=original.receipt_id,
            success=success,
            error=error,
        )
        self._write_receipt(receipt)
        with self._lock:
            self._receipts[receipt.receipt_id] = receipt
        return receipt

    def _validate_preconditions(self, observation: SetupObservation) -> None:
        if observation.board_model != self._BOARD_MODEL:
            raise SetupPreconditionError("canonical setup requires exact PlutoSDR Rev.C")
        if observation.identity.observed_firmware != CANONICAL_POLICY.device_firmware:
            raise SetupPreconditionError("active firmware is not the selected canonical release")
        if observation.qspi_firmware_sha256 != CANONICAL_POLICY.fit_body_sha256:
            raise SetupPreconditionError("persistent QSPI firmware hash is not canonical")
        if observation.boot_provenance not in self._SAFE_BOOT_PROVENANCE:
            raise SetupPreconditionError("persistent QSPI boot provenance is not verified")
        if observation.uboot.get("mode") not in {"1r1t", "2r2t", None}:
            raise SetupPreconditionError("existing U-Boot mode is invalid")

    @staticmethod
    def _validate_identity(
        expected: SetupIdentity, observation: SetupObservation
    ) -> None:
        if observation.identity != expected:
            raise SetupPreconditionError("setup helper returned a different radio identity")

    def _validate_success(
        self, identity: SetupIdentity, observation: SetupObservation
    ) -> None:
        self._validate_identity(identity, observation)
        if observation.uboot != CANONICAL_UBOOT:
            raise SetupPreconditionError("canonical U-Boot tuple did not persist")
        if observation.live_phy_model != "ad9361":
            raise SetupPreconditionError("live PHY did not return as AD9361")
        required = {"voltage0", "voltage1", "voltage2", "voltage3"}
        if not required.issubset(observation.rx_scan_channels):
            raise SetupPreconditionError("dual receiver scan channels did not return")
        if observation.boot_provenance not in {
            "qspi_reboot_verified",
            "qspi_cold_boot_verified",
        }:
            raise SetupPreconditionError("radio did not return from verified QSPI reboot")
        if not observation.tx_safe:
            raise SetupPreconditionError("transmit state is not safe after reboot")

    def _authorize(
        self, plan: SetupPlan, token: str, now: datetime, *, consume: bool
    ) -> None:
        presented = hashlib.sha256(token.encode()).digest()
        with self._lock:
            record = self._tokens.get(plan.plan_id)
            if record is None or not hmac.compare_digest(record.digest, presented):
                raise SetupAuthorizationError("confirmation token is invalid")
            if record.plan != plan:
                raise SetupAuthorizationError("confirmation token is bound to another plan")
            if record.used:
                raise SetupAuthorizationError("confirmation token was already used")
            if now >= record.expires_at:
                raise SetupAuthorizationError("confirmation token has expired")
            if consume:
                record.used = True

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None:
            raise ValueError("setup clock must return a timezone-aware datetime")
        return value.astimezone(UTC)

    def _write_receipt(self, receipt: SetupReceipt) -> None:
        self._receipts_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self._receipts_directory, 0o700)
        destination = self._receipts_directory / f"{receipt.receipt_id}.json"
        temporary = destination.with_suffix(".tmp")
        payload = _receipt_document(receipt)
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, sort_keys=True, separators=(",", ":")))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(destination)
        directory_fd = os.open(self._receipts_directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

    def _load_receipts(self) -> None:
        if not self._receipts_directory.is_dir():
            return
        for path in self._receipts_directory.glob("*.json"):
            try:
                document = json.loads(path.read_text())
                receipt = _receipt_from_document(document)
            except (OSError, ValueError, TypeError, KeyError):
                continue
            if receipt.backup_path is None and receipt.outcome == "unknown":
                candidate = (
                    self._receipts_directory.parent
                    / "backups"
                    / receipt.identity.serial
                    / f"{receipt.plan_id}.json"
                )
                if candidate.is_file() and not candidate.is_symlink():
                    try:
                        digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
                    except OSError:
                        pass
                    else:
                        completed = ["preflight", "backup"]
                        legacy_error = (receipt.error or "").lower()
                        if "after reboot" in legacy_error or "host key" in legacy_error:
                            completed.extend(("mutation_dispatched", "reboot_observed"))
                        receipt = replace(
                            receipt,
                            backup_path=str(candidate),
                            backup_sha256=digest,
                            completed_phases=tuple(completed),
                        )
            self._receipts[receipt.receipt_id] = receipt


def _observation_document(observation: SetupObservation) -> dict[str, object]:
    return observation.model_dump(mode="json")


def _receipt_document(receipt: SetupReceipt) -> dict[str, object]:
    return {
        "schema_version": receipt.schema_version,
        "receipt_id": receipt.receipt_id,
        "plan_id": receipt.plan_id,
        "started_at": receipt.started_at.isoformat(),
        "finished_at": receipt.finished_at.isoformat(),
        "identity": receipt.identity.model_dump(mode="json"),
        "before": _observation_document(receipt.before),
        "after": None if receipt.after is None else _observation_document(receipt.after),
        "changes_items": list(receipt.changes_items),
        "backup_path": receipt.backup_path,
        "backup_sha256": receipt.backup_sha256,
        "outcome": receipt.outcome,
        "failure_phase": receipt.failure_phase,
        "completed_phases": list(receipt.completed_phases),
        "reconciliation_required": receipt.reconciliation_required,
        "reconciliation_of": receipt.reconciliation_of,
        "success": receipt.success,
        "error": receipt.error,
    }


def _receipt_from_document(document: Mapping[str, object]) -> SetupReceipt:
    after = document["after"]
    raw_changes = document["changes_items"]
    if not isinstance(raw_changes, list):
        raise TypeError("changes_items must be a list")
    changes: list[tuple[str, str | None]] = []
    for item in raw_changes:
        if not isinstance(item, list) or len(item) != 2:
            raise TypeError("each setup receipt change must be a pair")
        changes.append((str(item[0]), None if item[1] is None else str(item[1])))
    success = bool(document["success"])
    raw_completed = document.get("completed_phases", [])
    if not isinstance(raw_completed, list):
        raise TypeError("completed_phases must be a list")
    outcome = str(document.get("outcome", "verified" if success else "unknown"))
    if outcome not in {
        "verified",
        "failed_before_mutation",
        "unknown",
        "reconciled_verified",
        "reconciled_not_canonical",
    }:
        raise ValueError("invalid setup receipt outcome")
    return SetupReceipt(
        schema_version=int(str(document["schema_version"])),
        receipt_id=str(document["receipt_id"]),
        plan_id=str(document["plan_id"]),
        started_at=datetime.fromisoformat(str(document["started_at"])),
        finished_at=datetime.fromisoformat(str(document["finished_at"])),
        identity=SetupIdentity.model_validate(document["identity"]),
        before=SetupObservation.model_validate(document["before"]),
        after=None if after is None else SetupObservation.model_validate(after),
        changes_items=tuple(changes),
        backup_path=(
            None if document["backup_path"] is None else str(document["backup_path"])
        ),
        backup_sha256=(
            None
            if document["backup_sha256"] is None
            else str(document["backup_sha256"])
        ),
        outcome=outcome,  # type: ignore[arg-type]
        failure_phase=(
            None
            if document.get("failure_phase") is None
            else str(document["failure_phase"])
        ),
        completed_phases=tuple(str(item) for item in raw_completed),
        reconciliation_required=bool(
            document.get("reconciliation_required", outcome == "unknown")
        ),
        reconciliation_of=(
            None
            if document.get("reconciliation_of") is None
            else str(document["reconciliation_of"])
        ),
        success=success,
        error=None if document["error"] is None else str(document["error"]),
    )
