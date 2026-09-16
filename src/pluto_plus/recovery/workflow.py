"""Evidence-gated recovery orchestration; no blind retries or automatic reboot."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from typing import Protocol

from pluto_plus.radio_lock import acquire_radio_lock

from .contracts import (
    Blob,
    Dispatch,
    HistoricalBoot,
    Observation,
    Plan,
    Profile,
    Provenance,
    RecoveryError,
    ReturnEvidence,
    Sector,
    Target,
    canonical,
    digest,
)
from .planner import build_plan, validate_plan
from .profiles import qualify
from .store import Store, parse


class Backend(Protocol):
    """Implemented only by a qualified, exclusively bound transport adapter."""

    def lease(self) -> AbstractContextManager[None]: ...
    def observe(self) -> Observation: ...
    def read(self, start: int, size: int) -> bytes: ...
    def export_and_reload(self, data: bytes) -> None: ...
    def stage(self, payload: bytes) -> None: ...
    def erase(self, start: int, size: int) -> None: ...
    def program(self, start: int, size: int) -> None: ...
    def ram_boot(self, fit: bytes) -> ReturnEvidence: ...
    def return_to_sd(self) -> None: ...
    def attest_cold_boot(self) -> ReturnEvidence: ...


def same_target(expected: Target, current: Target) -> None:
    if expected != current:
        raise RecoveryError("target_mismatch", "physical target binding changed")


def same_observation(expected: Observation, current: Observation) -> bool:
    return expected.model_dump(exclude={"transcript"}) == current.model_dump(exclude={"transcript"})


class Workflow:
    def __init__(self, store: Store, profile: Profile, backend: Backend | None = None) -> None:
        self.store, self.profile, self._backend = store, profile, backend
        if store.session.profile_id != profile.profile_id:
            raise RecoveryError("profile_mismatch", "session profile differs")

    @property
    def backend(self) -> Backend:
        if self._backend is None:
            raise RecoveryError("backend_unqualified", "a qualified live backend is required")
        return self._backend

    def observe(self, *, mutation: bool = False) -> Observation:
        observed = self.backend.observe()
        if observed.target.adapter != self.store.session.adapter:
            raise RecoveryError("target_mismatch", "adapter differs from session")
        self.store.get(observed.transcript)
        qualify(self.profile, observed, mutation=mutation)
        return observed

    def read_full(self) -> bytes:
        # The qualification, not agreeing checksums, establishes physical placement.
        capacity = self.profile.geometry.capacity
        data = self.backend.read(0, capacity)
        if len(data) != capacity:
            raise RecoveryError("backup_invalid", "short physical flash read")
        # Deliberately revisit high -> low, plus overlapping boundary windows.
        points = {0, max(0, capacity - 256)}
        if capacity > 0x1000000:
            points.update({0x1000000 - 128, 0x1000000})
        for start in sorted(points, reverse=True):
            size = min(256, capacity - start)
            if self.backend.read(start, size) != data[start : start + size]:
                raise RecoveryError("physical_read_inconsistent", "boundary/repeated read differs")
        return data

    def capture(self, prepare_boot: Callable[[], None] | None = None) -> Blob:
        with self.store.lock(), self.backend.lease():
            if any(e.kind == "backup_verified" for e in self.store.events()):
                raise RecoveryError("backup_exists", "original backup is immutable; use resume")
            if prepare_boot is not None:
                prepare_boot()
            observed = self.observe()
            self.store.record("bootstrap_ready", {"observation": observed.model_dump(mode="json")})
            data = self.read_full()
            if (
                self.profile.original_flash_sha256
                and digest(data) != self.profile.original_flash_sha256
            ):
                raise RecoveryError(
                    "incident_image_mismatch", "current flash differs from bound incident"
                )
            candidate = self.store.put(data)
            self.store.record("backup_candidate", {"backup": candidate.model_dump()})
            self.backend.export_and_reload(data)
            again = self.observe()
            if not same_observation(again, observed):
                raise RecoveryError(
                    "observation_changed", "target/bootstrap changed during capture"
                )
            backup = self.store.put(data)
            self.store.get(backup)
            self.store.record(
                "backup_verified",
                {"backup": backup.model_dump(), "observation": observed.model_dump(mode="json")},
            )
            return backup

    def plan(self, boot: bytes, fit: bytes, provenance: Provenance, history: bytes) -> Plan:
        with self.store.lock():
            historical = parse(history, HistoricalBoot)
            if (
                digest(history) != provenance.historical_record_sha256
                or historical.target_uid != provenance.target_uid
                or historical.boot_sha256 != provenance.historical_boot_sha256
            ):
                raise RecoveryError("provenance_missing", "historical target boot receipt differs")
            self.store.put(history)
            if any(e.kind.endswith("_intent") for e in self.store.events()):
                raise RecoveryError(
                    "resume_required", "an attempt exists; inspect current hardware"
                )
            source = self.store.latest("backup_verified")
            observed = Observation.model_validate(source.data["observation"])
            original = self.store.get(Blob.model_validate(source.data["backup"]))
            plan = build_plan(
                session_id=self.store.session.session_id,
                profile=self.profile,
                observed=observed,
                original=original,
                boot=boot,
                fit=fit,
                provenance=provenance,
                history=history,
                put=self.store.put,
            )
            self._save_plan(plan)
            return plan

    def _save_plan(self, plan: Plan) -> None:
        blob = self.store.put(canonical(plan))
        self.store.record("plan_ready", {"plan": blob.model_dump(), "plan_sha256": plan.sha256})

    def current_plan(self) -> Plan:
        event = self.store.latest("plan_ready")
        plan = parse(self.store.get(Blob.model_validate(event.data["plan"])), Plan)
        if plan.session_id != self.store.session.session_id:
            raise RecoveryError("plan_invalid", "plan belongs to another session")
        validate_plan(plan, self.profile, self.store.get)
        return plan

    def _fresh(self, plan: Plan) -> Observation:
        observed = self.observe(mutation=True)
        same_target(plan.observation.target, observed.target)
        if self.read_full() != self.store.get(plan.current):
            raise RecoveryError("plan_stale", "current physical bytes differ; use resume")
        return observed

    def _runtime(self, evidence: ReturnEvidence, plan: Plan, source: str) -> None:
        same_target(plan.observation.target, evidence.target)
        self.store.get(evidence.transcript)
        expected = self.profile.rollback
        if (
            evidence.fit_sha256 != expected.sha256
            or evidence.firmware != expected.expected_firmware
            or evidence.layout != expected.expected_layout
            or evidence.boot_source != source
            or not all(
                (evidence.network_ok, evidence.iio_ok, evidence.rf_inactive, evidence.settings_ok)
            )
        ):
            raise RecoveryError(
                "return_unverified", "image, source, services, settings or RF differs"
            )

    def ram_test(
        self,
        prepare_return: Callable[[], None] | None = None,
        prepare_boot: Callable[[], None] | None = None,
    ) -> None:
        with self.store.lock(), self.backend.lease():
            plan = self.current_plan()
            if self.store.status()["state"] != "plan_ready":
                raise RecoveryError("resume_required", "RAM test requires a fresh ready plan")
            if prepare_boot is not None:
                prepare_boot()
            observed = self._fresh(plan)
            serial = observed.target.serial or f"recovery-{observed.target.uid}"
            with acquire_radio_lock(serial):
                self.store.record("ram_boot_intent", {"plan_sha256": plan.sha256})
                try:
                    fit_patch = next(p for p in plan.patches if p.kind == "fit")
                    evidence = self.backend.ram_boot(self.store.get(fit_patch.payload))
                    self._runtime(evidence, plan, "ram")
                    if prepare_return is not None:
                        prepare_return()
                    self.backend.return_to_sd()
                    after = self._fresh(plan)
                    self.store.record(
                        "ram_boot_verified",
                        {
                            "plan_sha256": plan.sha256,
                            "observation": after.model_dump(mode="json"),
                            "runtime": evidence.model_dump(mode="json"),
                        },
                    )
                except BaseException as error:
                    self._interrupted(error)
                    raise

    def _interrupted(self, error: BaseException) -> None:
        # Raw exception text may contain credentials or environment values.
        self.store.record(
            "interrupted",
            {
                "code": (
                    error.code
                    if isinstance(error, RecoveryError)
                    else "transport_or_storage_failure"
                )
            },
        )

    def execute(self, confirmation: str) -> None:
        with self.store.lock(), self.backend.lease():
            plan = self.current_plan()
            if confirmation != f"RECOVER {self.store.session.session_id} {plan.sha256}":
                raise RecoveryError(
                    "confirmation_mismatch", "confirm this session and exact plan digest"
                )
            if self.store.status()["state"] != "ram_boot_verified":
                raise RecoveryError("ram_test_required", "fresh RAM acceptance is required")
            ram = self.store.latest("ram_boot_verified")
            if ram.data["plan_sha256"] != plan.sha256:
                raise RecoveryError("ram_test_required", "RAM acceptance belongs to another plan")
            current = self._fresh(plan)
            bound = Observation.model_validate(ram.data["observation"])
            if not same_observation(current, bound):
                raise RecoveryError("plan_stale", "bootstrap epoch/evidence changed after RAM test")
            expected = bytearray(self.store.get(plan.current))
            serial = current.target.serial or f"recovery-{current.target.uid}"
            with acquire_radio_lock(serial):
                try:
                    for sector in plan.sectors:
                        payload = self.store.get(sector.after)
                        self.backend.stage(payload)
                        if not same_observation(self.observe(mutation=True), current):
                            raise RecoveryError(
                                "plan_stale", "writer or target changed after staging"
                            )
                        if (
                            self.backend.read(sector.start, sector.size)
                            != expected[sector.start : sector.start + sector.size]
                        ):
                            raise RecoveryError(
                                "integrity_failed", "unexpected intermediate flash change"
                            )
                        intent: dict[str, object] = {
                            "plan_sha256": plan.sha256,
                            "start": sector.start,
                            "size": sector.size,
                            "payload_sha256": sector.after.sha256,
                        }
                        self.store.record("erase_intent", intent)
                        self.backend.erase(sector.start, sector.size)
                        self.store.record("erase_completed", intent)
                        if not same_observation(self.observe(mutation=True), current):
                            raise RecoveryError("plan_stale", "target/writer changed after erase")
                        if self.backend.read(sector.start, sector.size) != b"\xff" * sector.size:
                            raise RecoveryError("integrity_failed", "erased sector did not verify")
                        self.store.record("program_intent", intent)
                        self.backend.program(sector.start, sector.size)
                        if self.backend.read(sector.start, sector.size) != payload:
                            raise RecoveryError("integrity_failed", "sector readback differs")
                        expected[sector.start : sector.start + sector.size] = payload
                        self.store.record("sector_verified", intent)
                    if self.read_full() != self.store.get(plan.expected):
                        raise RecoveryError("integrity_failed", "complete physical flash differs")
                    # Reconstructing the plan independently rechecks boot and env semantics.
                    validate_plan(plan, self.profile, self.store.get)
                    self.store.record(
                        "flash_verified",
                        {"plan_sha256": plan.sha256, "flash": plan.expected.model_dump()},
                    )
                    self.store.record("awaiting_cold_boot", {"plan_sha256": plan.sha256})
                except BaseException as error:
                    self._interrupted(error)
                    raise

    def resume(self, prepare_boot: Callable[[], None] | None = None) -> Plan:
        with self.store.lock(), self.backend.lease():
            plan = self.current_plan()
            if prepare_boot is not None:
                prepare_boot()
            current = self.observe(mutation=True)
            same_target(plan.observation.target, current.target)
            data = self.read_full()
            before = self.store.get(plan.current)
            expected = self.store.get(plan.expected)
            # Only a dispatched sector can explain bytes different from this attempt's baseline.
            intents = [
                Dispatch.model_validate(e.data)
                for e in self.store.events()
                if e.kind in {"erase_intent", "program_intent"}
                and e.data.get("plan_sha256") == plan.sha256
            ]
            dispatched = {(e.start, e.size) for e in intents}
            restored = bytearray(data)
            for start, size in dispatched:
                if not any(s.start == start and s.size == size for s in plan.sectors):
                    raise RecoveryError(
                        "journal_invalid", "dispatched footprint is not in the plan"
                    )
                restored[start : start + size] = before[start : start + size]
            if restored != before:
                raise RecoveryError(
                    "unexplained_flash_change", "bytes changed outside dispatched sectors"
                )
            sectors = tuple(
                Sector(
                    kind=s.kind,
                    start=s.start,
                    size=s.size,
                    before_sha256=digest(data[s.start : s.start + s.size]),
                    after=s.after,
                )
                for s in plan.sectors
                if data[s.start : s.start + s.size] != expected[s.start : s.start + s.size]
            )
            successor = Plan.model_validate(
                plan.model_dump()
                | {
                    "observation": current,
                    "current": self.store.put(data),
                    "sectors": sectors,
                    "parent_plan": plan.sha256,
                }
            )
            validate_plan(successor, self.profile, self.store.get)
            self._save_plan(successor)
            return successor

    def attest(self, prepare_boot: Callable[[], None] | None = None) -> ReturnEvidence:
        with self.store.lock(), self.backend.lease():
            plan = self.current_plan()
            if self.store.status()["state"] != "awaiting_cold_boot":
                raise RecoveryError(
                    "flash_verification_required", "complete flash verification required"
                )
            if self.store.latest("flash_verified").data["plan_sha256"] != plan.sha256:
                raise RecoveryError("plan_stale", "flash verification belongs to another plan")
            serial = plan.observation.target.serial or f"recovery-{plan.observation.target.uid}"
            with acquire_radio_lock(serial):
                if prepare_boot is not None:
                    prepare_boot()
                evidence = self.backend.attest_cold_boot()
                self._runtime(evidence, plan, "qspi")
                if (
                    evidence.reset_cause != "power_on"
                    or not evidence.operator_power_off
                    or not evidence.operator_sd_removed
                    or evidence.boot_epoch == plan.observation.boot_epoch
                ):
                    raise RecoveryError(
                        "cold_boot_unverified", "actual QSPI cold-boot evidence required"
                    )
                self.store.record(
                    "recovered",
                    {
                        "plan_sha256": plan.sha256,
                        "return": evidence.model_dump(mode="json"),
                        "linux_extended_writes_qualified": False,
                    },
                )
                return evidence
