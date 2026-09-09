"""Bounded PSS control evidence, distinct from result, RF and stop qualification.

Single current_index reads are u64 hardware snapshots. Collections of sysfs
attributes are separately sampled, never atomic snapshots. A successful enable
write is an acknowledgment; subsequent scheduling/submission counters are only
observations. The binding does not expose native attribute-write byte counts.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pluto_plus.errors import RadioConfigurationError

if TYPE_CHECKING:
    from pluto_plus.hardware.fine_schedule import FineScheduleManifest
    from pluto_plus.hardware.source_support import ObservationIdentity

CONTROL_FIELDS = (
    "fpga_identity", "abi_version", "rate_msps", "geometry", "capabilities", "status",
    "active_coefficient_generation", "schedule_first_center", "schedule_period_q32_32",
    "schedule_request_base", "schedule_count", "schedule_queue_target", "schedule_enable",
    "schedule_submitted", "packets_delivered", "buffer_push_failures",
    "packet_validation_failures", "fault_flags", "current_index",
)
_U64_FIELDS = {"current_index", "schedule_first_center", "schedule_period_q32_32"}
_CONSTANTS = {"fpga_identity": 0x50535354, "abi_version": 0x10002, "rate_msps": 15,
              "geometry": 0x003d8242, "capabilities": 0x3d}


@dataclass(frozen=True, slots=True)
class PssControlStep:
    """One operation at the binding boundary; raw text preserves whitespace.

    attempted=False means native I/O was not entered (for example deadline or
    timeout setup failure). returned=False after attempted=True is uncertain,
    including interrupted writes. A read's raw prefix may be truncated with its
    observed character count retained. Native byte count is deliberately absent.
    """

    phase: str
    action: str
    name: str
    requested: str | None = None
    attempted: bool = False
    returned: bool = False
    raw: str | None = None
    raw_characters: int | None = None
    value: int | None = None
    error: str | None = None


class PssWriteAcceptance(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    ACKNOWLEDGED = "acknowledged"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class PssTrackerControlReceipt:
    observation: ObservationIdentity
    requested_fields: tuple[str, ...]
    steps: tuple[PssControlStep, ...]
    context_identity: tuple[tuple[str, str | None], ...]
    errors: tuple[str, ...]

    @property
    def complete(self) -> bool:
        if (not isinstance(self.errors, tuple) or self.errors
                or self.requested_fields not in (CONTROL_FIELDS, ("current_index",))
                or not isinstance(self.steps, tuple)
                or len(self.steps) != len(self.requested_fields)):
            return False
        if not _identity_matches(self.observation, self.context_identity):
            return False
        return all(_valid_read(step, name) for step, name in zip(
            self.steps, self.requested_fields, strict=True))

    def value(self, name: str) -> int | None:
        """A decoded individual read, possibly diagnostic when the receipt failed."""
        return next((step.value for step in self.steps if step.name == name), None)

    @property
    def current_index(self) -> int | None:
        return self.value("current_index")

    @property
    def context_boot_id(self) -> str | None:
        """Cached context metadata, not a fresh boot attestation or inferred identity."""
        return dict(self.context_identity).get("boot_id")


@dataclass(frozen=True, slots=True)
class PssFineStartReceipt:
    manifest: FineScheduleManifest
    queue_target: int
    refill_results: int
    stream_id: str | None
    before: PssTrackerControlReceipt | None
    after: PssTrackerControlReceipt | None
    steps: tuple[PssControlStep, ...]
    errors: tuple[str, ...]
    cleanup_attempted: bool = False
    cleanup_verified: bool | None = None

    @property
    def enable_acceptance(self) -> PssWriteAcceptance:
        """Historical acknowledgment, NOT whether the producer remains enabled now."""
        if (not isinstance(self.steps, tuple) or len(self.steps) > 128
                or any(not isinstance(step, PssControlStep) for step in self.steps)):
            return PssWriteAcceptance.UNKNOWN
        matches = tuple(step for step in self.steps if step.phase == "open"
                        and step.action == "write" and step.name == "schedule_enable"
                        and step.requested == "1")
        if not matches:
            return PssWriteAcceptance.NOT_ATTEMPTED
        if len(matches) != 1:
            return PssWriteAcceptance.UNKNOWN
        step = matches[0]
        if step.attempted is False:
            return PssWriteAcceptance.NOT_ATTEMPTED
        return (PssWriteAcceptance.ACKNOWLEDGED if step.returned is True
                and step.attempted is True
                else PssWriteAcceptance.UNKNOWN)

    @property
    def complete(self) -> bool:
        if (not isinstance(self.errors, tuple) or self.errors
                or not isinstance(self.steps, tuple) or len(self.steps) > 128
                or self.enable_acceptance is not PssWriteAcceptance.ACKNOWLEDGED
                or self.before is None or not self.before.complete
                or self.after is None or not self.after.complete
                or not isinstance(self.stream_id, str) or not 1 <= len(self.stream_id) <= 256
                or self.cleanup_attempted is not False or self.cleanup_verified is not None
                or self.before.observation != self.manifest.observation
                or self.after.observation != self.manifest.observation
                or type(self.queue_target) is not int or not 1 <= self.queue_target <= 7
                or type(self.refill_results) is not int or not 1 <= self.refill_results <= 4096
                or self.manifest.count % self.refill_results):
            return False
        count = len(CONTROL_FIELDS)
        if (self.before.requested_fields != CONTROL_FIELDS
                or self.after.requested_fields != CONTROL_FIELDS
                or len(self.steps) != 1 + 2 * count + 10
                or (self.steps[0].phase, self.steps[0].action, self.steps[0].name)
                != ("identity", "metadata", "context_identity")
                or self.before.steps != self.steps[1:1 + count]
                or self.after.steps != self.steps[11 + count:]
                or any(step.attempted is not True or step.returned is not True
                       or step.error is not None for step in self.steps)):
            return False
        writes = tuple((step.name, step.requested) for step in self.steps
                       if step.phase == "open" and step.action == "write")
        expected = (("schedule_first_center", str(self.manifest.first_center)),
                    ("schedule_period_q32_32", str(self.manifest.period_q32_32)),
                    ("schedule_request_base", str(self.manifest.request_base)),
                    ("schedule_count", str(self.manifest.count)),
                    ("schedule_queue_target", str(self.queue_target)), ("schedule_enable", "1"))
        opened = tuple(step for step in self.steps if step.phase == "open")
        if writes != expected or opened != self.steps[1 + count:11 + count] or any(
            step.attempted is not True or step.returned is not True or step.error is not None
            for step in opened
        ):
            return False
        if tuple((step.action, step.name, step.requested) for step in opened
                 if step.action != "write") != (
            ("prepare", "disable_scan_channels", None), ("prepare", "enable_packet_scan", None),
            ("allocate", "fine_buffer", str(self.refill_results)),
            ("validate", "fine_buffer_geometry", None),
        ):
            return False
        return (not _start_control_errors(self.before, self.manifest, after=False,
                                         queue_target=self.queue_target)
                and not _start_control_errors(self.after, self.manifest, after=True,
                                             queue_target=self.queue_target)
                and self.before.current_index is not None and self.after.current_index is not None
                and self.after.current_index >= self.before.current_index)


class PssTrackerControlError(RadioConfigurationError):
    def __init__(self, receipt: PssTrackerControlReceipt) -> None:
        super().__init__("PSS control evidence incomplete: " + "; ".join(receipt.errors))
        self.receipt = receipt


class PssFineStartError(RadioConfigurationError):
    def __init__(self, receipt: PssFineStartReceipt) -> None:
        super().__init__("PSS fine start incomplete: " + "; ".join(receipt.errors))
        self.receipt = receipt


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"[:512]


def _identity_matches(
    observation: ObservationIdentity, identity: tuple[tuple[str, str | None], ...],
) -> bool:
    if not isinstance(identity, tuple) or len(identity) != 4:
        return False
    if any(not isinstance(item, tuple) or len(item) != 2 for item in identity):
        return False
    if tuple(name for name, _ in identity) != ("hw_serial", "usb,serial", "serial", "boot_id"):
        return False
    if any(value is not None and (not isinstance(value, str) or len(value) > 256)
           for _, value in identity):
        return False
    serials = [value for name, value in identity if name != "boot_id" and value]
    boot = identity[-1][1]
    return bool(serials) and all(value == observation.serial for value in serials) and (
        boot is None or boot == observation.boot_id)


def _valid_read(step: PssControlStep, name: str) -> bool:
    if (not isinstance(step, PssControlStep) or step.name != name or step.action != "read"
            or step.phase not in {"control", "before", "after"} or step.requested is not None
            or step.attempted is not True or step.returned is not True or step.error is not None
            or not isinstance(step.raw, str) or len(step.raw) > 128
            or type(step.raw_characters) is not int or step.raw_characters != len(step.raw)
            or type(step.value) is not int):
        return False
    try:
        parsed = int(step.raw.strip(), 0)
    except ValueError:
        return False
    maximum = (1 << (64 if name in _U64_FIELDS else 32)) - 1
    return (0 <= parsed <= maximum and parsed == step.value
            and (name not in _CONSTANTS or parsed == _CONSTANTS[name])
            and (name != "schedule_enable" or parsed in (0, 1)))


class _ControlJournal:
    """Internal fixed-work journal; callbacks are implementation operations, not user hooks."""

    def __init__(self, *, timeout_ms: int, budget_ms: int, setter: Callable[[int], Any]) -> None:
        for name, value in (("timeout_ms", timeout_ms), ("budget_ms", budget_ms)):
            if type(value) is not int or not 1 <= value <= 60_000:
                raise ValueError(f"{name} must be 1..60000 milliseconds")
        self.timeout_ms = timeout_ms
        self.deadline = time.monotonic() + budget_ms / 1000
        self.setter = setter
        self.steps: list[PssControlStep] = []
        self.stream_id: str | None = None
        self.cleanup_attempted = False

    def begin_cleanup(self) -> None:
        # Cleanup has its own finite reserve and must remain possible after the
        # acquisition budget expires. It does not reset the evidence of failure.
        self.cleanup_attempted = True
        self.deadline = time.monotonic() + min(2 * self.timeout_ms, 60_000) / 1000

    def call(
        self, phase: str, action: str, name: str, operation: Callable[[], Any], *,
        requested: str | None = None,
    ) -> Any:
        if len(self.steps) >= 128:
            raise ValueError("PSS control journal exceeded its fixed operation cap")
        index = len(self.steps)
        self.steps.append(PssControlStep(phase, action, name, requested))
        try:
            remaining = int((self.deadline - time.monotonic()) * 1000)
            if remaining < 1:
                raise TimeoutError("PSS control transaction budget expired")
            self.setter(min(self.timeout_ms, remaining))
            self.steps[index] = replace(self.steps[index], attempted=True)
            result = operation()
            # Preserve a known normal return before any read parsing can fail.
            self.steps[index] = replace(self.steps[index], returned=True)
            if action == "read":
                if not isinstance(result, str):
                    raise ValueError("IIO numeric attribute did not return text")
                self.steps[index] = replace(self.steps[index], raw=result[:128],
                                            raw_characters=len(result))
                if len(result) > 128:
                    raise ValueError("numeric attribute exceeds retained 128-character bound")
                value = int(result.strip(), 0)
                maximum = (1 << (64 if name in _U64_FIELDS else 32)) - 1
                if not 0 <= value <= maximum:
                    raise ValueError("numeric attribute is outside its unsigned field width")
                self.steps[index] = replace(self.steps[index], value=value)
            return result
        except BaseException as error:
            self.steps[index] = replace(self.steps[index], error=_error_text(error))
            raise

    def control_receipt(
        self, phase: str, *, observation: ObservationIdentity, fields: tuple[str, ...],
        identity: tuple[tuple[str, str | None], ...], errors: tuple[str, ...] = (),
    ) -> PssTrackerControlReceipt:
        steps = tuple(step for step in self.steps if step.phase == phase and step.action == "read")
        return _control_receipt(observation, fields, steps, identity, errors)


def _control_receipt(
    observation: ObservationIdentity, fields: tuple[str, ...], steps: tuple[PssControlStep, ...],
    identity: tuple[tuple[str, str | None], ...], errors: tuple[str, ...],
) -> PssTrackerControlReceipt:
    problems = list(errors)
    if tuple(step.name for step in steps) != fields:
        problems.append("control read coverage is incomplete")
    for step in steps:
        if not step.attempted or not step.returned or step.error is not None or step.value is None:
            problems.append(f"{step.name}: {step.error or 'numeric evidence unavailable'}")
        elif step.name in _CONSTANTS and step.value != _CONSTANTS[step.name]:
            problems.append(f"{step.name}: tracker contract mismatch")
        elif step.name == "schedule_enable" and step.value not in (0, 1):
            problems.append("schedule_enable: expected a boolean worker state")
    return PssTrackerControlReceipt(observation, fields, steps, identity, tuple(problems))


def _start_control_errors(
    receipt: PssTrackerControlReceipt, manifest: FineScheduleManifest, *, after: bool,
    queue_target: int,
) -> tuple[str, ...]:
    errors = list(receipt.errors)
    for field in ("fault_flags", "buffer_push_failures", "packet_validation_failures"):
        if receipt.value(field) != 0:
            errors.append(f"{field}: missing or nonzero fine-path health")
    status = receipt.value("status")
    if status is None or status & 9 != 9:
        errors.append("tracker reset release / coefficient validity is unavailable")
    if receipt.value("active_coefficient_generation") != manifest.coefficient_generation:
        errors.append("active coefficient generation differs from the manifest")
    if not after:
        if receipt.value("schedule_enable") != 0:
            errors.append("fine scheduler is not observed idle before setup")
        current = receipt.current_index
        if current is None or manifest.first_center < current + 65_536:
            errors.append("first center lacks the minimum lead at the observed index")
    else:
        expected = {"schedule_first_center": manifest.first_center,
                    "schedule_period_q32_32": manifest.period_q32_32,
                    "schedule_request_base": manifest.request_base,
                    "schedule_count": manifest.count, "schedule_queue_target": queue_target}
        for field, value in expected.items():
            if receipt.value(field) != value:
                errors.append(f"{field}: later readback differs from the requested schedule")
        submitted = receipt.value("schedule_submitted")
        if submitted is None or submitted > manifest.count:
            errors.append("submitted count is missing or exceeds the finite schedule")
        if receipt.value("schedule_enable") == 0 and submitted != manifest.count:
            errors.append("worker stopped without an observed full submission count")
    return tuple(errors)
