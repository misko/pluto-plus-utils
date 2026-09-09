"""Bounded ABI1.6 IIO operation evidence, never a stop/drain or RF verdict."""

from __future__ import annotations

import math
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.pss_control import (
    PssControlStep,
    PssWriteAcceptance,
    _error_text,
    _identity_matches,
)
from pluto_plus.hardware.pss_stop import PssMapStopReceipt

if TYPE_CHECKING:
    from pluto_plus.hardware.source_support import ObservationIdentity

STOP_CONTRACT = (
    ("fpga_identity", 0x50534d41), ("abi_version", 0x10006), ("capabilities", 0x33f),
    ("phase_bins", 20_000), ("tile_geometry", 0x00401002), ("input_rate_msps", 15),
    ("ddc_config", 0x000f0202), ("ddc_group_delay", 0), ("reassembly_chunks", 200),
)


def _stop_transition_error(
    previous: PssMapStopReceipt | None, current: PssMapStopReceipt,
) -> str | None:
    if previous is None:
        return None
    if current.accepted_ticket < previous.accepted_ticket:
        return "PSS accepted stop ticket regressed or hardware epoch reset"
    if current.accepted_ticket == previous.accepted_ticket:
        if (previous.terminal_valid and current.terminal_valid and
                previous.words[4:10] != current.words[4:10]):
            return "PSS valid terminal tuple changed within one accepted ticket"
        if previous.failure_reasons & ~current.failure_reasons:
            return "PSS stop failure reasons disappeared within one accepted ticket"
    return None


@dataclass(frozen=True, slots=True)
class PssMapStopOperation:
    """One fresh read or request transaction on one host context incarnation.

    A complete operation may contain a pending or FAILED stop. Completion here
    concerns the requested IIO observations only; use the separate pure PSST
    qualifier and independent health/delivery/identity evidence for any further
    claim. Context metadata may be cached; context_id is a host UUID, not proof
    of a hardware reset epoch. No attribute-write byte count is exposed by IIO.
    """

    operation: str
    observation: ObservationIdentity
    context_id: str
    ticket: int | None
    before: PssMapStopReceipt | None
    after: PssMapStopReceipt | None
    previous: PssMapStopReceipt | None
    steps: tuple[PssControlStep, ...]
    context_identity: tuple[tuple[str, str | None], ...]
    errors: tuple[str, ...]
    timeout_ms: int
    budget_ms: int
    elapsed_ms: float

    @property
    def write_acceptance(self) -> PssWriteAcceptance:
        """Historical binding return, not terminal completion or map delivery."""
        if (not isinstance(self.steps, tuple) or len(self.steps) > 32
                or any(not isinstance(step, PssControlStep) for step in self.steps)):
            return PssWriteAcceptance.UNKNOWN
        writes = tuple(step for step in self.steps if step.action == "write")
        if not writes:
            return PssWriteAcceptance.NOT_ATTEMPTED
        if len(writes) != 1:
            return PssWriteAcceptance.UNKNOWN
        step = writes[0]
        if (step.name != "acquisition_stop_request" or step.phase != "request"
                or step.requested != str(self.ticket)):
            return PssWriteAcceptance.UNKNOWN
        if step.attempted is False:
            return PssWriteAcceptance.NOT_ATTEMPTED
        return (PssWriteAcceptance.ACKNOWLEDGED if step.attempted is True and step.returned is True
                else PssWriteAcceptance.UNKNOWN)

    @property
    def observed_accepted_ticket(self) -> int | None:
        """Diagnostic readback; may remain available on a failed operation."""
        return self.after.accepted_ticket if self.after is not None else None

    @property
    def complete(self) -> bool:
        from pluto_plus.hardware.source_support import ObservationIdentity, ProcessingProfile

        profile = ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_STOP_V1
        if (type(self.timeout_ms) is not int or not 1 <= self.timeout_ms <= 60_000
                or type(self.budget_ms) is not int or not 1 <= self.budget_ms <= 60_000
                or type(self.elapsed_ms) not in (int, float)
                or not math.isfinite(self.elapsed_ms)
                or not 0 <= self.elapsed_ms < self.budget_ms):
            return False
        if (self.operation not in {"read", "request"} or not isinstance(self.errors, tuple)
                or self.errors or not isinstance(self.steps, tuple) or len(self.steps) > 32
                or not isinstance(self.context_id, str) or not 1 <= len(self.context_id) <= 64
                or not isinstance(self.observation, ObservationIdentity)
                or self.observation.profile is not profile
                or not _identity_matches(self.observation, self.context_identity)
                or not isinstance(self.after, PssMapStopReceipt)
                or (self.before is not None and not isinstance(self.before, PssMapStopReceipt))
                or (self.previous is not None and
                    not isinstance(self.previous, PssMapStopReceipt))):
            return False
        if (_stop_transition_error(self.previous, self.before or self.after) is not None or
                (self.before is not None and
                 _stop_transition_error(self.before, self.after) is not None)):
            return False
        if self.ticket is not None and (type(self.ticket) is not int or
                                       not 1 <= self.ticket <= 0xffffffff or
                                       self.after.accepted_ticket != self.ticket):
            return False
        expected = [("identity", "metadata", "context_identity")]
        expected += [("contract_before", "read", name) for name, _ in STOP_CONTRACT]
        if self.operation == "request":
            if (self.ticket is None or self.before is None or
                    self.write_acceptance is not PssWriteAcceptance.ACKNOWLEDGED):
                return False
            expected += [("before", "read", "acquisition_stop"),
                         ("request", "write", "acquisition_stop_request")]
        elif (self.before is not None or
              self.write_acceptance is not PssWriteAcceptance.NOT_ATTEMPTED):
            return False
        expected += [("after", "read", "acquisition_stop")]
        expected += [("contract_after", "read", name) for name, _ in STOP_CONTRACT]
        if len(self.steps) != len(expected):
            return False
        for step, identity in zip(self.steps, expected, strict=True):
            if (not isinstance(step, PssControlStep) or
                    (step.phase, step.action, step.name) != identity or
                    step.attempted is not True or step.returned is not True or
                    step.error is not None):
                return False
            if step.action == "read":
                bound = 512 if step.name == "acquisition_stop" else 128
                if (not isinstance(step.raw, str) or len(step.raw) > bound
                        or type(step.raw_characters) is not int
                        or step.raw_characters != len(step.raw)
                        or step.requested is not None):
                    return False
                if step.name == "acquisition_stop":
                    receipt = self.before if step.phase == "before" else self.after
                    if receipt is None or step.raw != receipt.raw or step.value is not None:
                        return False
                elif type(step.value) is not int or step.value != dict(STOP_CONTRACT)[step.name]:
                    return False
                else:
                    try:
                        if int(step.raw.strip(), 0) != step.value:
                            return False
                    except ValueError:
                        return False
        return True


class PssMapStopOperationError(RadioConfigurationError):
    def __init__(self, receipt: PssMapStopOperation) -> None:
        super().__init__("PSS stop operation incomplete: " + "; ".join(receipt.errors))
        self.receipt = receipt


class _StopJournal:
    """Fixed-size operation journal with no user-supplied callbacks or cleanup."""

    def __init__(self, *, timeout_ms: int, budget_ms: int, setter: Callable[[int], Any]) -> None:
        for name, value in (("timeout_ms", timeout_ms), ("budget_ms", budget_ms)):
            if type(value) is not int or not 1 <= value <= 60_000:
                raise ValueError(f"{name} must be 1..60000 milliseconds")
        self.timeout_ms = timeout_ms
        self.budget_ms = budget_ms
        self.started_at = time.monotonic()
        self.deadline = self.started_at + budget_ms / 1000
        self.setter = setter
        self.steps: list[PssControlStep] = []

    def require_budget(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError("PSS stop operation budget expired")

    @property
    def elapsed_ms(self) -> float:
        return (time.monotonic() - self.started_at) * 1000

    def call(
        self, phase: str, action: str, name: str, operation: Callable[[], Any], *,
        requested: str | None = None,
    ) -> Any:
        if len(self.steps) >= 32:
            raise ValueError("PSS stop journal exceeded its fixed operation cap")
        index = len(self.steps)
        self.steps.append(PssControlStep(phase, action, name, requested))
        try:
            remaining = int((self.deadline - time.monotonic()) * 1000)
            if remaining < 1:
                raise TimeoutError("PSS stop operation budget expired")
            self.setter(min(self.timeout_ms, remaining))
            self.require_budget()
            self.steps[index] = replace(self.steps[index], attempted=True)
            result = operation()
            self.steps[index] = replace(self.steps[index], returned=True)
            if action == "read":
                if not isinstance(result, str):
                    raise ValueError("IIO stop attribute did not return text")
                bound = 512 if name == "acquisition_stop" else 128
                self.steps[index] = replace(self.steps[index], raw=result[:bound],
                                            raw_characters=len(result))
                if len(result) > bound:
                    raise ValueError("IIO stop attribute exceeds its retained text bound")
                if name != "acquisition_stop":
                    value = int(result.strip(), 0)
                    if not 0 <= value <= 0xffffffff:
                        raise ValueError("IIO stop contract attribute is outside u32")
                    self.steps[index] = replace(self.steps[index], value=value)
            # Preserve what returned before rejecting a late native response.
            self.require_budget()
            return result
        except BaseException as error:
            self.steps[index] = replace(self.steps[index], error=_error_text(error))
            raise
