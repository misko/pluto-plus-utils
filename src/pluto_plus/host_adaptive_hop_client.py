"""One acquisition owner for native IQ and source-bound host decision feedback."""

from __future__ import annotations

import dataclasses
import errno
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from typing import Protocol

from .adaptive_hop import AdaptiveHopPolicyV2
from .adaptive_hop_stream import AdaptiveHopVisitV2
from .host_adaptive_hop import (
    HostAdaptiveHopRequestV3,
    HostAdaptiveHopStatusV3,
    HostDecisionConfigurationV1,
    HostFeedbackV1,
    require_host_adaptive_capabilities,
)
from .host_adaptive_hop_stream import (
    HostAdaptiveHopSampledVisitV3,
    HostAdaptiveHopStreamReceiptV3,
    HostAdaptiveHopStreamV3,
)
from .persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PersistentHopBackend,
    PersistentHopClientError,
    PersistentHopHostLifecycleReceiptV1,
    PersistentHopPlanPreparer,
    PersistentHopSessionState,
    PersistentHopStartClockBracketV1,
    SingleRxPersistentHopPlanV2,
    require_allowed_serial,
    require_physical_lan_uri,
)
from .tandem import TandemSessionRequestV1


class HostAdaptiveHopBackend(PersistentHopBackend, PersistentHopPlanPreparer, Protocol):
    def submit_metadata_feedback(self, payload: bytes) -> None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopCaptureReceiptV3:
    stream: HostAdaptiveHopStreamReceiptV3
    radio_serial: str
    radio_uri: str
    host_lifecycle: PersistentHopHostLifecycleReceiptV1 | None
    start_clock_bracket: PersistentHopStartClockBracketV1 | None
    kernel_buffers_requested: int
    kernel_buffers_readback: int | None


class HostAdaptiveHopClient:
    def __init__(
        self,
        uri: str,
        *,
        expected_serial: str,
        backend_factory: Callable[[str], HostAdaptiveHopBackend],
    ) -> None:
        self.uri = require_physical_lan_uri(uri)
        self.expected_serial = require_allowed_serial(expected_serial)
        self._backend_factory = backend_factory
        self._active = False

    def start(
        self,
        plan: SingleRxPersistentHopPlanV2,
        *,
        policy: AdaptiveHopPolicyV2,
        decision: HostDecisionConfigurationV1,
        session_id: int,
        tandem_request: TandemSessionRequestV1,
    ) -> HostAdaptiveHopSession:
        if not isinstance(plan, SingleRxPersistentHopPlanV2) or (
            plan.receiver_id != decision.receiver_id
        ):
            raise PersistentHopClientError("host adaptive plan must bind one physical RX")
        policy.require_pinned_policy()
        decision.pack()
        if self._active:
            raise PersistentHopClientError("host adaptive client already owns a session")
        backend = self._backend_factory(self.uri)
        if backend.uri != self.uri:
            raise PersistentHopClientError("host adaptive backend changed the exact LAN target")
        try:
            backend.open()
            attrs = backend.context_attributes()
            if (
                attrs.get("hw_serial") != self.expected_serial
                or attrs.get("iio,buffer-metadata") != "3"
                or any(attrs.get(name) != "1" for name in PERSISTENT_HOP_CAPABILITIES)
            ):
                raise PersistentHopClientError("host adaptive serial/lifecycle identity mismatch")
            require_host_adaptive_capabilities(attrs, policy)
            if getattr(backend, "metadata_extension", None) is not None:
                raise PersistentHopClientError("host adaptive capture cannot also run radio GLRT")
            prepared = backend.prepare_plan(plan)
            if (
                not isinstance(prepared, SingleRxPersistentHopPlanV2)
                or dataclasses.replace(prepared, profiles=plan.profiles) != plan
                or any(
                    dataclasses.replace(new, profile_crc32=old.profile_crc32) != old
                    for old, new in zip(plan.profiles, prepared.profiles, strict=True)
                )
            ):
                raise PersistentHopClientError("host adaptive preparation changed capture geometry")
            plan = prepared
            request = HostAdaptiveHopRequestV3(
                plan.request(session_id=session_id), policy, decision
            )
            # Fastlock CRCs are hardware evidence populated by prepare_plan.
            # Validate the complete wire request only after that preparation.
            request.pack()
            stream = HostAdaptiveHopStreamV3(
                request,
                samples_per_block=plan.samples_per_block,
                minimum_valid_duty_ppm=plan.minimum_valid_duty_ppm,
            )
            backend.start(
                request.append_to_tandem_request(
                    tandem_request, plan.samples_per_block, retention_frames=plan.kernel_buffers + 1
                ),
                samples_per_block=plan.samples_per_block,
                kernel_buffers=plan.kernel_buffers,
            )
            status = HostAdaptiveHopStatusV3.unpack(backend.read_status()).geometry
            if (
                status.session_id != session_id
                or status.planned_dwells != request.geometry.dwell_count
                or status.state
                not in {PersistentHopSessionState.ARMED, PersistentHopSessionState.RUNNING}
            ):
                raise PersistentHopClientError(
                    "host adaptive provider did not arm requested session"
                )
            session = HostAdaptiveHopSession(self, backend, plan, stream)
            _ = session.start_clock_bracket
        except BaseException as error:
            try:
                backend.close()
            except BaseException as cleanup:
                error.add_note(f"host adaptive startup cleanup also failed: {cleanup!r}")
            raise
        self._active = True
        return session


class HostAdaptiveHopSession:
    """Workers compute only; the iterator's thread alone submits their results."""

    def __init__(
        self,
        owner: HostAdaptiveHopClient,
        backend: HostAdaptiveHopBackend,
        plan: SingleRxPersistentHopPlanV2,
        stream: HostAdaptiveHopStreamV3,
    ) -> None:
        self._owner, self._backend, self._stream = owner, backend, stream
        self.plan, self.request = plan, stream.request
        self._thread = threading.get_ident()
        self._closed = self._iterated = self._cancel_requested = False
        self._receipt: HostAdaptiveHopCaptureReceiptV3 | None = None
        self._ready: deque[HostAdaptiveHopSampledVisitV3] = deque()
        self._awaiting_feedback: deque[AdaptiveHopVisitV2] = deque()

    def _require_owner(self) -> None:
        if threading.get_ident() != self._thread:
            raise PersistentHopClientError("host adaptive IIO belongs to the acquisition thread")

    @property
    def stream_generation(self) -> int | None:
        return self._stream.stream_generation

    @property
    def start_clock_bracket(self) -> PersistentHopStartClockBracketV1 | None:
        self._require_owner()
        value = self._backend.start_clock_bracket
        if value is not None and not isinstance(value, PersistentHopStartClockBracketV1):
            raise PersistentHopClientError("host adaptive start clock bracket is invalid")
        return value

    @property
    def receipt(self) -> HostAdaptiveHopCaptureReceiptV3:
        if self._receipt is None:
            raise PersistentHopClientError("host adaptive capture has no terminal receipt")
        return self._receipt

    def submit_feedback(self, feedback: HostFeedbackV1) -> bool:
        """True means provider accepted; False means the source has already stopped.

        Neither result claims the policy used this observation in a later hop.
        Actual HOPS choices are the authority for applied decisions.
        """
        self._require_owner()
        payload = feedback.pack()
        if not self._awaiting_feedback:
            raise PersistentHopClientError("host feedback has no emitted source visit")
        visit = self._awaiting_feedback[0]
        if (
            feedback.session_id != self.request.geometry.session_id
            or feedback.generation != self.request.policy.generation
            or feedback.stream_id != self.stream_generation
            or feedback.receiver_id != self.request.decision.receiver_id
            or feedback.configuration_sha256 != self.request.decision.configuration_sha256
            or feedback.visit != visit.event.dwell_index
            or feedback.event_sequence != visit.event.event_sequence
            or feedback.target_index != visit.profile.target_index
            or feedback.valid_start != visit.valid_start_counter
            or feedback.valid_end != visit.valid_end_counter_exclusive
        ):
            raise PersistentHopClientError(
                "host feedback does not bind the next actual source visit"
            )
        accepted = not self._closed
        if accepted:
            try:
                self._backend.submit_metadata_feedback(payload)
            except OSError as error:
                if error.errno != errno.ESHUTDOWN:
                    raise
                accepted = False
        self._awaiting_feedback.popleft()
        return accepted

    def _yield_ready(self) -> Iterator[HostAdaptiveHopSampledVisitV3]:
        while self._ready:
            sampled = self._ready.popleft()
            self._awaiting_feedback.append(sampled.visit)
            yield sampled
            self._require_owner()

    def visits(self) -> Iterator[HostAdaptiveHopSampledVisitV3]:
        self._require_owner()
        if self._iterated or self._closed:
            raise PersistentHopClientError("host adaptive visit iterator is single-use")
        self._iterated = True
        try:
            if not self._cancel_requested:
                for wire in self._backend.blocks():
                    self._ready.extend(self._stream.feed(wire))
                    yield from self._yield_ready()
                    if self._closed:
                        return
                    if self._cancel_requested:
                        break
            self._finish()
            yield from self._yield_ready()
        except BaseException as error:
            if threading.get_ident() != self._thread:
                raise
            if not self._closed:
                try:
                    self._backend.cancel()
                except BaseException as cleanup:
                    error.add_note(f"host adaptive cancellation also failed: {cleanup!r}")
                try:
                    self._release()
                except BaseException as cleanup:
                    error.add_note(f"host adaptive cleanup also failed: {cleanup!r}")
            raise

    def request_cancel(self) -> None:
        self._require_owner()
        if not self._closed and not self._cancel_requested:
            self._backend.cancel()
            self._cancel_requested = True

    def _finish(self) -> None:
        deadline = time.monotonic() + 10
        while True:
            status = HostAdaptiveHopStatusV3.unpack(self._backend.read_status())
            if status.geometry.state not in {
                PersistentHopSessionState.ARMED,
                PersistentHopSessionState.RUNNING,
            }:
                break
            if not self._cancel_requested or time.monotonic() >= deadline:
                raise PersistentHopClientError(
                    "host adaptive provider has not reached terminal state"
                )
            time.sleep(0.01)
        stream, terminal = self._stream.finish(status)
        self._ready.extend(terminal)
        bracket = self.start_clock_bracket
        requested = getattr(self._backend, "kernel_buffers_requested", self.plan.kernel_buffers)
        readback = getattr(self._backend, "kernel_buffers_readback", None)
        if requested != self.plan.kernel_buffers or readback not in (
            None,
            self.plan.kernel_buffers,
        ):
            raise PersistentHopClientError("host adaptive kernel-buffer geometry changed")
        lifecycle = self._release()
        self._receipt = HostAdaptiveHopCaptureReceiptV3(
            stream,
            self._owner.expected_serial,
            self._owner.uri,
            lifecycle,
            bracket,
            requested,
            readback,
        )

    def close(self) -> HostAdaptiveHopCaptureReceiptV3 | None:
        self._require_owner()
        if not self._closed:
            try:
                self.request_cancel()
                self._finish()
            finally:
                self._release()
        return self._receipt

    def take_terminal_visits(self) -> tuple[HostAdaptiveHopSampledVisitV3, ...]:
        self._require_owner()
        if not self._closed:
            raise PersistentHopClientError("host adaptive terminal visits require a closed capture")
        return tuple(self._yield_ready())

    def _release(self) -> PersistentHopHostLifecycleReceiptV1 | None:
        if self._closed:
            return None
        try:
            return self._backend.close()
        finally:
            self._closed = True
            self._owner._active = False

    def __enter__(self) -> HostAdaptiveHopSession:
        self._require_owner()
        if self._closed:
            raise PersistentHopClientError("host adaptive capture is closed")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
