"""Explicit adaptive capture lifecycle over the existing narrow backend port."""

from __future__ import annotations

import dataclasses
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import suppress

from .adaptive_hop import (
    AdaptiveHopEvidenceV2,
    AdaptiveHopPolicyV2,
    AdaptiveHopRequestV2,
    AdaptiveHopStatusV2,
    require_adaptive_capabilities,
)
from .adaptive_hop_stream import (
    AdaptiveHopSampledVisitV2,
    AdaptiveHopStreamReceiptV2,
    AdaptiveHopStreamV2,
)
from .metadata_extension import PersistentHopMetadataExtension
from .persistent_hop import (
    PERSISTENT_HOP_CAPABILITIES,
    PersistentHopBackend,
    PersistentHopClientError,
    PersistentHopHostLifecycleReceiptV1,
    PersistentHopPlanV1,
    PersistentHopSessionState,
    PersistentHopStartClockBracketV1,
    require_allowed_serial,
    require_physical_lan_uri,
)
from .tandem import TandemSessionRequestV1


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopCaptureReceiptV2:
    stream: AdaptiveHopStreamReceiptV2
    radio_serial: str
    radio_uri: str
    host_lifecycle: PersistentHopHostLifecycleReceiptV1 | None
    start_clock_bracket: PersistentHopStartClockBracketV1 | None
    kernel_buffers_requested: int
    kernel_buffers_readback: int | None
    metadata_extension_error: str | None


class AdaptiveHopClient:
    def __init__(
        self,
        uri: str,
        *,
        expected_serial: str,
        backend_factory: Callable[[str], PersistentHopBackend],
    ) -> None:
        self.uri = require_physical_lan_uri(uri)
        self.expected_serial = require_allowed_serial(expected_serial)
        self._backend_factory = backend_factory
        self._active = False

    def start(
        self,
        plan: PersistentHopPlanV1,
        *,
        policy: AdaptiveHopPolicyV2,
        session_id: int,
        tandem_request: TandemSessionRequestV1,
    ) -> AdaptiveHopSession:
        policy.require_pinned_policy()
        if self._active:
            raise PersistentHopClientError("adaptive client already owns a session")
        backend = self._backend_factory(self.uri)
        if backend.uri != self.uri:
            raise PersistentHopClientError("adaptive backend changed the exact LAN target")
        try:
            backend.open()
            attrs = backend.context_attributes()
            if (
                attrs.get("hw_serial") != self.expected_serial
                or attrs.get("iio,buffer-metadata") != "3"
            ):
                raise PersistentHopClientError("adaptive serial/metadata identity mismatch")
            if any(attrs.get(name) != "1" for name in PERSISTENT_HOP_CAPABILITIES):
                raise PersistentHopClientError("adaptive capture lacks base lifecycle capabilities")
            require_adaptive_capabilities(attrs, policy)
            if getattr(backend, "metadata_extension", None) is None:
                raise PersistentHopClientError("adaptive capture requires a detector metadata port")
            prepare = getattr(backend, "prepare_plan", None)
            if callable(prepare):
                prepared = prepare(plan)
                if (
                    not isinstance(prepared, PersistentHopPlanV1)
                    or dataclasses.replace(prepared, profiles=plan.profiles) != plan
                    or any(
                        dataclasses.replace(new, profile_crc32=old.profile_crc32) != old
                        for old, new in zip(plan.profiles, prepared.profiles, strict=True)
                    )
                ):
                    raise PersistentHopClientError("adaptive hardware preparation changed geometry")
                plan = prepared
            request = AdaptiveHopRequestV2(plan.request(session_id=session_id), policy)
            stream = AdaptiveHopStreamV2(
                request,
                samples_per_block=plan.samples_per_block,
                minimum_valid_duty_ppm=plan.minimum_valid_duty_ppm,
            )
            backend.start(
                request.append_to_tandem_request(
                    tandem_request,
                    plan.samples_per_block,
                    retention_frames=plan.kernel_buffers + 1,
                ),
                samples_per_block=plan.samples_per_block,
                kernel_buffers=plan.kernel_buffers,
            )
            status = AdaptiveHopStatusV2.unpack(backend.read_status()).geometry
            if (
                status.session_id != session_id
                or status.planned_dwells != request.geometry.dwell_count
                or status.state
                not in {PersistentHopSessionState.ARMED, PersistentHopSessionState.RUNNING}
            ):
                raise PersistentHopClientError(
                    "adaptive provider did not arm the requested session"
                )
            session = AdaptiveHopSession(self, backend, plan, stream)
            # Validate a provided bracket now, as well as after first-IQ refinement.
            _ = session.start_clock_bracket
        except BaseException as error:
            try:
                backend.close()
            except BaseException as cleanup:
                error.add_note(f"adaptive startup cleanup also failed: {cleanup!r}")
            raise
        self._active = True
        return session


class AdaptiveHopSession:
    """One capture. The consumer must exhaust visits or explicitly close it."""

    def __init__(
        self,
        owner: AdaptiveHopClient,
        backend: PersistentHopBackend,
        plan: PersistentHopPlanV1,
        stream: AdaptiveHopStreamV2,
    ) -> None:
        self._owner, self._backend = owner, backend
        self.plan, self.request = plan, stream.request
        self._stream = stream
        self._closed = self._iterated = self._cancel_requested = False
        self._receipt: AdaptiveHopCaptureReceiptV2 | None = None
        self._terminal_visits: tuple[AdaptiveHopSampledVisitV2, ...] = ()
        self._ready: deque[AdaptiveHopSampledVisitV2] = deque()
        self._extension: PersistentHopMetadataExtension | None = getattr(
            backend, "metadata_extension", None
        )
        self._extension_error: str | None = getattr(backend, "metadata_extension_error", None)

    @property
    def start_clock_bracket(self) -> PersistentHopStartClockBracketV1 | None:
        value = self._backend.start_clock_bracket
        if value is not None and not isinstance(value, PersistentHopStartClockBracketV1):
            raise PersistentHopClientError("adaptive start clock bracket is invalid")
        return value

    @property
    def receipt(self) -> AdaptiveHopCaptureReceiptV2:
        if self._receipt is None:
            raise PersistentHopClientError("adaptive capture has no terminal receipt")
        return self._receipt

    def visits(self) -> Iterator[AdaptiveHopSampledVisitV2]:
        if self._iterated or self._closed:
            raise PersistentHopClientError("adaptive visit iterator is single-use")
        self._iterated = True
        try:
            if self._cancel_requested:
                # Cancellation may precede the first refill. The provider is
                # already terminal: drain its status/results without asking a
                # stopped acquisition for an ordinary IQ frame.
                self._finish()
                yield from self.take_terminal_visits()
                return
            for wire in self._backend.blocks():
                # Do not discard a returned buffer if cancellation raced its refill.
                self._ready.extend(self._stream.feed(wire))
                if self._extension is not None and self._extension_error is None:
                    if wire.extension_metadata is None:
                        self._fail_extension("adaptive frame lost detector metadata")
                    else:
                        try:
                            self._extension.consume(
                                wire.extension_metadata,
                                wire.iq_payload,
                                evidence=AdaptiveHopEvidenceV2.unpack(wire.evidence).geometry,
                            )
                        except Exception as error:
                            self._fail_extension(f"adaptive result consumption failed: {error}")
                while self._ready:
                    yield self._ready.popleft()
                    if self._closed:
                        return
                if self._cancel_requested:
                    break
            self._finish()
            yield from self.take_terminal_visits()
        except GeneratorExit:
            self.close()
            raise
        except BaseException as error:
            self._fail_extension("adaptive capture validation failed")
            if not self._closed:
                try:
                    self._backend.cancel()
                except BaseException as cleanup:
                    error.add_note(f"adaptive cancellation also failed: {cleanup!r}")
                try:
                    self._release()
                except BaseException as cleanup:
                    error.add_note(f"adaptive host cleanup also failed: {cleanup!r}")
            raise

    def request_cancel(self) -> None:
        if not self._closed and not self._cancel_requested:
            self._backend.cancel()
            self._cancel_requested = True

    def close(self) -> AdaptiveHopCaptureReceiptV2 | None:
        if self._closed:
            return self._receipt
        try:
            self.request_cancel()
            self._finish()
        finally:
            self._release()
        return self._receipt

    def take_terminal_visits(self) -> tuple[AdaptiveHopSampledVisitV2, ...]:
        if not self._closed:
            raise PersistentHopClientError("adaptive terminal visits require a closed capture")
        result = tuple(self._ready) + self._terminal_visits
        self._ready.clear()
        self._terminal_visits = ()
        return result

    def _finish(self) -> None:
        status = AdaptiveHopStatusV2.unpack(self._backend.read_status())
        receipt, terminal = self._stream.finish(status)
        self._terminal_visits = terminal
        extension = self._extension
        if extension is not None and self._extension_error is None:

            def drain(capacity: int) -> bytes:
                callback = getattr(self._backend, "drain_metadata", None)
                if not callable(callback):
                    raise NotImplementedError("adaptive backend lacks metadata-only drain")
                packet = callback(capacity)
                if not isinstance(packet, bytes) or not 0 < len(packet) <= capacity:
                    raise ValueError("invalid adaptive metadata-only drain payload")
                return packet

            try:
                extension.finish(status.geometry, drain)
            except Exception as error:
                self._fail_extension(f"adaptive terminal drain failed: {error}")
        bracket = self.start_clock_bracket
        requested = getattr(self._backend, "kernel_buffers_requested", self.plan.kernel_buffers)
        readback = getattr(self._backend, "kernel_buffers_readback", None)
        if requested != self.plan.kernel_buffers or readback not in (
            None,
            self.plan.kernel_buffers,
        ):
            raise PersistentHopClientError("adaptive kernel-buffer geometry changed")
        lifecycle = self._release()
        self._receipt = AdaptiveHopCaptureReceiptV2(
            receipt,
            self._owner.expected_serial,
            self._owner.uri,
            lifecycle,
            bracket,
            requested,
            readback,
            self._extension_error,
        )

    def _fail_extension(self, reason: str) -> None:
        if self._extension_error is None:
            self._extension_error = reason
        if self._extension is not None:
            with suppress(Exception):
                self._extension.fail(self._extension_error)

    def _release(self) -> PersistentHopHostLifecycleReceiptV1 | None:
        if self._closed:
            return None
        try:
            return self._backend.close()
        finally:
            self._closed = True
            self._owner._active = False

    def __enter__(self) -> AdaptiveHopSession:
        if self._closed:
            raise PersistentHopClientError("adaptive capture is closed")
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()
