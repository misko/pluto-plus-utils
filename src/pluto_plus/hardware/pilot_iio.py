"""Offline PIL1 pilot-IIO accounting; no radio access or firmware promotion.

This experimental single-RX ABI is separate from production TAG2/HOPS. Hardware
snapshots attest an AXIS prefix, not DDR completion, disk persistence, RF signal
presence, or PSS lock. The eventual reader must retain identities, IQ hashes,
frequency/filter contracts and FPGA results alongside these snapshots.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from fractions import Fraction
from typing import Self

PILOT_DEVICE = "starlink-pilot-capture"
PILOT_CAPTURE_ABI = "PIL1-1.0-upper-only"
PILOT_OUTPUT_RATE_HZ = 2_500_000
PILOT_CANONICAL_RATE_HZ = 15_000_000
PILOT_SOURCE_RATES_HZ = (15_000_000, 30_000_000, 60_000_000)
PILOT_DELAY_CANONICAL_SAMPLES = 269
PILOT_FIFO_CAPACITY = 32
_U64_MAX = (1 << 64) - 1


def _decimal(field: str, maximum: int, *, signed: bool = False) -> int:
    pattern = r"-?[0-9]+" if signed else r"[0-9]+"
    if not re.fullmatch(pattern, field, flags=re.ASCII):
        raise ValueError("PIL1 header requires decimal integers")
    value = int(field)
    if not (-maximum if signed else 0) <= value <= maximum:
        raise ValueError("PIL1 header integer is out of range")
    return value


def _count(value: int, name: str) -> int:
    if type(value) is not int or not 0 <= value <= _U64_MAX:
        raise ValueError(f"{name} must be an unsigned 64-bit integer")
    return value


@dataclass(frozen=True, slots=True)
class PilotSnapshot:
    """One immutable atomic hardware view plus contemporaneous kernel status.

    Decode retains known faults for diagnostics. Call require_complete_prefix()
    to admit a finite capture for subsequent analysis; decoding is not that gate.
    No boot/session/serial identity is carried on this wire, so callers must bind
    this record to an independently attested owner and capture session.
    """

    raw: str
    source_rate_hz: int
    generation: int
    recovery_failed: bool
    actual_source_rate_hz: int
    dma_error: int
    words: tuple[int, ...]
    first_newest_canonical_index: int
    last_newest_canonical_index: int
    admitted_samples: int
    axis_delivered_samples: int
    unsupported_samples: int
    fault_diagnostic_index: int
    ddc_accepted_samples: int
    ddc_emitted_samples: int

    @classmethod
    def decode(cls, text: str) -> Self:
        if not isinstance(text, str) or not text.isascii() or len(text) > 4096:
            raise ValueError("PIL1 snapshot must be bounded ASCII text")
        fields = text.split()
        if len(fields) != 34 or fields[:2] != ["PIL1", "00010000"]:
            raise ValueError("PIL1 snapshot envelope/version/word count is invalid")
        source, output, generation, recovery, actual = (
            _decimal(field, 0xffffffff) for field in fields[2:7]
        )
        dma_error = _decimal(fields[7], 4095, signed=True)
        if source not in PILOT_SOURCE_RATES_HZ or output != PILOT_OUTPUT_RATE_HZ:
            raise ValueError("PIL1 source/output rate is unsupported")
        if not generation or recovery not in (0, 1) or dma_error > 0:
            raise ValueError("PIL1 generation/recovery/DMA status is invalid")
        if any(not re.fullmatch(r"[0-9a-fA-F]{8}", word) for word in fields[8:]):
            raise ValueError("PIL1 payload requires exactly eight hex digits per word")
        words = tuple(int(word, 16) for word in fields[8:])
        if any(words[23:]) or words[17] >> 16 or words[18] & ~0x7f or words[19] & ~0x1f:
            raise ValueError("PIL1 reserved bits are nonzero")
        values = tuple(words[n] | (words[n+1] << 32) for n in range(0, 16, 2))
        first, last, admitted, delivered, unsupported, _, accepted, emitted = values
        queued = words[22]
        if not delivered <= admitted or admitted - delivered != queued:
            raise ValueError("PIL1 admitted/delivered/queued accounting disagrees")
        if not queued <= words[21] <= PILOT_FIFO_CAPACITY or words[17] >> 8 > 128:
            raise ValueError("PIL1 FIFO count/high water is out of bounds")
        if bool(words[19] & 2) != bool(queued) or bool(words[19] & 8) != bool(admitted):
            raise ValueError("PIL1 status disagrees with prefix/queue counters")
        if bool(words[19] & 4) != bool(words[18]):
            raise ValueError("PIL1 status disagrees with capture faults")
        if (words[19] & 1 or admitted) and (not words[19] & 16 or not words[20]):
            raise ValueError("PIL1 active/prefix state lacks an armed visit")
        if admitted:
            if first < 538 or first % 6 or last != first + 6 * (admitted - 1):
                raise ValueError("PIL1 supported prefix index/phase/span is inconsistent")
            source_last = (last - PILOT_DELAY_CANONICAL_SAMPLES) * (
                source // PILOT_CANONICAL_RATE_HZ
            )
            if source_last > _U64_MAX:
                raise ValueError("PIL1 prefix exceeds the original source counter")
        elif first or last:
            raise ValueError("PIL1 empty prefix must have zero first/last indexes")
        if emitted < admitted + unsupported or accepted < emitted:
            raise ValueError("PIL1 DDC counters cannot account for the exported prefix")
        return cls(text, source, generation, bool(recovery), actual, dma_error, words, *values)

    @property
    def active(self) -> bool:
        return bool(self.words[19] & 1)

    @property
    def visit_id(self) -> int:
        return self.words[20]

    @property
    def capture_faults(self) -> int:
        return self.words[18]

    @property
    def ddc_faults(self) -> int:
        return self.words[17] & 0xff

    @property
    def saturation_events(self) -> int:
        return self.words[16]

    def source_center(self, output_sample: int) -> int:
        """Original full-rate coordinate of an AXIS-delivered sample, not wall time."""
        _count(output_sample, "output_sample")
        if output_sample >= self.axis_delivered_samples:
            raise ValueError("sample is outside the AXIS-delivered prefix")
        # Upstream 30/60 conditioners already correct their own filter delay.
        return (self.first_newest_canonical_index + 6 * output_sample -
                PILOT_DELAY_CANONICAL_SAMPLES) * (
                    self.source_rate_hz // PILOT_CANONICAL_RATE_HZ)

    def require_complete_prefix(
        self, *, expected_visit_id: int, expected_source_rate_hz: int,
        expected_samples: int, received_bytes: int,
    ) -> None:
        """Check finite capture counts/health, NEVER claim detection or persistence.

        received_bytes must come from the actual IIO reader, not this snapshot.
        A clipped capture is retained but rejected from the initial comparison
        gate. Fault coordinates remain diagnostic, not the first missing RF beat.
        """
        if type(expected_visit_id) is not int or not 0 < expected_visit_id <= 0xffffffff:
            raise ValueError("expected_visit_id must be a nonzero u32")
        if (type(expected_source_rate_hz) is not int or
                expected_source_rate_hz not in PILOT_SOURCE_RATES_HZ):
            raise ValueError("expected source rate is unsupported")
        _count(expected_samples, "expected_samples")
        _count(received_bytes, "received_bytes")
        if not expected_samples:
            raise ValueError("expected_samples must be positive")
        if self.visit_id != expected_visit_id or self.source_rate_hz != expected_source_rate_hz:
            raise ValueError("PIL1 snapshot does not match the expected visit/source rate")
        if self.actual_source_rate_hz != self.source_rate_hz:
            raise ValueError("PIL1 actual PHY source rate changed")
        if self.active or self.words[22]:
            raise ValueError("PIL1 capture is still active or draining")
        if self.recovery_failed or self.dma_error or self.capture_faults or self.ddc_faults:
            raise ValueError("PIL1 capture has a hardware/DMA/recovery fault")
        if self.saturation_events:
            raise ValueError("PIL1 capture reports arithmetic saturation")
        if (self.admitted_samples != expected_samples or
                self.axis_delivered_samples != expected_samples):
            raise ValueError("PIL1 finite capture sample count is incomplete")
        if received_bytes != expected_samples * 4:
            raise ValueError("IIO reader byte count does not match the PIL1 prefix")
        if self.ddc_emitted_samples != self.admitted_samples + self.unsupported_samples:
            raise ValueError("PIL1 DDC emitted unaccounted samples")

    @property
    def axis_prefix_duration_seconds(self) -> Fraction:
        """N / Fs exposure, not the (N - 1) / Fs separation of endpoint centers."""
        return Fraction(self.axis_delivered_samples, PILOT_OUTPUT_RATE_HZ)
