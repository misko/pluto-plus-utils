"""Pure PSST v1 map-publication receipts; no IIO or firmware ABI admission.

This is the proposed 12-word stop protocol's offline decoder, not a claim that
any deployed image implements it. A boundary is neither health, radio/epoch
identity, kernel delivery nor host persistence. Callers must retain those
independent receipts, plus this raw text, and verify every map through M.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Self

_WORDS = 12
_MAGIC = 0x50535354
_VERSION_COUNT = 0x0001000C
_CANDIDATE_SPAN = 20_000 * 64
_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1


def _parse_words(text: str) -> tuple[int, ...]:
    if not isinstance(text, str) or not text.isascii() or len(text) > 512:
        raise ValueError("PSST requires bounded ASCII text")
    fields = text.split()
    if fields[:3] != ["PSST", "1", str(_WORDS)] or len(fields) != 3 + _WORDS:
        raise ValueError("PSST envelope/version/word count is invalid")
    if any(not re.fullmatch(r"[0-9a-f]{8}", field) for field in fields[3:]):
        raise ValueError("PSST words require eight lowercase hexadecimal digits")
    words = tuple(int(field, 16) for field in fields[3:])
    if words[:2] != (_MAGIC, _VERSION_COUNT):
        raise ValueError("PSST window magic/version/count is invalid")
    if words[2] & ~0x3F or words[10] & ~0x3F or words[11] > 5:
        raise ValueError("PSST reserved state/failure/command values are unsupported")
    return words


@dataclass(frozen=True, slots=True)
class PssMapStopReceipt:
    """One separately observed window receipt, including failures/old tuples.

    Schema decoding preserves pending, failed, empty and invalidated historical
    states. Semantic qualification is an explicit, separate operation. Words
    6..9 are candidate-start coordinates at the declared 15 MS/s profile, not
    the live ADC index, full FFT input support or pilot sample coordinates.
    """

    raw: str
    words: tuple[int, ...]

    def __post_init__(self) -> None:
        # Direct construction cannot manufacture a receipt inconsistent with
        # its raw evidence. Parsing is bounded before split/int allocation.
        parsed = _parse_words(self.raw)
        if (not isinstance(self.words, tuple) or len(self.words) != _WORDS
                or any(type(word) is not int for word in self.words)
                or self.words != parsed):
            raise ValueError("PSST words do not match the raw receipt")

    @classmethod
    def decode(cls, text: str) -> Self:
        return cls(text, _parse_words(text))

    @property
    def pending(self) -> bool:
        return bool(self.words[2] & 1)

    @property
    def terminal_valid(self) -> bool:
        return bool(self.words[2] & 2)

    @property
    def boundary_complete(self) -> bool:
        """Raw structural flag; use require_boundary_complete before adopting it."""
        return bool(self.words[2] & 4)

    @property
    def failed(self) -> bool:
        return bool(self.words[2] & 8)

    @property
    def has_map(self) -> bool:
        """Publication history exists, not necessarily a map from this visit."""
        return bool(self.words[2] & 16)

    @property
    def acquisition_enabled(self) -> bool:
        return bool(self.words[2] & 32)

    @property
    def accepted_ticket(self) -> int:
        return self.words[3]

    @property
    def terminal_ticket(self) -> int:
        return self.words[4]

    @property
    def terminal_generation(self) -> int:
        return self.words[5]

    @property
    def terminal_candidate_start(self) -> int:
        """Raw historical value, potentially invalid or unrelated to this visit."""
        return self.words[6] | (self.words[7] << 32)

    @property
    def terminal_candidate_end(self) -> int:
        """Raw end-exclusive candidate coordinate, NOT complete FFT input support."""
        return self.words[8] | (self.words[9] << 32)

    @property
    def failure_reasons(self) -> int:
        return self.words[10]

    @property
    def command_status(self) -> int:
        return self.words[11]

    def require_boundary_complete(self, *, expected_ticket: int) -> None:
        """Require this ticket's stopped structural fence, never an RF/health pass.

        The caller must independently admit the shared-15 stop-capable firmware
        profile, bind serial/boot/observation, and validate a fresh health receipt.
        No parsing or method here upgrades an IIO client's supported ABI list.
        Empty publication history is valid but provides no sample interval.
        """
        if type(expected_ticket) is not int or not 1 <= expected_ticket <= _U32_MAX:
            raise ValueError("expected stop ticket must be a nonzero u32")
        if self.accepted_ticket != expected_ticket or self.terminal_ticket != expected_ticket:
            raise ValueError("PSST accepted/terminal ticket does not match the request")
        if self.pending or not self.terminal_valid or not self.boundary_complete:
            raise ValueError("PSST boundary has not completed or was invalidated")
        if self.failed or self.failure_reasons or self.command_status:
            raise ValueError("PSST retains a stop failure or rejected command")
        if self.acquisition_enabled:
            raise ValueError("PSST coarse acquisition has not stopped")
        if not self.has_map:
            if (self.terminal_generation or self.terminal_candidate_start
                    or self.terminal_candidate_end):
                raise ValueError("PSST empty publication history has nonzero map coordinates")
        elif (not 1 <= self.terminal_generation < _U32_MAX
              or self.terminal_candidate_start > _U64_MAX - _CANDIDATE_SPAN
              or self.terminal_candidate_end != self.terminal_candidate_start + _CANDIDATE_SPAN):
            raise ValueError("PSST terminal map generation or exact candidate bounds are invalid")
