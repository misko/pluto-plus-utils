"""Narrow hardware port owned by the radio controller."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import numpy as np

from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings


@dataclass(frozen=True, slots=True)
class SampleBlock:
    utc_ns: int
    samples: np.ndarray

    def __post_init__(self) -> None:
        if self.utc_ns <= 0:
            raise ValueError("utc_ns must be positive")
        if self.samples.ndim != 2 or not self.samples.shape[0] or not self.samples.shape[1]:
            raise ValueError("samples must have receiver and sample dimensions")
        if not np.iscomplexobj(self.samples):
            raise ValueError("samples must be complex")


class RadioDevice(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    @property
    def capabilities(self) -> RadioCapabilities: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_settings(self) -> RadioSettings: ...

    def apply_settings(self, settings: RadioSettings) -> RadioSettings: ...

    def read_block(self, sample_count: int) -> SampleBlock: ...
