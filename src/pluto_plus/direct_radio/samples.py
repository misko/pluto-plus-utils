"""Conversion helpers for direct-radio dual-RX CI16 payloads."""

from __future__ import annotations

import numpy as np
import numpy.typing as npt

from .usb import ProtocolError


def ci16_dual_rx(payload: bytes | bytearray | memoryview) -> npt.NDArray[np.complex64]:
    """Convert ``[rx1_i, rx1_q, rx2_i, rx2_q]`` time rows to shape ``(2, N)``."""

    if len(payload) == 0 or len(payload) % 8:
        raise ProtocolError("CI16 dual-RX payload must contain complete non-empty 8-byte rows")
    words = np.frombuffer(payload, dtype="<i2").reshape(-1, 4)
    result = np.empty((2, words.shape[0]), dtype=np.complex64)
    result[0] = words[:, 0].astype(np.float32) + 1j * words[:, 1].astype(np.float32)
    result[1] = words[:, 2].astype(np.float32) + 1j * words[:, 3].astype(np.float32)
    return result
