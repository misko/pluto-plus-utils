from __future__ import annotations

import pytest
from pydantic import ValidationError

from pluto_plus.models import GainMode, RadioSettings, StreamRequest


def test_radio_settings_enforce_bandwidth_and_channel_contracts() -> None:
    with pytest.raises(ValidationError, match="bandwidth_hz cannot exceed"):
        RadioSettings(sample_rate_hz=1_000_000, bandwidth_hz=2_000_000)
    with pytest.raises(ValidationError, match="non-empty and unique"):
        RadioSettings(channels=(0, 0))
    with pytest.raises(ValidationError, match="must be 0 or 1"):
        RadioSettings(channels=(2,))


def test_gain_mode_contract_does_not_allow_ambiguous_gain() -> None:
    with pytest.raises(ValidationError, match="manual gain mode requires"):
        RadioSettings(gain_mode=GainMode.MANUAL, gain_db=None)
    with pytest.raises(ValidationError, match="automatic gain modes cannot"):
        RadioSettings(gain_mode=GainMode.SLOW_ATTACK, gain_db=20)
    automatic = RadioSettings(gain_mode=GainMode.SLOW_ATTACK, gain_db=None)
    assert automatic.gain_db is None


def test_persistent_capture_must_be_bounded() -> None:
    with pytest.raises(ValidationError, match="persistent captures must be bounded"):
        StreamRequest(persist=True)
    with pytest.raises(ValidationError, match="mutually exclusive"):
        StreamRequest(duration_s=1, sample_count=1000)


def test_fft_must_be_a_power_of_two_and_fit_block() -> None:
    with pytest.raises(ValidationError, match="power of two"):
        StreamRequest(block_size=4096, fft_size=3000)
    with pytest.raises(ValidationError, match="cannot exceed"):
        StreamRequest(block_size=1024, fft_size=2048)
