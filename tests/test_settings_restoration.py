from __future__ import annotations

import pytest

from pluto_plus.hardware.base import (
    ExactSettingsApplicationError,
    SettingsRestorationError,
    apply_settings_exact,
    restore_settings_exact,
)
from pluto_plus.models import RadioSettings


class QuantizedRadio:
    def __init__(
        self,
        snapshot: RadioSettings,
        *,
        reproducible_request_hz: int | None,
        change_sample_rate: bool = False,
        fail_apply: bool = False,
    ) -> None:
        self.snapshot = snapshot
        self.settings = snapshot
        self.reproducible_request_hz = reproducible_request_hz
        self.change_sample_rate = change_sample_rate
        self.fail_apply = fail_apply
        self.requests: list[int] = []
        self.read_count = 0

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        request = round(settings.center_frequency_hz)
        self.requests.append(request)
        if self.fail_apply:
            raise OSError("injected transport failure")
        if request == round(self.snapshot.center_frequency_hz):
            readback = request - 2
        elif request == self.reproducible_request_hz:
            readback = round(self.snapshot.center_frequency_hz)
        else:
            readback = request + 100
        sample_rate = (
            settings.sample_rate_hz + 1 if self.change_sample_rate else settings.sample_rate_hz
        )
        self.settings = settings.model_copy(
            update={
                "center_frequency_hz": float(readback),
                "sample_rate_hz": sample_rate,
            }
        )
        # Return a deliberately untrusted value: the helper must perform its own
        # read_settings call rather than accepting apply_settings's response.
        return settings

    def read_settings(self) -> RadioSettings:
        self.read_count += 1
        return self.settings


def _snapshot() -> RadioSettings:
    return RadioSettings(
        center_frequency_hz=1_690_312_498,
        sample_rate_hz=5_000_000,
        bandwidth_hz=2_500_000,
    )


def test_exact_restore_searches_nearby_requests_for_original_lo_readback() -> None:
    snapshot = _snapshot()
    radio = QuantizedRadio(
        snapshot,
        reproducible_request_hz=round(snapshot.center_frequency_hz) + 2,
    )

    result = restore_settings_exact(radio, snapshot, maximum_lo_offset_hz=4)

    assert result.restored == snapshot
    assert radio.requests == [
        1_690_312_498,
        1_690_312_499,
        1_690_312_497,
        1_690_312_500,
    ]
    assert radio.read_count == len(radio.requests)
    assert [attempt.readback.center_frequency_hz for attempt in result.attempts] == [
        1_690_312_496,
        1_690_312_599,
        1_690_312_597,
        1_690_312_498,
    ]


def test_exact_application_searches_nearby_requests_for_desired_lo_readback() -> None:
    requested = _snapshot()
    radio = QuantizedRadio(
        requested,
        reproducible_request_hz=round(requested.center_frequency_hz) + 2,
    )

    result = apply_settings_exact(radio, requested, maximum_lo_offset_hz=4)

    assert result.requested == requested
    assert result.applied == requested
    assert radio.requests == [
        1_690_312_498,
        1_690_312_499,
        1_690_312_497,
        1_690_312_500,
    ]
    assert result.attempts[-1].readback == requested


def test_exact_application_fails_closed_when_desired_lo_is_not_reproducible() -> None:
    requested = _snapshot()
    radio = QuantizedRadio(requested, reproducible_request_hz=None)

    with pytest.raises(ExactSettingsApplicationError, match=r"within \+/-2 Hz") as caught:
        apply_settings_exact(radio, requested, maximum_lo_offset_hz=2)

    assert len(caught.value.attempts) == 5


def test_exact_restore_fails_closed_with_bounded_attempt_evidence() -> None:
    snapshot = _snapshot()
    radio = QuantizedRadio(snapshot, reproducible_request_hz=None)

    with pytest.raises(SettingsRestorationError, match=r"within \+/-2 Hz") as caught:
        restore_settings_exact(radio, snapshot, maximum_lo_offset_hz=2)

    assert radio.requests == [
        1_690_312_498,
        1_690_312_499,
        1_690_312_497,
        1_690_312_500,
        1_690_312_496,
    ]
    assert len(caught.value.attempts) == 5


def test_exact_restore_never_searches_past_a_non_lo_mismatch() -> None:
    snapshot = _snapshot()
    radio = QuantizedRadio(
        snapshot,
        reproducible_request_hz=round(snapshot.center_frequency_hz) + 2,
        change_sample_rate=True,
    )

    with pytest.raises(SettingsRestorationError, match="changed a non-LO field") as caught:
        restore_settings_exact(radio, snapshot)

    assert radio.requests == [1_690_312_498]
    assert len(caught.value.attempts) == 1


def test_exact_restore_records_and_stops_on_transport_failure() -> None:
    snapshot = _snapshot()
    radio = QuantizedRadio(snapshot, reproducible_request_hz=None, fail_apply=True)

    with pytest.raises(SettingsRestorationError, match="during apply/readback") as caught:
        restore_settings_exact(radio, snapshot)

    assert radio.requests == [1_690_312_498]
    assert caught.value.attempts[0].readback is None
    assert caught.value.attempts[0].error == "OSError: injected transport failure"


@pytest.mark.parametrize("value", [-1, 1.5, True, 1025])
def test_exact_restore_rejects_an_invalid_search_bound(value: object) -> None:
    radio = QuantizedRadio(_snapshot(), reproducible_request_hz=None)

    with pytest.raises(ValueError, match="maximum_lo_offset_hz"):
        restore_settings_exact(radio, _snapshot(), maximum_lo_offset_hz=value)  # type: ignore[arg-type]

    assert radio.requests == []
