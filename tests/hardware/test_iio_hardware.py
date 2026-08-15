from __future__ import annotations

import os

import pytest

from pluto_plus.hardware.iio import IioRadioDevice

pytestmark = pytest.mark.hardware


def _serials() -> tuple[str, ...]:
    value = os.environ.get("PLUTO_HARDWARE_SERIALS", "")
    serials = tuple(item.strip() for item in value.split(",") if item.strip())
    if not serials:
        pytest.skip("set PLUTO_HARDWARE_SERIALS to opt into attached-radio tests")
    return serials


def test_each_selected_radio_attests_settings_and_paired_refill() -> None:
    for serial in _serials():
        radio = IioRadioDevice("usb:", serial=serial)
        radio.open()
        try:
            assert radio.identity.serial == serial
            original = radio.read_settings()
            paired = original.model_copy(update={"channels": (0, 1)})
            actual = radio.apply_settings(paired)
            assert actual.channels == (0, 1)
            block = radio.read_block(4096)
            assert block.samples.shape == (2, 4096)
            radio.apply_settings(original)
            assert radio.read_settings() == original
        finally:
            radio.close()


def test_two_selected_radios_have_distinct_stable_identities() -> None:
    serials = _serials()
    if len(serials) < 2:
        pytest.skip("two serials are required for the multi-radio identity gate")
    assert len(serials) == len(set(serials))
    radios = tuple(IioRadioDevice("usb:", serial=serial) for serial in serials[:2])
    try:
        for radio in radios:
            radio.open()
        assert {radio.identity.serial for radio in radios} == set(serials[:2])
    finally:
        for radio in radios:
            radio.close()
