from __future__ import annotations

import runpy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/run_v052_adaptive_live.py"


def test_slot_configuration_is_deterministic_and_balanced_across_slots() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["slot_configuration"]
    frequencies_by_rate = values["FREQUENCIES_BY_RATE"]
    slots = [configure(ordinal * 600) for ordinal in range(3_000)]
    assert slots == [configure(ordinal * 600) for ordinal in range(3_000)]
    assert all(rate in (2_500_000, 10_000_000, 15_000_000) for _, rate, _, _ in slots)
    assert all(
        frequencies == frequencies_by_rate[rate][0 if edge == "lower" else 1 :: 2]
        for _, rate, edge, frequencies in slots
    )
    assert all(
        900 < sum(rate == candidate for _, rate, _, _ in slots) < 1_100
        for candidate in values["RATES"]
    )
    assert 1_400 < sum(edge == "lower" for _, _, edge, _ in slots) < 1_600
    assert frequencies_by_rate[2_500_000][0] == 959_687_498
    assert frequencies_by_rate[10_000_000][0] == 960_000_000
    assert frequencies_by_rate[15_000_000][0] == 960_000_000


def test_campaign_configuration_accepts_exact_radio_and_sample_rate() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["campaign_configuration"]

    first = configure(1_760_000_000, "104000b29905000e17000800065934759d", 2_500_000)
    second = configure(1_760_000_000, "1040007c4a94000211000b009186843ef2", 10_000_000)
    third = configure(1_760_000_000, "1040007c4a94000211000b009186843ef2", 15_000_000)

    assert first[1] == 2_500_000
    assert second[1] == 10_000_000
    assert third[1] == 15_000_000
    assert first[4] != second[4]
    assert third[3][0] in (960_000_000, 1_190_000_000)

    with pytest.raises(ValueError, match="2.5, 10, or 15 MS/s"):
        configure(1_760_000_000, "radio", 5_000_000)


def test_rate_override_uses_the_selected_rates_frequency_centers() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["campaign_configuration"]

    for ordinal in range(100):
        epoch = ordinal * 600
        _, _, edge, _, _ = configure(epoch, "radio", 2_500_000)
        _, _, _, frequencies_2p5, _ = configure(epoch, "radio", 2_500_000)
        _, _, _, frequencies_15m, _ = configure(epoch, "radio", 15_000_000)
        offset = 0 if edge == "lower" else 1
        assert frequencies_2p5 == values["FREQUENCIES_2P5"][offset::2]
        assert frequencies_15m == values["FREQUENCIES_10M"][offset::2]
