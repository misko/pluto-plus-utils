from __future__ import annotations

import runpy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/run_v052_adaptive_live.py"


def test_slot_configuration_is_deterministic_and_balanced_across_slots() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["slot_configuration"]
    frequencies_by_rate = values["FREQUENCIES_BY_RATE"]
    slots = [configure(ordinal * 600) for ordinal in range(1_000)]
    assert slots == [configure(ordinal * 600) for ordinal in range(1_000)]
    assert all(rate in (2_500_000, 10_000_000) for _, rate, _, _ in slots)
    assert all(
        frequencies == frequencies_by_rate[rate][0 if edge == "lower" else 1 :: 2]
        for _, rate, edge, frequencies in slots
    )
    assert 450 < sum(rate == 2_500_000 for _, rate, _, _ in slots) < 550
    assert 450 < sum(edge == "lower" for _, _, edge, _ in slots) < 550
    assert frequencies_by_rate[2_500_000][0] == 959_687_498
    assert frequencies_by_rate[10_000_000][0] == 960_000_000


def test_campaign_configuration_accepts_exact_radio_and_sample_rate() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["campaign_configuration"]

    first = configure(1_760_000_000, "104000b29905000e17000800065934759d", 2_500_000)
    second = configure(1_760_000_000, "1040007c4a94000211000b009186843ef2", 10_000_000)

    assert first[1] == 2_500_000
    assert second[1] == 10_000_000
    assert first[4] != second[4]

    with pytest.raises(ValueError, match="2.5 or 10 MS/s"):
        configure(1_760_000_000, "radio", 5_000_000)
