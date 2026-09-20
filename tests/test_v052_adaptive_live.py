from __future__ import annotations

import runpy
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts/run_v052_adaptive_live.py"


def test_slot_configuration_cycles_rates_and_balanced_edge_families() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["slot_configuration"]
    frequencies = values["FREQUENCIES"]
    lower = values["LOWER_FREQUENCIES"]
    upper = values["UPPER_FREQUENCIES"]

    assert lower == tuple(frequencies[index] for index in (0, 2, 4, 6))
    assert upper == tuple(frequencies[index] for index in (1, 3, 5, 7))
    assert configure(0) == (0, 10_000_000, "lower", lower)
    assert configure(600)[1] == 15_000_000
    assert configure(600)[2:] == ("upper", upper)
    assert configure(1_200)[1] == 20_000_000
    assert configure(1_200)[2:] == ("lower", lower)
    assert configure(1_800)[1] == 10_000_000
    assert configure(1_800)[2:] == ("upper", upper)
    assert configure(2_400)[1:] == (15_000_000, "lower", lower)
    assert configure(3_000)[1:] == (20_000_000, "upper", upper)
    assert frequencies[0] == 959_687_498


def test_campaign_configuration_accepts_exact_radio_and_sample_rate() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["campaign_configuration"]

    first = configure(1_760_000_000, "104000b29905000e17000800065934759d", 15_000_000)
    second = configure(1_760_000_000, "1040007c4a94000211000b009186843ef2", 20_000_000)

    assert first[1] == 15_000_000
    assert second[1] == 20_000_000
    assert first[2:4] == second[2:4]
    assert first[4] != second[4]

    with pytest.raises(ValueError, match="10, 15, or 20 MS/s"):
        configure(1_760_000_000, "radio", 5_000_000)
