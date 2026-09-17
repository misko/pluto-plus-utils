from __future__ import annotations

import runpy
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts/run_v052_adaptive_live.py"


def test_slot_configuration_cycles_rates_and_omitted_channel() -> None:
    values = runpy.run_path(str(SCRIPT))
    configure = values["slot_configuration"]
    frequencies = values["FREQUENCIES"]

    assert configure(0) == (0, 10_000_000, frequencies[1:])
    assert configure(600)[1] == 15_000_000
    assert configure(1_200)[1] == 20_000_000
    assert configure(1_800)[1] == 10_000_000
    assert frequencies[1] not in configure(600)[2]
    assert len(configure(600)[2]) == 7
    assert frequencies[0] == 959_687_498
