import subprocess
from types import SimpleNamespace

import pytest

from pluto_plus.dfu_safety import guard_dfu_download, require_ram_alternates
from pluto_plus.flash_safety import FlashSafetyError


def row(alt, name, *, path="1-2.3", devnum=4):
    return (
        f"Found DFU: [0456:b674] ver=0200, devnum={devnum}, cfg=1, intf=0, "
        f'path="{path}", alt={alt}, name="{name}", serial="synthetic"\n'
    )


@pytest.mark.parametrize(
    "report",
    [
        row(1, "firmware.dfu"),
        row(0, "boot.dfu") + row(1, "firmware.dfu"),
        row(0, "dummy.dfu") + row(1, "firmware.dfu", path="1-2.4"),
        row(0, "dummy.dfu") + row(1, "firmware.dfu", devnum=5),
        row(0, "dummy.dfu") * 2 + row(1, "firmware.dfu"),
        "",
    ],
)
def test_persistent_or_ambiguous_mode_cannot_download(report):
    with pytest.raises(FlashSafetyError, match="dfu_mode_unqualified"):
        require_ram_alternates(report, "1-2.3")


def test_actual_download_boundary_queries_exact_path_first(monkeypatch):
    calls = []

    def run(argv, **kwargs):
        calls.append(tuple(argv))
        return SimpleNamespace(stdout=row(0, "dummy.dfu") + row(1, "firmware.dfu"))

    monkeypatch.setattr(subprocess, "run", run)
    guard_dfu_download(("dfu-util", "-p", "1-2.3", "-a", "firmware.dfu", "-D", "image.dfu"))
    assert calls == [("dfu-util", "-p", "1-2.3", "-d", "0456:b674", "-l")]
    guard_dfu_download(("dfu-util", "--version"))
    assert len(calls) == 1


@pytest.mark.parametrize(
    "module,runner",
    [
        ("pluto_plus.firmware", "SubprocessCommandRunner"),
        ("pluto_plus.volatile_firmware", "SubprocessDfuRunner"),
        ("pluto_plus.release_candidate_linux", "SubprocessLinuxCommandRunner"),
    ],
)
def test_every_production_dfu_runner_refuses_sf_before_download(monkeypatch, module, runner):
    import importlib

    calls = []

    def run(argv, **kwargs):
        calls.append(tuple(argv))
        return SimpleNamespace(stdout=row(0, "boot.dfu") + row(1, "firmware.dfu"))

    monkeypatch.setattr(subprocess, "run", run)
    instance = getattr(importlib.import_module(module), runner)()
    with pytest.raises(FlashSafetyError):
        instance.run(
            ("dfu-util", "-p", "1-2.3", "-a", "firmware.dfu", "-D", "image.dfu"), timeout_s=10
        )
    assert len(calls) == 1
    assert "-D" not in calls[0]
