"""Reject persistent/ambiguous DFU mode before a firmware download."""

from __future__ import annotations

import re
import subprocess
from collections.abc import Sequence

from pluto_plus.flash_safety import FlashSafetyError


def require_ram_alternates(report: str, topology: str) -> None:
    """Match the complete reviewed U-Boot RAM descriptor contract, not one name.

    SF mode advertises boot/environment/spare alternates in addition to the same
    firmware.dfu name. RAM mode advertises only dummy.dfu and firmware.dfu.
    """
    rows = [line for line in report.splitlines() if "Found DFU:" in line]
    expected = {(0, "dummy.dfu"), (1, "firmware.dfu")}
    found: set[tuple[int, str]] = set()
    devices: set[str] = set()
    for row in rows:
        match = re.search(
            r'Found DFU: \[0456:b674\].*?devnum=(\d+),.*?path="([^"]+)"'
            r'.*?alt=(\d+), name="([^"]+)"',
            row,
        )
        if match is None or match[2] != topology:
            raise FlashSafetyError("dfu_mode_unqualified", "DFU identity/mode is ambiguous")
        pair = (int(match[3]), match[4])
        if pair in found:
            raise FlashSafetyError("dfu_mode_unqualified", "duplicate DFU alternate")
        devices.add(match[1])
        found.add(pair)
    if found != expected or len(devices) != 1:
        raise FlashSafetyError(
            "dfu_mode_unqualified",
            "firmware.dfu is not proven RAM-only: expected exactly dummy.dfu and firmware.dfu; "
            "persistent SF downloads require separate writer qualification",
        )


def guard_dfu_download(argv: Sequence[str]) -> None:
    """Production subprocess boundary shared by RAM, resume and lifecycle routes."""
    if not argv or argv[0] != "dfu-util" or "-D" not in argv:
        return
    try:
        topology = argv[argv.index("-p") + 1]
        alternate = argv[argv.index("-a") + 1]
        if not re.fullmatch(r"[0-9]+-[0-9]+(?:\.[0-9]+)*", topology):
            raise ValueError("invalid topology")
        if alternate != "firmware.dfu":
            raise ValueError("persistent alternate")
    except (ValueError, IndexError) as error:
        raise FlashSafetyError("dfu_mode_unqualified", "unbound/persistent DFU download") from error
    result = subprocess.run(
        ("dfu-util", "-p", topology, "-d", "0456:b674", "-l"),
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )
    require_ram_alternates(result.stdout, topology)
