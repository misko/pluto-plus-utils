"""Live adapter composition is firmware-owned and explicitly registered."""

from __future__ import annotations

import zlib
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass

from .contracts import Observation, Profile, RecoveryError, ReturnEvidence, digest
from .store import Store
from .uboot import Console
from .workflow import Backend


@dataclass(frozen=True)
class Recipes:
    """Qualified board-specific probes/boot operations, never read from user JSON.

    Recipes must bind observed UID, topology, actual executing artifacts, flash
    geometry/protection, and hardware reset/source evidence. Their firmware
    qualification is part of the shipped profile's evidence identities.
    """

    observe: Callable[[], Observation]
    ram_boot: Callable[[bytes], ReturnEvidence]
    return_to_sd: Callable[[], None]
    cold_boot: Callable[[], ReturnEvidence]
    lease: Callable[[], AbstractContextManager[None]]


class SdUbootBackend:
    """Real U-Boot SF/SD data path with firmware-qualified identity/boot recipes.

    Stage files must already be copied to SD using their content-addressed names.
    A missing file fails before erase. No Linux flash writer is used.
    """

    def __init__(self, console: Console, profile: Profile, recipes: Recipes) -> None:
        self.console, self.profile, self.recipes = console, profile, recipes
        ram, compare_ram = profile.capture_address, profile.compare_address
        self.ram, self.compare_ram = ram, compare_ram
        self.staged_size: int | None = None
        capacity = profile.geometry.capacity
        if not (
            0 <= ram < ram + capacity <= profile.ddr_bytes
            and 0 <= compare_ram < compare_ram + capacity <= profile.ddr_bytes
            and (ram + capacity <= compare_ram or compare_ram + capacity <= ram)
        ):
            raise RecoveryError(
                "ram_unqualified", "capture/comparison RAM areas overlap or exceed DDR"
            )

    def lease(self) -> AbstractContextManager[None]:
        return self.recipes.lease()

    def observe(self) -> Observation:
        return self.recipes.observe()

    def read(self, start: int, size: int) -> bytes:
        if not 0 <= start < start + size <= self.profile.read_limit:
            raise RecoveryError("reader_unqualified", "read exceeds qualified range")
        result = bytearray()
        for offset in range(start, start + size, 65536):
            count = min(65536, start + size - offset)
            # Verification must never overwrite the already staged program buffer.
            self.console.sf("read", offset, count, ram=self.compare_ram)
            result.extend(self.console.memory(self.compare_ram, count))
        return bytes(result)

    def _load(self, name: str, size: int) -> None:
        output = self.console.command(f"fatload mmc 0:1 {self.ram:x} {name} {size + 1:x}")
        import re

        counts = re.findall(rb"(?m)^(\d+) bytes read(?: in .*|)$", output)
        if len(counts) != 1 or int(counts[0]) != size:
            raise RecoveryError("sd_transfer_invalid", "loaded file size differs")

    def stage(self, payload: bytes) -> None:
        self.staged_size = None
        name = f"ppu-repair/ppu-{digest(payload)}.bin"
        self._load(name, len(payload))
        observed = bytearray()
        for offset in range(0, len(payload), 65536):
            observed.extend(
                self.console.memory(self.ram + offset, min(65536, len(payload) - offset))
            )
        if observed != payload:
            raise RecoveryError("sd_transfer_invalid", "staged RAM payload differs")
        self.staged_size = len(payload)

    def export_and_reload(self, data: bytes) -> None:
        # Read flash into a complete qualified buffer, then roundtrip the saved SD
        # file. Host bytes were separately read through the same qualified reader.
        self.console.sf("read", 0, len(data), ram=self.ram)
        output = self.console.command(f"crc32 {self.ram:x} {len(data):x}")
        import re

        checks = re.findall(rb"==> ([0-9a-fA-F]{8})(?:\s|$)", output)
        if len(checks) != 1 or int(checks[0], 16) != zlib.crc32(data):
            raise RecoveryError("backup_invalid", "device capture CRC differs from host bytes")
        name = f"ppu-backup-{digest(data)}.bin"
        # Refuse an existing file rather than overwriting an earlier SD backup.
        exists = self.console.command(f"if test -e mmc 0:1 /{name}; then false; else true; fi")
        del exists
        output = self.console.command(f"fatwrite mmc 0:1 {self.ram:x} {name} {len(data):x}")
        counts = re.findall(rb"(?m)^(\d+) bytes written(?: in .*|)$", output)
        if len(counts) != 1 or int(counts[0]) != len(data):
            raise RecoveryError("backup_invalid", "SD export length differs")
        output = self.console.command(
            f"fatload mmc 0:1 {self.compare_ram:x} {name} {len(data) + 1:x}"
        )
        counts = re.findall(rb"(?m)^(\d+) bytes read(?: in .*|)$", output)
        if len(counts) != 1 or int(counts[0]) != len(data):
            raise RecoveryError("backup_invalid", "SD reload length differs")
        output = self.console.command(f"cmp.b {self.ram:x} {self.compare_ram:x} {len(data):x}")
        compared = re.findall(rb"Total of (\d+) byte\(s\) were the same", output)
        if len(compared) != 1 or int(compared[0]) != len(data):
            raise RecoveryError("backup_invalid", "exported SD file did not compare completely")

    def erase(self, start: int, size: int) -> None:
        self._sector(start, size)
        if self.staged_size != size or start + size > self.profile.write_limit:
            raise RecoveryError(
                "writer_unqualified", "erase lacks a verified complete-sector payload"
            )
        self.console.sf("erase", start, size)

    def program(self, start: int, size: int) -> None:
        self._sector(start, size)
        if self.staged_size != size or start + size > self.profile.write_limit:
            raise RecoveryError("writer_unqualified", "program lacks verified staging")
        self.console.sf("write", start, size, ram=self.ram)
        self.staged_size = None

    def _sector(self, start: int, size: int) -> None:
        if not any(
            p.start <= start
            and start + size <= p.end
            and size == p.erase_size
            and start % size == 0
            for p in self.profile.geometry.regions
        ):
            raise RecoveryError(
                "writer_unqualified", "operation must cover one complete erase sector"
            )

    def ram_boot(self, fit: bytes) -> ReturnEvidence:
        return self.recipes.ram_boot(fit)

    def return_to_sd(self) -> None:
        self.recipes.return_to_sd()

    def attest_cold_boot(self) -> ReturnEvidence:
        return self.recipes.cold_boot()


BackendFactory = Callable[[Store, Profile], Backend]


def _incident_backend(store: Store, profile: Profile) -> Backend:
    from .pluto_sd import PlutoSdBackend

    return PlutoSdBackend(store, profile)


BACKENDS: dict[str, BackendFactory] = {"plutoplus-incident-114": _incident_backend}


def backend_for(store: Store, profile: Profile) -> Backend:
    factory = BACKENDS.get(profile.profile_id)
    if factory is None:
        raise RecoveryError(
            "backend_unqualified", "no qualified live identity/boot recipe is shipped"
        )
    return factory(store, profile)
