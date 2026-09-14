"""Upload a pinned, RAM-only SHA-256 helper to the reviewed Zynq U-Boot.

The helper reads bounded DDR and writes only its 32-byte DDR result. It cannot
read or program flash itself. The caller must establish physical SPI addressing.
"""

from importlib.resources import files

from .contracts import RecoveryError, digest
from .uboot import Console

HELPER_SHA256 = "2dc2388c9df461cc6d22a158789ea6e0c5d283aef00211c6a3ed77add2060af1"
CODE = 0x06000000
RESULT = 0x06010000


def helper_bytes() -> bytes:
    data = files("pluto_plus.recovery").joinpath("assets/sha256_ram.bin").read_bytes()
    if digest(data) != HELPER_SHA256 or len(data) > 0x10000:
        raise RecoveryError("artifact_corrupt", "RAM digest helper differs from compiled pin")
    return data


class RamDigest:
    def __init__(self, console: Console) -> None:
        self.console = console
        self.loaded = False

    def install(self) -> None:
        data = helper_bytes()
        self.console.command("dcache off")
        self.console.command("icache off")
        padded = data + bytes((-len(data)) % 4)
        for start in range(0, len(padded), 32):
            commands = [
                f"mw.l {CODE + offset:x} {int.from_bytes(padded[offset : offset + 4], 'little'):x}"
                for offset in range(start, min(start + 32, len(padded)), 4)
            ]
            self.console.command("; ".join(commands))
        if self.console.memory(CODE, len(data)) != data:
            raise RecoveryError("artifact_corrupt", "RAM digest helper upload failed readback")
        self.console.command("icache on")
        self.loaded = True

    def sha256(self, address: int, size: int) -> str:
        if not self.loaded:
            self.install()
        if not 0x08000000 <= address < address + size <= 0x20000000 or size > 0x02000000:
            raise RecoveryError("ram_unqualified", "digest range is outside reviewed DDR")
        self.console.command(f"mw.b {RESULT:x} 0 20")
        output = self.console.command(f"go {CODE:x} {address:x} {size:x}")
        if b"Application terminated, rc = 0x0" not in output:
            raise RecoveryError("command_unverified", "RAM digest helper did not return success")
        return self.console.memory(RESULT, 32).hex()
