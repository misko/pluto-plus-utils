"""Incident-scoped Pluto+ SD recovery on the physically identified Winbond unit.

This is a conservative repair recipe, not a general hardware qualification grant.
It uses native four-byte SPI reads to cross-check SF placement, bounded RAM SHA256
for full-byte comparisons, and the retained target image as a content-addressed
cache. Cache bytes are returned only after matching a freshly read device digest.
"""

from __future__ import annotations

import json
import os
import queue
import re
import socket
import stat
import threading
import time
import uuid
import xml.etree.ElementTree as ET
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from importlib.resources import files
from pathlib import Path

from pluto_plus.flash_safety import LEGACY_ADDRESS_LIMIT

from .contracts import (
    Blob,
    Observation,
    Plan,
    Profile,
    RecoveryError,
    ReturnEvidence,
    Target,
    digest,
)
from .live import Recipes, SdUbootBackend
from .ram_digest import RamDigest
from .store import Store, read_regular
from .uboot import Console, SerialWire

PROFILE_ID = "plutoplus-incident-114"
CODE_SHA256 = "ffbebc5d9505099ca8b9b624ca0da48c8d34e8f65138620114a06e4e4d3b36d7"


def kit_root() -> Path:
    return Path.home() / ".local/share/pluto-plus-utils/recovery-kits/incident-114"


def network_context() -> bytes:
    """Read IIOD metadata over the incident radio's Ethernet connection."""
    try:
        with socket.create_connection(("192.168.1.14", 30431), timeout=5) as connection:
            connection.sendall(b"PRINT\n")
            with connection.makefile("rb") as stream:
                header = stream.readline(32)
                if not re.fullmatch(rb"[0-9]{1,7}\n", header):
                    raise ValueError("invalid IIOD frame")
                size = int(header)
                if not 0 < size <= 1024 * 1024:
                    raise ValueError("IIOD frame exceeds bound")
                data = stream.read(size)
                if len(data) != size or b"<!ENTITY" in data:
                    raise ValueError("incomplete or unsupported IIOD XML")
                context = ET.fromstring(data)
                names = {device.get("name") for device in context.findall("device")}
                if context.tag != "context" or not {"ad9361-phy", "cf-ad9361-lpc"} <= names:
                    raise ValueError("expected IIO devices missing")
                return data
    except (OSError, ValueError, ET.ParseError) as error:
        raise RecoveryError(
            "network_unverified", "IIOD on 192.168.1.14 did not return the expected context"
        ) from error


class BufferedWire:
    """Continuously retain UART output, including while an operator prompt waits."""

    MAX_PENDING_BYTES = 4 * 1024 * 1024

    def __init__(self, source: SerialWire, log: Callable[[bytes], object]) -> None:
        self.source, self.log = source, log
        self.pending: queue.Queue[bytes | BaseException] = queue.Queue()
        self.pending_bytes = 0
        self.pending_lock = threading.Lock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self) -> None:
        try:
            while not self.stop.is_set():
                data = self.source.read(0.1)
                if data:
                    self.log(data)
                    with self.pending_lock:
                        if self.pending_bytes + len(data) > self.MAX_PENDING_BYTES:
                            raise RecoveryError(
                                "transport_overflow",
                                "more than 4 MiB of unread UART data accumulated",
                            )
                        self.pending_bytes += len(data)
                    self.pending.put_nowait(data)
        except BaseException as error:
            self.pending.put_nowait(error)
            self.stop.set()

    def read(self, timeout: float) -> bytes:
        try:
            data = self.pending.get(timeout=max(0, timeout))
        except queue.Empty:
            if self.stop.is_set():
                raise RecoveryError("transport_disconnected", "UART capture stopped") from None
            return b""
        if isinstance(data, BaseException):
            raise RecoveryError("transport_disconnected", "UART capture failed") from data
        with self.pending_lock:
            self.pending_bytes -= len(data)
        return data

    def write(self, data: bytes) -> None:
        if self.stop.is_set():
            raise RecoveryError("transport_disconnected", "UART capture stopped")
        self.source.write(data)

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=1)


class PlutoSdBackend(SdUbootBackend):
    def __init__(self, store: Store, profile: Profile) -> None:
        self.store = store
        self.source = SerialWire(Path(store.session.adapter))
        self.wire: BufferedWire | None = None
        self.capture = bytearray()
        self.checked_boot = False
        self.epoch: str | None = None
        self.target: Target | None = None
        self.payload: bytes | None = None
        self.runtime_source = "sd"
        self.operator_cold_actions = False
        try:
            original = read_regular(kit_root() / "original.bin")
        except FileNotFoundError as error:
            raise RecoveryError(
                "incident_kit_missing",
                "this incident recipe needs its private retained kit on Gauss; "
                "the profile does not provide another radio's recovery artifacts",
            ) from error
        if digest(original) != profile.original_flash_sha256:
            raise RecoveryError(
                "artifact_corrupt", "incident backup does not match the compiled pin"
            )
        self.cache = bytearray(original)
        plans = [e for e in store.events() if e.kind == "plan_ready"]
        if plans:
            plan = Plan.model_validate_json(store.get(Blob.model_validate(plans[-1].data["plan"])))
            self.cache = bytearray(store.get(plan.current))
            for event in store.events()[plans[-1].sequence + 1 :]:
                if event.kind == "sector_verified" and event.data.get("plan_sha256") == plan.sha256:
                    start, size = int(str(event.data["start"])), int(str(event.data["size"]))
                    payload = store.get(Blob(sha256=str(event.data["payload_sha256"]), size=size))
                    self.cache[start : start + size] = payload
        # The Console is installed only while lease owns the physical adapter.
        super().__init__(
            Console(self.source, self._log),
            profile,
            Recipes(
                observe=self._observe,
                ram_boot=self._ram_boot,
                return_to_sd=self._return_sd,
                cold_boot=self._cold_boot,
                lease=self._lease,
            ),
        )
        self.hasher = RamDigest(self.console)

    def _log(self, data: bytes) -> None:
        self.capture.extend(data)
        if len(self.capture) > 4 * 1024 * 1024:
            self.store.put(bytes(self.capture))
            self.capture.clear()

    @contextmanager
    def _lease(self) -> Iterator[None]:
        # The host logger or another terminal must release the port first.
        with self.source.lease():
            fd = os.open(
                self.store.root / "uart.bin",
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                0o600,
            )
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_uid != os.getuid()
            ):
                os.close(fd)
                raise RecoveryError("evidence_invalid", "UART log must be a single regular file")

            def append(data: bytes) -> None:
                while data:
                    count = os.write(fd, data)
                    if count == 0:
                        raise OSError("UART log write made no progress")
                    data = data[count:]

            self.wire = BufferedWire(self.source, append)
            self.console = Console(self.wire, self._log)
            self.hasher = RamDigest(self.console)
            self.checked_boot = False
            try:
                yield
            finally:
                self.wire.close()
                self.wire = None
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)

    def _spi(self, command: bytes, count: int) -> bytes:
        data = command + bytes(count)
        if len(data) > 32:
            raise RecoveryError("command_invalid", "SPI probe exceeds the compiled U-Boot bound")
        result = self.console.command(f"sspi 0:0.0 {len(data) * 8} {data.hex()}")
        matches = re.findall(rb"(?m)^([0-9A-Fa-f]{" + str(len(data) * 2).encode() + rb"})$", result)
        if len(matches) != 1:
            raise RecoveryError("command_unverified", "SPI response length is ambiguous")
        return bytes.fromhex(matches[0].decode())[len(command) :]

    def _native(self, start: int, size: int) -> bytes:
        if not 0 <= start < start + size <= 0x2000000:
            raise RecoveryError("command_invalid", "native flash read is out of range")
        return b"".join(
            self._spi(b"\x13" + offset.to_bytes(4, "big"), min(16, start + size - offset))
            for offset in range(start, start + size, 16)
        )

    def _identity(self) -> tuple[str, int, int]:
        if self._spi(b"\x9f", 3).hex() != self.profile.jedec:
            raise RecoveryError("target_mismatch", "JEDEC flash identity differs")
        if self._spi(b"\x15", 1)[0] & 1:
            raise RecoveryError("writer_unqualified", "unexpected global four-byte address mode")
        uid = self._spi(b"\x4b" + bytes(4), 8).hex()
        if digest(uid.encode()) != self.profile.target_uid_sha256:
            raise RecoveryError("target_mismatch", "flash unique ID is not the incident target")
        sr1, sr2 = self._spi(b"\x05", 1)[0], self._spi(b"\x35", 1)[0]
        if sr1 != 0 or sr2 != 2:
            raise RecoveryError("flash_protected", "unexpected flash busy/protection/quad state")
        return uid, self._register(0xF8000258), self._register(0xF800025C) & 15

    def _register(self, address: int) -> int:
        # Zynq SLCR registers require word accesses; byte reads are not equivalent.
        output = self.console.command(f"md.l {address:x} 1")
        values = re.findall(
            rb"(?m)^" + f"{address:08x}".encode() + rb": ([0-9a-fA-F]{8})\s", output
        )
        if len(values) != 1:
            raise RecoveryError("command_unverified", "register word read is ambiguous")
        return int(values[0], 16)

    def _bank_zero(self) -> None:
        self.console.sf("read", 0, 16, ram=0x07000000)
        if self._spi(b"\xc8", 1) != b"\0":
            raise RecoveryError("writer_unqualified", "EAR bank zero was not established")
        if self.console.memory(0x07000000, 16) != self._native(0, 16):
            raise RecoveryError(
                "physical_read_inconsistent", "bank zero differs from native addressing"
            )

    def _observe(self) -> Observation:
        uid, reset, mode = self._identity()
        if mode != 5:
            raise RecoveryError("bootstrap_unverified", "target was not booted from SD")
        if self._register(0xF8000530) != 0x13722093:
            raise RecoveryError("target_mismatch", "Zynq silicon ID differs")
        if not self.checked_boot:
            version = self.console.command("version")
            if b"49f86d8991e192898b58599052b29e0280bcbd79" not in version:
                raise RecoveryError("bootstrap_unverified", "recovery U-Boot version differs")
            info = self.console.command("bdinfo")
            if not re.search(rb"size\s+= 0x20000000", info) or b"0x1FF42000" not in info:
                raise RecoveryError(
                    "bootstrap_unverified", "DDR or relocated U-Boot address differs"
                )
            self.console.command("sf probe 0:0 50000000 0")
            self.hasher.install()
            if self.hasher.sha256(0x1FF47000, 0x3B000) != CODE_SHA256:
                raise RecoveryError("writer_unqualified", "relocated U-Boot code differs from pin")
            for name, claim in self.profile.sd_files.items():
                output = self.console.command(
                    f"fatload mmc 0:1 {self.compare_ram:x} {name} {claim.size + 1:x}"
                )
                counts = re.findall(rb"(?m)^(\d+) bytes read(?: in .*|)$", output)
                if (
                    len(counts) != 1
                    or int(counts[0]) != claim.size
                    or self.hasher.sha256(self.compare_ram, claim.size) != claim.sha256
                ):
                    raise RecoveryError(
                        "bootstrap_unverified", "SD bootstrap files differ from pin"
                    )
            self.checked_boot = True
        epoch_out = self.console.command("echo EPOCH_${ppu_recovery_epoch}")
        found = re.findall(rb"(?m)^EPOCH_([a-f0-9]{32})$", epoch_out)
        if len(found) == 1:
            self.epoch = found[0].decode()
        elif b"EPOCH_\n" in epoch_out + b"\n":
            self.epoch = uuid.uuid4().hex
            self.console.command(f"setenv ppu_recovery_epoch {self.epoch}")
        else:
            raise RecoveryError("bootstrap_unverified", "invalid volatile boot epoch")
        self._bank_zero()
        endpoint = self.source.adapter.resolve(strict=True).name
        topology = str((Path("/sys/class/tty") / endpoint / "device").resolve(strict=True))
        self.target = Target(
            adapter=self.store.session.adapter,
            topology=topology,
            uid=uid,
            serial="winbond-" + uid,
            board=self.profile.board,
            soc=self.profile.soc,
            ddr_bytes=self.profile.ddr_bytes,
            jedec=self.profile.jedec,
        )
        transcript = self.store.put(bytes(self.capture))
        self.capture.clear()
        return Observation(
            target=self.target,
            geometry=self.profile.geometry,
            bootstrap_sha256=self.profile.bootstrap_sha256,
            writer_sha256=self.profile.writer_sha256,
            boot_epoch=self.epoch,
            qualification_id=self.profile.qualification_id,
            transcript=transcript,
            flash_protected=False,
        )

    def read(self, start: int, size: int) -> bytes:
        if not 0 <= start < start + size <= self.profile.read_limit:
            raise RecoveryError("reader_unqualified", "flash read exceeds profile")
        if size <= 256:
            return self._native(start, size)
        # sspi uses 1MHz on the shared slave. Re-establish the reviewed 50MHz
        # SF clock before bulk reads instead of leaving subsequent reads at 1MHz.
        self.console.command("sf probe 0:0 50000000 0")
        self.console.sf("read", start, size, ram=self.compare_ram)
        actual = self.hasher.sha256(self.compare_ram, size)
        expected = bytes(self.cache[start : start + size])
        # Cross-check actual physical endpoints with an independent native address opcode.
        for offset in {0, size - 16}:
            if self.console.memory(self.compare_ram + offset, 16) != self._native(
                start + offset, 16
            ):
                raise RecoveryError(
                    "physical_read_inconsistent", "SF read aliases native addressing"
                )
        if actual == digest(expected):
            return expected
        if not any(e.kind in {"erase_intent", "program_intent"} for e in self.store.events()):
            raise RecoveryError(
                "incident_image_mismatch", "flash differs from the bound incident backup"
            )
        # Reconcile unknown bytes after an interrupted dispatch without trusting the journal.
        recovered = bytearray()
        for offset in range(0, size, 65536):
            count = min(65536, size - offset)
            known = expected[offset : offset + count]
            if self.hasher.sha256(self.compare_ram + offset, count) == digest(known):
                recovered.extend(known)
            else:
                recovered.extend(self.console.memory(self.compare_ram + offset, count))
        if digest(bytes(recovered)) != actual:
            raise RecoveryError(
                "physical_read_inconsistent", "reconstructed read failed complete digest"
            )
        self.cache[start : start + size] = recovered
        return bytes(recovered)

    def export_and_reload(self, data: bytes) -> None:
        self.console.command("sf probe 0:0 50000000 0")
        self.console.sf("read", 0, len(data), ram=self.ram)
        if self.hasher.sha256(self.ram, len(data)) != digest(data):
            raise RecoveryError("backup_invalid", "fresh SD export source differs")
        name = f"ppu-backup-{digest(data)}.bin"
        # Idempotent across an interrupted export: an existing file must verify completely.
        result = self.console.command(
            f"if test -e mmc 0:1 /{name}; then echo EXISTS; else echo ABSENT; fi"
        )
        if b"ABSENT" in result:
            out = self.console.command(f"fatwrite mmc 0:1 {self.ram:x} {name} {len(data):x}")
            if not re.search(rb"(?m)^" + str(len(data)).encode() + rb" bytes written$", out):
                raise RecoveryError("backup_invalid", "SD backup write count differs")
        elif b"EXISTS" not in result:
            raise RecoveryError("backup_invalid", "SD backup presence is ambiguous")
        self._load(name, len(data))
        if self.hasher.sha256(self.ram, len(data)) != digest(data):
            raise RecoveryError("backup_invalid", "reloaded SD backup differs")
        self._bank_zero()

    def stage(self, payload: bytes) -> None:
        self.staged_size = None
        self.payload = None
        self._load(f"ppu-repair/ppu-{digest(payload)}.bin", len(payload))
        if self.hasher.sha256(self.ram, len(payload)) != digest(payload):
            raise RecoveryError("sd_transfer_invalid", "staged payload differs")
        self.staged_size = len(payload)
        self.payload = payload

    def erase(self, start: int, size: int) -> None:
        self._bank_zero()
        super().erase(start, size)
        self.cache[start : start + size] = b"\xff" * size

    def program(self, start: int, size: int) -> None:
        payload = self.payload
        self._bank_zero()
        super().program(start, size)
        if payload is None:
            raise RecoveryError("sd_transfer_invalid", "missing staged payload")
        self.cache[start : start + size] = payload
        self.payload = None

    def _wait(self, patterns: tuple[bytes, ...], timeout: float = 120) -> bytes:
        if self.wire is None:
            raise RecoveryError("transport_closed", "UART lease required")
        result = bytearray()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result.extend(self.wire.read(min(0.2, max(0, deadline - time.monotonic()))))
            if len(result) > 2**20:
                raise RecoveryError("command_invalid", "boot output exceeds bound")
            if any(p in result for p in patterns):
                self._log(bytes(result))
                return bytes(result)
        self._log(bytes(result) or b"no boot response")
        if not result:
            raise RecoveryError(
                "boot_timeout",
                "no UART bytes were received; verify radio power, common ground, radio TX to "
                "FTDI RX, and SD boot selection, then rerun the same session command",
            )
        raise RecoveryError(
            "boot_timeout", "expected boot state was not observed; inspect private UART log"
        )

    def _wait_sequence(
        self, first: bytes | tuple[bytes, ...], second: bytes, timeout: float = 120
    ) -> bytes:
        """Wait for two ordered boot tokens, even when both arrive in one UART chunk."""
        if self.wire is None:
            raise RecoveryError("transport_closed", "UART lease required")
        result = bytearray()
        first_end: int | None = None
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result.extend(self.wire.read(min(0.2, max(0, deadline - time.monotonic()))))
            if len(result) > 2**20:
                raise RecoveryError("command_invalid", "boot output exceeds bound")
            if first_end is None:
                candidates = first if isinstance(first, tuple) else (first,)
                matches = [
                    (result.find(candidate), candidate)
                    for candidate in candidates
                    if result.find(candidate) >= 0
                ]
                if matches:
                    position, matched = min(matches, key=lambda item: item[0])
                    first_end = position + len(matched)
            if first_end is not None and second in result[first_end:]:
                self._log(bytes(result))
                return bytes(result)
        self._log(bytes(result) or b"no boot response")
        if not result:
            raise RecoveryError(
                "boot_timeout",
                "no UART bytes were received; verify radio power, common ground, radio TX to "
                "FTDI RX, and SD boot selection, then rerun the same session command",
            )
        raise RecoveryError(
            "boot_timeout", "expected ordered SD boot markers were not observed; inspect UART log"
        )

    def _verify_cold_fit(self) -> str:
        """Verify the persisted FIT without reading an unqualified upper bank."""
        region = self.profile.geometry.region("fit")
        fit = self.profile.rollback
        if not region.start < region.start + fit.size <= min(region.end, LEGACY_ADDRESS_LIMIT):
            raise RecoveryError("flash_range_unqualified", "cold-boot FIT exceeds safe read range")
        self.console.command(
            f'test "$(cat /sys/class/mtd/mtd3/offset)" = {region.start} && '
            f'test "$(cat /sys/class/mtd/mtd3/size)" = {region.size} && '
            'test "$(cat /sys/class/mtd/mtd3/name)" = qspi-linux'
        )
        output = self.console.command(f"head -c {fit.size} /dev/mtd3 | sha256sum")
        match = re.fullmatch(rb"([0-9a-f]{64})  -", output.strip())
        if match is None or match[1].decode() != fit.sha256:
            raise RecoveryError("return_unverified", "cold-boot firmware FIT readback differs")
        return match[1].decode()

    def _runtime(self, source: str, *, cold: bool = False) -> ReturnEvidence:
        if self.target is None:
            raise RecoveryError("target_unbound", "missing prior target observation")
        pins = json.loads(
            files("pluto_plus.recovery").joinpath("assets/incident114-runtime.json").read_text()
        )
        version = self.console.command("cat /proc/version").strip()
        if version != pins.pop("kernel_version").encode():
            raise RecoveryError("return_unverified", "running kernel build differs")
        for name, claim in pins.items():
            out = self.console.command(
                f'test "$(wc -c </{name})" = {claim["size"]} && sha256sum /{name}'
            )
            if not re.search(rb"(?m)^" + claim["sha256"].encode() + rb"\s+", out):
                raise RecoveryError("return_unverified", "running rootfs artifact differs")
        if source == "ram":
            self.console.command("grep -q ppu_recovery=" + str(self.epoch) + " /proc/cmdline")
        out = self.console.command("devmem 0xf8000258 32; devmem 0xf800025c 32")
        regs = re.findall(rb"(?m)^0x([0-9A-Fa-f]{8})$", out)
        if len(regs) != 2:
            raise RecoveryError("return_unverified", "boot registers unavailable")
        reset, mode = (int(v, 16) for v in regs)
        if (cold and (mode & 15 != 2 or reset & 0x7F0000 != 0x400000)) or (
            not cold and mode & 15 != 5
        ):
            raise RecoveryError("cold_boot_unverified", "actual boot selection/reset differs")
        self.console.command(
            "(for i in 1 2 3 4 5 6 7 8 9 10; do "
            'test "$(cat /sys/class/net/eth0/carrier)" = 1 && exit 0; sleep 1; done; exit 1)'
        )
        self.console.command("ip -4 addr show dev eth0 | grep -q 'inet 192.168.1.14/'")
        self.console.command("pidof iiod >/dev/null")
        names = self.console.command("cat /sys/bus/iio/devices/iio:device*/name")
        if b"ad9361-phy" not in names or b"cf-ad9361-lpc" not in names:
            raise RecoveryError("return_unverified", "expected IIO devices missing")
        self.console.command(
            "(for f in /sys/bus/iio/devices/iio:device*/buffer/enable; "
            'do test "$(cat $f)" = 0 || exit 1; done)'
        )
        self.console.command(
            "(for f in /sys/bus/iio/devices/iio:device*/out_altvoltage*_raw; "
            'do test ! -f $f || test "$(cat $f)" = 0 || exit 1; done)'
        )
        latest = self.store.latest("plan_ready")
        plan = Plan.model_validate_json(self.store.get(Blob.model_validate(latest.data["plan"])))
        expected = self.store.get(plan.expected if cold else plan.current)
        # The pinned DT names these three low-bank partitions. Their hashes bind
        # the running radio to its previously observed UID and preserved settings.
        labels = ("qspi-fsbl-uboot", "qspi-uboot-env", "qspi-nvmfs")
        regions = ("boot", "environment", "spare")
        table = self.console.command("cat /proc/mtd")
        for number, (label, region_name) in enumerate(zip(labels, regions, strict=True)):
            region = self.profile.geometry.region(region_name)
            if not re.search(
                rb"(?m)^mtd"
                + str(number).encode()
                + rb': [0-9a-f]+ [0-9a-f]+ "'
                + label.encode()
                + rb'"$',
                table,
            ):
                raise RecoveryError("return_unverified", "running MTD layout differs")
            out = self.console.command(f"sha256sum /dev/mtd{number}")
            want = digest(expected[region.start : region.end]).encode()
            if not re.search(rb"(?m)^" + want + rb"\s+", out):
                raise RecoveryError("return_unverified", "boot or preserved target settings differ")
        fit_sha256 = self._verify_cold_fit() if cold else self.profile.rollback.sha256
        self._log(b"network_context_sha256=" + digest(network_context()).encode() + b"\n")
        transcript = self.store.put(bytes(self.capture))
        self.capture.clear()
        return ReturnEvidence(
            target=self.target,
            fit_sha256=fit_sha256,
            firmware=self.profile.rollback.expected_firmware,
            layout=self.profile.rollback.expected_layout,
            network_ok=True,
            iio_ok=True,
            rf_inactive=True,
            settings_ok=True,
            boot_source="qspi" if cold else "ram",
            reset_cause="power_on" if cold else "warm",
            boot_epoch=uuid.uuid4().hex,
            transcript=transcript,
            operator_power_off=cold and self.operator_cold_actions,
            operator_sd_removed=cold and self.operator_cold_actions,
        )

    def _ram_boot(self, fit: bytes) -> ReturnEvidence:
        self.stage(fit)
        if self.wire is None or self.epoch is None:
            raise RecoveryError("target_unbound", "missing boot session")
        self._bank_zero()
        self.console.command(
            "setenv bootargs console=ttyPS0,115200 maxcpus=2 rootfstype=ramfs "
            f"root=/dev/ram0 rw rdinit=/bin/sh ppu_recovery={self.epoch}"
        )
        self.wire.write(f"bootm {self.ram:x}#{self.profile.rollback.configuration}\n".encode())
        self._wait((b"/ # ", b"~ # ", b"Please press Enter to activate this console"))
        self.wire.write(b"\n")
        self.console.command("test -r /proc/cmdline || mount -t proc proc /proc")
        self.console.command("test -d /sys/class || mount -t sysfs sysfs /sys")
        self.console.command(
            "grep -q ' /dev devtmpfs ' /proc/mounts || mount -t devtmpfs devtmpfs /dev"
        )
        self.console.command(
            "ifconfig lo up && ifconfig eth0 192.168.1.14 netmask 255.255.255.0 up"
        )
        # IIOD is a long-running foreground server.  Detach its standard streams
        # from the recovery console so Console.command can observe completion,
        # then prove the child survived startup before running the full PID and
        # read-only network-context checks in _runtime.
        self.console.command(
            "{ /usr/sbin/iiod -D </dev/null >/tmp/ppu-iiod.log 2>&1 & "
            "ppu_iiod_pid=$!; echo $ppu_iiod_pid >/tmp/ppu-iiod.pid; "
            "sleep 1; kill -0 $ppu_iiod_pid; }"
        )
        return self._runtime("ram")

    def await_sd_console(self) -> None:
        """Wait for the buffered fresh boot before transmitting any commands."""
        self._return_sd()

    def _return_sd(self) -> None:
        # The console-only bootstrap intentionally reaches an early U-Boot prompt
        # before importing uEnv.txt and restarting its final diagnostic console.
        # Require the marker first, then the prompt that follows it. Accepting the
        # early prompt would either reject a valid boot or send commands too soon.
        try:
            self._wait_sequence(
                (b"PPU_SD_CONSOLE_READY", b"Waiting at U-Boot for recovery inspection"),
                b"Pluto+> ",
                timeout=60,
            )
        except RecoveryError as error:
            if error.code != "boot_timeout" or self.wire is None:
                raise
            # A USB/UART reader can attach after the console-only script has
            # finished. Prompt once, then let _observe prove SD boot mode, exact
            # executing code and both pinned SD files before trusting the console.
            self.wire.write(b"\n")
            self._wait((b"Pluto+> ",), timeout=5)
        self.checked_boot = False
        self.epoch = None
        self.hasher.loaded = False

    def _cold_boot(self) -> ReturnEvidence:
        if not self.operator_cold_actions:
            raise RecoveryError(
                "operator_actions_required", "use guide to record the physical cold boot"
            )
        # Preserve the identity chain established before writes and inspect the normal boot.
        latest = self.store.latest("plan_ready")
        plan = Plan.model_validate_json(self.store.get(Blob.model_validate(latest.data["plan"])))
        self.target = plan.observation.target
        output = self._wait((b"login:", b"/ # ", b"~ # "), timeout=180)
        if b"login:" in output:
            if self.wire is None:
                raise RecoveryError("transport_closed", "UART lease required")
            self.wire.write(b"root\n")
            output = self._wait((b"Password:", b"/ # ", b"~ # "))
            if b"Password:" in output:
                import typer

                password = typer.prompt("Radio root password", hide_input=True)
                self.wire.write(password.encode() + b"\n")
                self._wait((b"/ # ", b"~ # "))
        return self._runtime("qspi", cold=True)

    def confirm_operator_cold_boot(self) -> None:
        self.operator_cold_actions = True
        self.store.record("operator_cold_boot", {"power_off": True, "sd_removed": True})
