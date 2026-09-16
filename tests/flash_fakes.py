"""Synthetic NOR and transport; never contains device dumps or identifiers."""

from __future__ import annotations

import base64
import hashlib
import re
import zlib
from dataclasses import replace

from pluto_plus.flash_safety import (
    LEGACY_UPDATER_SHA256,
    FlashObservation,
    FlashPartition,
    decode_environment,
    validate_flash,
)
from pluto_plus.flash_safety_io import FLASH_COMMAND, OBSERVE_SCRIPT, observe_flash


def fit_bytes(size=96):
    body = bytearray(b"\x69" * size)
    body[:4] = b"\xd0\x0d\xfe\xed"
    body[4:8] = size.to_bytes(4, "big")
    body[40:66] = b"ITB PlutoSDR (ADALM-PLUTO)"
    return bytes(body)


def frm_bytes(size=96):
    fit = fit_bytes(size)
    return fit + hashlib.md5(fit, usedforsecurity=False).hexdigest().encode() + b"\n"


def environment(values=None):
    values = values or {b"fit_size": b"60", b"bootcmd": b"synthetic-boot"}
    payload = b"\0".join(key + b"=" + value for key, value in values.items()) + b"\0\0"
    payload = payload.ljust(0x20000 - 4, b"\xff")
    return zlib.crc32(payload).to_bytes(4, "little") + payload


class FlashMemoryTransport:
    def __init__(self, serial="SERIAL_A", fit=None):
        self.serial = serial
        self.flash = bytearray(b"\x55" * 0x2000000)
        self.flash[0x100000:0x120000] = environment()
        self.fit = fit or fit_bytes()
        self.flash[0x200000 : 0x200000 + len(self.fit)] = self.fit
        self.staged_fit = self.fit
        self.events = []
        self.scripts = []
        self.alias = False
        self.corrupt_boot = False
        self.corrupt_env = False
        self.fail_read = False
        self.locked = False
        self.boot_id = "boot-before"
        self.updater_output = "Done\n"
        self.on_update = None

    def report(self):
        return (
            f"serial={self.serial}\nboot_id={self.boot_id}\nkernel=test-kernel\n"
            f"board_identity={'e' * 64}\n"
            f"protected1={hashlib.sha256(self.flash[0x100000:0x120000]).hexdigest()}\n"
            f"protected2={hashlib.sha256(self.flash[0x120000:0x200000]).hexdigest()}\n"
            f"updater_sha256={LEGACY_UPDATER_SHA256}\ntools_sha256={'a' * 64}\n"
            f"environment_sha256={'b' * 64}\nflash_identity=winbond:w25q256:ef4019\n"
            "mtd0=qspi-fsbl-uboot:0:1048576:65536\n"
            "mtd1=qspi-uboot-env:1048576:131072:131072\n"
            "mtd2=qspi-nvmfs:1179648:917504:65536\n"
            "mtd3=qspi-linux:2097152:31457280:65536\ncapacity=33554432\n"
            f"boot_sha256={hashlib.sha256(self.flash[:0x100000]).hexdigest()}\n"
        )

    def read(self, physical, size):
        if self.alias:
            return bytes(self.flash[(physical + i) % 0x1000000] for i in range(size))
        return bytes(self.flash[physical : physical + size])

    def program(self, fit):
        if self.alias:
            for i, byte in enumerate(fit):
                self.flash[(0x200000 + i) % 0x1000000] = byte
        else:
            self.flash[0x200000 : 0x200000 + len(fit)] = fit
        env = decode_environment(bytes(self.flash[0x100000:0x120000]))
        env[b"fit_size"] = f"{len(fit):X}".encode()
        if self.corrupt_env:
            env[b"bootcmd"] = b"unexpected"
        self.flash[0x100000:0x120000] = environment(env)
        if self.corrupt_boot:
            self.flash[0] ^= 255

    def run(self, command, *, stdin=None, timeout_s=15):
        assert command == FLASH_COMMAND
        self.scripts.append(stdin)
        if stdin == OBSERVE_SCRIPT:
            self.events.append("observe")
            return self.report()
        script = (stdin or b"").decode()
        if "mkdir /tmp/ppu-physical-flash.lock" in script:
            if self.locked:
                raise RuntimeError("lock held")
            self.locked = True
            self.events.append("lock")
        elif "rmdir /tmp/ppu-physical-flash.lock" in script:
            self.locked = False
            self.events.append("unlock")
        elif match := re.search(r"set -- (\d+) /dev/mtd([0-3])", script):
            size, index = map(int, match.groups())
            self.events.append(f"read{index}")
            offset = (0, 0x100000, 0x120000, 0x200000)[index]
            data = self.read(offset, size)
            if self.fail_read:
                data = data[:-1]
            return base64.b64encode(data).decode()
        elif "/sbin/update_frm.sh " in script:
            self.events.append("update")
            if self.on_update is not None:
                self.on_update()
            self.program(self.staged_fit)
            return self.updater_output
        return ""


def decision(serial="SERIAL_A", fit=None):
    transport = FlashMemoryTransport(serial, fit)
    return validate_flash(observe_flash(transport), fit or fit_bytes())


def observation(serial="SERIAL_A") -> FlashObservation:
    return decision(serial).observation


def with_offset(observed, start):
    parts = (
        *observed.partitions[:2],
        FlashPartition(2, "qspi-nvmfs", 0x120000, start - 0x120000, 0x10000),
        FlashPartition(3, "qspi-linux", start, observed.capacity - start, 0x10000),
    )
    return replace(observed, partitions=parts)
