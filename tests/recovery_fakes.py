"""Synthetic FDTs and independent physical NOR state for recovery tests only."""

from __future__ import annotations

import gzip
import hashlib
import struct
import zlib
from contextlib import contextmanager

from pluto_plus.recovery.contracts import (
    Blob,
    FitContract,
    Geometry,
    HistoricalBoot,
    Observation,
    Profile,
    Provenance,
    Region,
    ReturnEvidence,
    Session,
    Target,
    canonical,
    digest,
)
from pluto_plus.recovery.store import Store
from pluto_plus.recovery.workflow import Workflow


def fdt(tree, *, total_size=None):
    strings = bytearray()
    structure = bytearray()
    offsets = {}

    def u32(value):
        structure.extend(struct.pack(">I", value))

    def pad():
        structure.extend(b"\0" * (-len(structure) % 4))

    def node(name, properties, children):
        u32(1)
        structure.extend(name.encode() + b"\0")
        pad()
        for key, value in properties.items():
            if key not in offsets:
                offsets[key] = len(strings)
                strings.extend(key.encode() + b"\0")
            u32(3)
            u32(len(value))
            u32(offsets[key])
            structure.extend(value)
            pad()
        for child in children:
            node(*child)
        u32(2)

    node(*tree)
    u32(9)
    actual_size = 56 + len(structure) + len(strings)
    total_size = total_size or actual_size
    assert total_size >= actual_size
    header = struct.pack(
        ">10I",
        0xD00DFEED,
        total_size,
        56,
        56 + len(structure),
        40,
        17,
        16,
        0,
        len(strings),
        len(structure),
    )
    return (header + b"\0" * 16 + structure + strings).ljust(total_size, b"\0")


def fit_bytes(size=4096, *, wrong_hash=False, compression=b"none\0", config="config@0"):
    components = []
    for i, name in enumerate(("kernel@1", "fdt@1")):
        payload = bytes(range(128)) + name.encode()
        if compression == b"gzip\0":
            payload = gzip.compress(payload, mtime=0)
        hashed = hashlib.sha256(payload).digest()
        components.append(
            (
                name,
                {
                    "data": payload,
                    "compression": compression,
                    "load": struct.pack(">I", 0x2000000 + i * 0x100000),
                },
                [
                    (
                        "hash@1",
                        {"algo": b"sha256\0", "value": (b"\0" * 32 if wrong_hash else hashed)},
                        [],
                    )
                ],
            )
        )
    tree = (
        "",
        {"description": b"ITB PlutoSDR (ADALM-PLUTO)\0"},
        [
            ("images", {}, components),
            ("configurations", {}, [(config, {"kernel": b"kernel@1\0", "fdt": b"fdt@1\0"}, [])]),
        ],
    )
    return fdt(tree, total_size=size)


def environment(fit_size=b"E0FD6F"):
    payload = (
        b"bootcmd=synthetic-qspi\0secret=SYNTHETIC_PRIVATE_SECRET\0fit_size=" + fit_size + b"\0\0"
    ).ljust(0x20000 - 4, b"\xff")
    return zlib.crc32(payload).to_bytes(4, "little") + payload


class NorBackend:
    def __init__(self, store, profile, target, flash):
        self.store, self.profile, self.target = store, profile, target
        self.flash = bytearray(flash)
        self.events = []
        self.staged = None
        self.epoch = "sd-boot-1"
        self.writer = profile.writer_sha256
        self.fail = None
        self.operation_count = {}
        self.alias = False
        self.short_read = False
        self.corrupt_export = False
        self.ram_changes_flash = False
        self.return_changes = {}
        self.leased = False

    @contextmanager
    def lease(self):
        assert not self.leased
        self.leased = True
        try:
            yield
        finally:
            self.leased = False

    def point(self, operation, when):
        if when == "before":
            self.operation_count[operation] = self.operation_count.get(operation, 0) + 1
        count = self.operation_count[operation]
        self.events.append((operation, when, count))
        if self.fail == (operation, count, when):
            raise ConnectionError("synthetic interrupted response")

    def observe(self):
        self.point("observe", "before")
        result = Observation(
            target=self.target,
            geometry=self.profile.geometry,
            bootstrap_sha256=self.profile.bootstrap_sha256,
            writer_sha256=self.writer,
            boot_epoch=self.epoch,
            qualification_id=self.profile.qualification_id,
            transcript=self.store.put(b"synthetic private observation"),
            flash_protected=False,
        )
        self.point("observe", "after")
        return result

    def read(self, start, size):
        self.point("read", "before")
        if self.alias:
            chunks = []
            while size:
                offset = start % 0x1000000
                count = min(size, 0x1000000 - offset)
                chunks.append(bytes(self.flash[offset : offset + count]))
                start += count
                size -= count
            result = b"".join(chunks)
        else:
            result = bytes(self.flash[start : start + size])
        self.point("read", "after")
        return result[:-1] if self.short_read else result

    def export_and_reload(self, data):
        self.point("export", "before")
        exported = bytes(data[:-1] if self.corrupt_export else data)
        if exported != data:
            raise ValueError("synthetic corrupt SD export")
        self.point("export", "after")

    def stage(self, payload):
        self.point("stage", "before")
        self.staged = payload
        self.point("stage", "after")

    def erase(self, start, size):
        self.point("erase", "before")
        assert start % size == 0 and self.staged is not None and len(self.staged) == size
        self.flash[start : start + size // 2] = b"\xff" * (size // 2)
        self.point("erase", "during")
        self.flash[start + size // 2 : start + size] = b"\xff" * (size - size // 2)
        self.point("erase", "after")

    def program(self, start, size):
        self.point("program", "before")
        assert self.staged is not None and len(self.staged) == size
        old = self.flash[start : start + size]
        programmed = bytes(a & b for a, b in zip(old, self.staged, strict=True))
        self.flash[start : start + size // 2] = programmed[: size // 2]
        self.point("program", "during")
        self.flash[start + size // 2 : start + size] = programmed[size // 2 :]
        self.point("program", "after")

    def evidence(self, source):
        return ReturnEvidence(
            target=self.target,
            fit_sha256=self.profile.rollback.sha256,
            firmware=self.profile.rollback.expected_firmware,
            layout=self.profile.rollback.expected_layout,
            network_ok=True,
            iio_ok=True,
            rf_inactive=True,
            settings_ok=True,
            boot_source=source,
            reset_cause="power_on" if source == "qspi" else "warm",
            boot_epoch="cold-boot-3" if source == "qspi" else "ram-boot-2",
            transcript=self.store.put(b"synthetic bound boot transcript"),
            operator_power_off=source == "qspi",
            operator_sd_removed=source == "qspi",
        ).model_copy(update=self.return_changes)

    def ram_boot(self, fit):
        self.point("ram", "before")
        assert digest(fit) == self.profile.rollback.sha256
        if self.ram_changes_flash:
            self.flash[0x130000] ^= 1
        self.point("ram", "after")
        return self.evidence("ram")

    def return_to_sd(self):
        self.epoch = "sd-boot-2"

    def attest_cold_boot(self):
        return self.evidence("qspi")


def fixture(tmp_path, *, capacity=0x400000, fit_size=4096, incident=False, boot_erase=0x10000):
    fit = fit_bytes(fit_size)
    geometry = Geometry(
        capacity=capacity,
        regions=(
            Region(name="boot", start=0, size=0x100000, erase_size=boot_erase),
            Region(name="environment", start=0x100000, size=0x20000, erase_size=0x20000),
            Region(name="spare", start=0x120000, size=0xE0000, erase_size=0x10000),
            Region(name="fit", start=0x200000, size=capacity - 0x200000, erase_size=0x10000),
        ),
    )
    target = Target(
        adapter="synthetic-adapter-A",
        topology="synthetic-port-A",
        uid="UID_A",
        serial="SYNTHETIC_" + digest(str(tmp_path).encode())[:16],
        board="board-A",
        soc="Z7010",
        ddr_bytes=0x20000000,
        jedec="ef4019",
    )
    profile = Profile(
        profile_id="synthetic-test-only",
        qualification_id="synthetic-qualification",
        board=target.board,
        soc=target.soc,
        ddr_bytes=target.ddr_bytes,
        jedec=target.jedec,
        geometry=geometry,
        bootstrap_sha256="a" * 64,
        writer_sha256="b" * 64,
        read_limit=capacity,
        write_limit=min(capacity, 0x1000000),
        read_evidence="c" * 64,
        write_evidence="d" * 64,
        cold_boot_evidence="e" * 64,
        console_only_evidence="f" * 64,
        ram_recipe_evidence="1" * 64,
        capture_address=0x8000000,
        compare_address=0x10000000,
        wiring_instructions="Synthetic fixture only; no wiring instructions.",
        boot_instructions="Synthetic fixture only; no hardware qualification.",
        environment_format="uboot-single-le-crc32-128k",
        rollback=FitContract(
            sha256=digest(fit),
            size=len(fit),
            configuration="config@0",
            soc="Z7010",
            components=("kernel@1", "fdt@1"),
            ram_start=0x2000000,
            ram_end=0x4000000,
            expected_firmware="synthetic-working",
            expected_layout="synthetic-iio",
        ),
        sd_files={"BOOT.BIN": Blob(sha256=digest(b"synthetic-bootstrap"), size=19)},
    )
    flash = bytearray().join(bytes([i % 239]) * 0x10000 for i in range(capacity // 0x10000))
    boot = bytes(flash[:0x100000])
    flash[0x100000:0x120000] = environment()
    if incident:
        candidate = (bytes(range(256)) * ((0xE0FD6F + 255) // 256))[:0xE0FD6F]
        flash[0x200000:0x1000000] = candidate[:0xE00000]
        flash[:0xFD6F] = candidate[0xE00000:]
    else:
        flash[:0x10000] = b"\xf1" * 0x10000
    history = canonical(
        HistoricalBoot(
            target_uid=target.uid, boot_sha256=digest(boot), source_receipt_sha256="2" * 64
        )
    )
    provenance = Provenance(
        target_uid=target.uid,
        historical_boot_sha256=digest(boot),
        historical_record_sha256=digest(history),
        boot_source_sha256=digest(boot),
        rollback_sha256=digest(fit),
        boot_restore_start=0,
        boot_restore_size=0x10000,
    )
    store = Store.create(
        tmp_path / "session",
        Session(
            session_id="synthetic-session", adapter=target.adapter, profile_id=profile.profile_id
        ),
    )
    backend = NorBackend(store, profile, target, flash)
    return (
        store,
        profile,
        backend,
        Workflow(store, profile, backend),
        boot,
        fit,
        provenance,
        history,
    )


def prepared(tmp_path, **kwargs):
    values = fixture(tmp_path, **kwargs)
    store, _, _, workflow, boot, fit, provenance, history = values
    workflow.capture()
    plan = workflow.plan(boot, fit, provenance, history)
    return values, plan
