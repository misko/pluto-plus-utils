from __future__ import annotations

import ctypes
import hashlib
import queue
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from recovery_fakes import fixture
from test_sd_recovery_io import ScriptedWire

from pluto_plus.recovery import pluto_sd, profiles
from pluto_plus.recovery.contracts import Profile, RecoveryError, digest
from pluto_plus.recovery.pluto_sd import BufferedWire, PlutoSdBackend
from pluto_plus.recovery.ram_digest import CODE, RamDigest, helper_bytes
from pluto_plus.recovery.uboot import Console


def backend_fixture(tmp_path, monkeypatch, *, capacity=0x400000):
    values = fixture(tmp_path, capacity=capacity)
    store, old_profile, nor, workflow, *_ = values
    uid = "0123456789abcdef"
    profile = Profile.model_validate(
        old_profile.model_dump()
        | {
            "support": "incident",
            "original_flash_sha256": digest(bytes(nor.flash)),
            "target_uid_sha256": digest(uid.encode()),
            "cold_boot_evidence": None,
            "ram_recipe_evidence": None,
        }
    )
    kit = tmp_path / "kit"
    kit.mkdir()
    (kit / "original.bin").write_bytes(nor.flash)
    monkeypatch.setattr(pluto_sd, "kit_root", lambda: kit)
    backend = PlutoSdBackend(store, profile)
    memory = {}
    commands = []

    class ModelConsole:
        alias = False

        def command(self, command, **kwargs):
            commands.append(command)
            if command.startswith("sf probe"):
                return b"SF: Detected W25Q256"
            if command.startswith("sspi "):
                request = bytes.fromhex(command.split()[-1])
                opcode = request[0]
                if opcode == 0x13:
                    start = int.from_bytes(request[1:5], "big")
                    data = b"\0" * 5 + bytes(nor.flash[start : start + len(request) - 5])
                else:
                    replies = {
                        0x9F: bytes.fromhex("ef4019"),
                        0x15: b"\x60",
                        0x4B: bytes.fromhex(uid),
                        0x05: b"\0",
                        0x35: b"\x02",
                        0xC8: b"\0",
                    }
                    reply = replies[opcode]
                    data = bytes(len(request) - len(reply)) + reply
                return data.hex().upper().encode() + b"\n"
            if command.startswith("md.l "):
                address = int(command.split()[1], 16)
                value = {0xF8000258: 0x00480000, 0xF800025C: 5, 0xF8000530: 0x13722093}[address]
                return f"{address:08x}: {value:08x}    ....\n".encode()
            raise AssertionError(command)

        def sf(self, operation, start, size, *, ram=0):
            commands.append((operation, start, size, ram))
            assert operation == "read"
            if self.alias:
                memory[ram] = bytes(nor.flash[(start + i) % 0x1000000] for i in range(size))
            else:
                memory[ram] = bytes(nor.flash[start : start + size])

        def memory(self, address, size):
            for start, data in memory.items():
                if start <= address and address + size <= start + len(data):
                    return data[address - start : address - start + size]
            raise AssertionError((address, size))

    console = ModelConsole()
    backend.console = console

    class Hash:
        def sha256(self, address, size):
            return digest(console.memory(address, size))

    backend.hasher = Hash()
    return values, backend, console, commands


def test_incident_profile_is_not_a_general_hardware_grant():
    profile = profiles.get_profile("plutoplus-incident-114")
    assert profile.support == "incident"
    assert profile.target_uid_sha256 and profile.original_flash_sha256
    assert profile.write_limit == 0x1000000
    assert profile.cold_boot_evidence is None and profile.ram_recipe_evidence is None
    with pytest.raises(ValueError):
        Profile.model_validate(profile.model_dump() | {"support": "qualified"})
    with pytest.raises(ValueError):
        Profile.model_validate(profile.model_dump() | {"target_uid_sha256": None})


def test_identity_uses_word_accesses_and_factory_uid(tmp_path, monkeypatch):
    _, backend, _, commands = backend_fixture(tmp_path, monkeypatch)
    uid, reset, mode = backend._identity()
    assert uid == "0123456789abcdef" and reset == 0x480000 and mode == 5
    assert backend._register(0xF8000530) == 0x13722093
    assert all(not isinstance(c, str) or not c.startswith("md.b f800") for c in commands)
    assert backend._native(0x200000, 35) == bytes(backend.cache[0x200000:0x200023])
    backend.profile = backend.profile.model_copy(update={"target_uid_sha256": "0" * 64})
    with pytest.raises(RecoveryError, match="target_mismatch"):
        backend._identity()


def test_digest_checked_cache_rejects_unexplained_live_changes(tmp_path, monkeypatch):
    values, backend, _, _ = backend_fixture(tmp_path, monkeypatch)
    _, _, nor, *_ = values
    assert backend.read(0, len(nor.flash)) == bytes(nor.flash)
    nor.flash[0x234567] ^= 1
    with pytest.raises(RecoveryError, match="incident_image_mismatch"):
        backend.read(0, len(nor.flash))


def test_native_address_check_detects_sf_alias(tmp_path, monkeypatch):
    _, backend, console, _ = backend_fixture(tmp_path, monkeypatch, capacity=0x2000000)
    console.alias = True
    with pytest.raises(RecoveryError, match="physical_read_inconsistent"):
        backend.read(0, 0x2000000)


def test_interrupted_bytes_are_read_from_hardware_not_invented(tmp_path, monkeypatch):
    values, backend, console, commands = backend_fixture(tmp_path, monkeypatch)
    store, _, nor, *_ = values
    with store.lock():
        store.record("erase_intent", {"plan_sha256": "1" * 64})
    nor.flash[0x200000:0x208000] = b"\xff" * 0x8000
    assert backend.read(0, len(nor.flash)) == bytes(nor.flash)
    assert bytes(backend.cache) == bytes(nor.flash)
    assert any(isinstance(c, str) and c == "sf probe 0:0 50000000 0" for c in commands)


def test_register_ambiguous_response_refuses(tmp_path, monkeypatch):
    _, backend, console, _ = backend_fixture(tmp_path, monkeypatch)
    monkeypatch.setattr(
        console, "command", lambda *_: b"f8000530: 00000093    ....\nf8000530: 13722093    ....\n"
    )
    with pytest.raises(RecoveryError, match="command_unverified"):
        backend._register(0xF8000530)


def test_cpu_fault_stops_console_immediately_but_version_is_allowed():
    for body in [b"undefined instruction\nResetting CPU", b"DRAM:  ECC disabled 512 MiB"]:
        wire = ScriptedWire(body=body)
        console = Console(wire, lambda _: None, monotonic=lambda wire=wire: wire.time)
        with pytest.raises(RecoveryError, match="target_reset"):
            console.command("go 6000000")
        assert console.poisoned
    wire = ScriptedWire(body=b"U-Boot PlutoSDR build\n")
    assert b"U-Boot" in Console(
        wire, lambda _: None, monotonic=lambda wire=wire: wire.time
    ).command("version")


def test_ram_helper_flushes_data_cache_and_verifies_all_uploaded_bytes():
    commands = []
    memory = {}

    class Model:
        def command(self, command, **kwargs):
            commands.append(command)
            for part in command.split("; "):
                if part.startswith("mw.l "):
                    _, addr, val = part.split()
                    a = int(addr, 16)
                    v = int(val, 16).to_bytes(4, "little")
                    for i, b in enumerate(v):
                        memory[a + i] = b
            return b"## Application terminated, rc = 0x0"

        def memory(self, address, size):
            return bytes(memory.get(address + i, 0) for i in range(size))

    helper = RamDigest(Model())
    helper.install()
    assert commands[:2] == ["dcache off", "icache off"]
    assert commands[-1] == "icache on"
    assert helper.console.memory(CODE, len(helper_bytes())) == helper_bytes()
    with pytest.raises(RecoveryError, match="ram_unqualified"):
        helper.sha256(0xF8000258, 4)


def test_background_capture_retains_boot_output_during_operator_wait():
    data = queue.Queue()
    received = []

    class Source:
        def read(self, timeout):
            try:
                return data.get(timeout=timeout)
            except queue.Empty:
                return b""

        def write(self, b):
            received.append(b)

    logged = []
    wire = BufferedWire(Source(), logged.append)
    try:
        data.put(b"boot banner\n")
        data.put(b"PPU_SD_CONSOLE_READY\n")
        assert wire.read(1) == b"boot banner\n"
        assert wire.read(1) == b"PPU_SD_CONSOLE_READY\n"
        assert b"".join(logged) == b"boot banner\nPPU_SD_CONSOLE_READY\n"
        wire.write(b"command\n")
        assert received == [b"command\n"]
    finally:
        wire.close()
    assert not wire.thread.is_alive()


def test_background_capture_is_bounded_by_bytes_not_fragment_count():
    data = queue.Queue()

    class Source:
        def read(self, timeout):
            try:
                return data.get(timeout=timeout)
            except queue.Empty:
                return b""

        def write(self, value):
            pass

    for _ in range(3000):
        data.put(b"x")
    wire = BufferedWire(Source(), lambda value: None)
    try:
        assert b"".join(wire.read(1) for _ in range(3000)) == b"x" * 3000
        assert not wire.stop.is_set()
    finally:
        wire.close()


def test_background_capture_reports_byte_overflow():
    data = queue.Queue()

    class Source:
        def read(self, timeout):
            try:
                return data.get(timeout=timeout)
            except queue.Empty:
                return b""

        def write(self, value):
            pass

    wire = BufferedWire(Source(), lambda value: None)
    wire.MAX_PENDING_BYTES = 4
    try:
        data.put(b"12345")
        with pytest.raises(RecoveryError, match="UART capture failed") as error:
            wire.read(1)
        assert isinstance(error.value.__cause__, RecoveryError)
        assert error.value.__cause__.code == "transport_overflow"
    finally:
        wire.close()


def test_failed_uart_log_stops_commands():
    class Source:
        def read(self, timeout):
            return b"boot"

        def write(self, data):
            pytest.fail("must not transmit after capture failure")

    def fail(_):
        raise OSError("disk full")

    wire = BufferedWire(Source(), fail)
    try:
        with pytest.raises(RecoveryError, match="transport_disconnected"):
            wire.read(1)
        with pytest.raises(RecoveryError, match="transport_disconnected"):
            wire.write(b"command")
    finally:
        wire.close()


def test_cold_boot_needs_separate_operator_record(tmp_path, monkeypatch):
    values, backend, _, _ = backend_fixture(tmp_path, monkeypatch)
    with pytest.raises(RecoveryError, match="operator_actions_required"):
        backend._cold_boot()
    with values[0].lock():
        backend.confirm_operator_cold_boot()
    assert values[0].latest("operator_cold_boot").data == {"power_off": True, "sd_removed": True}


def test_cold_boot_prompts_an_already_running_console(tmp_path, monkeypatch):
    _, backend, _, _ = backend_fixture(tmp_path, monkeypatch)
    backend.operator_cold_actions = True
    monkeypatch.setattr(
        backend.store,
        "latest",
        lambda kind: SimpleNamespace(data={"plan": {"sha256": "0" * 64, "size": 2}}),
    )
    monkeypatch.setattr(backend.store, "get", lambda blob: b"{}")
    monkeypatch.setattr(
        pluto_sd.Plan,
        "model_validate_json",
        classmethod(
            lambda cls, value: SimpleNamespace(
                observation=SimpleNamespace(target=SimpleNamespace())
            )
        ),
    )

    class Wire:
        writes = []

        def write(self, data):
            self.writes.append(data)

    wire = Wire()
    backend.wire = wire
    replies = iter((b"login:", b"Password:", b"\n# "))
    monkeypatch.setattr(backend, "_wait", lambda *args, **kwargs: next(replies))
    monkeypatch.setattr("typer.prompt", lambda *args, **kwargs: "analog")
    expected = object()
    monkeypatch.setattr(backend, "_runtime", lambda *args, **kwargs: expected)

    assert backend._cold_boot() is expected
    assert wire.writes == [b"\n", b"root\n", b"analog\n"]


def test_native_sha256_helper_matches_standard_vectors(tmp_path):
    compiler = shutil.which("gcc")
    if compiler is None:
        pytest.skip("native C compiler unavailable")
    source = Path(pluto_sd.__file__).parent / "assets/sha256_ram.c"
    library = tmp_path / "sha.so"
    subprocess.run(
        [compiler, "-shared", "-fPIC", "-O2", "-DPPU_HOST_TEST", str(source), "-o", str(library)],
        check=True,
    )
    native = ctypes.CDLL(str(library))
    native.ppu_sha256.argtypes = [ctypes.c_void_p, ctypes.c_uint, ctypes.c_void_p]
    for size in [0, 1, 3, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4096, 65536, 33554432]:
        data = (bytes(range(256)) * ((size + 255) // 256))[:size]
        output = ctypes.create_string_buffer(32)
        native.ppu_sha256(data, size, output)
        assert output.raw == hashlib.sha256(data).digest()


def test_legacy_fit_needs_strong_component_pins(tmp_path):
    from recovery_fakes import fdt

    from pluto_plus.recovery.fit import validate_fit

    values = fixture(tmp_path)
    contract = values[1].rollback
    kernel = b"kernel bytes"
    dt = b"device tree bytes"
    tree = (
        "",
        {},
        [
            (
                "images",
                {},
                [
                    (
                        "kernel@1",
                        {"data": kernel, "compression": b"none\0"},
                        [
                            (
                                "hash@1",
                                {
                                    "algo": b"md5\0",
                                    "value": hashlib.md5(kernel, usedforsecurity=False).digest(),
                                },
                                [],
                            )
                        ],
                    ),
                    ("fdt@1", {"data": dt, "compression": b"none\0"}, []),
                ],
            ),
            (
                "configurations",
                {},
                [("config@0", {"kernel": b"kernel@1\0", "fdt": b"fdt@1\0"}, [])],
            ),
        ],
    )
    data = fdt(tree, total_size=4096)
    pinned = contract.model_copy(
        update={
            "sha256": digest(data),
            "size": len(data),
            "component_sha256": {"kernel@1": digest(kernel), "fdt@1": digest(dt)},
        }
    )
    validate_fit(data, pinned, "Z7010")
    with pytest.raises(RecoveryError, match="fit_invalid"):
        validate_fit(data, pinned.model_copy(update={"component_sha256": {}}), "Z7010")
    with pytest.raises(RecoveryError, match="fit_invalid"):
        validate_fit(
            data,
            pinned.model_copy(
                update={"component_sha256": {"kernel@1": digest(kernel), "fdt@1": "0" * 64}}
            ),
            "Z7010",
        )


def test_pinned_environment_preserves_opaque_padding_and_offsets():
    import zlib

    from recovery_fakes import environment

    from pluto_plus.flash_safety import FlashSafetyError
    from pluto_plus.recovery.planner import environment_with_fit_size

    raw = environment()
    body = bytearray(raw[4:])
    end = body.index(b"\0\0") + 2
    body[end + 15 : end + 19] = b"old!"
    raw = zlib.crc32(body).to_bytes(4, "little") + body
    with pytest.raises(FlashSafetyError):
        environment_with_fit_size(raw, 0xC56117)
    result = environment_with_fit_size(raw, 0xC56117, opaque_padding=True)
    assert result[4 + end :] == raw[4 + end :]
    expected = bytes(body).replace(b"fit_size=E0FD6F", b"fit_size=C56117")
    assert result[4:] == expected
    assert int.from_bytes(result[:4], "little") == zlib.crc32(expected)
    with pytest.raises(RecoveryError, match="environment_unknown"):
        environment_with_fit_size(raw, 4096, opaque_padding=True)
    with pytest.raises(RecoveryError, match="environment_unknown"):
        environment_with_fit_size(b"bad!" + raw[4:], 0xC56117, opaque_padding=True)


@pytest.mark.parametrize(
    "kind", ["valid", "short", "negative", "oversize", "wrong_devices", "entity"]
)
def test_network_context_is_bounded_and_read_only(monkeypatch, kind):
    import io

    good = b'<context><device name="ad9361-phy"/><device name="cf-ad9361-lpc"/></context>'
    payload = good
    if kind == "wrong_devices":
        payload = b'<context><device name="another-radio"/></context>'
    if kind == "entity":
        payload = b'<!ENTITY x "expansion"><context/>'
    data = str(len(payload)).encode() + b"\n" + payload
    if kind == "short":
        data = data[:-5]
    if kind == "negative":
        data = b"-1\n"
    if kind == "oversize":
        data = b"1048577\n"

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def sendall(self, value):
            assert value == b"PRINT\n"

        def makefile(self, mode):
            assert mode == "rb"
            return io.BytesIO(data)

    def connect(address, timeout):
        assert address == ("192.168.1.14", 30431) and timeout == 5
        return Connection()

    monkeypatch.setattr(pluto_sd.socket, "create_connection", connect)
    if kind == "valid":
        assert pluto_sd.network_context() == good
    else:
        with pytest.raises(RecoveryError, match="network_unverified"):
            pluto_sd.network_context()


def test_incident_missing_kit_has_actionable_error(tmp_path, monkeypatch):
    store, profile, *_ = fixture(tmp_path)
    monkeypatch.setattr(pluto_sd, "kit_root", lambda: tmp_path / "absent")
    with pytest.raises(RecoveryError, match="incident_kit_missing"):
        PlutoSdBackend(store, profile)


def test_sd_boot_waits_for_marker_and_full_console_before_commands(tmp_path, monkeypatch):
    _, backend, _, _ = backend_fixture(tmp_path, monkeypatch)
    seen = []

    def wait_sequence(first, second, **kwargs):
        seen.append((first, second))
        return b"early Pluto+> PPU_SD_CONSOLE_READY final Pluto+> "

    monkeypatch.setattr(backend, "_wait_sequence", wait_sequence)
    backend.checked_boot = True
    backend.epoch = "old"
    backend.hasher.loaded = True
    backend.await_sd_console()
    assert seen == [
        (
            (b"PPU_SD_CONSOLE_READY", b"Waiting at U-Boot for recovery inspection"),
            b"Pluto+> ",
        )
    ]
    assert not backend.checked_boot and not backend.hasher.loaded and backend.epoch is None


def test_ordered_boot_wait_ignores_prompt_before_marker(tmp_path, monkeypatch):
    _, backend, _, _ = backend_fixture(tmp_path, monkeypatch)

    class Wire:
        chunks = [b"early Pluto+> ", b"PPU_SD_CONSOLE_READY final Pluto+> "]

        def read(self, timeout):
            return self.chunks.pop(0) if self.chunks else b""

    backend.wire = Wire()
    output = backend._wait_sequence(b"PPU_SD_CONSOLE_READY", b"Pluto+> ", timeout=1)
    assert output == b"early Pluto+> PPU_SD_CONSOLE_READY final Pluto+> "


def test_ordered_boot_wait_accepts_exact_recovery_tail(tmp_path, monkeypatch):
    _, backend, _, _ = backend_fixture(tmp_path, monkeypatch)

    class Wire:
        chunks = [b"Waiting at U-Boot for recovery inspection\r\nPluto+> "]

        def read(self, timeout):
            return self.chunks.pop(0) if self.chunks else b""

    backend.wire = Wire()
    output = backend._wait_sequence(
        (b"PPU_SD_CONSOLE_READY", b"Waiting at U-Boot for recovery inspection"),
        b"Pluto+> ",
        timeout=1,
    )
    assert output.endswith(b"Pluto+> ")


def test_sd_console_prompts_once_when_uart_attaches_after_boot(tmp_path, monkeypatch):
    _, backend, _, _ = backend_fixture(tmp_path, monkeypatch)

    class Wire:
        writes = []

        def write(self, data):
            self.writes.append(data)

    wire = Wire()
    backend.wire = wire
    monkeypatch.setattr(
        backend,
        "_wait_sequence",
        lambda *args, **kwargs: (_ for _ in ()).throw(RecoveryError("boot_timeout", "late")),
    )
    waits = []
    monkeypatch.setattr(
        backend, "_wait", lambda patterns, timeout: waits.append((patterns, timeout))
    )
    backend._return_sd()
    assert wire.writes == [b"\n"]
    assert waits == [((b"Pluto+> ",), 5)]


def test_ram_boot_uses_initramfs_rdinit_and_detaches_iiod(tmp_path, monkeypatch):
    _, backend, console, commands = backend_fixture(tmp_path, monkeypatch)

    def command(value, **kwargs):
        commands.append(value)
        return b""

    console.command = command

    class Wire:
        def write(self, data):
            pass

    backend.wire = Wire()
    backend.epoch = "1" * 32
    monkeypatch.setattr(backend, "stage", lambda payload: None)
    monkeypatch.setattr(backend, "_bank_zero", lambda: None)
    monkeypatch.setattr(backend, "_wait", lambda patterns: b"/ # ")
    expected = object()
    monkeypatch.setattr(backend, "_runtime", lambda source: expected)
    assert backend._ram_boot(b"fit") is expected
    bootargs = next(command for command in commands if command.startswith("setenv bootargs"))
    assert "rdinit=/bin/sh" in bootargs
    assert " init=/bin/sh" not in bootargs
    iiod = next(command for command in commands if "/usr/sbin/iiod" in command)
    assert "</dev/null >/tmp/ppu-iiod.log 2>&1 &" in iiod
    assert "ppu_iiod_pid=$!" in iiod
    assert "kill -0 $ppu_iiod_pid" in iiod


@pytest.mark.parametrize("case", ["valid", "changed_fit", "short_read", "wrong_geometry"])
def test_cold_acceptance_reads_actual_fit_before_recording_recovered(tmp_path, monkeypatch, case):
    import json
    from contextlib import nullcontext
    from importlib.resources import files

    values, backend, console, commands = backend_fixture(tmp_path, monkeypatch)
    store, _, nor, workflow, boot, fit, provenance, history = values
    workflow.capture()
    plan = workflow.plan(boot, fit, provenance, history)
    workflow.ram_test()
    workflow.execute(f"RECOVER {plan.session_id} {plan.sha256}")
    assert store.status()["state"] == "awaiting_cold_boot"
    if case == "changed_fit":
        nor.flash[0x200000 + len(fit) - 1] ^= 1
    pins = json.loads(files("pluto_plus.recovery").joinpath(
        "assets/incident114-runtime.json"
    ).read_text())
    labels = ("qspi-fsbl-uboot", "qspi-uboot-env", "qspi-nvmfs", "qspi-linux")

    def command(text, **kwargs):
        commands.append(text)
        if text == "cat /proc/version":
            return pins["kernel_version"].encode()
        if text.startswith('test "$(wc -c </'):
            name = text.rsplit("/", 1)[-1]
            claim = next(v for k, v in pins.items() if k.endswith("/" + name))
            return claim["sha256"].encode() + b"  /" + name.encode()
        if text.startswith("devmem "):
            return b"0x00400000\n0x00000001"
        if text == "cat /sys/bus/iio/devices/iio:device*/name":
            return b"ad9361-phy\ncf-ad9361-lpc"
        if text == "cat /proc/mtd":
            return "\n".join(
                f'mtd{i}: {r.size:08x} {r.erase_size:08x} "{label}"'
                for i, (r, label) in enumerate(
                    zip(backend.profile.geometry.regions, labels, strict=True)
                )
            ).encode()
        if text.startswith("sha256sum /dev/mtd"):
            region = backend.profile.geometry.regions[int(text[-1])]
            return digest(bytes(nor.flash[region.start:region.end])).encode() + b"  /dev/mtd"
        if text.startswith('test "$(cat /sys/class/mtd/mtd3/offset)"'):
            if case == "wrong_geometry":
                raise RecoveryError("command_failed", "observed offset differs")
            return b""
        if text == f"head -c {len(fit)} /dev/mtd3 | sha256sum":
            size = len(fit) - (1 if case == "short_read" else 0)
            return digest(bytes(nor.flash[0x200000:0x200000 + size])).encode() + b"  -"
        if text.startswith(("(for ", "ip -4 ", "pidof ")):
            return b""
        raise AssertionError(text)

    monkeypatch.setattr(console, "command", command)
    monkeypatch.setattr(backend, "lease", nullcontext)
    monkeypatch.setattr(backend, "_wait", lambda *a, **kw: b"/ # ")
    monkeypatch.setattr(pluto_sd, "network_context", lambda: b"synthetic verified context")
    backend.operator_cold_actions = True
    workflow._backend = backend
    if case == "valid":
        evidence = workflow.attest()
        assert evidence.fit_sha256 == digest(fit)
        assert store.status()["state"] == "recovered"
    else:
        with pytest.raises(RecoveryError, match="command_failed|return_unverified"):
            workflow.attest()
        assert store.status()["state"] == "awaiting_cold_boot"
        assert not any(event.kind == "recovered" for event in store.events())
    if case != "wrong_geometry":
        assert f"head -c {len(fit)} /dev/mtd3 | sha256sum" in commands
    assert "sha256sum /dev/mtd3" not in commands


def test_cold_fit_read_refuses_upper_bank_before_console_io(tmp_path, monkeypatch):
    _, backend, _, commands = backend_fixture(tmp_path, monkeypatch, capacity=0x2000000)
    backend.profile = backend.profile.model_copy(update={
        "rollback": backend.profile.rollback.model_copy(update={"size": 0xE00001}),
    })
    with pytest.raises(RecoveryError, match="flash_range_unqualified"):
        backend._verify_cold_fit()
    assert commands == []
