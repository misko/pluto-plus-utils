from __future__ import annotations

import json
import os
import re
import subprocess
import sys

import pytest
from recovery_fakes import fixture
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.recovery import live, profiles
from pluto_plus.recovery.contracts import RecoveryError
from pluto_plus.recovery.live import Recipes, SdUbootBackend
from pluto_plus.recovery.sd import prepare_bundle, verify_bundle
from pluto_plus.recovery.store import Store
from pluto_plus.recovery.uboot import Console, SerialWire


class ScriptedWire:
    def __init__(
        self,
        body=b"SF: 65536 bytes @ 0x200000 Written: OK",
        *,
        chunks=1,
        echo_only=False,
        disconnect=False,
    ):
        self.body = body
        self.chunks = chunks
        self.echo_only = echo_only
        self.disconnect = disconnect
        self.sent = []
        self.pending = []
        self.time = 0.0

    def write(self, data):
        self.sent.append(data)
        begin = re.search(rb"PPU_BEGIN_[0-9a-f]+", data)[0]
        ok = re.search(rb"PPU_OK_[0-9a-f]+", data)[0]
        raw = b"stale prompt =>\r\n" + data
        if not self.echo_only:
            raw += begin + b"\r\n" + self.body + b"\r\n" + ok + b"\r\n=> "
        if isinstance(self.chunks, tuple):
            split = self.chunks[0]
            self.pending = [raw[:split], raw[split:]]
        else:
            self.pending = [raw[i : i + self.chunks] for i in range(0, len(raw), self.chunks)]

    def read(self, timeout):
        self.time += 0.001 if self.pending else timeout
        if self.disconnect:
            raise OSError("synthetic disconnect")
        return self.pending.pop(0) if self.pending else b""


@pytest.mark.parametrize("split", range(1, 300))
def test_sf_parses_every_fragment_boundary_and_ignores_echo_and_stale_prompt(split):
    wire = ScriptedWire(chunks=(split,))
    logs = []
    console = Console(wire, logs.append, monotonic=lambda: wire.time)
    console.sf("write", 0x200000, 65536, ram=0x8000000)
    assert len(wire.sent) == 1 and len(logs) == 1


@pytest.mark.parametrize(
    "body",
    [
        b"SF: 12 bytes @ 0x200000 Written: OK",
        b"SF: 65536 bytes @ 0 Written: OK",
        b"SF: 65536 bytes @ 0x200000 Written: ERROR 5",
        b"SPI flash failed in erase step",
        b"=>",
        b"sf write 8000000 200000 10000",
        b"SF: 65536 bytes @ 0x200000 Written: OK\nERROR late command failure",
    ],
)
def test_sf_errors_short_counts_and_prompt_are_not_success(body):
    wire = ScriptedWire(body)
    console = Console(wire, lambda _: None, monotonic=lambda: wire.time)
    with pytest.raises(RecoveryError):
        console.sf("write", 0x200000, 65536)
    count = len(wire.sent)
    with pytest.raises(RecoveryError, match="reconnect_required"):
        console.command("reset")
    assert len(wire.sent) == count


@pytest.mark.parametrize("fault", ["echo", "disconnect"])
def test_timeout_and_disconnect_poison_connection_without_next_command(fault):
    wire = ScriptedWire(echo_only=fault == "echo", disconnect=fault == "disconnect")
    console = Console(wire, lambda _: None, monotonic=lambda: wire.time)
    with pytest.raises((RecoveryError, OSError)):
        console.command("sf probe", timeout=0.2)
    with pytest.raises(RecoveryError, match="reconnect_required"):
        console.command("reset")
    assert len(wire.sent) == 1


def test_unsupported_serial_endpoint_fails_before_open(tmp_path):
    path = tmp_path / "ttyUSB0"
    path.write_bytes(b"untouched")
    with pytest.raises(RecoveryError, match="target_unbound"), SerialWire(path).lease():
        pytest.fail("unstable endpoint accepted")
    assert path.read_bytes() == b"untouched"


def test_sd_bundle_portable_verifier_and_corrupt_transfer(tmp_path):
    _, profile, *_ = fixture(tmp_path)
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "BOOT.BIN").write_bytes(b"synthetic-bootstrap")
    output = tmp_path / "bundle"
    receipt = prepare_bundle(profile, assets, output)
    verify_bundle(profile, output)
    result = subprocess.run(
        [sys.executable, str(output / "verify.py"), str(output)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert receipt in result.stdout
    (output / "BOOT.BIN").write_bytes(b"bad")
    with pytest.raises(RecoveryError, match="artifact_corrupt"):
        verify_bundle(profile, output)
    result = subprocess.run(
        [sys.executable, str(output / "verify.py"), str(output)], capture_output=True, text=True
    )
    assert result.returncode != 0


def test_sd_missing_conflicting_and_symlink_assets_fail(tmp_path):
    _, profile, *_ = fixture(tmp_path)
    assets = tmp_path / "assets"
    assets.mkdir()
    with pytest.raises(OSError):
        prepare_bundle(profile, assets, tmp_path / "missing")
    source = tmp_path / "source"
    source.write_bytes(b"synthetic-bootstrap")
    (assets / "BOOT.BIN").symlink_to(source)
    with pytest.raises(RecoveryError):
        prepare_bundle(profile, assets, tmp_path / "linked")
    (assets / "BOOT.BIN").unlink()
    (assets / "BOOT.BIN").write_bytes(b"synthetic-bootstrap")
    bundle = tmp_path / "bundle"
    prepare_bundle(profile, assets, bundle)
    (bundle / "boot.scr").write_bytes(b"unplanned boot script")
    with pytest.raises(RecoveryError, match="sd_files_conflict"):
        verify_bundle(profile, bundle)


def test_cli_offline_diagnostics_and_public_receipt_do_not_claim_qualified_backup(tmp_path):
    runner = CliRunner()
    session = tmp_path / "diagnostic"
    result = runner.invoke(
        app,
        [
            "firmware",
            "recover",
            "start",
            "--session",
            str(session),
            "--adapter",
            "explicit-physical-adapter",
        ],
    )
    assert result.exit_code == 0, result.output
    secret = tmp_path / "raw-flash.bin"
    secret.write_bytes(b"SYNTHETIC_PRIVATE_SECRET")
    result = runner.invoke(
        app,
        [
            "firmware",
            "recover",
            "import-evidence",
            "--session",
            str(session),
            "--file",
            str(secret),
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["verified_physical_backup"] is False
    result = runner.invoke(app, ["firmware", "recover", "capture", "--session", str(session)])
    assert result.exit_code == 2
    assert "profile_unqualified" in result.output
    assert Store(session).status()["state"] == "discovered"
    output = tmp_path / "receipt.json"
    result = runner.invoke(
        app, ["firmware", "recover", "export", "--session", str(session), "--output", str(output)]
    )
    assert result.exit_code == 0, result.output
    assert "SYNTHETIC_PRIVATE_SECRET" not in output.read_text()
    assert "explicit-physical-adapter" not in output.read_text()


def test_cli_cannot_enable_test_qualification_or_execute_via_flag(tmp_path):
    assert all(p.support == "incident" for p in profiles.PROFILES)
    runner = CliRunner()
    result = runner.invoke(app, ["firmware", "recover", "profiles"])
    assert [p["profile_id"] for p in json.loads(result.output)["profiles"]] == [
        "plutoplus-incident-114"
    ]
    result = runner.invoke(
        app,
        [
            "firmware",
            "recover",
            "start",
            "--session",
            str(tmp_path / "s"),
            "--adapter",
            "A",
            "--profile",
            "synthetic-test-only",
        ],
    )
    assert result.exit_code == 2 and "profile_unqualified" in result.output
    assert not (tmp_path / "s").exists()
    result = runner.invoke(app, ["firmware", "recover", "execute", "--force"])
    assert result.exit_code != 0


def test_pty_fragmented_serial_integration_without_hardware():
    # A real PTY exercises byte streaming, while no radio endpoint is opened.
    import select
    import threading
    import tty

    master, slave = os.openpty()
    tty.setraw(slave)

    class PtyWire:
        def write(self, data):
            os.write(slave, data)

        def read(self, timeout):
            ready, _, _ = select.select([slave], [], [], timeout)
            return os.read(slave, 8192) if ready else b""

    def radio():
        command = bytearray()
        while not command.endswith(b"\n"):
            ready, _, _ = select.select([master], [], [], 2)
            if not ready:
                return
            command.extend(os.read(master, 8192))
        begin = re.search(rb"PPU_BEGIN_[0-9a-f]+", command)[0]
        ok = re.search(rb"PPU_OK_[0-9a-f]+", command)[0]
        reply = begin + b"\r\nSF: 65536 bytes @ 0 Erased: OK\r\n" + ok + b"\r\n"
        for byte in reply:
            os.write(master, bytes([byte]))

    thread = threading.Thread(target=radio, daemon=True)
    thread.start()
    try:
        Console(PtyWire(), lambda _: None).sf("erase", 0, 65536)
        thread.join(timeout=3)
        assert not thread.is_alive()
    finally:
        os.close(master)
        os.close(slave)


def test_live_backend_readback_does_not_overwrite_staged_payload(tmp_path):
    _, profile, backend, *_ = fixture(tmp_path)
    payload = b"\xa7" * 65536

    class MemoryConsole:
        def __init__(self):
            self.memory_bytes = {}
            self.commands = []

        def command(self, command):
            self.commands.append(command)
            assert command.startswith("fatload ")
            self.memory_bytes[profile.capture_address] = payload
            return b"65536 bytes read in 10 ms"

        def memory(self, address, size):
            return self.memory_bytes[address][:size]

        def sf(self, operation, start, size, *, ram=0):
            self.commands.append(operation)
            if operation == "read":
                self.memory_bytes[ram] = bytes(backend.flash[start : start + size])
            elif operation == "erase":
                backend.flash[start : start + size] = b"\xff" * size
            elif operation == "write":
                backend.flash[start : start + size] = self.memory_bytes[ram][:size]

    console = MemoryConsole()
    recipes = Recipes(
        backend.observe,
        backend.ram_boot,
        backend.return_to_sd,
        backend.attest_cold_boot,
        backend.lease,
    )
    live = SdUbootBackend(console, profile, recipes)
    live.stage(payload)
    assert live.read(0x200000, 65536) != payload
    live.erase(0x200000, 65536)
    live.program(0x200000, 65536)
    assert bytes(backend.flash[0x200000:0x210000]) == payload
    with pytest.raises(RecoveryError):
        live.erase(0x200001, 65536)


def test_cli_full_workflow_with_explicitly_injected_test_registry(tmp_path, monkeypatch):
    store, profile, backend, _, boot, fit, provenance, history = fixture(tmp_path)
    monkeypatch.setattr(profiles, "PROFILES", (profile,))
    monkeypatch.setattr(live, "BACKENDS", {profile.profile_id: lambda *_: backend})
    runner = CliRunner()

    def run(command, *args):
        result = runner.invoke(
            app, ["firmware", "recover", command, "--session", str(store.root), *args]
        )
        assert result.exit_code == 0, result.output
        return json.loads(result.output)

    run("capture")
    for name, payload in (
        ("boot.bin", boot),
        ("rollback.fit", fit),
        ("provenance.json", provenance.model_dump_json().encode()),
        ("history.json", history),
    ):
        (tmp_path / name).write_bytes(payload)
    selected = run(
        "plan",
        "--boot",
        str(tmp_path / "boot.bin"),
        "--fit",
        str(tmp_path / "rollback.fit"),
        "--provenance",
        str(tmp_path / "provenance.json"),
        "--history",
        str(tmp_path / "history.json"),
    )
    staging = tmp_path / "ppu-repair"
    staged = run("stage-sd", "--output", str(staging))
    assert staging.with_name("ppu-repair.zip").is_file()
    assert staged["action"].endswith("MOUNT/ppu-repair")
    result = subprocess.run(
        [sys.executable, str(staging / "verify-repair.py"), str(staging)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert staged["manifest_sha256"] in result.stdout
    assert run("ram-test")["state"] == "ram_boot_verified"
    assert run("execute", "--confirm", selected["confirmation"])["state"] == "awaiting_cold_boot"
    assert run("attest")["state"] == "recovered"
    exported = tmp_path / "public.json"
    run("export", "--output", str(exported))
    public = json.loads(exported.read_text())
    assert public["repair"]["expected_flash"]["sha256"] == selected["expected_flash_sha256"]
    assert "SYNTHETIC_PRIVATE_SECRET" not in exported.read_text()
