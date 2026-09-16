from __future__ import annotations

import hashlib
import zlib
from dataclasses import replace

import pytest
from flash_fakes import (
    FlashMemoryTransport,
    decision,
    environment,
    fit_bytes,
    frm_bytes,
    observation,
    with_offset,
)

from pluto_plus.firmware import validate_frm
from pluto_plus.flash_safety import (
    LEGACY_DUPLICATE_PREBOOT,
    FlashQualification,
    FlashSafetyError,
    decode_environment,
    require_same_flash,
    validate_flash,
    verify_protected,
)
from pluto_plus.flash_safety_io import FlashSession, observe_flash


@pytest.mark.parametrize(
    "size,allowed",
    [
        (12_935_447, True),
        (14_680_063, True),
        (14_680_064, True),
        (14_680_065, False),
        (14_744_943, False),
    ],
)
@pytest.mark.parametrize("vendor", ["winbond:w25q256:ef4019", "micron:n25q256:20ba19"])
def test_exact_incident_and_vendor_independent_boundary(size, allowed, vendor):
    observed = replace(observation(), flash_identity=vendor)
    fit = fit_bytes(size)
    if allowed:
        result = validate_flash(observed, fit)
        assert result.erase_end <= 0x1000000
    else:
        with pytest.raises(FlashSafetyError, match="flash_range_unqualified.*14680064"):
            validate_flash(observed, fit)


def test_offset_erase_rounding_and_frm_trailer():
    observed = with_offset(observation(), 0x300000)
    assert validate_flash(observed, fit_bytes(0xD00000)).payload_end == 0x1000000
    with pytest.raises(FlashSafetyError, match="flash_range_unqualified"):
        validate_flash(observed, fit_bytes(0xD00001))
    assert validate_flash(observation(), validate_frm(frm_bytes(0xE00000))).fit_size == 0xE00000


@pytest.mark.parametrize(
    "field,value",
    [
        ("start", -1),
        ("size", 0),
        ("size", 2**100),
        ("erase_size", 0),
        ("erase_size", True),
        ("start", 1),
    ],
)
def test_malformed_geometry_fails_closed(field, value):
    observed = observation()
    parts = (*observed.partitions[:3], replace(observed.partitions[3], **{field: value}))
    with pytest.raises(FlashSafetyError):
        validate_flash(replace(observed, partitions=parts), fit_bytes())


def test_partition_end_and_unknown_writer_identity():
    observed = observation()
    for changed in (
        replace(observed, serial=""),
        replace(observed, boot_id=""),
        replace(observed, updater_sha256="f" * 64),
        replace(observed, partitions=observed.partitions[:3]),
        replace(observed, capacity=0x1000000),
    ):
        with pytest.raises(FlashSafetyError):
            validate_flash(changed, fit_bytes())


@pytest.mark.parametrize("erase_size", [0x1000, 0x10000, 0x20000])
def test_environment_write_covers_all_its_actual_erase_blocks(erase_size):
    observed = observation()
    parts = tuple(
        replace(p, erase_size=erase_size) if p.index == 1 else p for p in observed.partitions
    )
    result = validate_flash(replace(observed, partitions=parts), fit_bytes())
    assert result.environment_start == 0x100000
    assert result.environment_end == 0x120000


def qualification(observed):
    return FlashQualification(
        "synthetic-test-only",
        observed.flash_identity,
        observed.kernel,
        observed.updater_sha256,
        observed.tools_sha256,
        observed.boot_sha256,
        observed.partitions,
        observed.capacity,
        observed.capacity,
        "c" * 64,
        "d" * 64,
        observed.board_identity,
    )


def test_qualification_requires_exact_write_and_boot_evidence():
    observed = observation()
    fit = fit_bytes(14_744_943)
    record = qualification(observed)
    accepted = validate_flash(observed, fit, qualifications=(record,))
    assert accepted.qualification_id == record.qualification_id
    for changed in (
        replace(record, flash_identity="different-chip"),
        replace(record, kernel="candidate-kernel"),
        replace(record, boot_sha256="e" * 64),
    ):
        with pytest.raises(FlashSafetyError, match="flash_range_unqualified"):
            validate_flash(observed, fit, qualifications=(changed,))
    with pytest.raises(FlashSafetyError, match="flash_qualification_invalid"):
        validate_flash(
            observed, fit, qualifications=(replace(record, cold_boot_evidence_sha256=""),)
        )


def test_payload_fits_but_erase_crosses_qualification():
    observed = observation()
    record = replace(qualification(observed), address_limit=0x1000001)
    with pytest.raises(FlashSafetyError, match="erase ends at 0x1010000"):
        validate_flash(observed, fit_bytes(0xE00001), qualifications=(record,))


@pytest.mark.parametrize(
    "field,value",
    [
        ("boot_id", "new-boot"),
        ("kernel", "new-kernel"),
        ("tools_sha256", "c" * 64),
        ("boot_sha256", "d" * 64),
        ("serial", "other-target"),
    ],
)
def test_stale_plan_rejected(field, value):
    planned = decision()
    fresh = validate_flash(replace(planned.observation, **{field: value}), fit_bytes())
    with pytest.raises(FlashSafetyError, match="flash_observation_changed"):
        require_same_flash(planned, fresh)
    with pytest.raises(FlashSafetyError):
        require_same_flash(None, fresh)


def test_synthetic_aliasing_passes_logical_fit_hash_but_damages_boot():
    memory = FlashMemoryTransport()
    before = {
        i: memory.read(offset, size)
        for i, offset, size in ((0, 0, 0x100000), (1, 0x100000, 0x20000), (2, 0x120000, 0xE0000))
    }
    fit = fit_bytes(14_744_943)
    memory.alias = True
    memory.program(fit)
    assert hashlib.sha256(memory.read(0x200000, len(fit))).digest() == hashlib.sha256(fit).digest()
    assert memory.flash[:64879] == fit[0xE00000:]
    after = {
        i: memory.read(offset, size)
        for i, offset, size in ((0, 0, 0x100000), (1, 0x100000, 0x20000), (2, 0x120000, 0xE0000))
    }
    with pytest.raises(FlashSafetyError, match="mtd0 changed"):
        verify_protected(before, after, len(fit))


@pytest.mark.parametrize("fault", [None, "boot", "environment", "short-read"])
def test_session_preserves_evidence_and_blocks_reboot_on_integrity_failure(tmp_path, fault):
    memory = FlashMemoryTransport()
    fit = fit_bytes()
    session = FlashSession(
        memory, validate_flash(observe_flash(memory), fit), fit, tmp_path / "backup"
    )
    session.prepare()
    assert (session.directory / "rollback.fit").read_bytes() == fit
    memory.corrupt_boot = fault == "boot"
    memory.corrupt_env = fault == "environment"
    session.invoke("/tmp/pluto-plus-utils/pluto.frm", hashlib.sha256(frm_bytes()).hexdigest())
    memory.fail_read = fault == "short-read"
    if fault:
        with pytest.raises(FlashSafetyError):
            session.verify()
        assert not session.verified
        assert not (session.directory / "integrity-verified.json").exists()
    else:
        session.verify()
        assert session.verified
    session.close()
    assert memory.locked  # cleared by reboot only; never unlock an uncertain write
    assert all(b"device_reboot" not in s for s in memory.scripts if s)


def test_session_rechecks_after_staging_and_cleans_only_prewrite_lock(tmp_path):
    memory = FlashMemoryTransport()
    fit = fit_bytes()
    session = FlashSession(
        memory, validate_flash(observe_flash(memory), fit), fit, tmp_path / "backup"
    )
    session.prepare()
    memory.boot_id = "changed-during-upload"
    with pytest.raises(FlashSafetyError, match="flash_observation_changed"):
        session.invoke("/tmp/pluto-plus-utils/pluto.frm", "a" * 64)
    session.close()
    assert not memory.locked
    assert "update" not in memory.events


def test_environment_crc_and_only_expected_change():
    before = {0: b"boot", 1: environment(), 2: b"spare"}
    values = decode_environment(before[1])
    values[b"fit_size"] = b"64"
    verify_protected(before, before | {1: environment(values)}, 100)
    with pytest.raises(FlashSafetyError, match="CRC"):
        decode_environment(before[1][:-1] + b"\x01")
    values[b"bootcmd"] = b"changed"
    with pytest.raises(FlashSafetyError):
        verify_protected(before, before | {1: environment(values)}, 100)


def test_exact_legacy_duplicate_preboot_is_one_way_normalized():
    duplicate = environment(
        {
            b"fit_size": b"60",
            b"preboot": b"",
            b"sentinel": b"unchanged",
        }
    )
    data = duplicate[4:]
    payload = data[: data.find(b"\0\0")].replace(
        b"preboot=\0sentinel=",
        b"preboot=\0preboot=" + LEGACY_DUPLICATE_PREBOOT + b"\0sentinel=",
    )
    payload = (payload + b"\0\0").ljust(0x20000 - 4, b"\xff")
    duplicate = zlib.crc32(payload).to_bytes(4, "little") + payload

    with pytest.raises(FlashSafetyError, match="duplicate environment key"):
        decode_environment(duplicate)
    assert (
        decode_environment(duplicate, allow_legacy_duplicate_preboot=True)[b"preboot"]
        == LEGACY_DUPLICATE_PREBOOT
    )

    normalized = environment(
        {
            b"fit_size": b"64",
            b"preboot": LEGACY_DUPLICATE_PREBOOT,
            b"sentinel": b"unchanged",
        }
    )
    verify_protected(
        {0: b"boot", 1: duplicate, 2: b"spare"},
        {0: b"boot", 1: normalized, 2: b"spare"},
        100,
    )


@pytest.mark.parametrize(
    "entries",
    [
        [b"preboot=" + LEGACY_DUPLICATE_PREBOOT, b"preboot="],
        [b"preboot=", b"sentinel=x", b"preboot=" + LEGACY_DUPLICATE_PREBOOT],
        [b"preboot=", b"preboot=changed"],
        [b"preboot=", b"preboot=" + LEGACY_DUPLICATE_PREBOOT, b"preboot=again"],
        [b"other=", b"other=value"],
    ],
)
def test_other_duplicate_environment_layouts_remain_rejected(entries):
    payload = (b"\0".join([b"fit_size=60", *entries]) + b"\0\0").ljust(0x20000 - 4, b"\xff")
    raw = zlib.crc32(payload).to_bytes(4, "little") + payload
    with pytest.raises(FlashSafetyError, match="duplicate environment key"):
        decode_environment(raw, allow_legacy_duplicate_preboot=True)


@pytest.mark.parametrize("change", [None, "report", "stage", "owner"])
def test_final_remote_shell_gate_rejects_changes_before_updater(tmp_path, change):
    """Execute the actual gate in a shell with isolated files and a fake observer."""
    import shlex
    import subprocess

    from pluto_plus.flash_safety_io import OBSERVE_SCRIPT

    class ShellGateTransport(FlashMemoryTransport):
        def run(self, command, *, stdin=None, timeout_s=15):
            if stdin and b"observe() {" in stdin:
                report = self.report()
                if change == "report":
                    report = report.replace("boot-before", "changed-after-host-check")
                script = stdin.replace(
                    OBSERVE_SCRIPT, f"printf '%s' {shlex.quote(report)}\n".encode()
                ).decode()
                script = script.replace("/tmp/ppu-physical-flash.lock", str(tmp_path / "lock"))
                script = script.replace("/tmp/pluto-plus-utils/pluto.frm", str(tmp_path / "stage"))
                script = script.replace("/sbin/update_frm.sh", f"sh {tmp_path / 'updater'}")
                result = subprocess.run(
                    ["sh", "-s"],
                    input=script,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if result.returncode:
                    raise RuntimeError("final remote guard rejected mutation")
                return result.stdout
            return super().run(command, stdin=stdin, timeout_s=timeout_s)

    memory = ShellGateTransport()
    fit = fit_bytes()
    session = FlashSession(
        memory, validate_flash(observe_flash(memory), fit), fit, tmp_path / "backup"
    )
    session.prepare()
    lock = tmp_path / "lock"
    lock.mkdir()
    (lock / "owner").write_text("wrong-owner" if change == "owner" else session.token)
    stage = tmp_path / "stage"
    stage.write_bytes(b"changed" if change == "stage" else frm_bytes())
    (tmp_path / "updater").write_text(f"touch {tmp_path / 'mutated'}\nprintf 'Done\\n'\n")
    if change:
        with pytest.raises(RuntimeError, match="final remote guard"):
            session.invoke(
                "/tmp/pluto-plus-utils/pluto.frm", hashlib.sha256(frm_bytes()).hexdigest()
            )
    else:
        assert (
            session.invoke(
                "/tmp/pluto-plus-utils/pluto.frm", hashlib.sha256(frm_bytes()).hexdigest()
            )
            == "Done\n"
        )
    assert (tmp_path / "mutated").exists() == (change is None)


def test_aliased_session_never_authorizes_reboot(tmp_path, monkeypatch):
    import pluto_plus.flash_safety as policy

    memory = FlashMemoryTransport()
    observed = observe_flash(memory)
    # Deliberately false test-only qualification exercises the independent second
    # defense. The production registry is empty and rejects before dispatch.
    monkeypatch.setattr(policy, "QUALIFICATIONS", (qualification(observed),))
    fit = fit_bytes(14_744_943)
    memory.staged_fit = fit
    memory.alias = True
    session = FlashSession(memory, validate_flash(observed, fit), fit, tmp_path / "backup")
    session.prepare()
    session.invoke("/tmp/pluto-plus-utils/pluto.frm", "a" * 64)
    with pytest.raises(FlashSafetyError, match="mtd0 changed"):
        session.verify()
    assert not session.verified
    assert memory.locked
    assert (session.directory / "integrity-observed.json").exists()


@pytest.mark.parametrize("alteration", ["duplicate", "missing", "negative", "extra", "short"])
def test_remote_observation_parser_fails_closed(alteration):
    memory = FlashMemoryTransport()
    report = memory.report()
    report = {
        "duplicate": report + "serial=another\n",
        "missing": report.replace("serial=SERIAL_A\n", ""),
        "negative": report.replace("2097152:31457280", "-1:31457280"),
        "extra": report + "qualified=true\n",
        "short": "",
    }[alteration]
    memory.run = lambda *args, **kwargs: report
    with pytest.raises(FlashSafetyError):
        observe_flash(memory)


@pytest.mark.parametrize("problem", [None, "short", "read-error", "encoder-error", "owner"])
def test_flash_reader_without_base64(tmp_path, problem):
    """Execute the production reader with only BusyBox's uuencode available."""
    import base64
    import os
    import shlex
    import shutil
    import subprocess

    from pluto_plus.flash_safety_io import FLASH_READ_SCRIPT

    # The optional prefix runs the released ARM BusyBox under qemu-user as well.
    prefix = shlex.split(os.environ.get("PPU_TEST_BUSYBOX", shutil.which("busybox") or ""))
    if not prefix:
        pytest.skip("BusyBox is required for the firmware shell regression")
    tools = tmp_path / "tools"
    tools.mkdir()
    for name in ("cat", "head", "wc", "rm", "sed", "uuencode"):
        executable = tools / name
        executable.write_text("#!/bin/sh\nexec " + shlex.join([*prefix, name]) + ' "$@"\n')
        executable.chmod(0o755)
    if problem == "read-error":
        (tools / "head").write_text("#!/bin/sh\nprintf 'abcd'\nexit 1\n")
    if problem == "encoder-error":
        (tools / "uuencode").write_text(
            "#!/bin/sh\nprintf 'begin-base64 644 -\\nYWJjZA==\\n====\\n'\nexit 1\n"
        )
    lock = tmp_path / "lock"
    lock.mkdir()
    (lock / "owner").write_text("wrong" if problem == "owner" else "token")
    device = tmp_path / "mtd"
    data = bytes(range(256)) * 257
    device.write_bytes(data[:-1] if problem == "short" else data)
    # Explicit paths prevent BusyBox's standalone applet lookup from bypassing
    # fault injection or finding the host's base64 outside the device inventory.
    script = FLASH_READ_SCRIPT.decode().replace("command -v base64", f"test -x {tools / 'base64'}")
    for name in ("cat", "head", "wc", "rm", "sed", "uuencode"):
        script = script.replace(name + " ", str(tools / name) + " ")
    result = subprocess.run(
        [*prefix, "sh", "-s", "--", str(len(data)), str(device), str(lock), "token"],
        input=script,
        text=True,
        capture_output=True,
        check=False,
        env=os.environ | {"PATH": str(tools)},
    )
    if problem is None:
        assert result.returncode == 0, result.stderr
        assert base64.b64decode("".join(result.stdout.split()), validate=True) == data
    else:
        assert result.returncode != 0
    assert not (lock / "read.bin").exists()


def test_reviewed_issue99_writer_preserves_conservative_limit():
    from pluto_plus.flash_writer import ISSUE99_TOOLS_SHA256S, ISSUE99_UPDATER_SHA256

    for tools_sha256 in ISSUE99_TOOLS_SHA256S:
        observed = replace(
            observation(), updater_sha256=ISSUE99_UPDATER_SHA256, tools_sha256=tools_sha256
        )
        assert validate_flash(observed, fit_bytes()).address_limit == 0x1000000
        with pytest.raises(FlashSafetyError, match="flash_range_unqualified"):
            validate_flash(observed, fit_bytes(0xE00001))
    with pytest.raises(FlashSafetyError, match="flash_writer_unknown"):
        validate_flash(replace(observed, tools_sha256="a" * 64), fit_bytes())


def test_each_writer_dependency_is_bound_to_the_reviewed_digest():
    from pluto_plus.flash_writer import (
        ISSUE99_FILES,
        ISSUE99_RELEASE_FILES,
        ISSUE99_RELEASE_TOOLS_SHA256,
        ISSUE99_TOOLS_SHA256,
        ISSUE99_UPDATER_SHA256,
    )

    def aggregate(items):
        return hashlib.sha256(
            "".join(f"{sha}  {path}\n" for path, sha in items).encode()
        ).hexdigest()

    assert aggregate(ISSUE99_FILES.items()) == ISSUE99_TOOLS_SHA256
    assert aggregate(ISSUE99_RELEASE_FILES.items()) == ISSUE99_RELEASE_TOOLS_SHA256
    observed = replace(observation(), updater_sha256=ISSUE99_UPDATER_SHA256)
    for path in ISSUE99_FILES:
        for changed in (dict(ISSUE99_FILES),):
            changed[path] = "0" * 64
            with pytest.raises(FlashSafetyError, match="flash_writer_unknown"):
                validate_flash(
                    replace(observed, tools_sha256=aggregate(changed.items())), fit_bytes()
                )
            del changed[path]
            with pytest.raises(FlashSafetyError, match="flash_writer_unknown"):
                validate_flash(
                    replace(observed, tools_sha256=aggregate(changed.items())), fit_bytes()
                )


def test_second_update_uses_new_writer_and_rejects_changed_helpers(tmp_path):
    from pluto_plus.flash_safety import LEGACY_UPDATER_SHA256
    from pluto_plus.flash_writer import ISSUE99_TOOLS_SHA256, ISSUE99_UPDATER_SHA256

    transport = FlashMemoryTransport()
    old_report = transport.report
    changed = False

    def report():
        return (
            old_report()
            .replace(LEGACY_UPDATER_SHA256, ISSUE99_UPDATER_SHA256)
            .replace(
                "tools_sha256=" + "a" * 64,
                "tools_sha256=" + ("b" * 64 if changed else ISSUE99_TOOLS_SHA256),
            )
        )

    transport.report = report
    fit = fit_bytes()
    session = FlashSession(
        transport, validate_flash(observe_flash(transport), fit), fit, tmp_path / "second-update"
    )
    session.prepare()
    changed = True
    with pytest.raises(FlashSafetyError, match="flash_writer_unknown"):
        session.invoke("/tmp/pluto-plus-utils/pluto.frm", hashlib.sha256(frm_bytes()).hexdigest())
    assert not session.dispatched
    changed = False
    session.invoke("/tmp/pluto-plus-utils/pluto.frm", hashlib.sha256(frm_bytes()).hexdigest())
    session.verify()
    assert session.verified


def test_reviewed_environment_ignores_inactive_tail_but_checks_crc_and_active_keys():
    import zlib

    raw = environment()
    data = bytearray(raw[4:])
    data[-64:-47] = b"old=inactive-key!"
    padded = zlib.crc32(data).to_bytes(4, "little") + data
    with pytest.raises(FlashSafetyError, match="encoding/padding"):
        decode_environment(padded)
    assert decode_environment(padded, opaque_padding=True) == decode_environment(raw)
    with pytest.raises(FlashSafetyError, match="size/CRC"):
        decode_environment(padded[:-1] + b"x", opaque_padding=True)
    before = {0: b"boot", 1: padded, 2: b"settings"}
    verify_protected(before, before, 96, opaque_padding=True)
    changed = before | {1: environment({b"fit_size": b"60", b"bootcmd": b"changed"})}
    with pytest.raises(FlashSafetyError, match="unexpected U-Boot"):
        verify_protected(before, changed, 96, opaque_padding=True)
