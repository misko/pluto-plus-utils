from __future__ import annotations

import json

import pytest
from recovery_fakes import environment, fit_bytes, fixture, prepared

from pluto_plus.flash_safety import (
    LEGACY_UPDATER_SHA256,
    FlashObservation,
    FlashPartition,
    decode_environment,
    validate_flash,
)
from pluto_plus.recovery.contracts import Blob, RecoveryError, canonical, digest
from pluto_plus.recovery.fit import nodes, validate_fit
from pluto_plus.recovery.planner import build_plan, environment_with_fit_size, validate_plan
from pluto_plus.recovery.profiles import get_profile
from pluto_plus.recovery.store import Store
from pluto_plus.recovery.workflow import Workflow


def confirm(plan):
    return f"RECOVER {plan.session_id} {plan.sha256}"


@pytest.mark.parametrize("boot_erase", [0x10000, 0x20000])
def test_exact_incident_reconstruction_preserves_unrelated_bytes(tmp_path, boot_erase):
    values, plan = prepared(
        tmp_path, capacity=0x2000000, fit_size=0xC56117, incident=True, boot_erase=boot_erase
    )
    store, profile, backend, _, boot, fit, _, _ = values
    before = store.get(plan.original)
    expected = store.get(plan.expected)
    assert before[:64879] == (bytes(range(256)) * 254)[:64879]
    oracle = bytearray(before)
    oracle[:0x10000] = boot[:0x10000]
    oracle[0x100000:0x120000] = environment_with_fit_size(before[0x100000:0x120000], len(fit))
    oracle[0x200000:0xE56117] = fit
    assert expected == oracle
    assert expected[0xE56117:] == before[0xE56117:]
    assert expected[:0x100000] == boot
    assert [s.start for s in plan.sectors if s.kind == "boot"] == [0]
    assert next(s.size for s in plan.sectors if s.kind == "boot") == boot_erase
    validate_plan(plan, profile, store.get)
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


def test_full_workflow_has_distinct_ram_flash_and_cold_boot_states(tmp_path):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    before = bytes(backend.flash)
    assert store.status()["state"] == "plan_ready"
    workflow.ram_test()
    assert bytes(backend.flash) == before
    assert store.status()["state"] == "ram_boot_verified"
    workflow.execute(confirm(plan))
    assert store.status()["state"] == "awaiting_cold_boot"
    assert bytes(backend.flash) == store.get(plan.expected)
    assert [s.kind for s in plan.sectors] == ["fit", "environment", "boot"]
    workflow.attest()
    assert Store(store.root).status()["state"] == "recovered"
    assert store.latest("recovered").data["linux_extended_writes_qualified"] is False
    assert store.get(plan.original) == before


@pytest.mark.parametrize("operation", ["erase", "program"])
@pytest.mark.parametrize("when", ["before", "during", "after"])
@pytest.mark.parametrize("sector_number", [1, 2, 3])
def test_interrupt_each_mutation_boundary_and_resume_from_bytes(
    tmp_path,
    operation,
    when,
    sector_number,
):
    values, plan = prepared(tmp_path)
    store, profile, backend, workflow, *_ = values
    workflow.ram_test()
    backend.fail = (operation, sector_number, when)
    with pytest.raises(ConnectionError):
        workflow.execute(confirm(plan))
    assert store.status()["state"] == "interrupted"
    assert not any(e.kind == "awaiting_cold_boot" for e in store.events())
    original = store.get(plan.original)
    backend.fail = None
    resumed = Workflow(Store(store.root), profile, backend)
    successor = resumed.resume()
    assert successor.parent_plan == plan.sha256
    assert successor.current.sha256 == digest(bytes(backend.flash))
    assert store.get(plan.original) == original
    assert store.status()["state"] == "plan_ready"
    with pytest.raises(RecoveryError, match="ram_test_required"):
        resumed.execute(confirm(successor))
    resumed.ram_test()
    resumed.execute(confirm(successor))
    assert bytes(backend.flash) == store.get(plan.expected)


@pytest.mark.parametrize(
    "event",
    [
        "erase_completed",
        "program_intent",
        "sector_verified",
        "flash_verified",
        "awaiting_cold_boot",
    ],
)
def test_storage_loss_after_dispatch_stays_uncertain(tmp_path, monkeypatch, event):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    workflow.ram_test()
    original = store.record

    def fail(kind, data=None):
        if kind == event:
            raise OSError("synthetic fsync failure")
        return original(kind, data)

    monkeypatch.setattr(store, "record", fail)
    with pytest.raises(OSError):
        workflow.execute(confirm(plan))
    assert store.status()["state"] == "interrupted"
    assert not any(e.kind == "recovered" for e in store.events())
    assert bytes(backend.flash) != b""


@pytest.mark.parametrize("change", ["uid", "adapter", "topology", "writer", "off-plan"])
def test_resume_rejects_swapped_hardware_and_unexplained_changes(tmp_path, change):
    values, plan = prepared(tmp_path)
    _, _, backend, workflow, *_ = values
    workflow.ram_test()
    backend.fail = ("program", 1, "before")
    with pytest.raises(ConnectionError):
        workflow.execute(confirm(plan))
    backend.fail = None
    previous = len(backend.events)
    if change == "writer":
        backend.writer = "f" * 64
    elif change == "off-plan":
        backend.flash[0x180000] ^= 1
    else:
        backend.target = backend.target.model_copy(update={change: "different"})
    with pytest.raises(RecoveryError):
        workflow.resume()
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events[previous:])


@pytest.mark.parametrize(
    "changed",
    [
        {"boot_source": "sd"},
        {"boot_source": "ram"},
        {"reset_cause": "warm"},
        {"operator_power_off": False},
        {"operator_sd_removed": False},
        {"iio_ok": False},
        {"network_ok": False},
        {"rf_inactive": False},
        {"settings_ok": False},
        {"firmware": "wrong"},
        {"fit_sha256": "0" * 64},
    ],
)
def test_ram_pass_and_flash_pass_cannot_mask_failed_cold_acceptance(tmp_path, changed):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    workflow.ram_test()
    workflow.execute(confirm(plan))
    backend.return_changes = changed
    with pytest.raises(RecoveryError):
        workflow.attest()
    assert store.status()["state"] == "awaiting_cold_boot"
    assert not any(e.kind == "recovered" for e in store.events())


def test_ram_hidden_environment_write_blocks_persistence(tmp_path):
    values, _ = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    backend.ram_changes_flash = True
    with pytest.raises(RecoveryError, match="plan_stale"):
        workflow.ram_test()
    assert store.status()["state"] == "interrupted"
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


@pytest.mark.parametrize("fault", ["short", "export", "unqualified", "missing_uid"])
def test_capture_and_identity_gates(tmp_path, fault):
    store, _, backend, workflow, boot, fit, provenance, history = fixture(tmp_path)
    backend.short_read = fault == "short"
    backend.corrupt_export = fault == "export"
    if fault == "unqualified":
        backend.writer = "f" * 64
    if fault == "missing_uid":
        backend.target = backend.target.model_copy(update={"uid": None})
        workflow.capture()
        with pytest.raises(RecoveryError, match="target_unbound"):
            workflow.plan(boot, fit, provenance, history)
    else:
        with pytest.raises((RecoveryError, ValueError)):
            workflow.capture()
        assert not any(e.kind == "backup_verified" for e in store.events())
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


def test_aliasing_matching_logical_hash_is_not_physical_qualification(tmp_path):
    store, profile, backend, workflow, *_ = fixture(tmp_path, capacity=0x2000000)
    candidate = bytes(range(256)) * 65536 + b"wrap-tail"
    for start in range(0, len(candidate), 0x1000000):
        chunk = candidate[start : start + 0x1000000]
        backend.flash[: len(chunk)] = chunk
    backend.alias = True
    logical = backend.read(0, 0x1000000)
    # Both logical addresses alias, while actual upper-bank bytes are different.
    assert backend.read(0x1000000, 0x1000000) == logical
    assert bytes(backend.flash[0x1000000:]) != logical
    backend.writer = "f" * 64
    with pytest.raises(RecoveryError, match="writer_unqualified"):
        workflow.capture()
    assert not any(e.kind == "backup_verified" for e in store.events())
    with pytest.raises(RecoveryError, match="profile_unqualified"):
        get_profile(profile.profile_id)


@pytest.mark.parametrize("field", ["historical_boot_sha256", "target_uid", "rollback_sha256"])
def test_provenance_missing_or_mismatched_blocks_plan(tmp_path, field):
    _, _, backend, workflow, boot, fit, provenance, history = fixture(tmp_path)
    workflow.capture()
    changed = "wrong-target" if field == "target_uid" else "0" * 64
    with pytest.raises(RecoveryError):
        workflow.plan(boot, fit, provenance.model_copy(update={field: changed}), history)
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


def test_plan_and_backup_tampering_are_detected_before_mutation(tmp_path):
    values, plan = prepared(tmp_path)
    store, profile, backend, workflow, *_ = values
    altered = plan.model_copy(update={"sectors": plan.sectors[:-1]})
    with pytest.raises(RecoveryError, match="plan_invalid"):
        validate_plan(altered, profile, store.get)
    path = store.root / "blobs" / plan.original.sha256
    path.write_bytes(store.get(plan.original)[:-1])
    with pytest.raises(RecoveryError):
        workflow.ram_test()
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


def test_environment_allows_only_fit_size_with_valid_crc_and_padding():
    for size in (4096, 0xC56117, 0x10000000):
        before = environment()
        after = environment_with_fit_size(before, size)
        assert decode_environment(after) == decode_environment(before) | {
            b"fit_size": f"{size:X}".encode()
        }
        assert len(after) == len(before)
    with pytest.raises(ValueError):
        environment_with_fit_size(before[:-1], 4096)


def test_fit_checks_components_configuration_soc_and_ram(tmp_path):
    _, profile, *_ = fixture(tmp_path)
    fit = fit_bytes()
    validate_fit(fit, profile.rollback, "Z7010")
    assert "/configurations/config@0" in nodes(fit)
    for contract, soc in (
        (profile.rollback.model_copy(update={"configuration": "wrong"}), "Z7010"),
        (profile.rollback, "Z7020"),
        (profile.rollback.model_copy(update={"ram_end": 1}), "Z7010"),
    ):
        with pytest.raises(RecoveryError):
            validate_fit(fit, contract, soc)
    for data in (fit_bytes(wrong_hash=True), fit_bytes(compression=b"gzip\0")):
        claim = profile.rollback.model_copy(update={"sha256": digest(data), "size": len(data)})
        with pytest.raises(RecoveryError):
            validate_fit(data, claim, "Z7010")


def test_private_journal_export_and_concurrent_ownership(tmp_path):
    values, _ = prepared(tmp_path)
    store, _, _, _, *_ = values
    assert "SYNTHETIC_PRIVATE_SECRET" not in json.dumps(store.sanitized())
    assert store.root.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in (store.root / "blobs").iterdir())
    with store.lock(), pytest.raises(RecoveryError, match="session_busy"), Store(store.root).lock():
        pytest.fail("second writer acquired session")
    events = store.events()
    event_file = store.root / "events" / "00000000.json"
    event_file.write_bytes(canonical(events[0]).replace(b'"sequence":0', b'"sequence":1'))
    with pytest.raises(RecoveryError, match="journal_invalid"):
        Store(store.root).status()


def test_blob_symlinks_and_duplicate_contract_keys_are_rejected(tmp_path):
    store, *_ = fixture(tmp_path)
    outside = tmp_path / "private"
    outside.write_bytes(b"secret")
    blob = Blob(sha256=digest(b"secret"), size=6)
    (store.root / "blobs" / blob.sha256).symlink_to(outside)
    with pytest.raises((RecoveryError, OSError)):
        store.get(blob)
    session = store.root / "session.json"
    raw = session.read_bytes().replace(
        b'"schema_version":1', b'"schema_version":1,"schema_version":1'
    )
    session.write_bytes(raw)
    with pytest.raises(RecoveryError, match="duplicate JSON"):
        Store(store.root)


@pytest.mark.parametrize(
    "size,allowed", [(0xDFFFFF, True), (0xE00000, True), (0xE00001, False), (0xE0FD6F, False)]
)
def test_same_address_policy_applies_to_recovery_and_ordinary_deployment(tmp_path, size, allowed):
    store, profile, backend, _, boot, fit, provenance, history = fixture(
        tmp_path,
        capacity=0x2000000,
        fit_size=size,
    )
    observed = backend.observe()
    legacy = FlashObservation(
        serial=observed.target.serial,
        boot_id="linux-boot",
        kernel="known-legacy",
        updater_sha256=LEGACY_UPDATER_SHA256,
        tools_sha256="a" * 64,
        boot_sha256=digest(boot),
        flash_identity=observed.target.jedec,
        capacity=profile.geometry.capacity,
        partitions=tuple(
            FlashPartition(
                i,
                ("qspi-fsbl-uboot", "qspi-uboot-env", "qspi-nvmfs", "qspi-linux")[i],
                p.start,
                p.size,
                p.erase_size,
            )
            for i, p in enumerate(profile.geometry.regions)
        ),
        environment_sha256="b" * 64,
        report_sha256="c" * 64,
        board_identity="d" * 64,
    )

    def recovery():
        return build_plan(
            session_id=store.session.session_id,
            profile=profile,
            observed=observed,
            original=bytes(backend.flash),
            boot=boot,
            fit=fit,
            provenance=provenance,
            history=history,
            put=lambda data: Blob(sha256=digest(data), size=len(data)),
        )

    if allowed:
        assert validate_flash(legacy, fit).erase_end <= 0x1000000
        assert all(s.start + s.size <= 0x1000000 for s in recovery().sectors)
    else:
        for call in (lambda: validate_flash(legacy, fit), recovery):
            with pytest.raises(ValueError, match="flash_range_unqualified"):
                call()
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


def test_gzip_requires_bounded_qualified_expanded_sizes(tmp_path):
    _, profile, *_ = fixture(tmp_path)
    data = fit_bytes(compression=b"gzip\0")
    sizes = {"kernel@1": 136, "fdt@1": 133}
    contract = profile.rollback.model_copy(
        update={"sha256": digest(data), "size": len(data), "expanded_sizes": sizes}
    )
    validate_fit(data, contract, "Z7010")
    for sizes in ({"kernel@1": 1, "fdt@1": 133}, {}, {"kernel@1": 999999, "fdt@1": 133}):
        with pytest.raises(RecoveryError):
            validate_fit(data, contract.model_copy(update={"expanded_sizes": sizes}), "Z7010")


def test_missing_historical_receipt_is_not_replaced_by_a_claimed_digest(tmp_path):
    _, _, _, workflow, boot, fit, provenance, history = fixture(tmp_path)
    workflow.capture()
    with pytest.raises(ValueError):
        workflow.plan(boot, fit, provenance, b"{}\n")
    with pytest.raises(RecoveryError, match="provenance_missing"):
        workflow.plan(boot, fit, provenance, history.replace(b"UID_A", b"UID_B"))


def test_unexplained_boot_changes_outside_explicit_repair_are_not_silently_restored(tmp_path):
    _, _, backend, workflow, boot, fit, provenance, history = fixture(tmp_path)
    backend.flash[0x50000] ^= 1
    workflow.capture()
    with pytest.raises(RecoveryError, match="outside approved restoration"):
        workflow.plan(boot, fit, provenance, history)


def test_changed_writer_after_erase_never_dispatches_program(tmp_path, monkeypatch):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    workflow.ram_test()
    erase = backend.erase

    def changed(start, size):
        erase(start, size)
        backend.writer = "f" * 64

    monkeypatch.setattr(backend, "erase", changed)
    with pytest.raises(RecoveryError):
        workflow.execute(confirm(plan))
    assert store.status()["state"] == "interrupted"
    assert not any(op == "program" for op, _, _ in backend.events)


def test_erased_sector_verification_failure_never_programs(tmp_path, monkeypatch):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    workflow.ram_test()
    erase = backend.erase

    def bad_erase(start, size):
        erase(start, size)
        backend.flash[start] = 0

    monkeypatch.setattr(backend, "erase", bad_erase)
    with pytest.raises(RecoveryError, match="erased sector"):
        workflow.execute(confirm(plan))
    assert store.status()["state"] == "interrupted"
    assert not any(op == "program" for op, _, _ in backend.events)
