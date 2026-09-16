from __future__ import annotations

import json
from contextlib import contextmanager

import pytest
import typer
from recovery_fakes import fixture, prepared
from typer.testing import CliRunner

from pluto_plus.cli import app
from pluto_plus.recovery import guided, live, profiles
from pluto_plus.recovery.contracts import RecoveryError
from pluto_plus.recovery.sd import export_repair, export_repair_archive


def invoke(store, *args, **kwargs):
    return CliRunner().invoke(
        app, ["firmware", "recover", "guide", "--session", str(store.root), *args], **kwargs
    )


def configure(monkeypatch, values):
    store, profile, backend, workflow, *_ = values
    monkeypatch.setattr(profiles, "PROFILES", (profile,))
    monkeypatch.setattr(live, "BACKENDS", {profile.profile_id: lambda *_: backend})
    questions = []
    leased = []

    @contextmanager
    def lease():
        leased.append(True)
        try:
            yield
        finally:
            leased.pop()

    monkeypatch.setattr(backend, "lease", lease)

    def confirm(message, **kwargs):
        questions.append(message)
        if "UART is acquired" in message or "RAM image" in message:
            assert leased, "listen before requesting the physical boot"
        return True

    def prompt(message, **kwargs):
        assert message == "Confirmation"
        questions.append(message)
        plan = workflow.current_plan()
        return f"RECOVER {store.session.session_id} {plan.sha256}"

    monkeypatch.setattr(guided.typer, "confirm", confirm)
    monkeypatch.setattr(guided.typer, "prompt", prompt)
    return questions


def artifacts(tmp_path, values):
    _, profile, _, _, boot, fit, provenance, history = values
    assets = tmp_path / "assets"
    assets.mkdir()
    (assets / "BOOT.BIN").write_bytes(b"synthetic-bootstrap")
    result = ["--assets", str(assets)]
    for name, data in (
        ("boot", boot),
        ("fit", fit),
        ("provenance", provenance.model_dump_json().encode()),
        ("history", history),
    ):
        path = tmp_path / name
        path.write_bytes(data)
        result.extend(["--" + name, str(path)])
    assert profile.profile_id == "synthetic-test-only"
    return result


def test_guide_runs_capture_through_cold_boot_in_one_invocation(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    store, _, backend, workflow, *_ = values
    before = bytes(backend.flash)
    questions = configure(monkeypatch, values)
    console_waits = []

    def await_sd_console():
        assert questions and "UART is acquired" in questions[-1]
        console_waits.append(True)

    monkeypatch.setattr(backend, "await_sd_console", await_sd_console, raising=False)
    result = invoke(store, *artifacts(tmp_path, values))
    assert result.exit_code == 0, result.output
    assert store.status()["state"] == "recovered"
    plan = workflow.current_plan()
    assert bytes(backend.flash) == store.get(plan.expected)
    assert store.get(plan.original) == before
    assert len(questions) == 5
    assert len(console_waits) == 2
    receipt = next(store.root.glob("receipt-*.json"))
    public = json.loads(receipt.read_text())
    assert public["state"] == "recovered"
    assert "SYNTHETIC_PRIVATE_SECRET" not in result.output + receipt.read_text()
    assert "UART transfer may be slow" in result.output
    assert "ppu-repair" in result.output
    assert "Complete repair ZIP:" in result.output
    assert "The verifier argument is the ppu-repair directory" in result.output
    assert "/Volumes/CARD/ppu-repair/verify-repair.py" in result.output
    # Completed sessions reopen without any hardware or repeated prompts.
    backend.events.clear()
    monkeypatch.setattr(live, "BACKENDS", {})
    result = invoke(store)
    assert result.exit_code == 0, result.output
    assert backend.events == []
    assert len(questions) == 5


def test_guide_creates_new_bound_session(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    store, profile, backend, _, *_ = values
    args = artifacts(tmp_path, values)
    monkeypatch.setattr(profiles, "PROFILES", (profile,))
    monkeypatch.setattr(live, "BACKENDS", {profile.profile_id: lambda *_: backend})
    root = tmp_path / "new-session"
    result = CliRunner().invoke(
        app,
        [
            "firmware",
            "recover",
            "guide",
            "--session",
            str(root),
            "--adapter",
            store.session.adapter,
            "--profile",
            profile.profile_id,
            *args,
        ],
        input="n\n",
    )
    assert result.exit_code == 1, result.output
    assert root.exists()
    assert (root / "diagnostic-sd" / "manifest.json").is_file()
    assert not backend.events


@pytest.mark.parametrize("answer", ["n\n", ""])
def test_decline_or_eof_before_ram_keeps_ready_plan_without_writes(tmp_path, monkeypatch, answer):
    values, plan = prepared(tmp_path)
    store, profile, backend, *_ = values
    monkeypatch.setattr(profiles, "PROFILES", (profile,))
    monkeypatch.setattr(live, "BACKENDS", {profile.profile_id: lambda *_: backend})
    backend.events.clear()
    result = invoke(store, input=answer)
    assert result.exit_code == 1
    assert store.status()["state"] == "plan_ready"
    assert bytes(backend.flash) == store.get(plan.original)
    assert not backend.events
    assert "Continue with:" in result.output


def test_incorrect_confirmation_never_dispatches_flash(tmp_path, monkeypatch):
    values, plan = prepared(tmp_path)
    store, _, backend, *_ = values
    configure(monkeypatch, values)
    monkeypatch.setattr(guided.typer, "prompt", lambda *a, **kw: "yes")
    result = invoke(store)
    assert result.exit_code == 2, result.output
    assert "confirmation_mismatch" in result.output
    assert bytes(backend.flash) == store.get(plan.original)
    assert not any(op in {"erase", "program"} for op, _, _ in backend.events)


@pytest.mark.parametrize("operation", ["erase", "program"])
def test_guide_reconciles_partial_write_then_tests_and_confirms_successor(
    tmp_path, monkeypatch, operation
):
    values, original = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    questions = configure(monkeypatch, values)
    backend.fail = (operation, 1, "during")
    result = invoke(store)
    assert result.exit_code == 2, result.output
    assert store.status()["state"] == "interrupted"
    backend.fail = None
    result = invoke(store)
    assert result.exit_code == 0, result.output
    plan = workflow.current_plan()
    assert plan.parent_plan == original.sha256
    assert plan.original == original.original
    assert bytes(backend.flash) == store.get(original.expected)
    assert store.latest("ram_boot_verified").data["plan_sha256"] == plan.sha256
    assert store.status()["state"] == "recovered"
    assert any("no second power cycle is needed" in question for question in questions)


def test_guide_rechecks_previous_ram_acceptance_after_restart(tmp_path, monkeypatch):
    values, original = prepared(tmp_path)
    store, _, _, workflow, *_ = values
    workflow.ram_test()
    configure(monkeypatch, values)
    result = invoke(store)
    assert result.exit_code == 0, result.output
    assert workflow.current_plan().parent_plan == original.sha256
    assert len([e for e in store.events() if e.kind == "ram_boot_verified"]) == 2


@pytest.mark.parametrize("gap", [False, True])
def test_guide_continues_verified_flash_without_reflashing(tmp_path, monkeypatch, gap):
    values, plan = prepared(tmp_path)
    store, _, backend, workflow, *_ = values
    workflow.ram_test()
    workflow.execute(f"RECOVER {plan.session_id} {plan.sha256}")
    if gap:
        # Simulate a crash after flash_verified, before awaiting_cold_boot publication.
        last = sorted((store.root / "events").glob("*.json"))[-1]
        assert json.loads(last.read_text())["kind"] == "awaiting_cold_boot"
        last.unlink()
    backend.events.clear()
    configure(monkeypatch, values)
    result = invoke(store)
    assert result.exit_code == 0, result.output
    assert not backend.events
    assert store.status()["state"] == "recovered"


def test_physical_confirmation_cannot_substitute_for_cold_boot_evidence(tmp_path, monkeypatch):
    values, _ = prepared(tmp_path)
    store, _, backend, *_ = values
    configure(monkeypatch, values)
    backend.return_changes = {"reset_cause": "warm", "operator_power_off": False}
    result = invoke(store)
    assert result.exit_code == 2
    assert "cold_boot_unverified" in result.output
    assert store.status()["state"] == "awaiting_cold_boot"
    assert not list(store.root.glob("receipt-*.json"))


def test_abort_return_to_sd_records_interruption_without_writes(tmp_path, monkeypatch):
    values, original = prepared(tmp_path)
    store, _, backend, *_ = values
    configure(monkeypatch, values)

    def confirm(message, **kwargs):
        if "verify that flash is unchanged" in message:
            raise typer.Abort()
        return True

    monkeypatch.setattr(guided.typer, "confirm", confirm)
    result = invoke(store)
    assert result.exit_code == 1
    assert store.status()["state"] == "interrupted"
    assert bytes(backend.flash) == store.get(original.original)


def test_no_shipped_profiles_refuses_before_session_or_uart(tmp_path, monkeypatch):
    monkeypatch.setattr(profiles, "PROFILES", ())
    monkeypatch.setattr(live, "backend_for", lambda *_: pytest.fail("must not open UART"))
    root = tmp_path / "session"
    result = CliRunner().invoke(
        app, ["firmware", "recover", "guide", "--session", str(root)], input=""
    )
    assert result.exit_code == 2
    assert "live_recovery_unavailable" in result.output
    assert "No UART was opened" in result.output
    assert not root.exists()


def test_missing_backend_and_changed_binding_refuse(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    store, profile, backend, *_ = values
    monkeypatch.setattr(profiles, "PROFILES", (profile,))
    monkeypatch.setattr(live, "BACKENDS", {})
    result = invoke(store)
    assert result.exit_code == 2
    assert "backend_unqualified" in result.output
    result = invoke(store, "--adapter", "another-radio")
    assert result.exit_code == 2
    assert "target_mismatch" in result.output
    assert not backend.events


def test_second_guide_refuses_while_first_waits_for_operator(tmp_path, monkeypatch):
    values = fixture(tmp_path)
    store, _, backend, *_ = values
    configure(monkeypatch, values)
    with store.lock(guide=True):
        result = invoke(store)
    assert result.exit_code == 2
    assert "session_busy" in result.output
    assert not backend.events


def test_repair_export_resumes_partial_transfer_and_refuses_modified_bytes(tmp_path):
    values, plan = prepared(tmp_path)
    store = values[0]
    output = tmp_path / "ppu-repair"
    expected = export_repair(plan, store.get, output)
    (output / "repair-manifest.json").unlink()
    assert export_repair(plan, store.get, output) == expected
    payload = next(output.glob("ppu-*.bin"))
    payload.write_bytes(b"corrupt")
    with pytest.raises(RecoveryError, match="artifact_corrupt"):
        export_repair(plan, store.get, output)


def test_repair_archive_has_one_complete_card_directory(tmp_path):
    values, plan = prepared(tmp_path)
    output = tmp_path / "repair"
    export_repair(plan, values[0].get, output)
    archive = tmp_path / "repair.zip"
    first = export_repair_archive(output, archive)
    assert export_repair_archive(output, archive) == first
    import zipfile

    with zipfile.ZipFile(archive) as bundle:
        names = set(bundle.namelist())
        assert "ppu-repair/repair-manifest.json" in names
        assert "ppu-repair/verify-repair.py" in names
        assert f"ppu-repair/ppu-{plan.patches[0].payload.sha256}.bin" in names


@pytest.mark.parametrize("corrupt", [False, True])
def test_guide_handles_interrupted_diagnostic_export(tmp_path, monkeypatch, corrupt):
    values = fixture(tmp_path)
    store, _, backend, *_ = values
    configure(monkeypatch, values)
    args = artifacts(tmp_path, values)
    output = store.root / "diagnostic-sd"
    output.mkdir(mode=0o700)
    (output / "BOOT.BIN").write_bytes(b"changed" if corrupt else b"synthetic-bootstrap")
    result = invoke(store, *args)
    if corrupt:
        assert result.exit_code == 2
        assert "artifact_corrupt" in result.output
        assert not backend.events
    else:
        assert result.exit_code == 0, result.output
        assert store.status()["state"] == "recovered"
