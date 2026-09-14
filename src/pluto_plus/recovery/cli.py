"""Guided recovery CLI; offline evidence never impersonates a live observation."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Annotated, Any

import typer
from pydantic import ValidationError
from typer.core import TyperGroup

from . import profiles
from .contracts import Provenance, RecoveryError, Session, canonical, digest
from .discovery import discover
from .live import backend_for
from .sd import (
    copy_to_media,
    export_repair,
    export_repair_archive,
    media_identity,
    prepare_bundle,
)
from .store import Store, publish, read_regular
from .workflow import Workflow


class RecoveryGroup(TyperGroup):
    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except RecoveryError as error:
            typer.echo(json.dumps({"code": error.code, "message": str(error)}), err=True)
            raise typer.Exit(2) from None
        except (OSError, ValidationError, ValueError) as error:
            typer.echo(
                json.dumps(
                    {
                        "code": "recovery_input_or_storage_invalid",
                        "error_type": type(error).__name__,
                    }
                ),
                err=True,
            )
            raise typer.Exit(2) from None


app = typer.Typer(
    cls=RecoveryGroup,
    no_args_is_help=True,
    help="Guided SD recovery with private, resumable evidence.",
)
SessionPath = Annotated[Path, typer.Option("--session", help="Private recovery session directory.")]


def _emit(value: object) -> None:
    typer.echo(json.dumps(value, sort_keys=True, indent=2))


def _workflow(session: Path, *, live: bool = False) -> Workflow:
    store = Store(session)
    profile = profiles.get_profile(store.session.profile_id or "")
    return Workflow(store, profile, backend_for(store, profile) if live else None)


@app.command("profiles")
def list_profiles() -> None:
    """Show only combinations with shipped qualification records."""
    _emit(
        {
            "profiles": [
                {
                    "profile_id": p.profile_id,
                    "qualification_id": p.qualification_id,
                    "support": p.support,
                    "write_limit": p.write_limit,
                }
                for p in profiles.PROFILES
            ],
            "unqualified_action": "retain diagnostics; request qualified firmware recovery recipes",
        }
    )


@app.command("discover")
def discover_entrypoints() -> None:
    """List host-visible USB/UART entry points without opening a radio."""
    _emit(discover())


@app.command()
def start(
    session: SessionPath,
    adapter: Annotated[str, typer.Option("--adapter")],
    profile: Annotated[str | None, typer.Option("--profile")] = None,
) -> None:
    """Create a diagnostic session; does not open or select a radio automatically."""
    if profile is not None:
        profiles.get_profile(profile)
    store = Store.create(
        session, Session(session_id=uuid.uuid4().hex, adapter=adapter, profile_id=profile)
    )
    _emit(store.status())


@app.command()
def status(session: SessionPath) -> None:
    """Report evidence state and the next permitted action."""
    _emit(Store(session).status())


@app.command("import-evidence")
def import_evidence(session: SessionPath, file: Annotated[Path, typer.Option("--file")]) -> None:
    """Retain a private dump/log without claiming qualified physical capture."""
    store = Store(session)
    with store.lock():
        blob = store.put(read_regular(file))
        store.record("unverified_import", {"blob": blob.model_dump()})
    _emit({"sha256": blob.sha256, "size": blob.size, "verified_physical_backup": False})


@app.command("prepare-sd")
def prepare_sd(
    session: SessionPath,
    assets: Annotated[Path, typer.Option("--assets")],
    output: Annotated[Path, typer.Option("--output")],
    media: Annotated[Path | None, typer.Option("--media")] = None,
    media_id: Annotated[str | None, typer.Option("--media-id")] = None,
) -> None:
    """Build a verified console-only bundle; optionally copy to explicitly bound media."""
    store = Store(session)
    profile = profiles.get_profile(store.session.profile_id or "")
    if media is not None and media_id is None:
        _emit({"media_identity": media_identity(media), "action": "repeat with this --media-id"})
        return
    with store.lock():
        manifest = prepare_bundle(profile, assets, output)
        if media is not None and media_id is not None:
            copy_to_media(profile, output, media, media_id)
        store.record(
            "sd_bundle_verified", {"manifest_sha256": manifest, "profile_sha256": profile.sha256}
        )
    _emit(
        {
            "manifest_sha256": manifest,
            "instructions": profile.boot_instructions,
            "wiring": profile.wiring_instructions,
            "transfer": "Run python3 verify.py MOUNT on the SD reader computer; compare hashes.",
        }
    )


@app.command()
def capture(session: SessionPath) -> None:
    """Capture complete physical flash through the qualified SD reader."""
    _emit(_workflow(session, live=True).capture().model_dump())


@app.command()
def plan(
    session: SessionPath,
    boot: Annotated[Path, typer.Option("--boot")],
    fit: Annotated[Path, typer.Option("--fit")],
    provenance: Annotated[Path, typer.Option("--provenance")],
    history: Annotated[Path, typer.Option("--history")],
) -> None:
    """Reconstruct a minimal sector repair from target-specific historical provenance."""
    evidence = Provenance.model_validate(json.loads(read_regular(provenance, 1024 * 1024)))
    result = _workflow(session).plan(
        read_regular(boot), read_regular(fit), evidence, read_regular(history, 1024 * 1024)
    )
    # Include no environment contents or private target observations in stdout.
    _emit(
        {
            "plan_sha256": result.sha256,
            "expected_flash_sha256": result.expected.sha256,
            "sectors": [s.model_dump() for s in result.sectors],
            "confirmation": f"RECOVER {result.session_id} {result.sha256}",
        }
    )


@app.command("stage-sd")
def stage_sd(session: SessionPath, output: Annotated[Path, typer.Option("--output")]) -> None:
    """Export exact full-sector files for the SD reader computer; never writes flash."""
    workflow = _workflow(session)
    with workflow.store.lock():
        selected = workflow.current_plan()
        manifest_sha256 = export_repair(selected, workflow.store.get, output)
        archive = output.parent / f"{output.name}.zip"
        archive_sha256 = export_repair_archive(output, archive)
    _emit(
        {
            "plan_sha256": selected.sha256,
            "manifest_sha256": manifest_sha256,
            "archive": str(archive),
            "archive_sha256": archive_sha256,
            "action": (
                "extract the ZIP at the SD root, then run "
                "python3 MOUNT/ppu-repair/verify-repair.py MOUNT/ppu-repair"
            ),
        }
    )


@app.command("guide")
def guide(
    session: SessionPath,
    adapter: Annotated[str | None, typer.Option("--adapter")] = None,
    profile: Annotated[str | None, typer.Option("--profile")] = None,
    assets: Annotated[Path | None, typer.Option("--assets")] = None,
    boot: Annotated[Path | None, typer.Option("--boot")] = None,
    fit: Annotated[Path | None, typer.Option("--fit")] = None,
    provenance: Annotated[Path | None, typer.Option("--provenance")] = None,
    history: Annotated[Path | None, typer.Option("--history")] = None,
) -> None:
    """Walk through recovery; rerun with the same session to continue safely."""
    from .guided import Inputs, run

    run(session, adapter, profile, Inputs(assets, boot, fit, provenance, history))


@app.command("ram-test")
def ram_test(session: SessionPath) -> None:
    workflow = _workflow(session, live=True)
    workflow.ram_test()
    _emit(workflow.store.status())


@app.command()
def execute(session: SessionPath, confirm: Annotated[str, typer.Option("--confirm")]) -> None:
    workflow = _workflow(session, live=True)
    workflow.execute(confirm)
    _emit(workflow.store.status())


@app.command()
def resume(session: SessionPath) -> None:
    """Read current hardware and generate a successor plan; does not write flash."""
    selected = _workflow(session, live=True).resume()
    _emit(
        {
            "plan_sha256": selected.sha256,
            "remaining_sectors": len(selected.sectors),
            "action": "review successor plan, repeat RAM test, then explicitly execute",
        }
    )


@app.command()
def attest(session: SessionPath) -> None:
    workflow = _workflow(session, live=True)
    workflow.attest()
    _emit(workflow.store.status())


@app.command("export")
def export_receipt(session: SessionPath, output: Annotated[Path, typer.Option("--output")]) -> None:
    receipt = Store(session).sanitized()
    publish(output, canonical(receipt))
    _emit({"receipt_sha256": digest(canonical(receipt)), "state": receipt["state"]})
