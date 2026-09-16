"""Interactive composition of the same evidence-gated recovery operations."""

from __future__ import annotations

import json
import shlex
import uuid
from dataclasses import dataclass
from pathlib import Path

import typer

from . import live, profiles
from .contracts import Plan, Provenance, RecoveryError, Session, canonical, digest
from .discovery import discover
from .sd import export_repair, export_repair_archive, prepare_bundle, verify_bundle
from .store import Store, publish, read_regular
from .workflow import Workflow


@dataclass(frozen=True)
class Inputs:
    assets: Path | None = None
    boot: Path | None = None
    fit: Path | None = None
    provenance: Path | None = None
    history: Path | None = None


def _path(value: Path | None, label: str) -> Path:
    return value if value is not None else Path(typer.prompt(label)).expanduser()


def _ready(message: str) -> None:
    typer.confirm(message, default=False, abort=True)


def _sd_console(workflow: Workflow) -> None:
    ready = getattr(workflow.backend, "await_sd_console", None)
    if ready is not None:
        ready()


def _open(root: Path, adapter: str | None, profile_id: str | None) -> Store:
    if root.exists() or root.is_symlink():
        store = Store(root)
        if (adapter is not None and adapter != store.session.adapter) or (
            profile_id is not None and profile_id != store.session.profile_id
        ):
            raise RecoveryError("target_mismatch", "adapter/profile differs from saved session")
        return store
    if not profiles.PROFILES:
        raise RecoveryError(
            "live_recovery_unavailable",
            "this installation has no qualified live recovery profiles. "
            "The guided command cannot repair hardware yet; board-specific identity, "
            "RAM-boot and cold-boot recipes and hardware validation are required. "
            "No UART was opened. Use discover/start/import-evidence for diagnostics.",
        )
    if profile_id is None:
        typer.echo("Available profiles: " + ", ".join(p.profile_id for p in profiles.PROFILES))
        profile_id = typer.prompt(
            "Profile for the physically identified board",
            default=profiles.PROFILES[0].profile_id if len(profiles.PROFILES) == 1 else None,
        )
    profile = profiles.get_profile(profile_id)
    if profile.profile_id not in live.BACKENDS:
        raise RecoveryError("backend_unqualified", "this profile has no shipped live recipe")
    if adapter is None:
        typer.echo(json.dumps(discover(), indent=2))
        adapter = typer.prompt("Stable UART adapter path connected to this radio")
    if not adapter.strip():
        raise RecoveryError("target_unbound", "an explicit UART adapter is required")
    return Store.create(
        root,
        Session(session_id=uuid.uuid4().hex, adapter=adapter, profile_id=profile.profile_id),
    )


def _review(plan: Plan) -> None:
    typer.echo(f"Repair plan: {plan.sha256}")
    typer.echo(f"Original backup: {plan.original.sha256}")
    typer.echo(f"Expected complete flash: {plan.expected.sha256}")
    count = sum(s.size for s in plan.sectors)
    typer.echo(f"{len(plan.sectors)} sectors, {count} bytes to rewrite:")
    # Show contiguous ranges without hundreds of nearly identical sector rows.
    ranges: list[tuple[str, int, int]] = []
    for sector in plan.sectors:
        end = sector.start + sector.size
        if ranges and ranges[-1][0] == sector.kind and ranges[-1][2] == sector.start:
            kind, start, _ = ranges[-1]
            ranges[-1] = kind, start, end
        else:
            ranges.append((sector.kind, sector.start, end))
    for kind, start, end in ranges:
        typer.echo(f"  {kind}: 0x{start:08x} to 0x{end:08x} (end exclusive)")


def _receipt(store: Store) -> None:
    with store.lock():
        data = canonical(store.sanitized())
        path = store.root / f"receipt-{digest(data)}.json"
        if path.exists():
            if read_regular(path) != data:
                raise RecoveryError("evidence_changed", "saved receipt differs")
        else:
            publish(path, data)
    typer.echo(f"Recovery verified. Sanitized receipt: {path}")
    typer.echo("Conservative firmware update limits still apply.")


def _steps(store: Store, inputs: Inputs) -> None:
    state = store.status()["state"]
    reconciled_this_run = False
    if state == "recovered":
        _receipt(store)
        return
    profile = profiles.get_profile(store.session.profile_id or "")
    if profile.support == "incident":
        from .pluto_sd import kit_root

        kit = kit_root()
        inputs = Inputs(
            inputs.assets or kit / "sdcard",
            inputs.boot or kit / "boot.bin",
            inputs.fit or kit / "rollback.itb",
            inputs.provenance or kit / "provenance.json",
            inputs.history or kit / "history.json",
        )
        typer.echo(
            "Incident-scoped recovery: exact radio and retained image only. "
            "General hardware qualification remains pending."
        )
    if profile.profile_id not in live.BACKENDS:
        raise RecoveryError("backend_unqualified", "this profile has no shipped live recipe")
    typer.echo(f"Session: {store.root}\nUART: {store.session.adapter}")
    typer.echo(f"Profile: {profile.profile_id}")
    typer.echo(profile.wiring_instructions)
    typer.echo(profile.boot_instructions)
    workflow = Workflow(store, profile, live.backend_for(store, profile))

    if state in {"discovered", "bootstrap_ready"}:
        bundle = store.root / "diagnostic-sd"
        with store.lock():
            if (bundle / "manifest.json").exists() and (bundle / "verify.py").exists():
                verify_bundle(profile, bundle)
                manifest = digest(read_regular(bundle / "manifest.json"))
            else:
                # An interrupted export can be finished from the qualified source.
                manifest = ""
        if not manifest:
            assets = _path(inputs.assets, "Directory containing the qualified SD boot assets")
            with store.lock():
                manifest = prepare_bundle(profile, assets, bundle)
                store.record("sd_bundle_verified", {"manifest_sha256": manifest})
        typer.echo(f"Diagnostic SD files: {bundle}\nManifest SHA-256: {manifest}")
        typer.echo(
            "On the SD reader computer, copy the bundle contents to the prepared card, "
            "run python3 verify.py MOUNT and compare the manifest digest, then eject. "
            "If this exact bundle is already on the card, verify and reuse it."
        )

        def capture_ready() -> None:
            _ready(
                "UART is acquired and listening now. While this question remains open, keep "
                "power off, insert the verified SD, select SD boot, power on, and wait 15 "
                "seconds. Then answer yes to inspect and back up"
            )
            _sd_console(workflow)

        typer.echo("Next: capture and verify the complete flash backup; UART transfer may be slow.")
        workflow.capture(prepare_boot=capture_ready)
        state = store.status()["state"]

    if state == "backup_verified":
        boot = _path(inputs.boot, "Full historical boot partition file")
        fit = _path(inputs.fit, "Verified rollback FIT file")
        provenance = _path(inputs.provenance, "Target provenance JSON file")
        history = _path(inputs.history, "Canonical historical boot receipt file")
        evidence = Provenance.model_validate(json.loads(read_regular(provenance, 1024 * 1024)))
        workflow.plan(
            read_regular(boot), read_regular(fit), evidence, read_regular(history, 1024 * 1024)
        )
        state = store.status()["state"]

    if state in {"interrupted", "ram_boot_verified"}:
        typer.echo(
            "Interrupted-session recovery requires one SD boot to reread physical flash and "
            "build a successor plan. Keep that question open while power-cycling, wait 15 "
            "seconds, then answer yes. Once reconciliation passes in this invocation, the "
            "verified SD console continues directly into the RAM test without another boot."
        )

        def resume_ready() -> None:
            _ready(
                "UART is acquired and listening now. While this question remains open, "
                "re-enter SD recovery, power on, and wait 15 seconds. Then answer yes to "
                "inspect current flash and build a fresh plan"
            )
            _sd_console(workflow)

        # Never reuse old RAM acceptance after a new invocation or replay a write.
        workflow.resume(prepare_boot=resume_ready)
        state = store.status()["state"]
        reconciled_this_run = True

    if state == "plan_ready":
        with store.lock():
            if store.status()["state"] != "plan_ready":
                raise RecoveryError("plan_stale", "session changed before SD transfer")
            plan = workflow.current_plan()
            output = store.root / f"repair-{plan.sha256}"
            manifest = export_repair(plan, store.get, output)
            archive = store.root / f"ppu-repair-{plan.sha256}.zip"
            archive_sha256 = export_repair_archive(output, archive)
        _review(plan)
        typer.echo(
            f"Repair SD files: {output}\nComplete repair ZIP: {archive}\n"
            f"Repair ZIP SHA-256: {archive_sha256}\nRepair manifest SHA-256: {manifest}"
        )
        typer.echo(
            "With the radio powered off, copy the ZIP to the Mac and extract it at the SD card "
            "root. The resulting path must be /Volumes/CARD/ppu-repair; replace an old "
            "ppu-repair directory instead of nesting or merging it. Preserve BOOT.bin, "
            "uEnv.txt and backups. Example (replace USER, RECOVERY_HOST and CARD):\n"
            f"scp USER@RECOVERY_HOST:{archive} ~/Downloads/\n"
            f"unzip -o ~/Downloads/{archive.name} -d /Volumes/CARD\n"
            "Verify the card itself with:\n"
            "python3 /Volumes/CARD/ppu-repair/verify-repair.py "
            "/Volumes/CARD/ppu-repair\n"
            "The verifier argument is the ppu-repair directory, not /Volumes/CARD. Compare "
            "the printed manifest digest above, safely eject, and reinsert with radio power off."
        )

        def ram_ready() -> None:
            if workflow.current_plan().sha256 != plan.sha256:
                raise RecoveryError("plan_stale", "plan changed during SD transfer")
            if reconciled_this_run:
                _ready(
                    "Reconciliation verified this exact radio, SD console and unchanged flash. "
                    "Leave the radio powered on in SD recovery mode and answer yes to continue "
                    "directly into the RAM test; no second power cycle is needed"
                )
                return
            _ready(
                "UART is acquired and listening now. The radio must begin this step fully "
                "powered off, even if it is already at a Pluto+ prompt. While this question "
                "remains open, insert the verified card, select SD boot, power on, and wait "
                "15 seconds. Only then answer yes to validate and test the firmware in RAM"
            )
            _sd_console(workflow)

        def sd_return() -> None:
            typer.echo("RAM image, identity and service checks passed.")
            _ready(
                "PPU is listening. While this question remains open, power off, return to SD "
                "boot, power on, and wait 15 seconds. Then answer yes to verify that flash is "
                "unchanged"
            )

        workflow.ram_test(prepare_boot=ram_ready, prepare_return=sd_return)
        _review(plan)
        expected = f"RECOVER {store.session.session_id} {plan.sha256}"
        typer.echo(f"To authorize this exact flash repair, type:\n{expected}")
        confirmation = typer.prompt("Confirmation", default="", show_default=False)
        # The executor independently checks the exact plan, target, epoch and bytes.
        workflow.execute(confirmation)
        state = store.status()["state"]

    if state == "flash_verified":
        # A process may stop between the two durable completion events.
        with store.lock():
            if store.status()["state"] != "flash_verified":
                raise RecoveryError("plan_stale", "session changed while guiding cold boot")
            plan = workflow.current_plan()
            if store.latest("flash_verified").data["plan_sha256"] != plan.sha256:
                raise RecoveryError("plan_stale", "flash verification belongs to another plan")
            store.record("awaiting_cold_boot", {"plan_sha256": plan.sha256})
        state = "awaiting_cold_boot"

    if state == "awaiting_cold_boot":
        typer.echo("Complete flash readback passed. Next: verify a real QSPI cold boot.")

        def cold_ready() -> None:
            _ready(
                "UART is acquired and listening now. While this question remains open, fully "
                "power off, remove the SD card, restore normal QSPI boot selection, power on, "
                "and wait 15 seconds. Then answer yes to record the completed actions"
            )
            confirmed = getattr(workflow.backend, "confirm_operator_cold_boot", None)
            if confirmed is not None:
                confirmed()

        workflow.attest(prepare_boot=cold_ready)
        _receipt(store)
        return
    raise RecoveryError("guide_state_unsupported", f"inspect session before continuing: {state}")


def run(root: Path, adapter: str | None, profile: str | None, inputs: Inputs) -> None:
    store = _open(root, adapter, profile)
    command = "pluto firmware recover guide --session " + shlex.quote(str(store.root))
    typer.echo(f"To continue after stopping, run:\n{command}")
    try:
        with store.lock(guide=True):
            _steps(store, inputs)
    except (typer.Abort, RecoveryError, OSError, ValueError, KeyboardInterrupt):
        typer.echo(f"Recovery has not completed. Retain this session. Continue with:\n{command}")
        raise
