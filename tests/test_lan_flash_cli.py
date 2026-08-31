from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pluto_plus.bootstrap_firmware as bootstrap
from pluto_plus.cli import app

runner = CliRunner()


def _plan(image: Path) -> bootstrap.LanFlashPlan:
    return bootstrap.LanFlashPlan(
        plan_id="plan-lan",
        host="192.168.1.20",
        target_serial="SERIAL_LAN",
        before_firmware="v-old",
        before_model="Analog Devices PlutoSDR Rev.C",
        before_phy="ad9361",
        image_path=str(image.resolve()),
        image_sha256="1" * 64,
        fit_sha256="2" * 64,
        fit_size=100,
        frm_sha256="3" * 64,
        expected_firmware="v-new",
        mutation_profile_id="qualified-profile",
        expected_metadata_abi=3,
        expected_tandem_agc=True,
        confirmation_phrase="FLASH LAN SERIAL_LAN 192.168.1.20",
    )


def test_lan_flash_cli_is_read_only_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "qualified.dfu"
    image.write_bytes(b"image")
    plan = _plan(image)
    monkeypatch.setattr(bootstrap, "prepare_lan_flash_plan", lambda *args, **kwargs: (plan, b"frm"))
    monkeypatch.setattr(
        bootstrap,
        "execute_lan_flash_plan",
        lambda *args, **kwargs: pytest.fail("dry run must not execute"),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "flash-lan",
            str(image),
            "--serial",
            plan.target_serial,
            "--host",
            plan.host,
            "--profile",
            plan.mutation_profile_id,
            "--ssh-known-hosts-file",
            str(tmp_path / "known_hosts"),
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["will_write"] is False
    assert payload["will_rotate_ephemeral_ssh_key"] is False
    assert payload["plan"]["target_serial"] == plan.target_serial


def test_lan_flash_cli_requires_confirmation_before_password_or_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "qualified.dfu"
    image.write_bytes(b"image")
    plan = _plan(image)
    monkeypatch.setattr(bootstrap, "prepare_lan_flash_plan", lambda *args, **kwargs: (plan, b"frm"))
    monkeypatch.setattr(
        bootstrap,
        "BoundSshBootstrapTransport",
        lambda **kwargs: pytest.fail("wrong confirmation must not create transport"),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "flash-lan",
            str(image),
            "--serial",
            plan.target_serial,
            "--host",
            plan.host,
            "--profile",
            plan.mutation_profile_id,
            "--ssh-known-hosts-file",
            str(tmp_path / "known_hosts"),
            "--execute",
            "--confirm",
            "FLASH LAN WRONG 192.168.1.20",
        ],
    )

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "lan_flash_confirmation_required"


def test_lan_flash_cli_composes_pinned_transport_and_rotation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image = tmp_path / "qualified.dfu"
    image.write_bytes(b"image")
    plan = _plan(image)
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("key\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("secret\n")
    password.chmod(0o600)
    observed: dict[str, object] = {}
    monkeypatch.setattr(bootstrap, "prepare_lan_flash_plan", lambda *args, **kwargs: (plan, b"frm"))

    class Transport:
        def __init__(self, **kwargs: object) -> None:
            observed["transport"] = kwargs

    monkeypatch.setattr(bootstrap, "BoundSshBootstrapTransport", Transport)

    def execute(*args: object, **kwargs: object) -> bootstrap.BootstrapResult:
        observed["execute"] = kwargs
        return bootstrap.BootstrapResult(
            receipt_id="receipt-lan",
            outcome="success",
            phases=("lan_ssh_host_key_rotated",),
            receipt_path=str(tmp_path / "receipt.json"),
            returned_serial=plan.target_serial,
            returned_firmware=plan.expected_firmware,
            returned_phy="ad9361",
        )

    monkeypatch.setattr(bootstrap, "execute_lan_flash_plan", execute)

    result = runner.invoke(
        app,
        [
            "firmware",
            "flash-lan",
            str(image),
            "--serial",
            plan.target_serial,
            "--host",
            plan.host,
            "--profile",
            plan.mutation_profile_id,
            "--ssh-known-hosts-file",
            str(known_hosts),
            "--ssh-password-file",
            str(password),
            "--execute",
            "--confirm",
            plan.confirmation_phrase,
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed["transport"] == {
        "interface": None,
        "password": "secret",
        "known_hosts_file": known_hosts.resolve(),
        "host": plan.host,
    }
    execution = observed["execute"]
    assert isinstance(execution, dict)
    assert callable(execution["host_key_rotator"])
    assert json.loads(result.stdout)["returned_firmware"] == plan.expected_firmware
