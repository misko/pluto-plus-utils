from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pluto_plus.bootstrap_firmware as bootstrap
from pluto_plus.cli import app

runner = CliRunner()


def _facts() -> dict[str, object]:
    return {
        "hw_serial": "SERIAL_A",
        "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
        "fw_version": bootstrap.CANONICAL_POLICY.device_firmware,
        "ad9361-phy,model": "ad9361",
        "iio,buffer-metadata": "1",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc"),
        "cf-ad9361-lpc,scan_channels": (
            "voltage0",
            "voltage1",
            "voltage2",
            "voltage3",
        ),
    }


def test_lan_ssh_enrollment_cli_dry_run_names_weaker_trust_and_exact_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap, "_inspect_iio_context", lambda host: _facts())
    destination = tmp_path / "SERIAL_A.known_hosts"

    result = runner.invoke(
        app,
        [
            "firmware",
            "enroll-lan-ssh",
            "SERIAL_A",
            "--host",
            "192.168.1.20",
            "--known-hosts-file",
            str(destination),
            "--profile",
            "libiio-metadata-v6",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["will_trust_host_key"] is False
    assert "weaker than USB-anchored" in payload["warning"]
    assert payload["plan"]["trust_model"] == "explicit_lan_tofu"
    assert payload["plan"]["confirmation_phrase"] == (
        "TRUST LAN SSH SERIAL_A 192.168.1.20"
    )
    assert not destination.exists()


def test_lan_ssh_enrollment_cli_rejects_wrong_confirmation_before_default_password_use(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap, "_inspect_iio_context", lambda host: _facts())
    destination = tmp_path / "SERIAL_A.known_hosts"

    result = runner.invoke(
        app,
        [
            "firmware",
            "enroll-lan-ssh",
            "SERIAL_A",
            "--host",
            "192.168.1.20",
            "--known-hosts-file",
            str(destination),
            "--profile",
            "libiio-metadata-v6",
            "--execute",
            "--use-default-password",
            "--confirm",
            "TRUST LAN SSH SERIAL_A 192.168.1.21",
        ],
    )

    assert result.exit_code == 2
    error = json.loads(result.stderr)["error"]
    assert error["code"] == "lan_ssh_confirmation_required"
    assert "TRUST LAN SSH SERIAL_A 192.168.1.20" in error["message"]
    assert not destination.exists()

    missing_authorization = runner.invoke(
        app,
        [
            "firmware",
            "enroll-lan-ssh",
            "SERIAL_A",
            "--host",
            "192.168.1.20",
            "--known-hosts-file",
            str(destination),
            "--profile",
            "libiio-metadata-v6",
            "--execute",
            "--confirm",
            "TRUST LAN SSH SERIAL_A 192.168.1.20",
        ],
    )
    assert missing_authorization.exit_code == 2
    authorization_error = json.loads(missing_authorization.stderr)["error"]
    assert authorization_error["code"] == "lan_ssh_default_password_authorization_required"
    assert not destination.exists()
