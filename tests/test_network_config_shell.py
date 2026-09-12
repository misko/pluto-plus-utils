"""Exercise the actual radio shell scripts with a minimal BusyBox-like PATH."""
from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pluto_plus.ip_firmware import _NETWORK_APPLY_SCRIPT, _NETWORK_INSPECT_SCRIPT
from pluto_plus.network_config import persistent_environment_sha256


@pytest.fixture
def radio_shell(tmp_path: Path) -> tuple[Path, dict[str, str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("cat", "sed", "tr", "sha256sum", "awk", "mkdir", "chmod", "sync", "rm"):
        source = shutil.which(name)
        assert source is not None
        (bin_dir / name).symlink_to(source)
    values = {
        "ipaddr": "192.168.2.1", "ipaddr_host": "192.168.2.10",
        "netmask": "255.255.255.0", "ipaddr_eth": "",
        "netmask_eth": "255.255.255.0",
    }
    (tmp_path / "environment").write_text(
        "hostname=pluto\n" + "".join(f"{k}={v}\n" for k, v in values.items())
    )
    (tmp_path / "serial").write_text("SERIAL_A\n")
    (tmp_path / "config").write_text("[WLAN]\npwd_wlan = secret\n[NETWORK]\n")
    scripts = {
        "fw_printenv": '''from pathlib import Path
import sys
values = Path("environment").read_text()
if len(sys.argv) > 1:
    key = sys.argv[-1]
    print(dict(line.split("=", 1) for line in values.splitlines()).get(key, ""))
else:
    print(values, end="")
''',
        "fw_setenv": '''from pathlib import Path
import sys
Path("mutation").touch()
values = dict(line.split("=", 1) for line in Path("environment").read_text().splitlines())
for line in Path(sys.argv[-1]).read_text().splitlines():
    key, _, value = line.partition(" ")
    values[key] = value
Path("environment").write_text("".join(f"{k}={v}\\n" for k, v in values.items()))
''',
        "ip": 'print("    inet 192.168.1.174/24 scope global eth0")\n',
    }
    for name, body in scripts.items():
        path = bin_dir / name
        path.write_text(f"#!{sys.executable}\n" + body)
        path.chmod(0o700)
    return tmp_path, values


def run_script(root: Path, script: bytes, *args: str) -> subprocess.CompletedProcess[bytes]:
    script = script.replace(
        b"/sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber",
        os.fsencode(root / "serial"),
    ).replace(b"/opt/config.txt", os.fsencode(root / "config")).replace(
        b"/root/.pluto-plus-network-config", os.fsencode(root / "backups")
    )
    return subprocess.run(
        ["/bin/sh", "-s", "--", "SERIAL_A", *args], input=script,
        cwd=root, env={"PATH": str(root / "bin")}, capture_output=True, check=False,
    )


@pytest.mark.parametrize("encoder", ["base64", "uuencode"])
@pytest.mark.parametrize("password", [b"secret\n", b"\r\n", b"secret\r\n"])
def test_network_scripts_encode_config_and_complete_backup(
    radio_shell: tuple[Path, dict[str, str]], encoder: str, password: bytes,
) -> None:
    root, values = radio_shell
    (root / "config").write_bytes(b"[WLAN]\r\npwd_wlan = " + password)
    if encoder == "uuencode":
        busybox = shutil.which("busybox")
        if busybox is None:
            pytest.skip("BusyBox is required to exercise its actual uuencode applet")
        (root / "bin" / encoder).symlink_to(busybox)
    else:
        source = shutil.which("base64")
        assert source is not None
        (root / "bin" / encoder).symlink_to(source)
    result = run_script(root, _NETWORK_INSPECT_SCRIPT)
    assert result.returncode == 0, result.stderr
    fields = dict(line.split(b"\t", 2)[1:] for line in result.stdout.splitlines())
    redacted = base64.b64decode(fields[b"config_txt_redacted_b64"], validate=True)
    assert b"secret" not in redacted
    assert b"pwd_wlan = <redacted>" in redacted
    assert all(b"<redacted>" in line for line in redacted.splitlines()
               if line.lstrip().startswith(b"pwd_wlan"))
    backup = (root / "environment").read_bytes()
    result = run_script(
        root, _NETWORK_APPLY_SCRIPT, persistent_environment_sha256(values),
        "a" * 32, "ipaddr_eth", "192.168.1.22",
    )
    assert result.returncode == 0, result.stderr
    fields = dict(line.split(b"\t", 2)[1:] for line in result.stdout.splitlines())
    assert base64.b64decode(fields[b"backup_b64"], validate=True) == backup
    assert fields[b"backup_sha256"].decode() == hashlib.sha256(backup).hexdigest()
    assert fields[b"mutation_completed"] == b"1"
    assert b"ipaddr_eth=192.168.1.22\n" in (root / "environment").read_bytes()


@pytest.mark.parametrize("encoder", [None, "base64", "uuencode"])
def test_missing_or_failed_encoder_stops_before_mutation(
    radio_shell: tuple[Path, dict[str, str]], encoder: str | None,
) -> None:
    root, values = radio_shell
    if encoder is not None:
        executable = root / "bin" / encoder
        executable.write_text("#!/bin/sh\nprintf partial\nexit 1\n")
        executable.chmod(0o700)
    inspected = run_script(root, _NETWORK_INSPECT_SCRIPT)
    assert inspected.returncode != 0
    applied = run_script(
        root, _NETWORK_APPLY_SCRIPT, persistent_environment_sha256(values),
        "a" * 32, "ipaddr_eth", "192.168.1.22",
    )
    assert applied.returncode != 0
    assert not (root / "mutation").exists()
