from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pluto_plus.doctor import CANONICAL_POLICY, CANONICAL_UBOOT
from pluto_plus.setup import (
    SetupExecutorFailure,
    SetupIdentity,
    SetupObservation,
    SetupPlan,
)
from pluto_plus.setup_helper import (
    BoundSshTransport,
    FixedSshSetupExecutor,
    SetupHelperError,
    SetupTransport,
)


def test_bound_ssh_transport_supports_private_lan_without_usb_bind(
    tmp_path: Path,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)

    transport = BoundSshTransport(
        host="192.168.1.14",
        interface=None,
        password="analog",
        known_hosts_file=known_hosts,
    )

    assert transport.host == "192.168.1.14"
    assert transport.interface is None


def test_bound_ssh_transport_rejects_public_or_named_hosts(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)

    for host in ("example.com", "8.8.8.8"):
        with pytest.raises(ValueError):
            BoundSshTransport(
                host=host,
                interface=None,
                password="analog",
                known_hosts_file=known_hosts,
            )


def test_bound_ssh_transport_refuses_route_ambiguity_before_setup(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)

    def ambiguous() -> None:
        raise SetupHelperError(
            "USB-bound SSH interface 'enx_path_a' is ambiguous; BindInterface alone is unsafe"
        )

    with pytest.raises(ValueError, match="BindInterface alone"):
        BoundSshTransport(
            host="192.168.2.1",
            interface="enx_path_a",
            password="analog",
            known_hosts_file=known_hosts,
            route_preflight=ambiguous,
        )


def test_bound_ssh_transport_rechecks_route_before_each_operation(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)
    checks = 0

    def topology_changes_after_enrollment() -> None:
        nonlocal checks
        checks += 1
        if checks > 1:
            raise SetupHelperError("competing route appeared; refusing mutation")

    transport = BoundSshTransport(
        host="192.168.2.1",
        interface="enx_path_a",
        password="analog",
        known_hosts_file=known_hosts,
        route_preflight=topology_changes_after_enrollment,
    )

    with pytest.raises(SetupHelperError, match="refusing mutation"):
        transport.run("fw_printenv mode")

    assert checks == 2


class RecordingTransport(SetupTransport):
    def __init__(self) -> None:
        self.commands: list[tuple[str, bytes | None]] = []
        self.responses: list[str] = []

    def run(self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15) -> str:
        self.commands.append((command, stdin))
        return self.responses.pop(0)


def _identity() -> SetupIdentity:
    return SetupIdentity(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        observed_firmware=CANONICAL_POLICY.device_firmware,
    )


def _observation(*, canonical: bool, tx_safe: bool) -> SetupObservation:
    return SetupObservation(
        identity=_identity(),
        board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
        live_phy_model="ad9361" if canonical else "ad9363a",
        uboot=(
            dict(CANONICAL_UBOOT)
            if canonical
            else {
                # The real-world reverted state: attr_name/attr_val present, which fires
                # the malformed AD9364 branch and persists mode=1r1t on every boot.
                "attr_name": "compatible",
                "attr_val": "ad9361",
                "compatible": "ad9361",
                "mode": "1r1t",
            }
        ),
        environment_sha256=("2" if canonical else "1") * 64,
        versions_sha256="3" * 64,
        qspi_firmware_sha256=CANONICAL_POLICY.fit_body_sha256,
        boot_provenance=("qspi_reboot_verified" if canonical else "qspi_image_verified"),
        rx_scan_channels=("voltage0", "voltage1", "voltage2", "voltage3"),
        tx_safe=tx_safe,
    )


def _plan(before: SetupObservation) -> SetupPlan:
    created = datetime(2026, 8, 15, tzinfo=UTC)
    return SetupPlan(
        plan_id="plan-a",
        created_at=created,
        expires_at=created + timedelta(minutes=5),
        identity=_identity(),
        profile_id=CANONICAL_POLICY.profile_id,
        environment_sha256=before.environment_sha256,
        before=before,
        changes_items=(
            ("attr_name", None),
            ("attr_val", None),
            ("mode", "2r2t"),
        ),
        tx_mute_required=not before.tx_safe,
    )


class ScriptedExecutor(FixedSshSetupExecutor):
    def __init__(
        self,
        tmp_path: Path,
        observations: list[SetupObservation],
        *,
        fail_write: bool = False,
    ) -> None:
        self.events: list[str] = []
        self._observations = iter(observations)
        self.recording_transport = RecordingTransport()
        self.recording_transport.responses.append("")
        if fail_write:
            self.recording_transport.run = self._fail_transport  # type: ignore[method-assign]
        super().__init__(
            identity=_identity(),
            transport=self.recording_transport,
            state_root=tmp_path,
        )

    def inspect(self, identity: SetupIdentity | None = None) -> SetupObservation:
        self.events.append("inspect")
        return next(self._observations)

    def _write_backup(
        self, plan: SetupPlan, observation: SetupObservation
    ) -> tuple[Path, str]:
        self.events.append("backup")
        return Path("/private/backup.json"), "4" * 64

    def _mute_transmit(self) -> None:
        self.events.append("mute")

    def _wait_for_reenumeration(self) -> None:
        self.events.append("reenumerate")

    def _fail_transport(
        self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15
    ) -> str:
        self.recording_transport.commands.append((command, stdin))
        raise SetupHelperError("synthetic write failure")


def test_executor_backs_up_before_exact_batch_write_and_reboot(tmp_path: Path) -> None:
    transport = RecordingTransport()
    executor = FixedSshSetupExecutor(
        identity=SetupIdentity(
            serial="SERIAL_A",
            usb_sysfs_path="/sys/bus/usb/devices/3-8",
            observed_firmware="v-test",
        ),
        transport=transport,
        state_root=tmp_path,
    )

    batch = executor.canonical_batch(
        {"attr_name": None, "attr_val": None, "compatible": "ad9361"}
    )
    # A line carrying no value deletes the variable in fw_setenv --script mode.
    assert batch == b"attr_name\nattr_val\ncompatible ad9361\n"
    assert b"mode" not in batch
    with pytest.raises(SetupHelperError):
        executor.canonical_batch({"arbitrary": "value"})
    assert CANONICAL_UBOOT["mode"] == "2r2t"


def test_executor_has_no_arbitrary_command_or_value_surface(tmp_path: Path) -> None:
    transport = RecordingTransport()
    executor = FixedSshSetupExecutor(
        identity=SetupIdentity(
            serial="SERIAL_A",
            usb_sysfs_path="/sys/bus/usb/devices/3-8",
            observed_firmware="v-test",
        ),
        transport=transport,
        state_root=tmp_path,
    )
    with pytest.raises(SetupHelperError):
        executor.canonical_batch({"attr_name": "$(reboot)"})


def test_provision_orders_backup_mute_exact_batch_reboot_and_verification(
    tmp_path: Path,
) -> None:
    before = _observation(canonical=False, tx_safe=False)
    executor = ScriptedExecutor(
        tmp_path,
        [
            before,
            before.model_copy(update={"tx_safe": True}),
            _observation(canonical=True, tx_safe=True),
        ],
    )

    result = executor.provision(_plan(before))

    assert executor.events == ["inspect", "backup", "mute", "inspect", "reenumerate", "inspect"]
    assert len(executor.recording_transport.commands) == 1
    command, stdin = executor.recording_transport.commands[0]
    assert before.environment_sha256 in command
    assert command.endswith("/usr/sbin/device_reboot reset")
    assert stdin == b"attr_name\nattr_val\nmode 2r2t\n"
    assert result.observation.live_phy_model == "ad9361"
    assert result.backup_path == "/private/backup.json"


def test_failure_after_backup_preserves_backup_reference_and_never_retries(
    tmp_path: Path,
) -> None:
    before = _observation(canonical=False, tx_safe=True)
    executor = ScriptedExecutor(tmp_path, [before], fail_write=True)

    with pytest.raises(SetupExecutorFailure) as caught:
        executor.provision(_plan(before))

    assert caught.value.backup_path == "/private/backup.json"
    assert caught.value.backup_sha256 == "4" * 64
    assert executor.events == ["inspect", "backup"]
    assert len(executor.recording_transport.commands) == 1


def _tx_mute_fragment() -> str:
    """The TX-attenuation step out of _MUTE_SCRIPT, runnable on its own.

    Sliced between the phy/dds guard and the DDS buffer write, so the fragment
    is whatever that step happens to be -- a hardcoded pair of writes or a loop
    over present channels. The test then judges the step by what it *does* on a
    given radio, not by how it is spelled.

    The surrounding script reads the USB gadget serial out of configfs, which
    cannot be faked without a chroot, so only this step is extracted.
    """
    from pluto_plus.setup_helper import _MUTE_SCRIPT

    text = _MUTE_SCRIPT.decode()
    start = text.index("\n", text.index('[ -n "$phy" ]')) + 1
    end = text.index('printf \'%s\\n\' 0 >"$dds/buffer/enable"')
    return 'set -eu\nphy="$1"\n' + text[start:end]


def _run_mute(tmp_path, channels):
    """Run the fragment against a phy directory exposing `channels` TX gains.

    The directory is made read-only after the attribute files are created, so
    that writing to an attribute the radio does not have fails the way it fails
    on the real part. sysfs will not create new entries; an ordinary temporary
    directory happily will, and a fake tree without this would let a preflight
    that writes to a non-existent transmitter pass here and fail on hardware --
    which is exactly how the bug reached a radio.
    """
    import os
    import subprocess

    phy = tmp_path / "phy"
    phy.mkdir()
    for ch in channels:
        (phy / f"out_voltage{ch}_hardwaregain").write_text("0.000000\n")
    os.chmod(phy, 0o555)
    try:
        proc = subprocess.run(
            ["sh", "-c", _tx_mute_fragment(), "sh", str(phy)],
            capture_output=True, text=True,
        )
        written = {
            ch: (phy / f"out_voltage{ch}_hardwaregain").read_text().strip()
            for ch in channels
        }
    finally:
        os.chmod(phy, 0o755)
    return proc, written


def test_tx_mute_succeeds_on_a_one_transmitter_radio(tmp_path):
    """A 1R1T radio has no out_voltage1_hardwaregain.

    Canonical setup exists to convert exactly such a radio to 2R2T, so a
    preflight that requires the second transmitter to already be present can
    never run on the only hardware that needs it. Writing to the absent path
    fails as `can't create ...: Permission denied`, which reads like a
    privilege problem and is not one.
    """
    proc, written = _run_mute(tmp_path, channels=[0])
    assert proc.returncode == 0, f"mute failed on a 1R1T radio: {proc.stderr}"
    assert written == {0: "-80"}


def test_tx_mute_covers_every_transmitter_on_a_two_transmitter_radio(tmp_path):
    """Skipping absent channels must not become skipping present ones."""
    proc, written = _run_mute(tmp_path, channels=[0, 1])
    assert proc.returncode == 0, proc.stderr
    assert written == {0: "-80", 1: "-80"}


def _tx_fields(*, transmitters, raws, scales, scans, gain=-80.0):
    from pluto_plus.setup_helper import _tx_safe  # noqa: F401  (import check)

    return {
        "tx_dds_raw": ",".join("0" for _ in range(raws)),
        "tx_dds_scale": ",".join("0" for _ in range(scales)),
        "tx_hardwaregain_db": ",".join(str(gain) for _ in range(transmitters)),
        "tx_buffer_enable": "0",
        "tx_data_available": "0",
        "tx_scan_enable": ",".join("0" for _ in range(scans)),
    }


def test_tx_safe_accepts_a_muted_one_transmitter_radio():
    """Measured on a Pluto+ in 1r1t: 4 DDS tones, 4 scales, 2 TX scan elements.

    Requiring the 2R2T counts here made the fail-closed check unsatisfiable on
    exactly the radios canonical setup exists to convert.
    """
    from pluto_plus.setup_helper import _tx_safe

    assert _tx_safe(_tx_fields(transmitters=1, raws=4, scales=4, scans=2))


def test_tx_safe_accepts_a_muted_two_transmitter_radio():
    from pluto_plus.setup_helper import _tx_safe

    assert _tx_safe(_tx_fields(transmitters=2, raws=8, scales=8, scans=4))


def test_tx_safe_still_rejects_an_unmuted_transmitter():
    """Accepting a second shape must not weaken what the check is for."""
    from pluto_plus.setup_helper import _tx_safe

    assert not _tx_safe(_tx_fields(transmitters=1, raws=4, scales=4, scans=2, gain=0.0))
    assert not _tx_safe(_tx_fields(transmitters=2, raws=8, scales=8, scans=4, gain=-79.0))


def test_tx_safe_rejects_a_shape_that_matches_neither_configuration():
    """A half-reported radio must not slip through as a smaller one."""
    from pluto_plus.setup_helper import _tx_safe

    assert not _tx_safe(_tx_fields(transmitters=2, raws=4, scales=4, scans=2))
    assert not _tx_safe(_tx_fields(transmitters=1, raws=8, scales=8, scans=4))
