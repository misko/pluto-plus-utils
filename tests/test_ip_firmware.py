from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Callable, Sequence
from pathlib import Path

import pytest

from pluto_plus.firmware import (
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
    FirmwareExecutorFailure,
    RadioFirmwareIdentity,
)
from pluto_plus.ip_firmware import (
    IpFirmwareAttestation,
    IpFirmwareEnrollment,
    IpFirmwareError,
    IpFirmwareExecutor,
    IpFirmwareHostKeyChanged,
    IpFirmwareQspiEvidence,
    IpFirmwareStagedFile,
    PinnedSshFirmwareTransport,
    SshCommandResult,
    UsbSshRouteAmbiguous,
    require_unambiguous_usb_ssh_route,
)
from pluto_plus.network_config import (
    NetworkAddressMode,
    NetworkConfigIdentity,
    NetworkConfigManager,
    NetworkInterface,
    persistent_environment_sha256,
)


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _frm() -> bytes:
    fit = _fit()
    md5 = hashlib.md5(fit, usedforsecurity=False).hexdigest().encode()  # noqa: S324
    return fit + md5 + b"\n"


FINGERPRINT = "SHA256:" + "A" * 43


def _ip_json_reader(
    *,
    addresses: dict[str, tuple[str, ...]],
    routes: tuple[tuple[str, str], ...],
) -> Callable[[Sequence[str]], str]:
    address_json = json.dumps(
        [
            {
                "ifname": name,
                "addr_info": [
                    {"family": "inet", "local": address, "prefixlen": 24}
                    for address in values
                ],
            }
            for name, values in addresses.items()
        ]
    )
    route_json = json.dumps([{"dev": dev, "dst": dst} for dev, dst in routes])

    def read(argv: Sequence[str]) -> str:
        return address_json if "address" in argv else route_json

    return read


def test_usb_ssh_route_accepts_one_unique_interface_and_route() -> None:
    observation = require_unambiguous_usb_ssh_route(
        "enx_path_a",
        "192.168.2.1",
        ip_json_reader=_ip_json_reader(
            addresses={"enx_path_a": ("192.168.2.10",), "eth0": ("192.168.1.10",)},
            routes=(("enx_path_a", "192.168.2.0/24"),),
        ),
    )

    assert observation.destination_routes == (("enx_path_a", "192.168.2.0/24"),)


def test_usb_path_a_refuses_duplicate_source_address_that_can_reach_path_b() -> None:
    with pytest.raises(UsbSshRouteAmbiguous, match="BindInterface alone"):
        require_unambiguous_usb_ssh_route(
            "enx_path_a",
            "192.168.2.1",
            ip_json_reader=_ip_json_reader(
                addresses={
                    "enx_path_a": ("192.168.2.10",),
                    "enx_path_b": ("192.168.2.10",),
                },
                routes=(
                    ("enx_path_a", "192.168.2.0/24"),
                    ("enx_path_b", "192.168.2.0/24"),
                ),
            ),
        )


def test_usb_ssh_route_accepts_strictly_less_specific_lan_route() -> None:
    """A /22 LAN route cannot win against the USB /24 under longest-prefix match.

    Handing out a prefix shorter than /24 that happens to cover the USB subnet
    is ordinary DHCP behaviour, and the kernel will still select the USB
    interface.  Refusing it made the guarded SSH firmware and canonical setup
    paths unusable on such hosts without readdressing the LAN.
    """
    observation = require_unambiguous_usb_ssh_route(
        "enx_path_a",
        "192.168.2.1",
        ip_json_reader=_ip_json_reader(
            addresses={"enx_path_a": ("192.168.2.10",), "eth0": ("192.168.1.10",)},
            routes=(
                ("enx_path_a", "192.168.2.0/24"),
                ("eth0", "192.168.0.0/22"),
            ),
        ),
    )

    assert ("eth0", "192.168.0.0/22") in observation.destination_routes


def test_usb_ssh_route_refuses_equally_specific_competing_route() -> None:
    """Equal prefix length is a genuine tie, broken only by metric."""
    with pytest.raises(UsbSshRouteAmbiguous, match=r"192\.168\.2\.0/24 via eth0"):
        require_unambiguous_usb_ssh_route(
            "enx_path_a",
            "192.168.2.1",
            ip_json_reader=_ip_json_reader(
                addresses={"enx_path_a": ("192.168.2.10",), "eth0": ("192.168.1.10",)},
                routes=(
                    ("enx_path_a", "192.168.2.0/24"),
                    ("eth0", "192.168.2.0/24"),
                ),
            ),
        )


def test_usb_ssh_route_refuses_more_specific_competing_route() -> None:
    """A longer prefix elsewhere actively steals the destination."""
    with pytest.raises(UsbSshRouteAmbiguous, match=r"192\.168\.2\.0/25 via eth0"):
        require_unambiguous_usb_ssh_route(
            "enx_path_a",
            "192.168.2.1",
            ip_json_reader=_ip_json_reader(
                addresses={"enx_path_a": ("192.168.2.10",), "eth0": ("192.168.1.10",)},
                routes=(
                    ("enx_path_a", "192.168.2.0/24"),
                    ("eth0", "192.168.2.0/25"),
                ),
            ),
        )


def test_usb_ssh_route_uses_most_specific_bound_route_as_the_threshold() -> None:
    """With several routes on the bound interface, the longest one governs."""
    observation = require_unambiguous_usb_ssh_route(
        "enx_path_a",
        "192.168.2.1",
        ip_json_reader=_ip_json_reader(
            addresses={"enx_path_a": ("192.168.2.10",), "eth0": ("192.168.1.10",)},
            routes=(
                ("enx_path_a", "192.168.2.0/24"),
                ("enx_path_a", "192.168.2.0/25"),
                ("eth0", "192.168.2.0/24"),
            ),
        ),
    )

    assert ("eth0", "192.168.2.0/24") in observation.destination_routes


def _enrollment() -> IpFirmwareEnrollment:
    return IpFirmwareEnrollment(
        endpoint="192.168.2.15",
        serial="SERIAL_A",
        board_model="Analog Devices PlutoSDR Rev.C",
        observed_firmware="old-v1",
        host_key_fingerprint=FINGERPRINT,
    )


def _attestation(
    *, firmware: str = "old-v1", boot_id: str = "boot-before"
) -> IpFirmwareAttestation:
    enrollment = _enrollment()
    return IpFirmwareAttestation(
        serial=enrollment.serial,
        board_model=enrollment.board_model,
        active_firmware=firmware,
        boot_id=boot_id,
        endpoint=enrollment.endpoint,
        host_key_fingerprint=enrollment.host_key_fingerprint,
    )


def _radio(*, firmware: str = "old-v1") -> RadioFirmwareIdentity:
    enrollment = _enrollment()
    return RadioFirmwareIdentity(
        serial=enrollment.serial,
        usb_sysfs_path=None,
        observed_firmware=firmware,
        endpoint=enrollment.endpoint,
        host_key_fingerprint=enrollment.host_key_fingerprint,
    )


class FakeMonotonic:
    def __init__(self) -> None:
        self.value = 0.0

    def __call__(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.value += duration


class FakeTransport:
    endpoint = "192.168.2.15"
    host_key_fingerprint = FINGERPRINT

    def __init__(self) -> None:
        self.events: list[str] = []
        self.attestations: list[IpFirmwareAttestation | BaseException] = [
            _attestation(),
            _attestation(firmware="new-v2", boot_id="boot-after"),
        ]
        self.fail_at: str | None = None
        self.update_output = "Done\n"
        self.staged_override: IpFirmwareStagedFile | None = None
        self.qspi_override: IpFirmwareQspiEvidence | None = None

    def _event(self, name: str) -> None:
        self.events.append(name)
        if self.fail_at == name:
            raise RuntimeError(f"synthetic {name} failure")

    def attest(self) -> IpFirmwareAttestation:
        self._event("attest")
        value = self.attestations.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value

    def ensure_tx_safe(self, serial: str) -> None:
        assert serial == "SERIAL_A"
        self._event("tx_safe")

    def stage_frm(self, data: bytes) -> IpFirmwareStagedFile:
        self._event("stage")
        return self.staged_override or IpFirmwareStagedFile(
            hashlib.sha256(data).hexdigest(), len(data)
        )

    def invoke_update_frm(self) -> str:
        self._event("update")
        return self.update_output

    def inspect_mtd3(self, fit_size: int) -> IpFirmwareQspiEvidence:
        self._event("mtd3")
        fit = _fit()
        assert fit_size == len(fit)
        return self.qspi_override or IpFirmwareQspiEvidence(
            fit_sha256=hashlib.sha256(fit).hexdigest(),
            fit_size=len(fit),
            header_hex=fit[:8].hex(),
        )

    def cleanup_stage(self) -> None:
        self._event("cleanup")

    def sync(self) -> None:
        self._event("sync")

    def reset(self) -> None:
        self._event("reset")


def _executor(
    tmp_path: Path,
    transport: FakeTransport,
    *,
    expected_firmware: str | None = "new-v2",
    post_reset_probe=None,
    post_reset_tx_guard=None,
) -> IpFirmwareExecutor:
    monotonic = FakeMonotonic()
    return IpFirmwareExecutor(
        enrollment=_enrollment(),
        transport=transport,
        evidence_directory=(tmp_path / "evidence").absolute(),
        expected_firmware=expected_firmware,
        post_reset_probe=post_reset_probe,
        post_reset_tx_guard=post_reset_tx_guard,
        return_timeout_s=2,
        poll_interval_s=1,
        monotonic=monotonic,
        sleep=monotonic.sleep,
    )


def _image(tmp_path: Path) -> Path:
    path = tmp_path / "pluto.frm"
    path.write_bytes(_frm())
    return path


def test_happy_path_is_fixed_order_hashes_fit_and_journals(tmp_path: Path) -> None:
    transport = FakeTransport()
    executor = _executor(tmp_path, transport)

    executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert transport.events == [
        "attest",
        "tx_safe",
        "stage",
        "update",
        "mtd3",
        "cleanup",
        "sync",
        "reset",
        "attest",
        "tx_safe",
    ]
    evidence = executor.last_evidence
    assert evidence is not None
    assert evidence.outcome == "verified"
    assert evidence.frm_sha256 == hashlib.sha256(_frm()).hexdigest()
    assert evidence.fit_sha256 == hashlib.sha256(_fit()).hexdigest()
    assert evidence.fit_size == len(_fit())
    assert evidence.qspi is not None
    document = json.loads((tmp_path / "evidence" / f"{evidence.attempt_id}.json").read_text())
    assert document["outcome"] == "verified"
    assert document["mutation_dispatched"] is True
    assert (tmp_path / "evidence").stat().st_mode & 0o077 == 0


def test_identity_or_active_firmware_change_fails_before_upload(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.attestations[0] = _attestation(firmware="changed")
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert caught.value.outcome == "failed"
    assert caught.value.failure_phase == "remote_preflight"
    assert caught.value.reconciliation_required is False
    assert transport.events == ["attest"]
    assert caught.value.evidence_reference == executor.last_evidence.attempt_id  # type: ignore[union-attr]


@pytest.mark.parametrize("failure", ["tx_safe", "stage"])
def test_pre_updater_faults_never_invoke_update(
    tmp_path: Path, failure: str
) -> None:
    transport = FakeTransport()
    transport.fail_at = failure
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert caught.value.outcome == "failed"
    assert "update" not in transport.events
    assert executor.last_evidence is not None
    assert executor.last_evidence.mutation_dispatched is False


def test_remote_stage_hash_mismatch_never_invokes_updater(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.staged_override = IpFirmwareStagedFile("0" * 64, len(_frm()))

    with pytest.raises(FirmwareExecutorFailure) as caught:
        _executor(tmp_path, transport).flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.outcome == "failed"
    assert transport.events[-2:] == ["stage", "cleanup"]


@pytest.mark.parametrize("output", ["Failed\n", "Done\nFailed\n", "", "updated\n"])
def test_update_requires_done_and_rejects_failed_even_exit_zero(
    tmp_path: Path, output: str
) -> None:
    transport = FakeTransport()
    transport.update_output = output
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert caught.value.outcome == "unknown"
    assert caught.value.failure_phase == "update_frm"
    assert caught.value.reconciliation_required is True
    assert "mtd3" not in transport.events
    assert executor.last_evidence is not None
    assert executor.last_evidence.updater_output == output


def test_qspi_body_mismatch_prevents_reset_and_is_uncertain(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.qspi_override = IpFirmwareQspiEvidence(
        fit_sha256="0" * 64,
        fit_size=len(_fit()),
        header_hex=_fit()[:8].hex(),
    )

    with pytest.raises(FirmwareExecutorFailure) as caught:
        _executor(tmp_path, transport).flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.failure_phase == "qspi_verification"
    assert caught.value.outcome == "unknown"
    assert "reset" not in transport.events


@pytest.mark.parametrize("failure", ["cleanup", "sync", "reset"])
def test_post_update_transport_faults_are_reconcilable_unknown(
    tmp_path: Path, failure: str
) -> None:
    transport = FakeTransport()
    transport.fail_at = failure

    with pytest.raises(FirmwareExecutorFailure) as caught:
        _executor(tmp_path, transport).flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.outcome == "unknown"
    assert caught.value.reconciliation_required is True
    assert "qspi_fit_verified" in caught.value.completed_phases


def test_return_timeout_is_unknown_after_qspi_verification(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.attestations[1:] = [RuntimeError("offline"), RuntimeError("offline")]

    with pytest.raises(FirmwareExecutorFailure) as caught:
        _executor(tmp_path, transport).flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.failure_phase == "post_reset_attestation"
    assert caught.value.outcome == "unknown"
    assert "qspi_fit_verified" in caught.value.completed_phases


def test_post_reset_tx_guard_failure_is_unknown(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.fail_at = "tx_safe"
    # Permit the first TX guard and fail the second.
    calls = 0

    def selective(serial: str) -> None:
        nonlocal calls
        calls += 1
        transport.events.append("tx_safe")
        if calls == 2:
            raise RuntimeError("unsafe TX")

    transport.ensure_tx_safe = selective  # type: ignore[method-assign]

    with pytest.raises(FirmwareExecutorFailure) as caught:
        _executor(tmp_path, transport).flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.failure_phase == "tx_safe_after_reset"
    assert caught.value.outcome == "unknown"


def test_host_key_rotation_never_auto_trusts_and_locks_future_mutation(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()
    transport.attestations[1] = IpFirmwareHostKeyChanged("key changed")
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert caught.value.outcome == "unknown"
    assert executor.key_reconciliation_required is True
    assert executor.last_evidence is not None
    assert executor.last_evidence.key_reconciliation_required is True
    with pytest.raises(Exception, match="stale"):
        executor.authorize_execution()


def test_independent_return_and_tx_guard_remain_unknown_after_stale_key(
    tmp_path: Path,
) -> None:
    transport = FakeTransport()
    transport.attestations[1] = IpFirmwareHostKeyChanged("key changed")
    identity = RadioFirmwareIdentity(
        serial="SERIAL_A",
        usb_sysfs_path=None,
        observed_firmware="new-v2",
        endpoint="192.168.2.15",
        host_key_fingerprint=None,
    )
    executor = _executor(
        tmp_path,
        transport,
        post_reset_probe=lambda _serial: identity,
        post_reset_tx_guard=lambda _serial: True,
    )

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="pluto.frm"
        )

    assert caught.value.outcome == "unknown"
    assert caught.value.failure_phase == "ssh_reenrollment_required"
    assert caught.value.reconciliation_required is True
    assert executor.last_evidence is not None
    assert executor.last_evidence.outcome == "unknown"
    assert executor.last_evidence.after is not None
    assert executor.last_evidence.after.host_key_fingerprint == (
        "unverified:host-key-changed"
    )
    assert executor.last_evidence.key_reconciliation_required is True
    assert executor.key_reconciliation_required is True


def test_reconcile_requires_active_firmware_tx_safe_and_exact_fit(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.attestations = [_attestation(firmware="new-v2", boot_id="returned")]
    executor = _executor(tmp_path, transport)

    phases = executor.reconcile_persistent_qspi(
        _radio(),
        expected_firmware="new-v2",
        expected_fit_sha256=hashlib.sha256(_fit()).hexdigest(),
        expected_fit_size=len(_fit()),
    )

    assert phases == (
        "reconciled_remote_attestation",
        "reconciled_tx_safe",
        "reconciled_qspi_fit_verified",
    )
    assert transport.events == ["attest", "tx_safe", "mtd3"]


def test_reconcile_fit_mismatch_remains_unknown(tmp_path: Path) -> None:
    transport = FakeTransport()
    transport.attestations = [_attestation(firmware="new-v2", boot_id="returned")]
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.reconcile_persistent_qspi(
            _radio(),
            expected_firmware="new-v2",
            expected_fit_sha256="0" * 64,
            expected_fit_size=len(_fit()),
        )

    assert caught.value.outcome == "unknown"
    assert caught.value.reconciliation_required is True


def test_rejects_volatile_mode_direct_paths_and_generic_target(tmp_path: Path) -> None:
    transport = FakeTransport()
    executor = _executor(tmp_path, transport)
    with pytest.raises(FirmwareExecutorFailure, match="does not permit volatile"):
        executor.load_volatile_dfu(_radio(), _image(tmp_path))
    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(
            _radio(), _image(tmp_path), target_name="/dev/mtd3"
        )
    assert caught.value.outcome == "failed"
    assert transport.events == []


def test_evidence_directory_symlink_fails_before_any_remote_action(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "evidence").symlink_to(target, target_is_directory=True)
    transport = FakeTransport()
    executor = _executor(tmp_path, transport)

    with pytest.raises(FirmwareExecutorFailure) as caught:
        executor.flash_persistent_qspi(_radio(), _image(tmp_path), target_name="pluto.frm")

    assert caught.value.outcome == "failed"
    assert caught.value.reconciliation_required is False
    assert caught.value.failure_phase == "evidence_initialization"
    assert transport.events == []


class RecordingSshRunner:
    def __init__(self, results: list[SshCommandResult]) -> None:
        self.results = results
        self.calls: list[tuple[tuple[str, ...], bytes | None, float]] = []

    def run(
        self, argv: Sequence[str], *, stdin: bytes | None, timeout_s: float
    ) -> SshCommandResult:
        self.calls.append((tuple(argv), stdin, timeout_s))
        return self.results.pop(0)


def _ssh_transport(tmp_path: Path, runner: RecordingSshRunner) -> PinnedSshFirmwareTransport:
    key_bytes = b"test host key bytes"
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text(
        f"192.168.2.15 ssh-ed25519 {base64.b64encode(key_bytes).decode()}\n"
    )
    private_key = tmp_path / "id_ed25519"
    private_key.write_text("not-used-by-fake-runner")
    known_hosts.chmod(0o600)
    private_key.chmod(0o600)
    return PinnedSshFirmwareTransport(
        endpoint="192.168.2.15",
        known_hosts_file=known_hosts,
        private_key_file=private_key,
        command_runner=runner,
    )


def test_pinned_ssh_transport_uses_key_only_strict_host_checking_and_fixed_updater(
    tmp_path: Path,
) -> None:
    runner = RecordingSshRunner([SshCommandResult(0, b"Done\n", b"")])
    transport = _ssh_transport(tmp_path, runner)

    assert transport.invoke_update_frm() == "Done\n"
    argv, stdin, _timeout = runner.calls[0]
    assert stdin is None
    assert "BatchMode=yes" in argv
    assert "StrictHostKeyChecking=yes" in argv
    assert "GlobalKnownHostsFile=/dev/null" in argv
    assert "PasswordAuthentication=no" in argv
    assert argv[-1] == "/sbin/update_frm.sh /root/.pluto-plus-ip-firmware/pluto.frm"
    assert all("mtd" not in argument for argument in argv)


def test_concrete_transport_accepts_only_its_fixed_attest_stage_and_mtd3_scripts(
    tmp_path: Path,
) -> None:
    fit = _fit()
    runner = RecordingSshRunner(
        [
            SshCommandResult(
                0,
                (
                    b"PPU\tserial\tSERIAL_A\n"
                    b"PPU\tboard_model\tAnalog Devices PlutoSDR Rev.C\n"
                    b"PPU\tactive_firmware\told-v1\n"
                    b"PPU\tboot_id\tboot-a\n"
                ),
                b"",
            ),
            SshCommandResult(
                0,
                (
                    f"PPU\tstage_sha256\t{hashlib.sha256(_frm()).hexdigest()}\n"
                    f"PPU\tstage_size\t{len(_frm())}\n"
                ).encode(),
                b"",
            ),
            SshCommandResult(
                0,
                (
                    f"PPU\theader_hex\t{fit[:8].hex()}\n"
                    f"PPU\tfit_size\t{len(fit)}\n"
                    f"PPU\tfit_sha256\t{hashlib.sha256(fit).hexdigest()}\n"
                ).encode(),
                b"",
            ),
        ]
    )
    transport = _ssh_transport(tmp_path, runner)

    assert transport.attest().serial == "SERIAL_A"
    assert transport.stage_frm(_frm()).size == len(_frm())
    assert transport.inspect_mtd3(len(fit)).fit_sha256 == hashlib.sha256(fit).hexdigest()

    attest_call, stage_call, mtd_call = runner.calls
    assert "\n" in attest_call[0][-1]
    assert stage_call[1] == _frm()
    assert mtd_call[0][-1] == f"/bin/sh -s -- {len(fit)}"
    assert mtd_call[1] is not None


def test_pinned_transport_reads_redacted_config_and_applies_only_bound_network_plan(
    tmp_path: Path,
) -> None:
    before_values = {
        "ipaddr": "192.168.2.1",
        "ipaddr_host": "192.168.2.10",
        "netmask": "255.255.255.0",
        "ipaddr_eth": "",
        "netmask_eth": "255.255.255.0",
    }
    after_values = {**before_values, "ipaddr_eth": "192.168.1.165"}
    redacted = b"[WLAN]\r\npwd_wlan = <redacted>\r\n"
    backup = b"hostname=pluto\nipaddr_eth=\n"

    def inspection(values: dict[str, str]) -> SshCommandResult:
        lines = [
            "PPU\tserial\tSERIAL_A",
            "PPU\thostname\tpluto",
            *(f"PPU\t{key}\t{value}" for key, value in values.items()),
            f"PPU\tenvironment_sha256\t{persistent_environment_sha256(values)}",
            f"PPU\tconfig_txt_sha256\t{hashlib.sha256(b'original').hexdigest()}",
            f"PPU\tconfig_txt_redacted_b64\t{base64.b64encode(redacted).decode()}",
        ]
        return SshCommandResult(0, ("\n".join(lines) + "\n").encode(), b"")

    runner = RecordingSshRunner(
        [
            inspection(before_values),
            inspection(before_values),
            inspection(before_values),
            SshCommandResult(
                0,
                (
                    "PPU\tserial\tSERIAL_A\n"
                    "PPU\tbackup_path\t/root/.pluto-plus-network-config/plan.env\n"
                    f"PPU\tbackup_sha256\t{hashlib.sha256(backup).hexdigest()}\n"
                    f"PPU\tbackup_b64\t{base64.b64encode(backup).decode()}\n"
                    f"PPU\tenvironment_sha256\t{persistent_environment_sha256(after_values)}\n"
                    "PPU\tmutation_completed\t1\n"
                ).encode(),
                b"",
            ),
            inspection(after_values),
        ]
    )
    transport = _ssh_transport(tmp_path, runner)
    identity = NetworkConfigIdentity(
        serial="SERIAL_A",
        endpoint=transport.endpoint,
        host_key_fingerprint=transport.host_key_fingerprint,
    )
    manager = NetworkConfigManager(
        identity=identity,
        backend=transport,
        receipt_directory=tmp_path / "network-receipts",
    )
    observed = manager.inspect()
    assert "<redacted>" in observed.config_txt_redacted
    planned = manager.create_plan(
        interface=NetworkInterface.ETHERNET,
        mode=NetworkAddressMode.STATIC,
        address="192.168.1.165",
        netmask="255.255.255.0",
        host_address=None,
    )
    receipt = manager.execute(
        planned.plan,
        planned.confirmation_token,
        planned.plan.confirmation,
    )
    assert receipt.success is True
    assert receipt.backup_path is not None
    assert Path(receipt.backup_path).read_bytes() == backup
    apply_argv, apply_stdin, _timeout = runner.calls[3]
    assert apply_argv[-1].endswith(
        " ipaddr_eth 192.168.1.165"
    )
    assert apply_stdin is not None
    assert b"fw_setenv -s" in apply_stdin
    assert b"device_reboot" not in apply_stdin


def test_pinned_transport_rejects_hostnames_loose_files_and_changed_key(
    tmp_path: Path,
) -> None:
    runner = RecordingSshRunner([])
    with pytest.raises(ValueError, match="literal IP"):
        PinnedSshFirmwareTransport(
            endpoint="pluto.local",
            known_hosts_file=tmp_path / "missing",
            private_key_file=tmp_path / "missing-key",
            command_runner=runner,
        )

    good_runner = RecordingSshRunner(
        [
            SshCommandResult(
                255,
                b"",
                b"WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
            )
        ]
    )
    transport = _ssh_transport(tmp_path, good_runner)
    with pytest.raises(IpFirmwareHostKeyChanged):
        transport.invoke_update_frm()

    private_key = tmp_path / "id_ed25519"
    private_key.chmod(0o644)
    with pytest.raises(ValueError, match="group/other"):
        PinnedSshFirmwareTransport(
            endpoint="192.168.2.15",
            known_hosts_file=tmp_path / "known_hosts",
            private_key_file=private_key,
            command_runner=runner,
        )


def test_pinned_transport_rejects_credential_file_changes_after_enrollment(
    tmp_path: Path,
) -> None:
    runner = RecordingSshRunner([SshCommandResult(0, b"Done\n", b"")])
    transport = _ssh_transport(tmp_path, runner)
    (tmp_path / "known_hosts").write_text(
        f"192.168.2.15 ssh-ed25519 {base64.b64encode(b'replacement').decode()}\n"
    )

    with pytest.raises(IpFirmwareError, match="changed after enrollment"):
        transport.invoke_update_frm()

    assert runner.calls == []
