from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import asdict, replace
from pathlib import Path

import pytest

import pluto_plus.bootstrap_firmware as bootstrap
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _dfu() -> bytes:
    suffix = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            DFU_PRODUCT_ID.to_bytes(2, "little"),
            DFU_VENDOR_ID.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD",
            b"\x10",
        )
    )
    partial = _fit() + suffix
    crc = 0xFFFFFFFF
    for byte in partial:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xEDB88320 if crc & 1 else crc >> 1
    return partial + crc.to_bytes(4, "little")


def _local(path: Path, *, serial: str | None = None) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=17,
        product="PlutoSDR+ with timestamp support",
        serial=serial,
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
        terminal_devices=("/dev/ttyACM0",),
        storage_devices=("/dev/sdb1",),
    )


def _lan_iio_facts(*, serial: str = "SERIAL_A") -> dict[str, object]:
    return {
        "hw_serial": serial,
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


def _install_lan_ssh_fake(
    monkeypatch: pytest.MonkeyPatch,
    *,
    remote_serial: str,
) -> tuple[list[list[str]], list[bytes]]:
    spawned_arguments: list[list[str]] = []
    submitted_passwords: list[bytes] = []

    class SuccessfulChild:
        exitstatus = 0
        signalstatus = None

        def __init__(self, output: bytes) -> None:
            self.before = b""
            self._output = output
            self._expects = 0

        def expect(self, patterns: object, timeout: float | None = None) -> int:
            del patterns, timeout
            self._expects += 1
            if self._expects == 1:
                self.before = b""
                return 0
            self.before = self._output
            return 1

        def sendline(self, value: bytes) -> None:
            submitted_passwords.append(value)

        def close(self, force: bool = False) -> None:
            del force

    def spawn(binary: str, arguments: list[str], **kwargs: object) -> SuccessfulChild:
        del kwargs
        assert binary == "ssh"
        spawned_arguments.append(list(arguments))
        if "StrictHostKeyChecking=accept-new" in arguments:
            known_hosts_argument = next(
                item for item in arguments if item.startswith("UserKnownHostsFile=")
            )
            Path(known_hosts_argument.partition("=")[2]).write_text(
                "192.168.1.20 ssh-ed25519 AAAATESTKEY\n"
            )
            return SuccessfulChild(b"")
        return SuccessfulChild(f"serial={remote_serial}\n".encode())

    import pexpect

    monkeypatch.setattr(pexpect, "spawn", spawn)
    return spawned_arguments, submitted_passwords


@pytest.fixture
def planned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[bootstrap.BootstrapPlan, bytes, Path]:
    usb_root = tmp_path / "usb"
    target = usb_root / "3-11"
    target.mkdir(parents=True)
    image = tmp_path / "canonical.dfu"
    image.write_bytes(_dfu())
    policy = bootstrap.BOOTSTRAP_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "device_firmware": "v5",
        }
    )
    monkeypatch.setattr(bootstrap, "_USB_ROOT", usb_root)
    monkeypatch.setattr(bootstrap, "BOOTSTRAP_POLICY", policy)
    monkeypatch.setattr(bootstrap, "scan_local_usb_plutos", lambda: (_local(target),))
    monkeypatch.setattr(bootstrap, "_attest_partition", lambda target, part: Path("/dev/sdb"))
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "",
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9363A)",
            "fw_version": "v0.32-dirty",
            "ad9361-phy,model": "ad9363a",
        },
    )
    plan, frm = bootstrap.prepare_bootstrap_plan(image, target)
    return plan, frm, target


def test_prepare_is_canonical_path_bound_and_read_only(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
) -> None:
    plan, frm, target = planned

    assert plan.usb_sysfs_path == str(target)
    assert plan.confirmation_phrase == "BOOTSTRAP 3-11"
    assert plan.partition == "/dev/sdb1"
    assert plan.block_device == "/dev/sdb"
    assert plan.before_firmware == "v0.32-dirty"
    assert hashlib.sha256(frm).hexdigest() == plan.frm_sha256


def test_prepare_rejects_an_image_outside_immutable_policy(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "BOOTSTRAP_POLICY",
        bootstrap.BOOTSTRAP_POLICY.model_copy(update={"asset_sha256": "0" * 64}),
    )

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="exact qualified DFU"):
        bootstrap.prepare_bootstrap_plan(Path(plan.image_path), target)


def test_prepare_refuses_to_bypass_normal_serial_flow(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "scan_local_usb_plutos",
        lambda: (_local(target, serial="SERIAL_A"),),
    )

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="firmware flash"):
        bootstrap.prepare_bootstrap_plan(Path(plan.image_path), target)


def test_usb_ssh_enrollment_for_path_a_never_accepts_serial_b(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    usb_root = tmp_path / "usb"
    target = usb_root / "3-8"
    target.mkdir(parents=True)
    monkeypatch.setattr(bootstrap, "_USB_ROOT", usb_root)
    monkeypatch.setattr(
        bootstrap,
        "_one_local_target",
        lambda path: _local(target, serial="SERIAL_A"),
    )
    monkeypatch.setattr(bootstrap, "_require_usb_ssh_route", lambda interface, host: None)

    class WrongRadioChild:
        before = b"serial=SERIAL_B\n"
        exitstatus = 0
        signalstatus = None

        def expect(self, patterns: object, timeout: float | None = None) -> int:
            del patterns, timeout
            return 1

        def sendline(self, value: bytes) -> None:
            del value

        def close(self, force: bool = False) -> None:
            del force

    import pexpect

    spawned_arguments: list[str] = []

    def spawn(binary: str, arguments: list[str], **kwargs: object) -> WrongRadioChild:
        del binary, kwargs
        spawned_arguments.extend(arguments)
        return WrongRadioChild()

    monkeypatch.setattr(pexpect, "spawn", spawn)
    destination = tmp_path / "SERIAL_A.known_hosts"

    with pytest.raises(
        bootstrap.BootstrapFirmwareError,
        match="attested serial 'SERIAL_B', expected 'SERIAL_A'",
    ):
        bootstrap.enroll_bound_usb_ssh_host_key(
            serial="SERIAL_A",
            usb_sysfs_path=target,
            known_hosts_file=destination,
            password="unused",
        )

    assert not destination.exists()
    assert "GlobalKnownHostsFile=/dev/null" in spawned_arguments


def test_bound_ssh_bootstrap_upload_uses_only_the_selected_known_hosts_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)
    spawned_arguments: list[str] = []

    class SuccessfulChild:
        before = b""
        exitstatus = 0
        signalstatus = None

        def expect(self, patterns: object, timeout: float | None = None) -> int:
            del patterns, timeout
            return 1

        def close(self, force: bool = False) -> None:
            del force

    def spawn(binary: str, arguments: list[str], **kwargs: object) -> SuccessfulChild:
        del binary, kwargs
        spawned_arguments.extend(arguments)
        return SuccessfulChild()

    import pexpect

    monkeypatch.setattr(pexpect, "spawn", spawn)
    transport = bootstrap.BoundSshBootstrapTransport(
        interface=None,
        password="analog",
        known_hosts_file=known_hosts,
    )

    transport.upload_frm(b"firmware")

    assert f"UserKnownHostsFile={known_hosts}" in spawned_arguments
    assert "GlobalKnownHostsFile=/dev/null" in spawned_arguments


def test_lan_ssh_enrollment_attests_then_uses_isolated_tofu_and_pinned_sessions(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspected_hosts: list[str] = []

    def inspect(host: str) -> dict[str, object]:
        inspected_hosts.append(host)
        return _lan_iio_facts()

    monkeypatch.setattr(bootstrap, "_inspect_iio_context", inspect)
    monkeypatch.setattr(bootstrap, "_run_output", lambda argv, timeout_s: "SHA256:key radio")
    spawned, passwords = _install_lan_ssh_fake(monkeypatch, remote_serial="SERIAL_A")
    destination = tmp_path / "trust" / "SERIAL_A.known_hosts"
    plan = bootstrap.prepare_lan_ssh_host_key_enrollment(
        serial="SERIAL_A",
        host="192.168.1.20",
        known_hosts_file=destination,
        profile_id="libiio-metadata-v6",
    )

    result = bootstrap.execute_lan_ssh_host_key_enrollment(
        plan,
        confirmation="TRUST LAN SSH SERIAL_A 192.168.1.20",
    )

    assert inspected_hosts == ["192.168.1.20", "192.168.1.20"]
    assert plan.confirmation_phrase == "TRUST LAN SSH SERIAL_A 192.168.1.20"
    assert result["trust_model"] == "explicit_lan_tofu"
    assert result["serial"] == "SERIAL_A"
    assert result["metadata_abi"] == 1
    assert destination.read_text() == "192.168.1.20 ssh-ed25519 AAAATESTKEY\n"
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    assert passwords == [b"analog", b"analog"]
    assert len(spawned) == 2
    assert "StrictHostKeyChecking=accept-new" in spawned[0]
    assert "StrictHostKeyChecking=yes" in spawned[1]
    for arguments in spawned:
        assert arguments[:2] == ["-F", "/dev/null"]
        assert "GlobalKnownHostsFile=/dev/null" in arguments
        assert "PubkeyAuthentication=no" in arguments
        assert "PreferredAuthentications=password" in arguments
        assert sum(item.startswith("UserKnownHostsFile=") for item in arguments) == 1


def test_lan_ssh_enrollment_rejects_pinned_remote_serial_mismatch_without_publish(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap, "_inspect_iio_context", lambda host: _lan_iio_facts())
    monkeypatch.setattr(bootstrap, "_run_output", lambda argv, timeout_s: "unused")
    spawned, _passwords = _install_lan_ssh_fake(monkeypatch, remote_serial="SERIAL_MITM")
    destination = tmp_path / "trust" / "SERIAL_A.known_hosts"
    plan = bootstrap.prepare_lan_ssh_host_key_enrollment(
        serial="SERIAL_A",
        host="192.168.1.20",
        known_hosts_file=destination,
        profile_id="libiio-metadata-v6",
    )

    with pytest.raises(
        bootstrap.BootstrapFirmwareError,
        match="pinned LAN SSH endpoint attested serial 'SERIAL_MITM', expected 'SERIAL_A'",
    ):
        bootstrap.execute_lan_ssh_host_key_enrollment(
            plan,
            confirmation=plan.confirmation_phrase,
        )

    assert len(spawned) == 2
    assert not destination.exists()
    assert not tuple(destination.parent.glob(f".{destination.name}.*"))


def test_lan_ssh_enrollment_rejects_iio_serial_mismatch_before_tofu(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        bootstrap,
        "_inspect_iio_context",
        lambda host: _lan_iio_facts(serial="SERIAL_OTHER"),
    )

    def unexpected_spawn(*args: object, **kwargs: object) -> object:
        pytest.fail(f"IIO identity mismatch must prevent SSH TOFU: {args!r} {kwargs!r}")

    import pexpect

    monkeypatch.setattr(pexpect, "spawn", unexpected_spawn)
    with pytest.raises(
        bootstrap.BootstrapFirmwareError,
        match="attested serial 'SERIAL_OTHER', expected 'SERIAL_A'",
    ):
        bootstrap.prepare_lan_ssh_host_key_enrollment(
            serial="SERIAL_A",
            host="192.168.1.20",
            known_hosts_file=tmp_path / "SERIAL_A.known_hosts",
            profile_id="libiio-metadata-v6",
        )


def test_lan_ssh_enrollment_refuses_existing_destination_before_network_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    destination = tmp_path / "SERIAL_A.known_hosts"
    destination.write_text("keep\n")

    def unexpected_inspection(host: str) -> dict[str, object]:
        pytest.fail(f"existing destination must fail before inspecting {host}")

    monkeypatch.setattr(bootstrap, "_inspect_iio_context", unexpected_inspection)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="already exists"):
        bootstrap.prepare_lan_ssh_host_key_enrollment(
            serial="SERIAL_A",
            host="192.168.1.20",
            known_hosts_file=destination,
            profile_id="libiio-metadata-v6",
        )

    assert destination.read_text() == "keep\n"


def test_lan_ssh_enrollment_requires_exact_serial_and_host_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(bootstrap, "_inspect_iio_context", lambda host: _lan_iio_facts())
    plan = bootstrap.prepare_lan_ssh_host_key_enrollment(
        serial="SERIAL_A",
        host="192.168.1.20",
        known_hosts_file=tmp_path / "SERIAL_A.known_hosts",
        profile_id="libiio-metadata-v6",
    )

    def unexpected_spawn(*args: object, **kwargs: object) -> object:
        pytest.fail(f"wrong confirmation must not start SSH: {args!r} {kwargs!r}")

    import pexpect

    monkeypatch.setattr(pexpect, "spawn", unexpected_spawn)
    with pytest.raises(bootstrap.BootstrapFirmwareError, match="confirmation must be exactly"):
        bootstrap.execute_lan_ssh_host_key_enrollment(
            plan,
            confirmation="TRUST LAN SSH SERIAL_A 192.168.1.21",
        )


@pytest.mark.parametrize(
    "host",
    ("radio.local", "8.8.8.8", "127.0.0.1", "192.168.2.1"),
)
def test_lan_ssh_enrollment_accepts_only_literal_private_lan_ipv4(
    host: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_inspection(candidate: str) -> dict[str, object]:
        pytest.fail(f"invalid LAN host must fail before IIOD access: {candidate}")

    monkeypatch.setattr(bootstrap, "_inspect_iio_context", unexpected_inspection)
    with pytest.raises(bootstrap.BootstrapFirmwareError, match="LAN SSH"):
        bootstrap.prepare_lan_ssh_host_key_enrollment(
            serial="SERIAL_A",
            host=host,
            known_hosts_file=tmp_path / "SERIAL_A.known_hosts",
            profile_id="libiio-metadata-v6",
        )


def test_selected_forward_profile_is_exact_and_blank_recovery_stays_canonical(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    canonical_plan, _, target = planned
    image = Path(canonical_plan.image_path)
    policy = bootstrap.TANDEM_V6_DEVELOPMENT_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "fit_body_sha256": canonical_plan.fit_sha256,
            "fit_body_size": canonical_plan.fit_size,
        }
    )
    profile_id = policy.profile_id
    monkeypatch.setitem(
        bootstrap.STANDALONE_FLASH_PROFILES,
        profile_id,
        bootstrap.StandaloneFlashProfile(policy, 2, True),
    )
    monkeypatch.setattr(
        bootstrap,
        "scan_local_usb_plutos",
        lambda: (_local(target, serial="SERIAL_A"),),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_A",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v6",
            "ad9361-phy,model": "ad9361",
        },
    )

    plan, _ = bootstrap.prepare_usb_flash_plan(
        image,
        target,
        mutation_profile_id=profile_id,
    )

    assert plan.mutation_profile_id == profile_id
    assert plan.expected_metadata_abi == 2
    assert plan.expected_tandem_agc is True
    with pytest.raises(bootstrap.BootstrapFirmwareError, match="blank-serial recovery"):
        bootstrap.prepare_usb_flash_plan(
            image,
            target,
            force_blank_serial=True,
            mutation_profile_id=profile_id,
        )


def test_latch_clear_persistence_requires_distinct_promotion_profile() -> None:
    ram = bootstrap.STANDALONE_FLASH_PROFILES[
        "libiio-metadata-v6-tandem-latch-clear-ram"
    ]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "libiio-metadata-v6-tandem-latch-clear-persistent-promotion"
    ]

    assert ram.persistent_allowed is False
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != ram.policy.profile_id
    assert promotion.policy.asset_sha256 == ram.policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == ram.policy.fit_body_sha256
    assert promotion.policy.device_firmware == ram.policy.device_firmware
    assert promotion.metadata_abi == ram.metadata_abi == 2
    assert promotion.tandem_agc is ram.tandem_agc is True


def test_tandem_v7_ram_profile_remains_distinct_from_persistent_promotion() -> None:
    policy = bootstrap.TANDEM_AGC_V7_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "tandem-agc-v7-release-persistent-promotion"
    ]

    assert policy.release_tag == "v0.40-plutoplus-spf-tandem-agc-v7"
    assert policy.device_firmware == policy.release_tag
    assert policy.source_commit == "e0049c2d0077770eeb1f6850b957878a373623d9"
    assert policy.asset_sha256 == (
        "4fe286f9756e3c721d5322ba9c18831f43ab4678c34bb9ef7f238cbb1236debe"
    )
    assert policy.fit_body_sha256 == (
        "4c19876d09082adfdbd255726e84be397eb4e18a4c0d96b9722d7d543c2ebae7"
    )
    assert policy.fit_body_size == 12_776_823
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 2
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != policy.profile_id
    assert promotion.policy.asset_sha256 == policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == policy.fit_body_sha256
    assert promotion.policy.source_commit == policy.source_commit
    assert promotion.policy.hardware_qualified is True
    assert promotion.metadata_abi == profile.metadata_abi == 2
    assert promotion.tandem_agc is profile.tandem_agc is True


def test_single_rx_metadata_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.SINGLE_RX_METADATA_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "plutoplus-spf-single-rx-metadata-rc1-c83345490234"
    assert policy.device_firmware == "v0.42-plutoplus-spf-single-rx-metadata-rc1"
    assert policy.source_commit == "c833454902343843e4af7f3f6c97c40d4a809c90"
    assert policy.asset_sha256 == (
        "3d38a74234823937995e20c32099f61923284df50b530f1e39df1b72f5e80aaf"
    )
    assert policy.fit_body_sha256 == (
        "dff0c0f4d607beb5c5adc050e9cf6d2bbb09d1cd5c13a7c57a4771c2cbf17dab"
    )
    assert policy.fit_body_size == 12_793_263
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v1_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V1_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v1-rc1-fdbe3ffaed60"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v1-rc1"
    assert policy.source_commit == "fdbe3ffaed604cc83f89252a10d2ec8b51b5be58"
    assert policy.asset_sha256 == (
        "9024ed3c0ce38efeaf2e30dd71f903e2d65a234b90e7af175d3c196042dc6591"
    )
    assert policy.fit_body_sha256 == (
        "b9ceebdbadf144e91be78c2b87aad30691f3ade068f91ad8ab61c72b1b4035d4"
    )
    assert policy.fit_body_size == 12_796_131
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v1_rc2_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V1_RC2_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v1-rc2-b046b80fd280"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v1-rc2"
    assert policy.source_commit == "b046b80fd280dc827b8e0eef75374cda8bdf15a6"
    assert policy.asset_sha256 == (
        "2164eed7450cfe8e29ea1e57ee1b556c06e912a4bbca6f186721f0ecc744d0b8"
    )
    assert policy.fit_body_sha256 == (
        "8c06c17aecebb724e021470f43f31440ed850327ac7fd4d4b0238c5a3563eda7"
    )
    assert policy.fit_body_size == 12_796_723
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v1_rc3_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V1_RC3_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v1-rc3-19abd4a4184b"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v1-rc3"
    assert policy.source_commit == "19abd4a4184b155153eaf1d1b7fd3b393bcb6ace"
    assert policy.asset_sha256 == (
        "18f0ce26e4c242f24fcacbd04e71b633e24ccf5b740332a263dc15e778a231fa"
    )
    assert policy.fit_body_sha256 == (
        "0f46a47d41c994c71c4d58d409cfe73ec90b198a07553586a5188ae4321230f9"
    )
    assert policy.fit_body_size == 12_796_875
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v1_rc5_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V1_RC5_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v1-rc5-58f382f69776"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v1-rc5"
    assert policy.source_commit == "58f382f69776f39b04eac9e289064d6e22edd433"
    assert policy.asset_sha256 == (
        "ba364191cdfd0eb17af81d952f92d69481c7e31fbcdd8baac79590eab8afe98c"
    )
    assert policy.fit_body_sha256 == (
        "bd888473054b269643e94e599f835a71fad2ed8cb08f21258c5f418bfd380aab"
    )
    assert policy.fit_body_size == 12_793_407
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v2_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V2_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v2-rc1-e2a6458ae9fa"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v2-rc1"
    assert policy.source_commit == "e2a6458ae9fabafdf4a7dfa56bc9294d5355bc3d"
    assert policy.asset_sha256 == (
        "c1e80d1f5748e33e7668a2641961e4de07e725d5b8c6588830f61e45c7a14b60"
    )
    assert policy.fit_body_sha256 == (
        "4088680502052e828e81380dad0a9b0aa9ae0cf4a0c891933897f62e2fdcabd4"
    )
    assert policy.fit_body_size == 12_797_471
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v2_rc2_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V2_RC2_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v2-rc2-1b811c744012"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v2-rc2"
    assert policy.source_commit == "1b811c744012227f01f19a79af17e2d9ba8ca90b"
    assert policy.asset_sha256 == (
        "284e5f87e853055ee182c2caa9db8bdacae34a9b20d0f3187dd001f87c0cf011"
    )
    assert policy.fit_body_sha256 == (
        "c4f517cb3f442617d6154c1e44779c30181ad4af44325b32300fc5413b7e4891"
    )
    assert policy.fit_body_size == 12_797_859
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v2_rc3_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_BURST_V2_RC3_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-burst-v2-rc3-29d61452badb"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v2-rc3"
    assert policy.source_commit == "29d61452badb364ca4ab95278de720514ee87a2c"
    assert policy.asset_sha256 == (
        "f13576d89548416a85b11486d22203acfab5166d97e85e49980a973bd763a599"
    )
    assert policy.fit_body_sha256 == (
        "8f788bb1af9f392b2decfcda0477749971083a4edd3d28638bbab550e60aec80"
    )
    assert policy.fit_body_size == 12_797_807
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_burst_v2_release_requires_distinct_persistent_promotion() -> None:
    policy = bootstrap.DDR_BURST_V2_RELEASE_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "ddr-burst-v2-release-persistent-promotion"
    ]

    assert policy.release_tag == "v0.42-plutoplus-spf-ddr-burst-v2"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v2"
    assert policy.source_commit == "3cc434da22a655937dc0c2d2e6fb9d97b4b8d1e5"
    assert policy.asset_sha256 == (
        "274506a9ce3f283eb9d5cf4cc254ad294c669d70647fa656ebc051358ccb5ad0"
    )
    assert policy.fit_body_sha256 == (
        "ff93c3335f61f224ae85b414e83d2acab1a2bfd47daa2183ad920586ba94187b"
    )
    assert policy.fit_body_size == 12_798_367
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != policy.profile_id
    assert promotion.policy.asset_sha256 == policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == policy.fit_body_sha256
    assert promotion.policy.fit_body_size == policy.fit_body_size
    assert promotion.policy.source_commit == policy.source_commit
    assert promotion.policy.hardware_qualified is True
    assert promotion.metadata_abi == profile.metadata_abi == 3
    assert promotion.tandem_agc is profile.tandem_agc is True
    assert promotion.ddr_burst_max_iq_bytes == profile.ddr_burst_max_iq_bytes
    assert promotion.ddr_burst_reserve_bytes == profile.ddr_burst_reserve_bytes


def test_ddr_capacity_test_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_CAPACITY_TEST_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-capacity-test-rc1-84f05685a590"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-capacity-test-rc1"
    assert policy.source_commit == "84f05685a59007a01448628bf0f2be258594ee87"
    assert policy.asset_name == (
        "plutoplus-spf-ddr-capacity-test-rc1-84f05685a590-pluto.dfu"
    )
    assert policy.asset_sha256 == (
        "eab63fd6003751ee007230cdaafab341a93bbe830e71747166cac5be777f11ce"
    )
    assert policy.fit_body_sha256 == (
        "510f5848442376bb2f03ded4390ad916de074791fff2f4bd85c37aa96f263338"
    )
    assert policy.fit_body_size == 12_798_519
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 300_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_ring_v1_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_RING_V1_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-ring-v1-rc1-d6b3029aa6f2"
    assert policy.device_firmware == "v0.43-plutoplus-spf-ddr-ring-v1-rc1"
    assert policy.source_commit == "d6b3029aa6f21810f754fffd56428c149479ef05"
    assert policy.asset_name == "plutoplus-spf-ddr-ring-v1-rc1-d6b3029aa6f2-pluto.dfu"
    assert policy.asset_sha256 == (
        "3dddf1eefed9ad87981183febddb7c3f9ae3cd43aa8c8c74901bb0b2ce3d9f7e"
    )
    assert policy.fit_body_sha256 == (
        "9d350b9fd94f2e1f350d368458309a69cf412100bdb472b8f1c792d4cb16abfe"
    )
    assert policy.fit_body_size == 12_809_275
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_ring_v1_rc2_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_RING_V1_RC2_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-ring-v1-rc2-33fe77ca6319"
    assert policy.device_firmware == "v0.43-plutoplus-spf-ddr-ring-v1-rc2"
    assert policy.source_commit == "33fe77ca631961d5230e678fddc0d802f1522d68"
    assert policy.asset_name == "plutoplus-spf-ddr-ring-v1-rc2-33fe77ca6319-pluto.dfu"
    assert policy.asset_sha256 == (
        "0da8fc12ac8677b18b17f203903cd3e65dca171d31d65f6ba25c6d5702066f91"
    )
    assert policy.fit_body_sha256 == (
        "19476b9f88e80cff1bfc34f42ad78a090eb35b6dd08ebc8339b855db5380462e"
    )
    assert policy.fit_body_size == 12_809_955
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_ring_prefill_v1_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.DDR_RING_PREFILL_V1_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "ddr-ring-prefill-v1-rc1-ac100b76ec75"
    assert policy.device_firmware == "v0.44-plutoplus-spf-ddr-ring-prefill-v1-rc1"
    assert policy.source_commit == "ac100b76ec7577f74df92bdca678ef6a4ccc664b"
    assert (
        policy.asset_name
        == "plutoplus-spf-ddr-ring-prefill-v1-rc1-ac100b76ec75-pluto.dfu"
    )
    assert policy.asset_sha256 == (
        "0107fb1d57be2ade703bc6950ff64a20c9cf6efb06f3eb4ea71dabecbb4343fa"
    )
    assert policy.fit_body_sha256 == (
        "ee61df2729cfd5e8f4b8f5c8b24994a56ae5f7b280f0a2ea7044372c0721e78e"
    )
    assert policy.fit_body_size == 12_809_531
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_ring_prefill_v1_release_requires_distinct_persistent_promotion() -> None:
    policy = bootstrap.DDR_RING_PREFILL_V1_RELEASE_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "ddr-ring-prefill-v1-release-persistent-promotion"
    ]

    assert policy.release_tag == "v0.44-plutoplus-spf-ddr-ring-prefill-v1"
    assert policy.device_firmware == "v0.44-plutoplus-spf-ddr-ring-prefill-v1"
    assert policy.source_commit == "0c49d6837847cefba9b139106dcffb1942f0ee22"
    assert (
        policy.asset_name
        == "plutoplus-spf-ddr-ring-prefill-v1-0c49d6837847-pluto.dfu"
    )
    assert policy.asset_sha256 == (
        "eb7d39f2f456d79f005239ddcff204166c9c607cd3647f1dd90464f99f439925"
    )
    assert policy.fit_body_sha256 == (
        "589a33b865161ac5820031ae0666d7b04b5346f0aad56fc422dd94a50f43c24d"
    )
    assert policy.fit_body_size == 12_809_519
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != policy.profile_id
    assert promotion.policy.asset_sha256 == policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == policy.fit_body_sha256
    assert promotion.policy.fit_body_size == policy.fit_body_size
    assert promotion.policy.source_commit == policy.source_commit
    assert promotion.policy.hardware_qualified is True
    assert promotion.metadata_abi == profile.metadata_abi == 3
    assert promotion.tandem_agc is profile.tandem_agc is True
    assert promotion.ddr_burst_max_iq_bytes == profile.ddr_burst_max_iq_bytes
    assert promotion.ddr_burst_reserve_bytes == profile.ddr_burst_reserve_bytes
    assert promotion.ddr_ring_max_iq_bytes == profile.ddr_ring_max_iq_bytes
    assert promotion.ddr_ring_modes == profile.ddr_ring_modes == "finite,continuous"
    assert promotion.buffer_metadata_status is profile.buffer_metadata_status is True


def test_iio_throughput_hold_v1_rc1_profile_is_exactly_bound_and_ram_only() -> None:
    policy = bootstrap.IIO_THROUGHPUT_HOLD_V1_RC1_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]

    assert policy.release_tag == "iio-throughput-hold-v1-rc1-425b20b352cc"
    assert policy.device_firmware == "v0.45-plutoplus-spf-iio-throughput-hold-v1-rc1"
    assert policy.source_commit == "425b20b352ccaba697cb90b5d95db00635f80118"
    assert (
        policy.asset_name
        == "plutoplus-spf-iio-throughput-hold-v1-rc1-425b20b352cc-pluto.dfu"
    )
    assert policy.asset_sha256 == (
        "c10dbf365099f718cb0134b1be8a01fca24db7028e55a98d9340813d3c9f35e4"
    )
    assert policy.fit_body_sha256 == (
        "869a4de6b608ba3801f891bb4ca097a48adc7fafb49a20cad2a336cf063972be"
    )
    assert policy.fit_body_size == 12_811_503
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert not any(
        candidate.policy.source_commit == policy.source_commit and candidate.persistent_allowed
        for candidate in bootstrap.STANDALONE_FLASH_PROFILES.values()
    )


def test_ddr_ring_v1_release_requires_distinct_persistent_promotion() -> None:
    policy = bootstrap.DDR_RING_V1_RELEASE_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "ddr-ring-v1-release-persistent-promotion"
    ]

    assert policy.release_tag == "v0.43-plutoplus-spf-ddr-ring-v1"
    assert policy.device_firmware == "v0.43-plutoplus-spf-ddr-ring-v1"
    assert policy.source_commit == "49bb746577485463e32be0ef3c55bd723ea170aa"
    assert policy.asset_name == "plutoplus-spf-ddr-ring-v1-49bb74657748-pluto.dfu"
    assert policy.asset_sha256 == (
        "73714ac4caea187f69d4006d36bc461f7f9e1d1c7d6a3536997273420eac24db"
    )
    assert policy.fit_body_sha256 == (
        "9bee5cfd9cc5cc3bebf50be1ce823d7f1af2e752a9962d842a8fa605ee1df74d"
    )
    assert policy.fit_body_size == 12_809_347
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert profile.ddr_ring_max_iq_bytes == 200_000_000
    assert profile.ddr_ring_modes == "finite,continuous"
    assert profile.buffer_metadata_status is True
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != policy.profile_id
    assert promotion.policy.asset_sha256 == policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == policy.fit_body_sha256
    assert promotion.policy.fit_body_size == policy.fit_body_size
    assert promotion.policy.source_commit == policy.source_commit
    assert promotion.policy.hardware_qualified is True
    assert promotion.metadata_abi == profile.metadata_abi == 3
    assert promotion.tandem_agc is profile.tandem_agc is True
    assert promotion.ddr_burst_max_iq_bytes == profile.ddr_burst_max_iq_bytes
    assert promotion.ddr_burst_reserve_bytes == profile.ddr_burst_reserve_bytes
    assert promotion.ddr_ring_max_iq_bytes == profile.ddr_ring_max_iq_bytes
    assert promotion.ddr_ring_modes == profile.ddr_ring_modes == "finite,continuous"
    assert promotion.buffer_metadata_status is profile.buffer_metadata_status is True


def test_ddr_burst_v1_release_requires_distinct_persistent_promotion() -> None:
    policy = bootstrap.DDR_BURST_V1_RELEASE_RAM_POLICY
    profile = bootstrap.STANDALONE_FLASH_PROFILES[policy.profile_id]
    promotion = bootstrap.STANDALONE_FLASH_PROFILES[
        "ddr-burst-v1-release-persistent-promotion"
    ]

    assert policy.release_tag == "v0.42-plutoplus-spf-ddr-burst-v1"
    assert policy.device_firmware == "v0.42-plutoplus-spf-ddr-burst-v1"
    assert policy.source_commit == "a6b78df100f67c1bcd2528e2fbc0c86b2a8ee2ba"
    assert policy.asset_sha256 == (
        "47bb23ff1d498a5899c4503de33bc818aa908c567eab4e0fc535602ffa296877"
    )
    assert policy.fit_body_sha256 == (
        "f40542a7b1a53f4f1b06a5733f068e7b69f1eddff7ab0eb46c0f37f9f37d295a"
    )
    assert policy.fit_body_size == 12_793_395
    assert policy.hardware_qualified is False
    assert profile.metadata_abi == 3
    assert profile.tandem_agc is True
    assert profile.persistent_allowed is False
    assert profile.ddr_burst_max_iq_bytes == 200_000_000
    assert profile.ddr_burst_reserve_bytes == 128 * 1024 * 1024
    assert promotion.persistent_allowed is True
    assert promotion.policy.profile_id != policy.profile_id
    assert promotion.policy.asset_sha256 == policy.asset_sha256
    assert promotion.policy.fit_body_sha256 == policy.fit_body_sha256
    assert promotion.policy.fit_body_size == policy.fit_body_size
    assert promotion.policy.source_commit == policy.source_commit
    assert promotion.policy.hardware_qualified is True
    assert promotion.metadata_abi == profile.metadata_abi == 3
    assert promotion.tandem_agc is profile.tandem_agc is True
    assert promotion.ddr_burst_max_iq_bytes == profile.ddr_burst_max_iq_bytes
    assert promotion.ddr_burst_reserve_bytes == profile.ddr_burst_reserve_bytes


def test_normal_flash_requires_matching_stable_usb_and_iiod_serial(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(
        bootstrap,
        "scan_local_usb_plutos",
        lambda: (_local(target, serial="SERIAL_A"),),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_A",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v0.37",
            "ad9361-phy,model": "ad9361",
        },
    )

    normal, _ = bootstrap.prepare_usb_flash_plan(Path(plan.image_path), target)

    assert normal.operation == "flash"
    assert normal.target_serial == "SERIAL_A"
    assert normal.confirmation_phrase == "FLASH SERIAL_A"

    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_B",
            "hw_model": "Analog Devices PlutoSDR Rev.C",
            "fw_version": "v0.37",
            "ad9361-phy,model": "ad9361",
        },
    )
    with pytest.raises(bootstrap.BootstrapFirmwareError, match="serials do not match"):
        bootstrap.prepare_usb_flash_plan(Path(plan.image_path), target)


def test_execute_requires_exact_confirmation_before_operations(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path], tmp_path: Path
) -> None:
    plan, frm, _ = planned

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="confirmation"):
        bootstrap.execute_bootstrap_plan(
            plan,
            frm,
            confirmation="BOOTSTRAP wrong",
            receipt_directory=tmp_path / "receipts",
        )

    assert not (tmp_path / "receipts").exists()


def test_execute_writes_only_pluto_frm_and_attests_return(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, target = planned
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "info.html").write_text("Pluto")
    commands: list[tuple[str, ...]] = []
    path_waits: list[tuple[bool, float]] = []

    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_preflight_udisks", lambda **kwargs: None)
    monkeypatch.setattr(bootstrap, "_resolve_udisks_drive", lambda device: "/drives/pluto")
    monkeypatch.setattr(bootstrap, "_mount_partition", lambda partition: mountpoint)
    monkeypatch.setattr(bootstrap, "_run", lambda argv, timeout_s: commands.append(tuple(argv)))
    monkeypatch.setattr(bootstrap, "_validate_scsi_eject_target", lambda **kwargs: None)
    monkeypatch.setattr(bootstrap, "_eject_scsi_media", lambda **kwargs: None)
    monkeypatch.setattr(
        bootstrap,
        "_wait_for_path",
        lambda path, present, timeout_s: path_waits.append((present, timeout_s)),
    )
    monkeypatch.setattr(
        bootstrap,
        "_one_local_target",
        lambda path: _local(target, serial="SERIAL_NEW"),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_NEW",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        return_timeout_s=75,
    )

    assert result.outcome == "success"
    assert result.returned_serial == "SERIAL_NEW"
    assert (mountpoint / "pluto.frm").read_bytes() == frm
    assert sorted(path.name for path in mountpoint.iterdir()) == ["info.html", "pluto.frm"]
    assert commands == [
        ("sync", "-f", str(mountpoint / "pluto.frm")),
        ("udisksctl", "unmount", "--block-device", "/dev/sdb1"),
    ]
    assert "media_ejected" in result.phases
    assert path_waits == [(False, 75), (True, 75)]
    receipt_path = Path(result.receipt_path)
    assert receipt_path.stat().st_mode & 0o777 == 0o600
    assert json.loads(receipt_path.read_text())["outcome"] == "success"


def test_failure_after_staging_proves_qspi_write_never_started(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "info.html").write_text("Pluto")
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_preflight_udisks", lambda **kwargs: None)
    monkeypatch.setattr(bootstrap, "_resolve_udisks_drive", lambda device: "/drives/pluto")
    monkeypatch.setattr(bootstrap, "_mount_partition", lambda partition: mountpoint)

    def fail_sync(argv: tuple[str, ...], *, timeout_s: float) -> None:
        del timeout_s
        if argv[0] == "sync":
            raise bootstrap.BootstrapFirmwareError("sync failed")

    monkeypatch.setattr(bootstrap, "_run", fail_sync)

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
    )

    assert result.outcome == "failed"
    assert result.retryable is True
    assert result.failure_phase == "sync"
    assert result.failure_classification == "qspi_write_not_started"
    assert "sync failed" in (result.error or "")
    assert json.loads(Path(result.receipt_path).read_text())["outcome"] == "failed"


def test_resolve_udisks_drive_requires_one_exact_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    block = tmp_path / "sdb"
    block.touch()
    output = """/org/freedesktop/UDisks2/block_devices/sdb:
  org.freedesktop.UDisks2.Block:
    Drive: '/org/freedesktop/UDisks2/drives/Linux_File_Stor_Gadget_123'
"""
    monkeypatch.setattr(bootstrap, "_run_output", lambda argv, timeout_s: output)

    assert bootstrap._resolve_udisks_drive(block) == (
        "/org/freedesktop/UDisks2/drives/Linux_File_Stor_Gadget_123"
    )

    monkeypatch.setattr(bootstrap, "_run_output", lambda argv, timeout_s: "Drive: '/'\n")
    with pytest.raises(bootstrap.UdisksFailure) as caught:
        bootstrap._resolve_udisks_drive(block)
    assert caught.value.classification == "drive_mapping_invalid"


def test_scsi_eject_uses_drive_api_and_proves_lun_removal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "usb" / "3-11"
    target.mkdir(parents=True)
    block = tmp_path / "sdb"
    partition = tmp_path / "sdb1"
    block.touch()
    partition.touch()
    block_root = tmp_path / "block"
    (block_root / "sdb").mkdir(parents=True)
    size = block_root / "sdb" / "size"
    size.write_text("4096\n")
    monkeypatch.setattr(bootstrap, "_BLOCK_ROOT", block_root)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        bootstrap, "_run", lambda argv, timeout_s: calls.append(tuple(argv))
    )

    def media_removed(duration: float) -> None:
        del duration
        partition.unlink(missing_ok=True)
        size.write_text("0\n")

    monkeypatch.setattr(bootstrap.time, "sleep", media_removed)

    drive = "/org/freedesktop/UDisks2/drives/Linux_File_Stor_Gadget_123"
    bootstrap._eject_scsi_media(
        drive_object=drive,
        usb_sysfs_path=target,
        block_device=block,
        partition=partition,
        timeout_s=2,
    )

    assert calls == [
        (
            "gdbus",
            "call",
            "--system",
            "--dest",
            "org.freedesktop.UDisks2",
            "--object-path",
            drive,
            "--method",
            "org.freedesktop.UDisks2.Drive.Eject",
            "{}",
        )
    ]


def test_scsi_eject_rejects_composite_disconnect_without_media_proof(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "usb" / "3-11"
    target.mkdir(parents=True)
    block = tmp_path / "sdb"
    partition = tmp_path / "sdb1"
    block.touch()
    partition.touch()
    monkeypatch.setattr(bootstrap, "_run", lambda argv, timeout_s: target.rmdir())

    with pytest.raises(bootstrap.UdisksFailure) as caught:
        bootstrap._eject_scsi_media(
            drive_object="/org/freedesktop/UDisks2/drives/Linux_File_Stor_Gadget_123",
            usb_sysfs_path=target,
            block_device=block,
            partition=partition,
            timeout_s=2,
        )

    assert caught.value.classification == "composite_disappeared"


def test_udisks_preflight_succeeds_before_attempt_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partition = tmp_path / "sdb1"
    block_device = tmp_path / "sdb"
    partition.touch()
    block_device.touch()
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(bootstrap, "_mountpoint_for", lambda path: None)
    monkeypatch.setattr(
        bootstrap,
        "_run",
        lambda argv, timeout_s: calls.append(tuple(argv)),
    )

    bootstrap._preflight_udisks(partition=partition, block_device=block_device)

    assert calls == [("udisksctl", "status")]


@pytest.mark.parametrize(
    ("detail", "classification"),
    (
        ("Error connecting to the udisks daemon: service unavailable", "daemon_unavailable"),
        ("Error connecting to the udisks daemon: Timeout was reached", "daemon_timeout"),
        ("GDBus.Error: Not authorized to perform operation", "authorization_denied"),
    ),
)
def test_udisks_preflight_classifies_daemon_failures(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
    classification: str,
) -> None:
    partition = tmp_path / "sdb1"
    block_device = tmp_path / "sdb"
    partition.touch()
    block_device.touch()
    monkeypatch.setattr(bootstrap, "_mountpoint_for", lambda path: None)

    def fail(argv: tuple[str, ...], *, timeout_s: float) -> None:
        del argv, timeout_s
        raise bootstrap.BootstrapFirmwareError(detail)

    monkeypatch.setattr(bootstrap, "_run", fail)

    with pytest.raises(bootstrap.UdisksFailure) as caught:
        bootstrap._preflight_udisks(partition=partition, block_device=block_device)

    assert caught.value.classification == classification
    assert "Remediation:" in str(caught.value)


def test_udisks_preflight_classifies_already_mounted_and_disappeared(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partition = tmp_path / "sdb1"
    block_device = tmp_path / "sdb"
    partition.touch()
    block_device.touch()
    monkeypatch.setattr(bootstrap, "_mountpoint_for", lambda path: tmp_path / "mount")

    with pytest.raises(bootstrap.UdisksFailure) as mounted:
        bootstrap._preflight_udisks(partition=partition, block_device=block_device)
    assert mounted.value.classification == "already_mounted"

    partition.unlink()
    with pytest.raises(bootstrap.UdisksFailure) as disappeared:
        bootstrap._preflight_udisks(partition=partition, block_device=block_device)
    assert disappeared.value.classification == "device_disappeared"


def test_failed_udisks_preflight_does_not_create_or_consume_receipt(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    receipts = tmp_path / "receipts"
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )

    def fail(**kwargs: object) -> None:
        del kwargs
        raise bootstrap.UdisksFailure(
            "daemon_timeout",
            "status timed out",
            "Restore udisks2.service and retry.",
        )

    monkeypatch.setattr(bootstrap, "_preflight_udisks", fail)

    with pytest.raises(bootstrap.UdisksFailure, match="daemon_timeout"):
        bootstrap.execute_bootstrap_plan(
            plan,
            frm,
            confirmation=plan.confirmation_phrase,
            receipt_directory=receipts,
        )

    assert not receipts.exists()


def test_mount_failure_is_failed_and_receipt_allows_retry(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_preflight_udisks", lambda **kwargs: None)
    monkeypatch.setattr(bootstrap, "_resolve_udisks_drive", lambda device: "/drives/pluto")

    def fail_mount(partition: Path) -> Path:
        del partition
        raise bootstrap.UdisksFailure(
            "authorization_denied",
            "mount denied",
            "Correct the host policy and retry.",
        )

    monkeypatch.setattr(bootstrap, "_mount_partition", fail_mount)

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
    )

    assert result.outcome == "failed"
    assert result.failure_phase == "mount"
    assert result.failure_classification == "authorization_denied"
    assert result.retryable is True
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert receipt["retryable"] is True
    assert "pluto_frm_written" not in receipt["phases"]


@pytest.mark.parametrize(
    ("detail", "classification"),
    (
        ("Error connecting to the udisks daemon: unavailable", "daemon_unavailable"),
        ("Error connecting to the udisks daemon: Timeout was reached", "daemon_timeout"),
        ("GDBus.Error: Not authorized", "authorization_denied"),
    ),
)
def test_mount_command_faults_are_classified_without_writing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    detail: str,
    classification: str,
) -> None:
    partition = tmp_path / "sdb1"
    partition.touch()
    monkeypatch.setattr(bootstrap, "_mountpoint_for", lambda path: None)

    def fail(argv: tuple[str, ...], *, timeout_s: float) -> None:
        del argv, timeout_s
        raise bootstrap.BootstrapFirmwareError(detail)

    monkeypatch.setattr(bootstrap, "_run", fail)

    with pytest.raises(bootstrap.UdisksFailure) as caught:
        bootstrap._mount_partition(partition)

    assert caught.value.classification == classification


def test_mount_partition_enforces_requested_safety_options(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    partition = tmp_path / "sdb1"
    mountpoint = tmp_path / "mount"
    partition.touch()
    mountpoint.mkdir()
    calls: list[str] = []
    monkeypatch.setattr(
        bootstrap,
        "_run_udisks",
        lambda operation, device, timeout_s: calls.append(operation),
    )
    monkeypatch.setattr(bootstrap, "_mount_options_for", lambda path: {"nodev", "nosuid"})

    # The initial mounted check and post-command check need distinct results.
    mount_checks = iter((None, mountpoint))
    monkeypatch.setattr(bootstrap, "_mountpoint_for", lambda path: next(mount_checks))

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="noexec"):
        bootstrap._mount_partition(partition)

    assert calls == ["mount", "unmount"]


@pytest.mark.parametrize("failed_operation", ("unmount", "pre-eject", "eject"))
def test_post_staging_classification_tracks_eject_dispatch(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failed_operation: str,
) -> None:
    plan, frm, _ = planned
    mountpoint = tmp_path / "mount"
    mountpoint.mkdir()
    (mountpoint / "info.html").write_text("Pluto")
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )
    monkeypatch.setattr(bootstrap, "_preflight_udisks", lambda **kwargs: None)
    monkeypatch.setattr(bootstrap, "_resolve_udisks_drive", lambda device: "/drives/pluto")
    monkeypatch.setattr(bootstrap, "_mount_partition", lambda partition: mountpoint)

    def udisks(operation: str, device: Path | None, *, timeout_s: float) -> None:
        del device, timeout_s
        if operation == failed_operation:
            raise bootstrap.UdisksFailure(
                "daemon_timeout",
                f"{operation} timed out",
                "Restore udisks2.service; reconcile before retrying.",
            )

    monkeypatch.setattr(bootstrap, "_run_udisks", udisks)
    monkeypatch.setattr(bootstrap, "_run", lambda argv, timeout_s: None)

    def validate(**kwargs: object) -> None:
        del kwargs
        if failed_operation == "pre-eject":
            raise bootstrap.UdisksFailure(
                "device_disappeared",
                "target disappeared before eject",
                "Reconnect and re-plan.",
            )

    monkeypatch.setattr(bootstrap, "_validate_scsi_eject_target", validate)

    def eject(**kwargs: object) -> None:
        del kwargs
        if failed_operation == "eject":
            raise bootstrap.UdisksFailure(
                "media_removal_timeout",
                "media removal timed out",
                "Reconcile before retrying.",
            )

    monkeypatch.setattr(bootstrap, "_eject_scsi_media", eject)

    result = bootstrap.execute_bootstrap_plan(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
    )

    if failed_operation == "unmount":
        assert result.outcome == "failed"
        assert result.failure_phase == "unmount"
        assert result.failure_classification == "daemon_timeout"
        assert result.retryable is True
    elif failed_operation == "pre-eject":
        assert result.outcome == "failed"
        assert result.failure_phase == "scsi_eject"
        assert result.failure_classification == "device_disappeared"
        assert result.retryable is True
    else:
        assert result.outcome == "unknown"
        assert result.failure_phase == "scsi_eject"
        assert result.failure_classification == "media_removal_timeout"
        assert result.retryable is False
    assert "pluto_frm_written" in result.phases


class FakeSshTransport:
    def __init__(self, plan: bootstrap.BootstrapPlan, *, updater_output: str = "Done\n") -> None:
        self.plan = plan
        self.updater_output = updater_output
        self.calls: list[tuple[str, bytes | None]] = []

    def upload_frm(self, data: bytes, *, timeout_s: float = 120) -> None:
        del timeout_s
        self.calls.append(("upload_frm", data))

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        del timeout_s
        self.calls.append((command, stdin))
        if command == bootstrap._REMOTE_ATTEST_COMMAND:
            return (
                "serial=\n"
                f"model={self.plan.before_model}\n"
                f"firmware={self.plan.before_firmware}\n"
                "updater=/sbin/update_frm.sh\n"
            )
        if command == bootstrap._REMOTE_STAGE_HASH_COMMAND:
            return f"{self.plan.frm_sha256}  /tmp/pluto-plus-utils/pluto.frm\n"
        if command == bootstrap._REMOTE_UPDATE_COMMAND:
            return self.updater_output
        if command.startswith("head -c "):
            return f"{self.plan.fit_sha256}  -\n"
        return ""


def test_bound_ssh_force_flash_verifies_stage_mtd3_and_return(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, target = planned
    transport = FakeSshTransport(plan)
    path_waits: list[tuple[bool, float]] = []
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )
    monkeypatch.setattr(
        bootstrap,
        "_wait_for_path",
        lambda path, present, timeout_s: path_waits.append((present, timeout_s)),
    )
    monkeypatch.setattr(
        bootstrap,
        "_one_local_target",
        lambda path: _local(target, serial="SERIAL_NEW"),
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_NEW",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    result = bootstrap.execute_usb_flash_plan_ssh(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        transport=transport,
        return_timeout_s=75,
    )

    assert result.outcome == "success"
    assert "mtd3_fit_verified" in result.phases
    stage = next(call for call in transport.calls if call[0] == "upload_frm")
    assert stage[1] == frm
    assert transport.calls[-1][0] == bootstrap._REMOTE_REBOOT_COMMAND
    assert path_waits == [(False, 75), (True, 75)]


def test_bound_ssh_ambiguous_updater_result_is_unknown(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, frm, _ = planned
    transport = FakeSshTransport(plan, updater_output="Failed\nDone\n")
    monkeypatch.setattr(
        bootstrap,
        "prepare_usb_flash_plan",
        lambda image, path, force_blank_serial, **kwargs: (plan, frm),
    )

    result = bootstrap.execute_usb_flash_plan_ssh(
        plan,
        frm,
        confirmation=plan.confirmation_phrase,
        receipt_directory=tmp_path / "receipts",
        transport=transport,
    )

    assert result.outcome == "unknown"
    assert "unambiguous Done" in (result.error or "")


class ReadOnlyReconciliationTransport:
    def __init__(self, plan: bootstrap.BootstrapPlan) -> None:
        self.plan = plan
        self.calls: list[tuple[str, bytes | None]] = []

    def upload_frm(self, data: bytes, *, timeout_s: float = 120) -> None:
        del data, timeout_s
        pytest.fail("reconciliation must never upload firmware")

    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str:
        del timeout_s
        self.calls.append((command, stdin))
        return (
            f"PPU\tserial\t{self.plan.target_serial}\n"
            f"PPU\tfirmware\t{self.plan.expected_firmware}\n"
            f"PPU\tfit_sha256\t{self.plan.fit_sha256}\n"
            "PPU\ttx_hardwaregain_db\t-80,-80\n"
            "PPU\ttx_buffer_enable\t0\n"
            "PPU\ttx_scan_enable\t0,0,0,0\n"
            "PPU\ttx_dds_raw\t0,0,0,0,0,0,0,0\n"
            "PPU\ttx_dds_scale\t0,0,0,0,0,0,0,0\n"
        )


def _uncertain_serial_receipt(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[bootstrap.BootstrapPlan, Path, str]:
    source, _, target = planned
    profile_id = "test-persistent-profile"
    policy = bootstrap.BOOTSTRAP_POLICY.model_copy(
        update={
            "profile_id": profile_id,
            "asset_sha256": source.image_sha256,
            "fit_body_sha256": source.fit_sha256,
            "fit_body_size": source.fit_size,
            "device_firmware": source.expected_firmware,
            "hardware_qualified": True,
        }
    )
    monkeypatch.setitem(
        bootstrap.STANDALONE_FLASH_PROFILES,
        profile_id,
        bootstrap.StandaloneFlashProfile(policy, 2, True),
    )
    plan = replace(
        source,
        mutation_profile_id=profile_id,
        expected_metadata_abi=2,
        expected_tandem_agc=True,
        operation="flash",
        target_serial="SERIAL_A",
    )
    monkeypatch.setattr(
        bootstrap, "_one_local_target", lambda path: _local(target, serial="SERIAL_A")
    )
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "SERIAL_A",
            "fw_version": plan.expected_firmware,
            "iio,buffer-metadata": "2",
            "device_names": ("ad9361-phy", "tandem-agc"),
        },
    )
    receipt_id = "11111111-2222-3333-4444-555555555555"
    receipt_directory = tmp_path / "receipts"
    bootstrap._write_receipt(
        receipt_directory / f"{receipt_id}.json",
        {
            "schema_version": 1,
            "receipt_id": receipt_id,
            "transport": "bound_ssh_frm",
            "outcome": "unknown",
            "plan": asdict(plan),
            "phases": ["reboot_dispatched", "reappeared"],
        },
    )
    return plan, receipt_directory, receipt_id


def test_standalone_reconciliation_is_read_only_and_verifies_exact_fit(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    transport = ReadOnlyReconciliationTransport(plan)

    result = bootstrap.reconcile_usb_flash_receipt(
        receipt_id,
        receipt_directory=receipt_directory,
        usb_sysfs_path=Path(plan.usb_sysfs_path),
        mutation_profile_id=plan.mutation_profile_id,
        transport=transport,
    )

    assert result.outcome == "reconciled_verified"
    assert result.tx_safe is True
    assert result.fit_sha256 == plan.fit_sha256
    assert len(transport.calls) == 1
    command, script = transport.calls[0]
    assert command == f"sh -s -- SERIAL_A {plan.fit_size}"
    assert script == bootstrap._REMOTE_RECONCILE_SCRIPT
    assert b"update_frm" not in (script or b"")
    assert b"device_reboot" not in (script or b"")
    persisted = json.loads((receipt_directory / f"{receipt_id}.json").read_text())
    assert persisted["original_outcome"] == "unknown"
    assert persisted["outcome"] == "reconciled_verified"


def test_standalone_reconciliation_accepts_proven_post_eject_mass_storage_receipt(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    receipt_path = receipt_directory / f"{receipt_id}.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("transport")
    receipt.update(
        {
            "failure_classification": "post_eject_uncertain",
            "retryable": False,
            "phases": ["preflight_revalidated", "eject_requested", "media_ejected"],
        }
    )
    bootstrap._write_receipt(receipt_path, receipt)
    transport = ReadOnlyReconciliationTransport(plan)

    result = bootstrap.reconcile_usb_flash_receipt(
        receipt_id,
        receipt_directory=receipt_directory,
        usb_sysfs_path=Path(plan.usb_sysfs_path),
        mutation_profile_id=plan.mutation_profile_id,
        transport=transport,
    )

    assert result.outcome == "reconciled_verified"
    assert result.tx_safe is True
    assert len(transport.calls) == 1


def test_standalone_reconciliation_reverifies_successful_mass_storage_receipt(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    receipt_path = receipt_directory / f"{receipt_id}.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("transport")
    receipt.update(
        {
            "outcome": "success",
            "error": None,
            "phases": [
                "preflight_revalidated",
                "eject_requested",
                "media_ejected",
                "reappeared",
                "return_attested",
                "tx_safe_attested",
            ],
        }
    )
    bootstrap._write_receipt(receipt_path, receipt)
    transport = ReadOnlyReconciliationTransport(plan)

    result = bootstrap.reconcile_usb_flash_receipt(
        receipt_id,
        receipt_directory=receipt_directory,
        usb_sysfs_path=Path(plan.usb_sysfs_path),
        mutation_profile_id=plan.mutation_profile_id,
        transport=transport,
    )

    assert result.outcome == "reconciled_verified"
    assert result.fit_sha256 == plan.fit_sha256
    assert result.tx_safe is True
    assert len(transport.calls) == 1
    persisted = json.loads(receipt_path.read_text())
    assert persisted["original_outcome"] == "success"
    assert persisted["outcome"] == "reconciled_verified"


def test_standalone_reconciliation_rejects_ambiguous_mass_storage_receipt(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    receipt_path = receipt_directory / f"{receipt_id}.json"
    receipt = json.loads(receipt_path.read_text())
    receipt.pop("transport")
    receipt["phases"] = ["preflight_revalidated", "mounted"]
    bootstrap._write_receipt(receipt_path, receipt)
    transport = ReadOnlyReconciliationTransport(plan)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="post-eject"):
        bootstrap.reconcile_usb_flash_receipt(
            receipt_id,
            receipt_directory=receipt_directory,
            usb_sysfs_path=Path(plan.usb_sysfs_path),
            mutation_profile_id=plan.mutation_profile_id,
            transport=transport,
        )

    assert transport.calls == []


def test_standalone_reconciliation_rejects_profile_mismatch_before_remote_access(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    transport = ReadOnlyReconciliationTransport(plan)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="profile does not match"):
        bootstrap.reconcile_usb_flash_receipt(
            receipt_id,
            receipt_directory=receipt_directory,
            usb_sysfs_path=Path(plan.usb_sysfs_path),
            mutation_profile_id="wrong-profile",
            transport=transport,
        )

    assert transport.calls == []


def test_standalone_reconciliation_rejects_untrusted_receipt_serial(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, receipt_directory, receipt_id = _uncertain_serial_receipt(
        planned, tmp_path, monkeypatch
    )
    receipt_path = receipt_directory / f"{receipt_id}.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["plan"]["target_serial"] = "SERIAL_A;reboot"
    bootstrap._write_receipt(receipt_path, receipt)
    transport = ReadOnlyReconciliationTransport(plan)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="invalid radio serial"):
        bootstrap.reconcile_usb_flash_receipt(
            receipt_id,
            receipt_directory=receipt_directory,
            usb_sysfs_path=Path(plan.usb_sysfs_path),
            mutation_profile_id=plan.mutation_profile_id,
            transport=transport,
        )

    assert transport.calls == []


def test_force_flash_can_verify_v5_when_hardware_serial_remains_blank(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target = planned
    monkeypatch.setattr(bootstrap, "_one_local_target", lambda path: _local(target))
    monkeypatch.setattr(
        bootstrap,
        "inspect_bound_iiod",
        lambda interface: {
            "hw_serial": "",
            "fw_version": plan.expected_firmware,
            "ad9361-phy,model": "ad9363a",
            "iio,buffer-metadata": "1",
        },
    )

    serial, firmware, phy = bootstrap._attest_return(plan)

    assert serial is None
    assert firmware == plan.expected_firmware
    assert phy == "ad9363a"


def test_return_attestation_retries_transient_iiod_startup(
    planned: tuple[bootstrap.BootstrapPlan, bytes, Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _ = planned
    attempts = 0

    def attest(current: bootstrap.BootstrapPlan) -> tuple[None, str, str]:
        nonlocal attempts
        assert current == plan
        attempts += 1
        if attempts == 1:
            raise bootstrap.BootstrapFirmwareError("IIOD timed out")
        return None, plan.expected_firmware, "ad9363a"

    monkeypatch.setattr(bootstrap, "_attest_return", attest)
    monkeypatch.setattr(bootstrap.time, "sleep", lambda duration: None)

    result = bootstrap._attest_return_when_ready(plan, timeout_s=1)

    assert result == (None, plan.expected_firmware, "ad9363a")
    assert attempts == 2


def test_returned_radio_mute_preflights_native_iio_before_radio_access(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Environment:
        healthy = False
        actionable_message = "explicit native libiio could not be loaded"

    monkeypatch.setattr(
        bootstrap,
        "inspect_iio_environment",
        lambda **_kwargs: Environment(),
    )

    with pytest.raises(
        bootstrap.BootstrapFirmwareError,
        match="returned-radio IIO environment failed.*explicit native libiio",
    ):
        bootstrap.mute_returned_radio("SERIAL_A")
