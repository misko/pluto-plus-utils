from __future__ import annotations

import hashlib
import json
import stat
from collections.abc import Sequence
from dataclasses import asdict, replace
from pathlib import Path

import pytest

import pluto_plus.bootstrap_firmware as bootstrap
import pluto_plus.volatile_firmware as volatile
from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
)
from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.local_reboot import LocalRebootAttestation, LocalRebootCapabilities


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


def _radio(path: Path) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(path),
        bus_number=3,
        device_number=7,
        product="PlutoSDR+",
        serial="SERIAL_A",
        speed_mbps=480,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name="enx001", ipv4_addresses=("192.168.2.10",)),
        ),
    )


def _facts(firmware: str) -> dict[str, object]:
    return {
        "hw_serial": "SERIAL_A",
        "hw_model": "Analog Devices PlutoSDR Rev.C",
        "fw_version": firmware,
        "ad9361-phy,model": "ad9361",
        "iio,buffer-metadata": "2",
        "device_names": ("ad9361-phy", "cf-ad9361-lpc", "tandem-agc"),
    }


@pytest.fixture
def ram_plan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]]:
    usb_root = tmp_path / "usb"
    target = usb_root / "3-7"
    target.mkdir(parents=True)
    (target / "busnum").write_text("3\n")
    (target / "devnum").write_text("7\n")
    image = tmp_path / "candidate.dfu"
    image.write_bytes(_dfu())
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("192.168.1.15 ssh-ed25519 AAAATEST\n")
    known_hosts.chmod(0o600)
    fit = _fit()
    policy = bootstrap.TANDEM_V6_LATCH_CLEAR_RAM_POLICY.model_copy(
        update={
            "asset_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
            "fit_body_sha256": hashlib.sha256(fit).hexdigest(),
            "fit_body_size": len(fit),
            "device_firmware": "candidate-v1",
        }
    )
    profile_id = policy.profile_id
    monkeypatch.setitem(
        volatile.STANDALONE_FLASH_PROFILES,
        profile_id,
        bootstrap.StandaloneFlashProfile(policy, 2, True, persistent_allowed=False),
    )
    monkeypatch.setattr(volatile, "_USB_ROOT", usb_root)
    radios = (_radio(target),)
    plan = volatile.prepare_ram_boot_plan(
        image,
        target,
        profile_id=profile_id,
        transition_host="192.168.1.15",
        known_hosts_file=known_hosts,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("stable-v6"),
        usb_access_checker=lambda path: True,
    )
    return plan, known_hosts, target, radios


def test_plan_is_exact_profile_path_serial_and_explicitly_volatile(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, target, _ = ram_plan

    assert plan.usb_sysfs_path == str(target)
    assert plan.serial == "SERIAL_A"
    assert plan.transition_route_mode == "lan"
    assert plan.confirmation_phrase == "RAM BOOT SERIAL_A"
    assert plan.expected_firmware == "candidate-v1"
    assert plan.fit_size == len(_fit())


def test_ram_only_profile_is_rejected_by_persistent_flash(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, target, radios = ram_plan
    monkeypatch.setattr(bootstrap, "_USB_ROOT", target.parent)
    monkeypatch.setattr(bootstrap, "scan_local_usb_plutos", lambda: radios)

    with pytest.raises(bootstrap.BootstrapFirmwareError, match="RAM-only"):
        bootstrap.prepare_usb_flash_plan(
            Path(plan.image_path),
            target,
            mutation_profile_id=plan.profile_id,
        )


class RecordingTransition:
    def __init__(self, *, fail: bool = False) -> None:
        self.calls: list[str] = []
        self.fail = fail

    def enter_ram(self, plan: volatile.VolatileFirmwarePlan) -> None:
        self.calls.append(plan.serial)
        if self.fail:
            raise TimeoutError("radio disconnected during RAM transition")


class RecordingRunner:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], *, timeout_s: float) -> str:
        assert timeout_s > 0
        command = tuple(argv)
        self.commands.append(command)
        return "dfu-util 0.11"


class RecordingSshTransport:
    def __init__(self) -> None:
        self.commands: list[str] = []

    def run(self, command: str, *, stdin: bytes | None = None, timeout_s: float = 15) -> str:
        self.commands.append(command)
        return ""


class FixedAttestationRadio:
    def __init__(self, attestation: LocalRebootAttestation) -> None:
        self.attestation = attestation
        self.muted: list[str] = []

    def attest(self, serial: str) -> LocalRebootAttestation:
        assert serial == self.attestation.serial
        return self.attestation

    def ensure_tx_safe(self, serial: str) -> None:
        self.muted.append(serial)


def test_ssh_transition_accepts_equivalent_rev_c_models_from_iiod_and_device_tree(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, _, _ = ram_plan
    transport = RecordingSshTransport()
    transition = volatile.SshRamBootTransition(transport)  # type: ignore[arg-type]
    radio = FixedAttestationRadio(
        LocalRebootAttestation(
            serial=plan.serial,
            firmware=plan.before_firmware,
            boot_id="boot-a",
            capabilities=LocalRebootCapabilities(
                board_model="Analog Devices PlutoSDR Rev.C (Z7010/AD9363)",
                phy_model=plan.before_phy,
                rx_scan_channels=("voltage0", "voltage1"),
                tandem_agc=False,
            ),
        )
    )
    transition._radio = radio  # type: ignore[assignment]

    transition.enter_ram(plan)

    assert radio.muted == [plan.serial]
    assert len(transport.commands) == 1
    assert "/usr/sbin/device_reboot ram" in transport.commands[0]


def test_execute_uses_only_exact_path_firmware_alt_and_attests_return(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, known_hosts, _, radios = ram_plan
    facts = iter((_facts("stable-v6"), _facts("candidate-v1")))
    products = iter(("b674", "b673"))
    transition = RecordingTransition()
    runner = RecordingRunner()
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    result = volatile.execute_ram_boot_plan(
        plan,
        confirmation=plan.confirmation_phrase,
        known_hosts_file=known_hosts,
        transition=transition,
        receipt_directory=tmp_path / "receipts",
        command_runner=runner,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: next(facts),
        usb_access_checker=lambda path: True,
        usb_product_reader=lambda path: next(products),
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "success"
    assert transition.calls == ["SERIAL_A"]
    assert runner.commands[0] == ("dfu-util", "--version")
    assert runner.commands[1][:7] == (
        "dfu-util",
        "-p",
        "3-7",
        "-d",
        "0456:b673,0456:b674",
        "-a",
        "firmware.dfu",
    )
    assert runner.commands[1][-2:] == ("-D", plan.image_path)
    assert runner.commands[2][-1] == "-e"
    assert muted == [("SERIAL_A", Path(plan.usb_sysfs_path))]
    assert stat.S_IMODE(Path(result.receipt_path).stat().st_mode) == 0o600
    receipt = json.loads(Path(result.receipt_path).read_text())
    assert receipt["outcome"] == "success"
    assert "volatile_dfu_downloaded" in receipt["phases"]


def test_ram_return_attestation_requires_exact_ddr_burst_capability(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _, radios = ram_plan
    burst_plan = replace(
        plan,
        expected_ddr_burst_max_iq_bytes=200_000_000,
        expected_ddr_burst_reserve_bytes=128 * 1024 * 1024,
    )
    facts = _facts("candidate-v1")
    facts.update(
        {
            "iio,buffer-ddr-burst": "1",
            "iio,buffer-ddr-burst-max-iq-bytes": "200000000",
            "iio,buffer-ddr-burst-reserve-bytes": "134217728",
        }
    )
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    returned = volatile._attest_ram_return(
        burst_plan,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: facts,
        timeout_s=0.05,
        poll_interval_s=0.001,
    )

    assert returned == ("SERIAL_A", "candidate-v1", "ad9361")
    assert muted == [("SERIAL_A", Path(plan.usb_sysfs_path))]

    facts["iio,buffer-ddr-burst-max-iq-bytes"] = "199999999"
    with pytest.raises(volatile.VolatileFirmwareError, match="DDR burst capability"):
        volatile._attest_ram_return(
            burst_plan,
            scanner=lambda: radios,
            iiod_inspector=lambda interface: facts,
            timeout_s=0.01,
            poll_interval_s=0.001,
        )


def test_ram_return_attestation_requires_exact_ddr_ring_capability(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _, radios = ram_plan
    ring_plan = replace(
        plan,
        expected_ddr_ring_max_iq_bytes=200_000_000,
        expected_ddr_ring_modes="finite,continuous",
        expected_buffer_metadata_status=True,
    )
    facts = _facts("candidate-v1")
    facts.update(
        {
            "iio,buffer-ddr-ring": "1",
            "iio,buffer-ddr-ring-max-iq-bytes": "200000000",
            "iio,buffer-ddr-ring-modes": "finite,continuous",
            "iio,buffer-metadata-status": "1",
        }
    )
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    returned = volatile._attest_ram_return(
        ring_plan,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: facts,
        timeout_s=0.05,
        poll_interval_s=0.001,
    )

    assert returned == ("SERIAL_A", "candidate-v1", "ad9361")
    assert muted == [("SERIAL_A", Path(plan.usb_sysfs_path))]

    facts["iio,buffer-ddr-ring-modes"] = "finite"
    with pytest.raises(volatile.VolatileFirmwareError, match="DDR ring capability"):
        volatile._attest_ram_return(
            ring_plan,
            scanner=lambda: radios,
            iiod_inspector=lambda interface: facts,
            timeout_s=0.01,
            poll_interval_s=0.001,
        )


@pytest.mark.parametrize(
    ("expected", "observed", "accepted"),
    [
        (False, "", True),
        (False, "1", False),
        (True, "1", True),
        (True, "", False),
        (True, "0", False),
        (True, "2", False),
        (True, "true", False),
    ],
)
def test_ram_return_attestation_requires_exact_timing_log_capability(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
    expected: bool,
    observed: str,
    accepted: bool,
) -> None:
    plan, _, _, radios = ram_plan
    timing_plan = replace(plan, expected_buffer_metadata_timing_log=expected)
    facts = _facts("candidate-v1")
    if observed:
        facts["iio,buffer-metadata-timing-log"] = observed
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    if accepted:
        returned = volatile._attest_ram_return(
            timing_plan,
            scanner=lambda: radios,
            iiod_inspector=lambda interface: facts,
            timeout_s=0.05,
            poll_interval_s=0.001,
        )
        assert returned == ("SERIAL_A", "candidate-v1", "ad9361")
        assert muted == [("SERIAL_A", Path(plan.usb_sysfs_path))]
    else:
        with pytest.raises(volatile.VolatileFirmwareError, match="timing-log capability"):
            volatile._attest_ram_return(
                timing_plan,
                scanner=lambda: radios,
                iiod_inspector=lambda interface: facts,
                timeout_s=0.01,
                poll_interval_s=0.001,
            )
        assert muted == []


def test_receipt_cannot_change_the_profile_timing_log_requirement(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, _, _ = ram_plan
    volatile._revalidate_plan_image(plan)
    with pytest.raises(volatile.VolatileFirmwareError, match="immutable profile"):
        volatile._revalidate_plan_image(replace(plan, expected_buffer_metadata_timing_log=True))


@pytest.mark.parametrize(
    ("expected", "observed", "accepted"),
    [
        (None, "", True),
        (None, "1", False),
        (1, "1", True),
        (1, "", False),
        (1, "0", False),
        (1, "2", False),
    ],
)
def test_ram_return_attestation_requires_exact_iiod_cpu_affinity(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    monkeypatch: pytest.MonkeyPatch,
    expected: int | None,
    observed: str,
    accepted: bool,
) -> None:
    plan, _, _, radios = ram_plan
    affinity_plan = replace(plan, expected_iiod_cpu_affinity=expected)
    facts = _facts("candidate-v1")
    if observed:
        facts["iio,iiod-cpu-affinity"] = observed
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    if accepted:
        returned = volatile._attest_ram_return(
            affinity_plan,
            scanner=lambda: radios,
            iiod_inspector=lambda interface: facts,
            timeout_s=0.05,
            poll_interval_s=0.001,
        )
        assert returned == ("SERIAL_A", "candidate-v1", "ad9361")
        assert muted == [("SERIAL_A", Path(plan.usb_sysfs_path))]
    else:
        with pytest.raises(volatile.VolatileFirmwareError, match="CPU-affinity capability"):
            volatile._attest_ram_return(
                affinity_plan,
                scanner=lambda: radios,
                iiod_inspector=lambda interface: facts,
                timeout_s=0.01,
                poll_interval_s=0.001,
            )
        assert muted == []


def test_receipt_cannot_change_the_profile_iiod_cpu_affinity_requirement(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
) -> None:
    plan, _, _, _ = ram_plan
    volatile._revalidate_plan_image(plan)
    with pytest.raises(volatile.VolatileFirmwareError, match="immutable profile"):
        volatile._revalidate_plan_image(replace(plan, expected_iiod_cpu_affinity=1))


def test_transition_uncertainty_is_receipted_and_never_retryable(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, known_hosts, _, radios = ram_plan

    result = volatile.execute_ram_boot_plan(
        plan,
        confirmation=plan.confirmation_phrase,
        known_hosts_file=known_hosts,
        transition=RecordingTransition(fail=True),
        receipt_directory=tmp_path / "receipts",
        command_runner=RecordingRunner(),
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("stable-v6"),
        usb_access_checker=lambda path: True,
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "unknown"
    assert result.retryable is False
    assert "Do not retry" in (result.remediation or "")
    durable = json.loads(Path(result.receipt_path).read_text())
    assert durable["phases"][-1] == "ram_transition_dispatch_attempted"


def test_execute_refuses_unwritable_raw_usb_before_transition_or_receipt(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, known_hosts, _, radios = ram_plan
    blocked = plan.__class__(**(asdict(plan) | {"raw_usb_write_access": False}))
    transition = RecordingTransition()
    receipt_directory = tmp_path / "receipts"

    with pytest.raises(volatile.VolatileFirmwareError, match="not writable"):
        volatile.execute_ram_boot_plan(
            blocked,
            confirmation=blocked.confirmation_phrase,
            known_hosts_file=known_hosts,
            transition=transition,
            receipt_directory=receipt_directory,
            command_runner=RecordingRunner(),
            scanner=lambda: radios,
            iiod_inspector=lambda interface: _facts("stable-v6"),
            usb_access_checker=lambda path: False,
        )

    assert transition.calls == []
    assert not receipt_directory.exists()


def test_resume_exact_dfu_boundary_revalidates_downloads_and_attests_return(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _, radios = ram_plan
    source_id = "a" * 32
    source = tmp_path / f"{source_id}.json"
    source.write_text(
        json.dumps(
            {
                "receipt_id": source_id,
                "outcome": "unknown",
                "phases": [
                    "preflight_revalidated",
                    "dfu_util_ready",
                    "ram_transition_dispatch_attempted",
                    "ram_transition_dispatched",
                    "exact_path_entered_dfu",
                ],
                "plan": asdict(plan),
            }
        )
    )
    source.chmod(0o600)
    runner = RecordingRunner()
    products = iter(("b674", "b673"))
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )

    result = volatile.resume_ram_boot_receipt(
        source,
        confirmation=f"RESUME RAM BOOT {source_id}",
        receipt_directory=tmp_path / "resume-receipts",
        command_runner=runner,
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("candidate-v1"),
        usb_access_checker=lambda path: True,
        usb_product_reader=lambda path: next(products),
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "success"
    assert "0456:b673,0456:b674" in runner.commands[1]
    assert muted == [(plan.serial, Path(plan.usb_sysfs_path))]


def test_resume_rejects_receipt_after_download_phase(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, _, _, _ = ram_plan
    source_id = "b" * 32
    source = tmp_path / f"{source_id}.json"
    source.write_text(
        json.dumps(
            {
                "receipt_id": source_id,
                "outcome": "unknown",
                "phases": ["exact_path_entered_dfu", "volatile_dfu_downloaded"],
                "plan": asdict(plan),
            }
        )
    )
    source.chmod(0o600)

    with pytest.raises(volatile.VolatileFirmwareError, match="resumable DFU boundary"):
        volatile.resume_ram_boot_receipt(
            source,
            confirmation=f"RESUME RAM BOOT {source_id}",
            receipt_directory=tmp_path / "resume-receipts",
        )


def test_reconcile_returned_runtime_is_exact_path_and_has_no_dfu_runner(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan, _, _, radios = ram_plan
    source_id = "c" * 32
    source = tmp_path / f"{source_id}.json"
    source.write_text(
        json.dumps(
            {
                "receipt_id": source_id,
                "outcome": "unknown",
                "phases": [
                    "preflight_revalidated",
                    "dfu_util_ready",
                    "ram_transition_dispatch_attempted",
                    "ram_transition_dispatched",
                    "exact_path_entered_dfu",
                    "volatile_dfu_downloaded",
                    "dfu_detach_dispatched",
                    "exact_path_returned_runtime",
                ],
                "plan": asdict(plan),
            }
        )
    )
    source.chmod(0o600)
    muted: list[tuple[str, Path]] = []
    monkeypatch.setattr(
        volatile,
        "mute_returned_radio_at_path",
        lambda serial, path: muted.append((serial, path)),
    )
    monkeypatch.setattr(
        volatile.subprocess,
        "run",
        lambda *args, **kwargs: pytest.fail("reconciliation attempted an external command"),
    )

    result = volatile.reconcile_ram_boot_receipt(
        source,
        confirmation=f"RECONCILE RAM BOOT {source_id}",
        receipt_directory=tmp_path / "reconcile-receipts",
        scanner=lambda: radios,
        iiod_inspector=lambda interface: _facts("candidate-v1"),
        usb_product_reader=lambda path: "b673",
        timeout_s=0.1,
        poll_interval_s=0.001,
    )

    assert result.outcome == "success"
    assert result.source_receipt_id == source_id
    assert muted == [(plan.serial, Path(plan.usb_sysfs_path))]
    assert "source_receipt_reconciled" in result.phases
    durable = json.loads(Path(result.receipt_path).read_text())
    assert durable["source_receipt_id"] == source_id
    assert durable["outcome"] == "success"


def test_reconcile_refuses_receipt_before_exact_runtime_return(
    ram_plan: tuple[volatile.VolatileFirmwarePlan, Path, Path, tuple[LocalUsbPluto, ...]],
    tmp_path: Path,
) -> None:
    plan, _, _, _ = ram_plan
    source_id = "d" * 32
    source = tmp_path / f"{source_id}.json"
    source.write_text(
        json.dumps(
            {
                "receipt_id": source_id,
                "outcome": "unknown",
                "phases": [
                    "preflight_revalidated",
                    "dfu_util_ready",
                    "ram_transition_dispatch_attempted",
                    "ram_transition_dispatched",
                    "exact_path_entered_dfu",
                    "volatile_dfu_downloaded",
                    "dfu_detach_dispatched",
                ],
                "plan": asdict(plan),
            }
        )
    )
    source.chmod(0o600)

    with pytest.raises(volatile.VolatileFirmwareError, match="exact-path runtime return"):
        volatile.reconcile_ram_boot_receipt(
            source,
            confirmation=f"RECONCILE RAM BOOT {source_id}",
            receipt_directory=tmp_path / "reconcile-receipts",
        )
