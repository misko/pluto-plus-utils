from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Sequence
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.inventory import HostNetworkInterface, LocalUsbPluto
from pluto_plus.release_candidate import (
    HostRouteReceipt,
    QspiObservation,
    RuntimeObservation,
    SafeState,
    UsbInventoryTarget,
)
from pluto_plus.release_candidate_lifecycle import (
    PasswordFileIdentity,
    ReleaseCandidateLifecycleError,
    validate_password_file,
)
from pluto_plus.release_candidate_linux import (
    LinuxReleaseCandidateBackend,
    attest_clean_tool_repository,
)

SERIAL = "winbond-db6968136727402c"
TOPOLOGY = "3-7"
INTERFACE = "enx00e02215c53b"


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial=SERIAL,
        topology=TOPOLOGY,
        sysfs_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
        bus_number=3,
        device_number=29,
        network_interface=INTERFACE,
        source_ipv4="192.168.2.10",
    )


def _local(*, usb_path: str = f"/sys/bus/usb/devices/{TOPOLOGY}") -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=usb_path,
        bus_number=3,
        device_number=29,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480.0,
        interface_count=7,
        host_network_interfaces=(
            HostNetworkInterface(name=INTERFACE, ipv4_addresses=("192.168.2.10",)),
        ),
    )


def _runtime(*, boot_id: str) -> RuntimeObservation:
    return RuntimeObservation(
        serial=SERIAL,
        topology=TOPOLOGY,
        usb_uri="usb:3.31.5",
        hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
        firmware_version="v0.41-plutoplus-spf-tandem-agc-v8-rc12",
        metadata_abi="frame-metadata-v2",
        capabilities=("tandem-agc",),
        boot_id=boot_id,
        qspi=QspiObservation(bytes=31_457_280, sha256="9" * 64),
        safe_state=SafeState(
            tx_gain_db=(-80.0, -80.0),
            dds_raw=(0,) * 8,
            dds_scale=(0.0,) * 8,
            dac_selectors=(3, 3, 3, 3),
            tandem_state="IDLE",
            fifo_level=0,
            fault_flags=0,
        ),
    )


class RouteRunner:
    def __init__(self) -> None:
        self.route_present = False
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        argv: Sequence[str],
        *,
        timeout_s: float,
        pass_fds: Sequence[int] = (),
        allowed_returncodes: Sequence[int] = (0,),
    ) -> str:
        del timeout_s, pass_fds, allowed_returncodes
        call = tuple(argv)
        self.calls.append(call)
        if call[:5] == ("ip", "-j", "-4", "address", "show"):
            return json.dumps(
                [
                    {
                        "ifname": INTERFACE,
                        "addr_info": [
                            {
                                "family": "inet",
                                "scope": "global",
                                "local": "192.168.2.10",
                            }
                        ],
                    }
                ]
            )
        if call[:5] == ("ip", "-j", "-4", "route", "show"):
            return json.dumps(
                [
                    {
                        "dst": "192.168.2.1",
                        "dev": INTERFACE,
                        "prefsrc": "192.168.2.10",
                        "scope": "link",
                        "protocol": "static",
                        "table": "main",
                    }
                ]
                if self.route_present
                else []
            )
        if call[:5] == ("ip", "-j", "-4", "route", "get"):
            return json.dumps([{"dst": "192.168.2.1", "dev": INTERFACE, "prefsrc": "192.168.2.10"}])
        if call[:6] == ("sudo", "-n", "ip", "route", "add", "192.168.2.1/32"):
            assert not self.route_present
            self.route_present = True
            return ""
        if call[:6] == ("sudo", "-n", "ip", "route", "del", "192.168.2.1/32"):
            assert self.route_present
            self.route_present = False
            return ""
        raise AssertionError(f"unexpected command {call}")


def _backend(tmp_path: Path, runner: RouteRunner | None = None) -> LinuxReleaseCandidateBackend:
    return LinuxReleaseCandidateBackend(
        state_root=(tmp_path / "state").absolute(),
        scanner=lambda: (_local(),),
        command_runner=runner or RouteRunner(),
    )


def test_exact_host_route_is_added_verified_and_removed_under_locks(tmp_path: Path) -> None:
    runner = RouteRunner()
    backend = _backend(tmp_path, runner)
    target = _target()

    with backend.transaction_locks(target, "192.168.2.1"):
        assert backend.revalidate_target(target) == target
        route = backend.acquire_host_route(target, "192.168.2.1")
        assert route.destination == "192.168.2.1/32"
        assert route.interface == INTERFACE
        assert route.source == "192.168.2.10"
        backend.ensure_host_route(route, target)
        backend.release_host_route(route)

    assert runner.route_present is False
    assert any(call[:5] == ("sudo", "-n", "ip", "route", "add") for call in runner.calls)
    assert any(call[:5] == ("sudo", "-n", "ip", "route", "del") for call in runner.calls)


def test_preexisting_host_route_is_never_replaced_or_deleted(tmp_path: Path) -> None:
    runner = RouteRunner()
    runner.route_present = True
    backend = _backend(tmp_path, runner)

    with (
        backend.transaction_locks(_target(), "192.168.2.1"),
        pytest.raises(ReleaseCandidateLifecycleError, match="pre-existing"),
    ):
        backend.acquire_host_route(_target(), "192.168.2.1")

    assert runner.route_present is True
    assert not any(call[:5] == ("sudo", "-n", "ip", "route", "del") for call in runner.calls)


def test_global_daemon_lock_refuses_concurrent_candidate_transaction(tmp_path: Path) -> None:
    first = _backend(tmp_path)
    second = _backend(tmp_path)

    with (
        first.transaction_locks(_target(), "192.168.2.1"),
        pytest.raises(ReleaseCandidateLifecycleError, match="already owned"),
        second.transaction_locks(_target(), "192.168.2.1"),
    ):
        pytest.fail("second transaction unexpectedly acquired the lock")


def test_sealed_dfu_descriptor_is_immutable_and_disappears_after_scope(tmp_path: Path) -> None:
    backend = _backend(tmp_path)
    payload = b"candidate-dfu-bytes"

    with backend.sealed_dfu(payload) as path:
        descriptor = int(path.name)
        assert os.pread(descriptor, len(payload), 0) == payload
        with pytest.raises(OSError):
            os.write(descriptor, b"x")

    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_runtime_attestation_opens_exact_usb_uri_without_global_discovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    opened: list[str] = []

    class StopAfterOpen(RuntimeError):
        pass

    def context(uri: str) -> None:
        opened.append(uri)
        raise StopAfterOpen

    module = SimpleNamespace(Context=context)
    monkeypatch.setattr(
        "pluto_plus.release_candidate_linux.importlib.import_module",
        lambda name: module if name == "iio" else pytest.fail(name),
    )
    password = PasswordFileIdentity(
        path=(tmp_path / "password").absolute(),
        device=1,
        inode=2,
        bytes=7,
        modified_ns=3,
        changed_ns=4,
    )
    route = HostRouteReceipt(
        destination="192.168.2.1/32",
        interface=INTERFACE,
        source="192.168.2.10",
        release_verified=False,
    )

    with pytest.raises(StopAfterOpen):
        _backend(tmp_path)._attest_runtime_linux(_target(), "candidate-version", password, route)

    assert opened == ["usb:3.29.5"]


class AdvancingClock:
    def __init__(self) -> None:
        self.value = 0.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, duration: float) -> None:
        self.value += duration


def _dfu_sysfs(root: Path, *, serial: str | None) -> None:
    target = root / TOPOLOGY
    target.mkdir(parents=True)
    (target / "idVendor").write_text("0456\n")
    (target / "idProduct").write_text("b674\n")
    (target / "busnum").write_text("3\n")
    (target / "devnum").write_text("31\n")
    if serial is not None:
        (target / "serial").write_text(serial + "\n")


@pytest.mark.parametrize("serial", [None, "", SERIAL])
def test_exact_topology_dfu_accepts_absent_empty_or_matching_serial(
    tmp_path: Path, serial: str | None
) -> None:
    root = tmp_path / "usb"
    _dfu_sysfs(root, serial=serial)
    backend = LinuxReleaseCandidateBackend(
        state_root=(tmp_path / "state").absolute(),
        sysfs_root=root,
        scanner=lambda: (),
    )

    backend.wait_for_dfu(_target(), timeout_s=1)


def test_exact_topology_dfu_accepts_real_kernel_sysfs_symlink_shape(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sys" / "bus" / "usb" / "devices"
    root.mkdir(parents=True)
    physical_root = tmp_path / "sys" / "devices" / "pci0000:00" / "usb3"
    _dfu_sysfs(physical_root, serial=None)
    (root / TOPOLOGY).symlink_to(physical_root / TOPOLOGY)
    backend = LinuxReleaseCandidateBackend(
        state_root=(tmp_path / "state").absolute(),
        sysfs_root=root,
        scanner=lambda: (),
    )

    backend.wait_for_dfu(_target(), timeout_s=1)


def test_unknown_dfu_recovery_detaches_and_attests_unchanged_qspi(
    tmp_path: Path,
) -> None:
    root = tmp_path / "sys" / "bus" / "usb" / "devices"
    root.mkdir(parents=True)
    physical_root = tmp_path / "sys" / "devices" / "pci0000:00" / "usb3"
    _dfu_sysfs(physical_root, serial=None)
    (root / TOPOLOGY).symlink_to(physical_root / TOPOLOGY)

    class RecoveryRunner(RouteRunner):
        runtime_ready = False

        def run(
            self,
            argv: Sequence[str],
            *,
            timeout_s: float,
            pass_fds: Sequence[int] = (),
            allowed_returncodes: Sequence[int] = (0,),
        ) -> str:
            call = tuple(argv)
            if call and call[0] == "dfu-util":
                assert call == (
                    "dfu-util",
                    "-d",
                    "0456:b673,0456:b674",
                    "-p",
                    TOPOLOGY,
                    "-a",
                    "firmware.dfu",
                    "-e",
                )
                self.calls.append(call)
                self.runtime_ready = True
                return ""
            return super().run(
                argv,
                timeout_s=timeout_s,
                pass_fds=pass_fds,
                allowed_returncodes=allowed_returncodes,
            )

    runner = RecoveryRunner()

    class RecoveryBackend(LinuxReleaseCandidateBackend):
        def wait_for_runtime(
            self, target: UsbInventoryTarget, *, timeout_s: float
        ) -> UsbInventoryTarget:
            assert timeout_s == 45
            assert runner.runtime_ready
            return target

    password_path = tmp_path / "password"
    password_path.write_text("analog\n")
    password_path.chmod(0o600)
    password = validate_password_file(password_path.absolute())
    pre = _runtime(boot_id="11111111-1111-4111-8111-111111111111")
    recovered = _runtime(boot_id="22222222-2222-4222-8222-222222222222")
    backend = RecoveryBackend(
        state_root=(tmp_path / "state").absolute(),
        sysfs_root=root,
        scanner=lambda: (),
        command_runner=runner,
        runtime_attestor=lambda target, expected_firmware, password, route: recovered,
    )

    with backend.transaction_locks(_target(), "192.168.2.1"):
        observed, route = backend.recover_unknown_runtime(
            _target(),
            pre_runtime=pre,
            expected_firmware=pre.firmware_version,
            password=password,
            ssh_host="192.168.2.1",
            timeout_s=45,
        )

    assert observed == recovered
    assert route.release_verified is True
    assert runner.route_present is False
    assert any(call[0] == "dfu-util" for call in runner.calls)


def test_exact_topology_dfu_rejects_present_wrong_serial(tmp_path: Path) -> None:
    root = tmp_path / "usb"
    _dfu_sysfs(root, serial="OTHER")
    clock = AdvancingClock()
    backend = LinuxReleaseCandidateBackend(
        state_root=(tmp_path / "state").absolute(),
        sysfs_root=root,
        scanner=lambda: (),
        sleep=clock.sleep,
        monotonic=clock.monotonic,
    )

    with pytest.raises(ReleaseCandidateLifecycleError, match="different serial"):
        backend.wait_for_dfu(_target(), timeout_s=0.5)


def test_clean_tool_repository_attestation_rejects_dirty_tree(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    subprocess.run(("git", "-C", str(repository), "init", "-q"), check=True)
    subprocess.run(
        ("git", "-C", str(repository), "config", "user.email", "test@example.invalid"),
        check=True,
    )
    subprocess.run(("git", "-C", str(repository), "config", "user.name", "Test"), check=True)
    tracked = repository / "tracked.txt"
    tracked.write_text("one\n")
    subprocess.run(("git", "-C", str(repository), "add", "tracked.txt"), check=True)
    subprocess.run(("git", "-C", str(repository), "commit", "-qm", "initial"), check=True)
    subprocess.run(
        (
            "git",
            "-C",
            str(repository),
            "remote",
            "add",
            "origin",
            "git@github.com:misko/pluto-plus-utils.git",
        ),
        check=True,
    )

    source = attest_clean_tool_repository(repository)
    assert len(source.commit) == 40
    assert source.repository == "misko/pluto-plus-utils"
    tracked.write_text("two\n")
    with pytest.raises(ReleaseCandidateLifecycleError, match="fully clean"):
        attest_clean_tool_repository(repository)
