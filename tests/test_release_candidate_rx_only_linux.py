from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from pluto_plus.hardware import iio as hardware_iio
from pluto_plus.release_candidate import HostRouteReceipt, UsbInventoryTarget
from pluto_plus.release_candidate_lifecycle import (
    PasswordFileIdentity,
    ReleaseCandidateLifecycleError,
)
from pluto_plus.release_candidate_rx_only_linux import (
    LinuxRxOnlyReleaseCandidateBackend,
    _attribute_channel_ids,
    _attribute_channel_inventory,
    _require_exact_tx_control_inventory,
    _single_rx_setup,
    _topology_states,
)


def _channel(
    identifier: str,
    *attributes: str,
    output: bool = True,
    name: str | None = None,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=identifier,
        name=name or "",
        output=output,
        attrs={attribute: SimpleNamespace(value="0") for attribute in attributes},
    )


def _phy(*, extra_gain: bool = False, extra_lo: bool = False) -> SimpleNamespace:
    channels = [
        _channel("voltage0", "hardwaregain"),
        _channel("altvoltage0", "powerdown", name="RX_LO"),
        _channel("altvoltage1", "powerdown", name="TX_LO"),
    ]
    if extra_gain:
        channels.append(_channel("voltage1", "hardwaregain"))
    if extra_lo:
        channels.append(_channel("altvoltage2", "powerdown", name="EXTRA_LO"))
    return SimpleNamespace(channels=channels)


def _dds(*, count: int = 4) -> SimpleNamespace:
    return SimpleNamespace(
        channels=[
            _channel(f"altvoltage{index}", "raw", "scale") for index in range(count)
        ]
    )


def _remote(**changes: str) -> dict[str, str]:
    value = {
        "uboot_attr_name_present": "1",
        "uboot_attr_name": "compatible",
        "uboot_attr_val_present": "1",
        "uboot_attr_val": "ad9361",
        "uboot_compatible": "ad9361",
        "uboot_mode": "1r1t",
        "root_marker_present": "0",
        "rx_dma_dt_state": "enabled",
        "dds_dt_state": "enabled",
        "tx_dma_dt_state": "enabled",
        "tandem_dt_state": "enabled",
    }
    return value | changes


def test_linux_inventory_proves_one_gain_and_one_shared_lo_without_aliasing() -> None:
    phy = _phy()

    assert _attribute_channel_ids(phy, "hardwaregain") == ("voltage0",)
    assert _attribute_channel_inventory(phy, "powerdown") == (
        ("altvoltage0", "RX_LO"),
        ("altvoltage1", "TX_LO"),
    )
    _require_exact_tx_control_inventory(phy, _dds(), expected_layout="tx-capable")


@pytest.mark.parametrize(
    "phy",
    [
        SimpleNamespace(
            channels=[_channel("altvoltage1", "powerdown", name="TX_LO")]
        ),
        _phy(extra_gain=True),
        SimpleNamespace(
            channels=[
                _channel("voltage0", "hardwaregain"),
                _channel("altvoltage0", "powerdown", name="RX_LO"),
            ]
        ),
        _phy(extra_lo=True),
        SimpleNamespace(
            channels=[
                _channel("voltage0", "hardwaregain"),
                _channel("altvoltage0", "powerdown", name="RX_LO"),
                _channel("altvoltage1", "powerdown", name="WRONG_LO"),
            ]
        ),
    ],
)
def test_linux_inventory_rejects_missing_or_extra_gain_and_lo_controls(
    phy: SimpleNamespace,
) -> None:
    with pytest.raises(ReleaseCandidateLifecycleError, match="exactly"):
        _require_exact_tx_control_inventory(phy, _dds(), expected_layout="tx-capable")


@pytest.mark.parametrize("count", [0, 3, 5, 8])
def test_linux_tx_capable_inventory_rejects_non_1r1t_dds_shapes(count: int) -> None:
    with pytest.raises(ReleaseCandidateLifecycleError, match="DDS control inventory"):
        _require_exact_tx_control_inventory(
            _phy(), _dds(count=count), expected_layout="tx-capable"
        )


def test_linux_rx_only_inventory_requires_dds_absence() -> None:
    _require_exact_tx_control_inventory(_phy(), None, expected_layout="rx-only")
    with pytest.raises(ReleaseCandidateLifecycleError, match="unexpectedly exposes"):
        _require_exact_tx_control_inventory(
            _phy(), _dds(), expected_layout="rx-only"
        )


def test_linux_single_rx_setup_proves_exact_target_and_scan_geometry() -> None:
    setup = _single_rx_setup(
        {"phy_model": "ad9361", "rx_scan_channels": ("voltage0", "voltage1")},
        _remote(),
        "ad9361-1r1t",
    )

    assert setup.runtime_target == "ad9361-1r1t"
    assert setup.uboot_mode == "1r1t"
    with pytest.raises(ValidationError, match="1r1t|at most 2"):
        _single_rx_setup(
            {
                "phy_model": "ad9361",
                "rx_scan_channels": (
                    "voltage0",
                    "voltage1",
                    "voltage2",
                    "voltage3",
                ),
            },
            _remote(uboot_mode="2r2t"),
            "ad9361-1r1t",
        )


def test_linux_single_rx_setup_accepts_exact_ad9363a_target() -> None:
    setup = _single_rx_setup(
        {"phy_model": "ad9363a", "rx_scan_channels": ("voltage0", "voltage1")},
        _remote(
            uboot_attr_val="ad9363a",
            uboot_compatible="ad9363a",
        ),
        "ad9363a-1r1t",
    )

    assert setup.runtime_target == "ad9363a-1r1t"
    assert setup.phy_model == "ad9363a"


def test_linux_single_rx_setup_rejects_half_present_uboot_attr_pair() -> None:
    with pytest.raises(ReleaseCandidateLifecycleError, match="presence differs"):
        _single_rx_setup(
            {"phy_model": "ad9361", "rx_scan_channels": ("voltage0", "voltage1")},
            _remote(uboot_attr_val_present="0", uboot_attr_val=""),
            "ad9361-1r1t",
        )


def test_linux_topology_tuple_keeps_marker_and_every_dt_node_distinct() -> None:
    assert _topology_states(_remote()) == (
        False,
        "enabled",
        "enabled",
        "enabled",
        "enabled",
    )
    assert _topology_states(
        _remote(
            root_marker_present="1",
            dds_dt_state="disabled",
            tx_dma_dt_state="disabled",
            tandem_dt_state="disabled",
        )
    ) == (True, "enabled", "disabled", "disabled", "disabled")


class FakeChannel:
    def __init__(self, identifier: str, **attributes: str) -> None:
        self.id = identifier
        self.name = (
            "RX_LO"
            if identifier == "altvoltage0" and "powerdown" in attributes
            else "TX_LO"
            if identifier == "altvoltage1" and "powerdown" in attributes
            else ""
        )
        self.output = True
        self.attrs = {
            name: SimpleNamespace(value=value) for name, value in attributes.items()
        }


class FakeDevice:
    def __init__(
        self,
        name: str,
        channels: list[FakeChannel] | None = None,
        **attributes: str,
    ) -> None:
        self.name = name
        self.channels = channels or []
        self.attrs = {
            key: SimpleNamespace(value=value) for key, value in attributes.items()
        }
        self.registers: dict[int, int] = {}

    def find_channel(self, name: str, output: bool) -> FakeChannel | None:
        return next(
            (
                channel
                for channel in self.channels
                if channel.id == name and channel.output is output
            ),
            None,
        )

    def reg_read(self, address: int) -> int:
        return self.registers.get(address, 0)

    def reg_write(self, address: int, value: int) -> None:
        self.registers[address] = value


class FakeContext:
    def __init__(self, devices: list[FakeDevice], *, firmware: str) -> None:
        self.devices = devices
        self.attrs = {
            "hw_serial": "104000bac4950008230026001b440a003a",
            "fw_version": firmware,
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
        }
        self.timeout_ms: int | None = None
        self.closed = False

    def set_timeout(self, value: int) -> None:
        self.timeout_ms = value

    def close(self) -> None:
        self.closed = True


def _target() -> UsbInventoryTarget:
    return UsbInventoryTarget(
        serial="104000bac4950008230026001b440a003a",
        topology="5-2",
        sysfs_path=Path("/sys/bus/usb/devices/5-2"),
        bus_number=5,
        device_number=62,
        network_interface="enx00e0221686a8",
        source_ipv4="192.168.2.10",
    )


def _identity(**changes: str) -> dict[str, str]:
    return _remote() | {
        "boot_id": "11111111-1111-4111-8111-111111111111",
        "firmware_version": "persistent",
        "qspi_partition": "/dev/mtdblock3",
        "qspi_mtd_name": "qspi-linux",
        "qspi_bytes": "31457280",
        "qspi_sha256": "9" * 64,
    } | changes


def _attestation_inputs(tmp_path: Path) -> tuple[
    LinuxRxOnlyReleaseCandidateBackend,
    PasswordFileIdentity,
    HostRouteReceipt,
]:
    backend = LinuxRxOnlyReleaseCandidateBackend(
        state_root=(tmp_path / "state").absolute(), scanner=lambda: ()
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
        interface="enx00e0221686a8",
        source="192.168.2.10",
        release_verified=False,
    )
    return backend, password, route


def test_linux_preboot_attestor_quiesces_exact_tx_capable_1r1t(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    phy = FakeDevice(
        "ad9361-phy",
        [
            FakeChannel("voltage0", hardwaregain="-10"),
            FakeChannel("altvoltage0", powerdown="0"),
            FakeChannel("altvoltage1", powerdown="0"),
        ],
    )
    dds = FakeDevice(
        "cf-ad9361-dds-core-lpc",
        [
            FakeChannel(f"altvoltage{index}", raw="1", scale="0.5")
            for index in range(4)
        ],
    )
    context = FakeContext(
        [
            phy,
            FakeDevice("cf-ad9361-lpc"),
            dds,
            FakeDevice("tandem-agc", state="0", fifo_level="0", fault_flags="0"),
        ],
        firmware="persistent",
    )
    monkeypatch.setattr(
        hardware_iio,
        "context_facts",
        lambda value: {
            "phy_model": "ad9361",
            "rx_scan_channels": ("voltage0", "voltage1"),
            "buffer_metadata_abi": None,
        },
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.importlib.import_module",
        lambda name: SimpleNamespace(Context=lambda uri: context),
    )
    backend, password, route = _attestation_inputs(tmp_path)
    monkeypatch.setattr(
        backend,
        "_remote_identity_rx_only",
        lambda *args: _identity(),
    )

    observed = backend._attest_runtime_rx_only_linux(
        _target(),
        "persistent",
        password,
        route,
        "ad9361-1r1t",
        "tx-capable",
    )

    assert observed.layout.kind == "tx-capable"
    assert observed.single_rx_setup.runtime_target == "ad9361-1r1t"
    assert phy.find_channel("voltage0", True).attrs["hardwaregain"].value == "-80.0"  # type: ignore[union-attr]
    assert phy.find_channel("altvoltage0", True).attrs["powerdown"].value == "0"  # type: ignore[union-attr]
    assert phy.find_channel("altvoltage1", True).attrs["powerdown"].value == "1"  # type: ignore[union-attr]
    assert all(channel.attrs["raw"].value == "0.0" for channel in dds.channels)
    assert all(channel.attrs["scale"].value == "0.0" for channel in dds.channels)
    assert observed.layout.safe_state.shared_tx_lo.powerdown == (True,)
    assert context.closed


def test_linux_postboot_attestor_requires_marker_and_tx_devices_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    phy = FakeDevice(
        "ad9361-phy",
        [
            FakeChannel("voltage0", hardwaregain="-80"),
            FakeChannel("altvoltage0", powerdown="0"),
            FakeChannel("altvoltage1", powerdown="1"),
        ],
    )
    context = FakeContext(
        [phy, FakeDevice("cf-ad9361-lpc")], firmware="candidate"
    )
    monkeypatch.setattr(
        hardware_iio,
        "context_facts",
        lambda value: {
            "phy_model": "ad9361",
            "rx_scan_channels": ("voltage0", "voltage1"),
            "buffer_metadata_abi": None,
        },
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.importlib.import_module",
        lambda name: SimpleNamespace(Context=lambda uri: context),
    )
    backend, password, route = _attestation_inputs(tmp_path)
    monkeypatch.setattr(
        backend,
        "_remote_identity_rx_only",
        lambda *args: _identity(
            firmware_version="candidate",
            boot_id="22222222-2222-4222-8222-222222222222",
            root_marker_present="1",
            dds_dt_state="disabled",
            tx_dma_dt_state="disabled",
            tandem_dt_state="disabled",
        ),
    )

    observed = backend._attest_runtime_rx_only_linux(
        _target(),
        "candidate",
        password,
        route,
        "ad9361-1r1t",
        "rx-only",
    )

    assert observed.layout.kind == "rx-only"
    assert observed.layout.dds_device is None
    assert observed.layout.tx_dma_device is None
    assert observed.layout.tandem_device is None
    assert observed.layout.root_device_tree_marker == "misko,rx-only-fpga"
    assert observed.capabilities == ()


def test_linux_postboot_attestor_retries_incomplete_udev_iio_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    incomplete = FakeContext([], firmware="candidate")
    incomplete.close = None  # type: ignore[method-assign]
    incomplete._context = "legacy-native-context"  # type: ignore[attr-defined]
    phy = FakeDevice(
        "ad9361-phy",
        [
            FakeChannel("voltage0", hardwaregain="-80"),
            FakeChannel("altvoltage0", powerdown="0"),
            FakeChannel("altvoltage1", powerdown="1"),
        ],
    )
    settled = FakeContext(
        [phy, FakeDevice("cf-ad9361-lpc")], firmware="candidate"
    )
    contexts = iter((incomplete, settled))
    destroyed: list[object] = []
    monkeypatch.setattr(
        hardware_iio,
        "context_facts",
        lambda value: {
            "phy_model": "ad9361",
            "rx_scan_channels": ("voltage0", "voltage1"),
            "buffer_metadata_abi": None,
        },
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.importlib.import_module",
        lambda name: SimpleNamespace(
            Context=lambda uri: next(contexts),
            _destroy=destroyed.append,
        ),
    )
    backend, password, route = _attestation_inputs(tmp_path)
    delays: list[float] = []
    backend.sleep = delays.append
    monkeypatch.setattr(
        backend,
        "_remote_identity_rx_only",
        lambda *args: _identity(
            firmware_version="candidate",
            boot_id="22222222-2222-4222-8222-222222222222",
            root_marker_present="1",
            dds_dt_state="disabled",
            tx_dma_dt_state="disabled",
            tandem_dt_state="disabled",
        ),
    )

    observed = backend._attest_runtime_rx_only_linux(
        _target(),
        "candidate",
        password,
        route,
        "ad9361-1r1t",
        "rx-only",
    )

    assert observed.layout.kind == "rx-only"
    assert delays == [0.25]
    assert destroyed == ["legacy-native-context"]
    assert incomplete._context is None  # type: ignore[attr-defined]
    assert settled.closed


def test_linux_runtime_attestor_bounds_persistently_incomplete_iio_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contexts: list[FakeContext] = []

    def context_factory(uri: str) -> FakeContext:
        context = FakeContext([], firmware="candidate")
        contexts.append(context)
        return context

    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.importlib.import_module",
        lambda name: SimpleNamespace(Context=context_factory),
    )
    backend, password, route = _attestation_inputs(tmp_path)
    times = iter((0.0, 1.0))
    backend.timeout_s = 0.5
    backend.monotonic = lambda: next(times)

    with pytest.raises(
        ReleaseCandidateLifecycleError,
        match="timed out waiting for settled USB-IIO runtime",
    ):
        backend._attest_runtime_rx_only_linux(
            _target(),
            "candidate",
            password,
            route,
            "ad9361-1r1t",
            "rx-only",
        )

    assert len(contexts) == 1
    assert contexts[0].closed


def test_linux_runtime_attestor_does_not_retry_complete_wrong_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = FakeContext(
        [FakeDevice("ad9361-phy"), FakeDevice("cf-ad9361-lpc")],
        firmware="unexpected",
    )
    opens: list[str] = []

    def context_factory(uri: str) -> FakeContext:
        opens.append(uri)
        return context

    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.importlib.import_module",
        lambda name: SimpleNamespace(Context=context_factory),
    )
    backend, password, route = _attestation_inputs(tmp_path)
    backend.sleep = lambda delay: pytest.fail("identity mismatch must not retry")

    with pytest.raises(
        ReleaseCandidateLifecycleError,
        match="serial or firmware differs from expected runtime",
    ):
        backend._attest_runtime_rx_only_linux(
            _target(),
            "candidate",
            password,
            route,
            "ad9361-1r1t",
            "rx-only",
        )

    assert opens == ["usb:5.62.5"]
    assert context.closed


def test_linux_persistent_recovery_waits_for_departure_before_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, password, route = _attestation_inputs(tmp_path)
    target = _target()
    backend._active_target = target
    calls: list[str] = []
    pre = SimpleNamespace(
        single_rx_setup="setup",
        layout=SimpleNamespace(kind="tx-capable"),
        boot_id="pre-boot",
        qspi="qspi",
    )
    recovered = SimpleNamespace(
        single_rx_setup="setup",
        layout=SimpleNamespace(kind="tx-capable"),
        boot_id="recovered-boot",
        qspi="qspi",
    )
    monkeypatch.setattr(backend, "_runtime_targets", lambda: (target,))
    monkeypatch.setattr(
        backend,
        "acquire_host_route",
        lambda selected, ssh_host: route,
    )
    backend.runner = SimpleNamespace(
        run=lambda *args, **kwargs: calls.append("reset-command") or ""
    )
    monkeypatch.setattr(
        "pluto_plus.release_candidate_rx_only_linux.validate_password_file",
        lambda *args, **kwargs: password,
    )
    monkeypatch.setattr(
        backend,
        "_wait_for_runtime_departure",
        lambda selected, previous_identity, timeout_s: calls.append("departure"),
    )
    monkeypatch.setattr(backend, "_runtime_sysfs_identity", lambda selected: (1,))
    monkeypatch.setattr(
        backend,
        "wait_for_runtime",
        lambda selected, timeout_s: calls.append("return") or target,
    )
    monkeypatch.setattr(backend, "ensure_host_route", lambda *args: None)
    monkeypatch.setattr(
        backend,
        "quiesce_and_attest_preboot_v2",
        lambda *args, **kwargs: (
            recovered,
            SimpleNamespace(readback_verified=True),
        ),
    )
    monkeypatch.setattr(backend, "release_host_route", lambda selected: None)

    result = backend.recover_to_persistent_v2(
        target,
        pre_runtime=pre,  # type: ignore[arg-type]
        runtime_target="ad9361-1r1t",
        expected_firmware="persistent",
        password=password,
        ssh_host="192.168.2.1",
        timeout_s=1.0,
    )

    assert result.runtime is recovered
    assert result.pre_reset_usb_departure_verified
    assert calls == ["reset-command", "departure", "return"]


def test_linux_persistent_recovery_departure_barrier_rejects_stale_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, _, _ = _attestation_inputs(tmp_path)
    backend.sysfs_root = tmp_path / "sysfs"
    backend.sysfs_root.mkdir()
    sysfs_path = backend.sysfs_root / _target().topology
    sysfs_path.touch()
    previous = backend._runtime_sysfs_identity(_target())
    clock = iter((0.0, 0.1, 1.1))
    monkeypatch.setattr(backend, "monotonic", lambda: next(clock))
    monkeypatch.setattr(backend, "sleep", lambda delay: None)

    with pytest.raises(ReleaseCandidateLifecycleError, match="pre-reset runtime"):
        backend._wait_for_runtime_departure(
            _target(), previous_identity=previous, timeout_s=1.0
        )


def test_linux_persistent_recovery_departure_barrier_accepts_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, _, _ = _attestation_inputs(tmp_path)
    backend.sysfs_root = tmp_path / "sysfs"
    backend.sysfs_root.mkdir()
    sysfs_path = backend.sysfs_root / _target().topology
    sysfs_path.touch()
    previous = backend._runtime_sysfs_identity(_target())
    clock = iter((0.0, 0.1, 0.2))
    monkeypatch.setattr(backend, "monotonic", lambda: next(clock))
    monkeypatch.setattr(backend, "sleep", lambda delay: sysfs_path.unlink())

    backend._wait_for_runtime_departure(
        _target(), previous_identity=previous, timeout_s=1.0
    )


def test_linux_persistent_recovery_departure_barrier_accepts_replaced_node(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend, _, _ = _attestation_inputs(tmp_path)
    backend.sysfs_root = tmp_path / "sysfs"
    backend.sysfs_root.mkdir()
    sysfs_path = backend.sysfs_root / _target().topology
    sysfs_path.touch()
    previous = backend._runtime_sysfs_identity(_target())
    clock = iter((0.0, 0.1, 0.2))

    def replace(delay: float) -> None:
        sysfs_path.unlink()
        sysfs_path.mkdir()

    monkeypatch.setattr(backend, "monotonic", lambda: next(clock))
    monkeypatch.setattr(backend, "sleep", replace)

    backend._wait_for_runtime_departure(
        _target(), previous_identity=previous, timeout_s=1.0
    )
