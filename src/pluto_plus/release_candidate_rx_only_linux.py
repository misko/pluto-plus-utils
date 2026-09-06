"""Linux backend for the isolated RX-only release-candidate v2 lifecycle."""

from __future__ import annotations

import gc
import importlib
from collections.abc import Callable, Mapping
from typing import Any, Literal

from pydantic import ValidationError

from pluto_plus.release_candidate import (
    CleanupReceipt,
    HostRouteReceipt,
    QspiObservation,
    UsbInventoryTarget,
)
from pluto_plus.release_candidate_lifecycle import (
    DFU_ALTERNATE,
    DFU_SELECTOR,
    PasswordFileIdentity,
    ReleaseCandidateLifecycleError,
    ssh_fixed_argv,
    validate_password_file,
)
from pluto_plus.release_candidate_linux import (
    REMOTE_PERSISTENT_RESET_COMMAND,
    LinuxReleaseCandidateBackend,
    _channel,
    _first_float,
    _read_attr,
    _write_numeric,
)
from pluto_plus.release_candidate_rx_only import (
    DDS_DEVICE,
    RX_DMA_DEVICE,
    RX_ONLY_ROOT_DT_MARKER,
    SHARED_TX_LO_CONTROL,
    TANDEM_DEVICE,
    TX_DMA_DEVICE,
    PrebootQuiesceReceiptV2,
    ReleaseCandidatePlanV2,
    RuntimeObservationV2,
    RxOnlyLayoutV2,
    RxOnlyRuntimeTarget,
    SharedTxLoSafeState,
    SingleRxSafeStateV2,
    SingleRxSetupObservation,
    TxCapableLayoutV2,
    TxCapableSingleRxSafeStateV2,
)
from pluto_plus.release_candidate_rx_only_lifecycle import (
    RxOnlyFailureReconciliation,
    RxOnlyPersistentRecoveryResult,
)

REMOTE_RX_ONLY_IDENTITY_SCRIPT = r"""set -eu
boot_id=$(cat /proc/sys/kernel/random/boot_id)
firmware_version=$(awk '$1 == "device-fw" {print $2; exit}' /opt/VERSIONS)
qspi_partition=/dev/mtdblock3
qspi_mtd_name=$(cat /sys/class/mtd/mtd3/name)
qspi_bytes=$(cat /sys/class/mtd/mtd3/size)
qspi_sha256=$(sha256sum "$qspi_partition" | awk '{print $1}')
if attr_name=$(/usr/sbin/fw_printenv -n attr_name 2>/dev/null); then
  uboot_attr_name_present=1
else
  uboot_attr_name_present=0
  attr_name=
fi
if attr_val=$(/usr/sbin/fw_printenv -n attr_val 2>/dev/null); then
  uboot_attr_val_present=1
else
  uboot_attr_val_present=0
  attr_val=
fi
uboot_compatible=$(/usr/sbin/fw_printenv -n compatible)
uboot_mode=$(/usr/sbin/fw_printenv -n mode)
dt_state() {
  path=$1
  if [ ! -d "$path" ]; then printf absent; return; fi
  if [ ! -r "$path/status" ]; then printf enabled; return; fi
  value=$(tr -d '\000' <"$path/status")
  case "$value" in
    okay|ok) printf enabled ;;
    disabled) printf disabled ;;
    *) exit 1 ;;
  esac
}
dt_root=/sys/firmware/devicetree/base
root_marker_present=0
[ -e "$dt_root/misko,rx-only-fpga" ] && root_marker_present=1
rx_dma_dt_state=$(dt_state "$dt_root/fpga-axi@0/dma@7c400000")
dds_dt_state=$(dt_state "$dt_root/fpga-axi@0/cf-ad9361-dds-core-lpc@79024000")
tx_dma_dt_state=$(dt_state "$dt_root/fpga-axi@0/dma@7c420000")
tandem_dt_state=$(dt_state "$dt_root/fpga-axi@0/tandem-agc@7c450000")
[ -n "$boot_id" ]
[ -n "$firmware_version" ]
[ "$qspi_mtd_name" = qspi-linux ]
case "$qspi_bytes" in ''|*[!0-9]*) exit 1;; esac
[ "$qspi_bytes" -gt 0 ]
format='boot_id=%s\nfirmware_version=%s\nqspi_partition=%s\nqspi_mtd_name=%s\n'
format="${format}qspi_bytes=%s\nqspi_sha256=%s\n"
format="${format}uboot_attr_name_present=%s\nuboot_attr_name=%s\n"
format="${format}uboot_attr_val_present=%s\nuboot_attr_val=%s\n"
format="${format}uboot_compatible=%s\nuboot_mode=%s\n"
format="${format}root_marker_present=%s\nrx_dma_dt_state=%s\n"
format="${format}dds_dt_state=%s\ntx_dma_dt_state=%s\ntandem_dt_state=%s\n"
printf "$format" \
  "$boot_id" "$firmware_version" "$qspi_partition" "$qspi_mtd_name" \
  "$qspi_bytes" "$qspi_sha256" \
  "$uboot_attr_name_present" "$attr_name" \
  "$uboot_attr_val_present" "$attr_val" \
  "$uboot_compatible" "$uboot_mode" \
  "$root_marker_present" "$rx_dma_dt_state" \
  "$dds_dt_state" "$tx_dma_dt_state" "$tandem_dt_state"
"""

_V2_LAYOUT = Literal["tx-capable", "rx-only"]
_IIO_SETTLE_RETRY_SECONDS = 0.25
RxOnlyRuntimeAttestor = Callable[
    [
        Any,
        str,
        PasswordFileIdentity,
        HostRouteReceipt,
        RxOnlyRuntimeTarget,
        _V2_LAYOUT,
    ],
    RuntimeObservationV2,
]


class LinuxRxOnlyReleaseCandidateBackend(LinuxReleaseCandidateBackend):
    """Linux v2 backend; the inherited v1 attestor is never selected."""

    def __init__(
        self,
        *,
        rx_only_runtime_attestor: RxOnlyRuntimeAttestor | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.rx_only_runtime_attestor = (
            rx_only_runtime_attestor or self._attest_runtime_rx_only_linux
        )

    def quiesce_and_attest_preboot_v2(
        self,
        target: Any,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> tuple[RuntimeObservationV2, PrebootQuiesceReceiptV2]:
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        observed = self.rx_only_runtime_attestor(
            target,
            expected_firmware,
            password,
            route,
            runtime_target,
            "tx-capable",
        )
        return observed, PrebootQuiesceReceiptV2(readback_verified=True)

    def attest_rx_only_runtime_v2(
        self,
        target: Any,
        *,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> RuntimeObservationV2:
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        return self.rx_only_runtime_attestor(
            target,
            expected_firmware,
            password,
            route,
            runtime_target,
            "rx-only",
        )

    def reconcile_failure_v2(
        self,
        target: Any,
        *,
        candidate: ReleaseCandidatePlanV2,
        runtime_target: RxOnlyRuntimeTarget,
        pre_runtime: RuntimeObservationV2,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
        timeout_s: float,
    ) -> RxOnlyFailureReconciliation:
        errors: list[str] = []
        try:
            device = self._dfu_device(target.topology)
        except ReleaseCandidateLifecycleError:
            device = None
        if device is not None:
            try:
                self.detach_dfu(
                    (
                        "dfu-util",
                        "-d",
                        DFU_SELECTOR,
                        "-p",
                        target.topology,
                        "-a",
                        DFU_ALTERNATE,
                        "-e",
                    )
                )
            except BaseException as error:
                errors.append(f"DFU detach recovery: {error}")
        try:
            returned = self.wait_for_runtime(target, timeout_s=timeout_s)
            self.ensure_host_route(route, returned)
        except BaseException as error:
            errors.append(f"runtime recovery: {error}")
            return RxOnlyFailureReconciliation(
                runtime=None, cleanup=CleanupReceipt(verified=False, errors=tuple(errors))
            )
        observations: list[str] = []
        try:
            observed = self.attest_rx_only_runtime_v2(
                returned,
                runtime_target=runtime_target,
                expected_firmware=candidate.expected_runtime.firmware_version,
                password=password,
                route=route,
            )
            return RxOnlyFailureReconciliation(
                runtime=observed, cleanup=CleanupReceipt(verified=True)
            )
        except BaseException as error:
            observations.append(f"candidate RX-only: {error}")
        try:
            observed, _ = self.quiesce_and_attest_preboot_v2(
                returned,
                runtime_target=runtime_target,
                expected_firmware=pre_runtime.firmware_version,
                password=password,
                route=route,
            )
            return RxOnlyFailureReconciliation(
                runtime=observed, cleanup=CleanupReceipt(verified=True)
            )
        except BaseException as error:
            observations.append(f"persistent TX-capable: {error}")
        errors.append("safe runtime attestation: " + "; ".join(observations))
        return RxOnlyFailureReconciliation(
            runtime=None, cleanup=CleanupReceipt(verified=False, errors=tuple(errors))
        )

    def recover_to_persistent_v2(
        self,
        target: UsbInventoryTarget,
        *,
        pre_runtime: RuntimeObservationV2,
        runtime_target: RxOnlyRuntimeTarget,
        expected_firmware: str,
        password: PasswordFileIdentity,
        ssh_host: str,
        timeout_s: float,
    ) -> RxOnlyPersistentRecoveryResult:
        """Force an eligible PASS/UNKNOWN trial back through persistent QSPI boot."""

        if self._active_target != target:
            raise ReleaseCandidateLifecycleError("RX-only recovery target is not lock-bound")
        matches = tuple(
            item
            for item in self._runtime_targets()
            if item.serial == target.serial and item.topology == target.topology
        )
        if len(matches) > 1:
            raise ReleaseCandidateLifecycleError("recovery found multiple matching runtimes")
        detached = not matches
        if detached:
            device = self._dfu_device(target.topology)
            if device.serial and device.serial != target.serial:
                raise ReleaseCandidateLifecycleError(
                    "recovery DFU device exposed a different serial"
                )
            self.detach_dfu(
                (
                    "dfu-util",
                    "-d",
                    DFU_SELECTOR,
                    "-p",
                    target.topology,
                    "-a",
                    DFU_ALTERNATE,
                    "-e",
                )
            )
            returned = self.wait_for_runtime(target, timeout_s=timeout_s)
        else:
            returned = matches[0]
        if (
            returned.serial != target.serial
            or returned.topology != target.topology
            or returned.network_interface != target.network_interface
            or returned.source_ipv4 != target.source_ipv4
        ):
            raise ReleaseCandidateLifecycleError(
                "recovery returned a different physical target"
            )
        self._active_target = returned
        route = self.acquire_host_route(returned, ssh_host)
        try:
            command = ssh_fixed_argv(
                returned,
                ssh_host=ssh_host,
                password_path=password.path,
                remote_command=REMOTE_PERSISTENT_RESET_COMMAND,
            )
            validate_password_file(password.path, expected=password)
            pre_reset_sysfs_identity = self._runtime_sysfs_identity(returned)
            self.runner.run(
                command,
                timeout_s=self.timeout_s,
                allowed_returncodes=(0, 255),
            )
            self._wait_for_runtime_departure(
                returned,
                previous_identity=pre_reset_sysfs_identity,
                timeout_s=timeout_s,
            )
            persistent = self.wait_for_runtime(returned, timeout_s=timeout_s)
            self.ensure_host_route(route, persistent)
            recovered, quiesce = self.quiesce_and_attest_preboot_v2(
                persistent,
                runtime_target=runtime_target,
                expected_firmware=expected_firmware,
                password=password,
                route=route,
            )
            if (
                recovered.single_rx_setup != pre_runtime.single_rx_setup
                or recovered.layout.kind != "tx-capable"
                or recovered.boot_id == pre_runtime.boot_id
                or recovered.qspi != pre_runtime.qspi
            ):
                raise ReleaseCandidateLifecycleError(
                    "persistent recovery target, boot epoch, or QSPI identity changed"
                )
        except BaseException:
            self.release_host_route(route)
            raise
        self.release_host_route(route)
        return RxOnlyPersistentRecoveryResult(
            runtime=recovered,
            quiesce=quiesce,
            host_route=route.model_copy(update={"release_verified": True}),
            dfu_detach_completed=detached,
            pre_reset_usb_departure_verified=True,
        )

    def _wait_for_runtime_departure(
        self,
        target: UsbInventoryTarget,
        *,
        previous_identity: tuple[int, ...],
        timeout_s: float,
    ) -> None:
        """Require the pre-reset USB node to disappear or be replaced before return."""

        deadline = self.monotonic() + timeout_s
        sysfs_path = self.sysfs_root / target.topology
        while self.monotonic() < deadline:
            try:
                current = _sysfs_identity(sysfs_path.lstat())
            except FileNotFoundError:
                return
            except OSError as error:
                raise ReleaseCandidateLifecycleError(
                    f"cannot observe pre-reset USB departure: {error}"
                ) from error
            if current != previous_identity:
                return
            self.sleep(0.25)
        raise ReleaseCandidateLifecycleError(
            "timed out waiting for the pre-reset runtime to depart"
        )

    def _runtime_sysfs_identity(self, target: UsbInventoryTarget) -> tuple[int, ...]:
        path = self.sysfs_root / target.topology
        try:
            return _sysfs_identity(path.lstat())
        except OSError as error:
            raise ReleaseCandidateLifecycleError(
                f"pre-reset USB sysfs identity is unavailable: {error}"
            ) from error

    def _attest_runtime_rx_only_linux(
        self,
        target: Any,
        expected_firmware: str,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
        runtime_target: RxOnlyRuntimeTarget,
        expected_layout: _V2_LAYOUT,
    ) -> RuntimeObservationV2:
        try:
            iio = importlib.import_module("iio")
        except (ImportError, OSError) as error:
            raise ReleaseCandidateLifecycleError("pylibiio is required for attestation") from error
        uri = f"usb:{target.bus_number}.{target.device_number}.5"
        context: Any = None
        try:
            context, attrs = self._open_settled_runtime_iio_context(
                iio,
                uri=uri,
                target=target,
                expected_firmware=expected_firmware,
            )
            serial = attrs["serial"]
            firmware = attrs["firmware"]
            model = attrs["model"]
            phy = _one_named_device(context, "ad9361-phy")
            dds = _optional_named_device(context, DDS_DEVICE)
            tandem = _optional_named_device(context, TANDEM_DEVICE)
            remote = self._remote_identity_rx_only(target, password, route)
            if remote["firmware_version"] != firmware:
                raise ReleaseCandidateLifecycleError("SSH and USB-IIO firmware differ")

            from pluto_plus.hardware.iio import context_facts

            facts = context_facts(context)
            setup = _single_rx_setup(facts, remote, runtime_target)
            metadata_value = facts.get("buffer_metadata_abi")
            if metadata_value is not None and not isinstance(metadata_value, int):
                raise ReleaseCandidateLifecycleError("runtime metadata ABI is malformed")
            metadata = (
                None if metadata_value is None else f"frame-metadata-v{metadata_value}"
            )
            _require_exact_tx_control_inventory(phy, dds, expected_layout=expected_layout)
            _quiesce_phy(phy)
            shared_lo = _shared_tx_lo_state(phy)
            gains = (
                _first_float(_read_attr(_channel(phy, "voltage0", True), "hardwaregain")),
            )
            topology = _topology_states(remote)
            if expected_layout == "tx-capable":
                if dds is None or tandem is None:
                    raise ReleaseCandidateLifecycleError(
                        "TX-capable 1R1T preboot lacks DDS or tandem"
                    )
                if topology != (False, "enabled", "enabled", "enabled", "enabled"):
                    raise ReleaseCandidateLifecycleError(
                        "TX-capable 1R1T device-tree topology is not exact"
                    )
                for index in range(4):
                    channel = _channel(dds, f"altvoltage{index}", True)
                    _write_numeric(channel, "raw", 0.0, tolerance=1e-9)
                    _write_numeric(channel, "scale", 0.0, tolerance=1e-9)
                for index in range(2):
                    legacy = 0x0414 + index * 0x40
                    selector = 0x0418 + index * 0x40
                    dds.reg_write(legacy, int(dds.reg_read(legacy)) & ~1)
                    dds.reg_write(selector, 3)
                dds_raw = tuple(
                    round(
                        _first_float(
                            _read_attr(_channel(dds, f"altvoltage{index}", True), "raw")
                        )
                    )
                    for index in range(4)
                )
                dds_scale = tuple(
                    _first_float(
                        _read_attr(_channel(dds, f"altvoltage{index}", True), "scale")
                    )
                    for index in range(4)
                )
                selectors = tuple(
                    int(dds.reg_read(0x0418 + index * 0x40)) & 0xF for index in range(2)
                )
                state = round(_first_float(_read_attr(tandem, "state")))
                fifo = round(_first_float(_read_attr(tandem, "fifo_level")))
                faults = round(_first_float(_read_attr(tandem, "fault_flags")))
                layout: TxCapableLayoutV2 | RxOnlyLayoutV2 = TxCapableLayoutV2(
                    safe_state=TxCapableSingleRxSafeStateV2.model_validate(
                        {
                            "tx_gain_db": gains,
                            "dds_raw": dds_raw,
                            "dds_scale": dds_scale,
                            "dac_selectors": selectors,
                            "tandem_state": "IDLE" if state == 0 else f"STATE_{state}",
                            "fifo_level": fifo,
                            "fault_flags": faults,
                            "shared_tx_lo": shared_lo,
                        }
                    )
                )
            else:
                if dds is not None or tandem is not None:
                    raise ReleaseCandidateLifecycleError(
                        "RX-only runtime still exposes DDS or tandem"
                    )
                if topology != (True, "enabled", "disabled", "disabled", "disabled"):
                    raise ReleaseCandidateLifecycleError(
                        "RX-only marker/DMA device-tree topology is not exact"
                    )
                layout = RxOnlyLayoutV2(
                    safe_state=SingleRxSafeStateV2(
                        tx_gain_db=gains,
                        shared_tx_lo=shared_lo,
                    )
                )
            capabilities = ("tandem-agc",) if tandem is not None else ()
            return RuntimeObservationV2(
                serial=serial,
                topology=target.topology,
                usb_uri=uri,
                hardware_model=model,
                firmware_version=firmware,
                metadata_abi=metadata,
                capabilities=capabilities,
                boot_id=remote["boot_id"],
                qspi=QspiObservation(
                    bytes=int(remote["qspi_bytes"]), sha256=remote["qspi_sha256"]
                ),
                layout=layout,
                single_rx_setup=setup,
            )
        except ValidationError as error:
            raise ReleaseCandidateLifecycleError(
                "runtime does not satisfy the exact RX-only v2 contract"
            ) from error
        finally:
            if context is not None:
                _close_iio_context(iio, context)
                context = None
                gc.collect()

    def _open_settled_runtime_iio_context(
        self,
        iio: Any,
        *,
        uri: str,
        target: UsbInventoryTarget,
        expected_firmware: str,
    ) -> tuple[Any, dict[str, str]]:
        """Wait out bounded udev/libiio discovery claims after USB arrival."""

        deadline = self.monotonic() + self.timeout_s
        last_error = "USB-IIO runtime has not settled"
        while True:
            context: Any = None
            try:
                context = iio.Context(uri)
                setter = getattr(context, "set_timeout", None)
                if not callable(setter):
                    raise ReleaseCandidateLifecycleError(
                        "USB-IIO context cannot set timeout"
                    )
                setter(round(self.timeout_s * 1000))
                raw = {str(key): str(value) for key, value in context.attrs.items()}
                attrs = {
                    "serial": raw.get(
                        "hw_serial", raw.get("usb,serial", raw.get("serial", ""))
                    ),
                    "firmware": raw.get("fw_version", ""),
                    "model": raw.get("hw_model", ""),
                }
                if all(attrs.values()) and (
                    attrs["serial"] != target.serial
                    or attrs["firmware"] != expected_firmware
                ):
                    raise ReleaseCandidateLifecycleError(
                        "USB-IIO serial or firmware differs from expected runtime"
                    )
                counts = {
                    name: len(_named_devices(context, name))
                    for name in ("ad9361-phy", RX_DMA_DEVICE)
                }
                if all(attrs.values()) and all(count == 1 for count in counts.values()):
                    settled = context
                    context = None
                    return settled, attrs
                last_error = (
                    "USB-IIO identity or required-device inventory is incomplete: "
                    f"serial={bool(attrs['serial'])} firmware={bool(attrs['firmware'])} "
                    f"model={bool(attrs['model'])} devices={counts!r}"
                )
            except OSError as error:
                last_error = f"USB-IIO context open failed: {error}"
            finally:
                if context is not None:
                    _close_iio_context(iio, context)
                    context = None
                    gc.collect()

            remaining = deadline - self.monotonic()
            if remaining <= 0:
                raise ReleaseCandidateLifecycleError(
                    f"timed out waiting for settled USB-IIO runtime: {last_error}"
                )
            self.sleep(min(_IIO_SETTLE_RETRY_SECONDS, remaining))

    def _remote_identity_rx_only(
        self,
        target: Any,
        password: PasswordFileIdentity,
        route: HostRouteReceipt,
    ) -> dict[str, str]:
        self.ensure_host_route(route, target)
        validate_password_file(password.path, expected=password)
        output = self.runner.run(
            ssh_fixed_argv(
                target,
                ssh_host=route.destination.removesuffix("/32"),
                password_path=password.path,
                remote_command=REMOTE_RX_ONLY_IDENTITY_SCRIPT,
            ),
            timeout_s=self.timeout_s,
        )
        fields: dict[str, str] = {}
        for line in output.splitlines():
            if "=" not in line:
                raise ReleaseCandidateLifecycleError("runtime identity line is malformed")
            key, value = line.split("=", 1)
            if key in fields:
                raise ReleaseCandidateLifecycleError("runtime identity has duplicate field")
            fields[key] = value
        expected = {
            "boot_id",
            "firmware_version",
            "qspi_partition",
            "qspi_mtd_name",
            "qspi_bytes",
            "qspi_sha256",
            "uboot_attr_name_present",
            "uboot_attr_name",
            "uboot_attr_val_present",
            "uboot_attr_val",
            "uboot_compatible",
            "uboot_mode",
            "root_marker_present",
            "rx_dma_dt_state",
            "dds_dt_state",
            "tx_dma_dt_state",
            "tandem_dt_state",
        }
        if set(fields) != expected:
            raise ReleaseCandidateLifecycleError("runtime identity field inventory is not exact")
        if (
            fields["qspi_partition"] != "/dev/mtdblock3"
            or fields["qspi_mtd_name"] != "qspi-linux"
            or not fields["qspi_bytes"].isdigit()
            or int(fields["qspi_bytes"]) <= 0
            or len(fields["qspi_sha256"]) != 64
            or fields["uboot_attr_name_present"] not in {"0", "1"}
            or fields["uboot_attr_val_present"] not in {"0", "1"}
            or fields["root_marker_present"] not in {"0", "1"}
            or any(
                fields[key] not in {"absent", "enabled", "disabled"}
                for key in (
                    "rx_dma_dt_state",
                    "dds_dt_state",
                    "tx_dma_dt_state",
                    "tandem_dt_state",
                )
            )
        ):
            raise ReleaseCandidateLifecycleError("runtime identity values are malformed")
        return fields


def _named_devices(context: Any, name: str) -> tuple[Any, ...]:
    return tuple(device for device in context.devices if str(device.name) == name)


def _close_iio_context(iio: Any, context: Any) -> None:
    """Release both modern and legacy pylibiio contexts deterministically."""

    close = getattr(context, "close", None)
    if callable(close):
        close()
        return
    native = getattr(context, "_context", None)
    destroy = getattr(iio, "_destroy", None)
    if native is None or not callable(destroy):
        raise ReleaseCandidateLifecycleError(
            "pylibiio context exposes no deterministic close operation"
        )
    # Clear the Python wrapper first so its later __del__ cannot double-destroy
    # the native context if the ctypes call raises.
    context._context = None
    destroy(native)


def _one_named_device(context: Any, name: str) -> Any:
    matches = _named_devices(context, name)
    if len(matches) != 1:
        raise ReleaseCandidateLifecycleError(
            f"runtime requires exactly one {name!r} device; found {len(matches)}"
        )
    return matches[0]


def _optional_named_device(context: Any, name: str) -> Any | None:
    matches = _named_devices(context, name)
    if len(matches) > 1:
        raise ReleaseCandidateLifecycleError(
            f"runtime exposes multiple {name!r} devices"
        )
    return matches[0] if matches else None


def _attribute_channel_ids(device: Any, attribute: str) -> tuple[str, ...]:
    values: list[str] = []
    for channel in device.channels:
        if not bool(channel.output) or attribute not in channel.attrs:
            continue
        values.append(str(channel.id))
    return tuple(sorted(values))


def _attribute_channel_inventory(
    device: Any, attribute: str
) -> tuple[tuple[str, str], ...]:
    values: list[tuple[str, str]] = []
    for channel in device.channels:
        if not bool(channel.output) or attribute not in channel.attrs:
            continue
        values.append((str(channel.id), str(channel.name or "")))
    return tuple(sorted(values))


def _require_exact_tx_control_inventory(
    phy: Any, dds: Any | None, *, expected_layout: _V2_LAYOUT
) -> None:
    if _attribute_channel_ids(phy, "hardwaregain") != ("voltage0",):
        raise ReleaseCandidateLifecycleError(
            "1R1T runtime must expose exactly voltage0 TX hardwaregain"
        )
    if _attribute_channel_inventory(phy, "powerdown") != (
        ("altvoltage0", "RX_LO"),
        ("altvoltage1", "TX_LO"),
    ):
        raise ReleaseCandidateLifecycleError(
            "1R1T runtime must expose exactly RX_LO and shared TX_LO powerdown controls"
        )
    if expected_layout == "tx-capable":
        if dds is None:
            raise ReleaseCandidateLifecycleError("TX-capable runtime lacks the DDS device")
        raw = _attribute_channel_ids(dds, "raw")
        scale = _attribute_channel_ids(dds, "scale")
        expected = tuple(f"altvoltage{index}" for index in range(4))
        if raw != expected or scale != expected:
            raise ReleaseCandidateLifecycleError(
                "TX-capable 1R1T DDS control inventory is not exact"
            )
    elif dds is not None:
        raise ReleaseCandidateLifecycleError("RX-only runtime unexpectedly exposes DDS controls")


def _quiesce_phy(phy: Any) -> None:
    _write_numeric(_channel(phy, "voltage0", True), "hardwaregain", -80.0, tolerance=0.26)
    _write_numeric(_channel(phy, "altvoltage1", True), "powerdown", 1, tolerance=1e-9)


def _shared_tx_lo_state(phy: Any) -> SharedTxLoSafeState:
    value = round(_first_float(_read_attr(_channel(phy, "altvoltage1", True), "powerdown")))
    return SharedTxLoSafeState.model_validate(
        {
            "controls": (SHARED_TX_LO_CONTROL,),
            "powerdown": (value == 1,),
        }
    )


def _single_rx_setup(
    facts: Mapping[str, object],
    remote: Mapping[str, str],
    runtime_target: RxOnlyRuntimeTarget,
) -> SingleRxSetupObservation:
    channels = facts.get("rx_scan_channels")
    if not isinstance(channels, (tuple, list)):
        raise ReleaseCandidateLifecycleError("runtime RX scan layout is absent or malformed")
    name_present = remote["uboot_attr_name_present"] == "1"
    value_present = remote["uboot_attr_val_present"] == "1"
    if name_present != value_present:
        raise ReleaseCandidateLifecycleError("U-Boot attr_name/attr_val presence differs")
    return SingleRxSetupObservation.model_validate(
        {
            "runtime_target": runtime_target,
            "uboot_attr_name": remote["uboot_attr_name"] if name_present else None,
            "uboot_attr_val": remote["uboot_attr_val"] if value_present else None,
            "uboot_compatible": remote["uboot_compatible"],
            "uboot_mode": remote["uboot_mode"],
            "phy_model": facts.get("phy_model"),
            "rx_scan_channels": tuple(str(channel) for channel in channels),
        }
    )


def _topology_states(remote: Mapping[str, str]) -> tuple[bool, str, str, str, str]:
    return (
        remote["root_marker_present"] == "1",
        remote["rx_dma_dt_state"],
        remote["dds_dt_state"],
        remote["tx_dma_dt_state"],
        remote["tandem_dt_state"],
    )


def _sysfs_identity(value: Any) -> tuple[int, ...]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_mode),
        int(value.st_mtime_ns),
        int(value.st_ctime_ns),
    )


assert RX_ONLY_ROOT_DT_MARKER == "misko,rx-only-fpga"
assert TX_DMA_DEVICE == "dma@7c420000"
