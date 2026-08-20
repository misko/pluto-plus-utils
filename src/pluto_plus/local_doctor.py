"""Daemon-independent, read-only diagnostics for locally attached Pluto radios."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pluto_plus.bootstrap_firmware import (
    BOOTSTRAP_POLICY,
    BootstrapFirmwareError,
    inspect_bound_iiod,
)
from pluto_plus.diagnostic_profiles import (
    DIAGNOSTIC_PROFILES,
    UPGRADE_TARGET_PROFILE,
    MetadataAbiState,
    parse_metadata_abi,
    select_diagnostic_profile,
    upgrade_target_for,
)
from pluto_plus.doctor import CANONICAL_UBOOT
from pluto_plus.hardware.preflight import IioEnvironmentReport, inspect_iio_environment
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.setup_repair import SetupProbeOutcome, SetupRepairRecord

CheckStatus = Literal["pass", "fail", "unknown"]
# Reads (and, when enabled, repairs) one radio's persistent U-Boot tuple.  Injected so
# the read-only lane stays free of any SSH or credential dependency.
SetupProbe = Callable[[LocalUsbPluto, "str | None"], SetupProbeOutcome]
LOCAL_POLICY = BOOTSTRAP_POLICY
# Rendered from the single canonical definition so the advertised tuple cannot drift
# away from the one the provisioner actually writes.
CANONICAL_UBOOT_SUMMARY = ", ".join(
    f"{key} unset" if value is None else f"{key}={value}" for key, value in CANONICAL_UBOOT.items()
)


@dataclass(frozen=True, slots=True)
class LocalDoctorCheck:
    code: str
    status: CheckStatus
    actual: object
    expected: object
    summary: str


@dataclass(frozen=True, slots=True)
class LocalDoctorRadio:
    usb_sysfs_path: str
    usb_bus_device: str | None
    serial: str | None
    usb_interface: str | None
    storage_partition: str | None
    firmware_version: str | None
    model: str | None
    phy_model: str | None
    diagnostic_profile_id: str | None
    metadata_enabled: bool | None
    metadata_abi: int | None
    tandem_agc: bool | None
    overall: CheckStatus
    checks: tuple[LocalDoctorCheck, ...]
    error: str | None = None
    setup_repair: SetupRepairRecord | None = None


@dataclass(frozen=True, slots=True)
class HostLibiioCheck:
    """Host-local libiio health. Not a per-radio fact: it gates every radio."""

    status: str
    healthy: bool
    summary: str
    remediation: str | None
    libiio_version: str | None
    backends: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class LocalDoctorReport:
    generated_at: str
    canonical_firmware: str
    canonical_image_sha256: str
    radios: tuple[LocalDoctorRadio, ...]
    diagnostic_profiles: tuple[str, ...] = ()
    host_libiio: HostLibiioCheck | None = None


def diagnose_local_usb_radios(
    usb_sysfs_path: Path | None = None,
    *,
    devices: tuple[LocalUsbPluto, ...] | None = None,
    setup_probe: SetupProbe | None = None,
    environment_probe: Callable[[], IioEnvironmentReport] = inspect_iio_environment,
) -> LocalDoctorReport:
    """Freshly inspect each selected USB Pluto without opening an IIO buffer."""

    selected = scan_local_usb_plutos() if devices is None else devices
    if usb_sysfs_path is not None:
        requested = str(usb_sysfs_path)
        selected = tuple(device for device in selected if device.usb_path == requested)
        if len(selected) != 1:
            raise ValueError(
                f"expected exactly one local Pluto at {usb_sysfs_path}, found {len(selected)}"
            )
    radios = tuple(_diagnose_radio(device, setup_probe) for device in selected)
    return LocalDoctorReport(
        generated_at=datetime.now(UTC).isoformat(),
        canonical_firmware=LOCAL_POLICY.device_firmware,
        canonical_image_sha256=LOCAL_POLICY.asset_sha256,
        diagnostic_profiles=tuple(profile.profile_id for profile in DIAGNOSTIC_PROFILES),
        radios=radios,
        host_libiio=_host_libiio(environment_probe),
    )


def _diagnose_radio(
    device: LocalUsbPluto, setup_probe: SetupProbe | None = None
) -> LocalDoctorRadio:
    checks: list[LocalDoctorCheck] = []
    usb_bus_device = (
        f"{device.bus_number:03d}:{device.device_number:03d}"
        if device.bus_number is not None and device.device_number is not None
        else None
    )
    _check(
        checks,
        "identity.usb_serial",
        "pass" if device.serial else "fail",
        device.serial,
        "one non-empty stable serial",
        "USB serial is stable" if device.serial else "USB serial is blank",
    )
    _usb_topology_checks(checks, device)
    interface = (
        device.host_network_interfaces[0].name if len(device.host_network_interfaces) == 1 else None
    )
    _check(
        checks,
        "transport.usb_network",
        "pass" if interface else "fail",
        tuple(item.name for item in device.host_network_interfaces),
        "exactly one USB network interface",
        "USB network transport is unambiguous"
        if interface
        else "USB network transport is missing or ambiguous",
    )
    storage = device.storage_devices[0] if len(device.storage_devices) == 1 else None
    _check(
        checks,
        "transport.updater_storage",
        "pass" if storage else "fail",
        device.storage_devices,
        "exactly one updater partition",
        "Updater storage is unambiguous" if storage else "Updater storage is missing or ambiguous",
    )
    if interface is None:
        _unknown_facts(checks)
        return _radio_result(
            device,
            usb_bus_device,
            interface,
            storage,
            checks,
            error="cannot inspect IIOD without one exact USB network interface",
        )
    try:
        facts = inspect_bound_iiod(interface)
    except BootstrapFirmwareError as error:
        _unknown_facts(checks)
        return _radio_result(
            device,
            usb_bus_device,
            interface,
            storage,
            checks,
            error=str(error),
        )

    live_serial = str(facts.get("hw_serial") or "").strip() or None
    identity_ok = device.serial is not None and live_serial == device.serial
    _check(
        checks,
        "identity.iio_serial",
        "pass" if identity_ok else "fail",
        live_serial,
        device.serial or "same non-empty USB serial",
        "USB and IIOD serials match"
        if identity_ok
        else "IIOD identity is blank or does not match USB",
    )
    model = str(facts.get("hw_model") or "").strip() or None
    model_ok = model is not None and "plutosdr rev.c" in model.lower()
    _check(
        checks,
        "hardware.rev_c",
        "pass" if model_ok else "fail",
        model,
        "PlutoSDR Rev.C",
        "Live board model is Rev.C" if model_ok else "Live board model is not attested Rev.C",
    )
    firmware = str(facts.get("fw_version") or "").strip() or None
    profile = select_diagnostic_profile(firmware)
    _check(
        checks,
        "firmware.diagnostic_profile",
        "pass" if profile is not None else "fail",
        firmware,
        tuple(item.firmware_version for item in DIAGNOSTIC_PROFILES),
        f"Active firmware matches diagnostic profile {profile.profile_id}"
        if profile is not None
        else "Active firmware has no supported diagnostic profile",
    )
    upgrade = upgrade_target_for(profile)
    _check(
        checks,
        "firmware.release_currency",
        "unknown" if profile is None else "fail" if upgrade is not None else "pass",
        firmware,
        UPGRADE_TARGET_PROFILE.firmware_version,
        "Active firmware has no known profile, so it cannot be ranked"
        if profile is None
        else f"A newer qualified release is available: {upgrade.firmware_version}"
        if upgrade is not None
        else "Active firmware is at or newer than the newest qualified release",
    )
    phy = str(facts.get("ad9361-phy,model") or "").strip() or None
    _check(
        checks,
        "rf.phy_model",
        "pass" if phy == "ad9361" else "fail",
        phy,
        "ad9361",
        "Live PHY is AD9361" if phy == "ad9361" else "Live PHY is not AD9361",
    )
    metadata = parse_metadata_abi(facts.get("iio,buffer-metadata"))
    metadata_ok = profile is not None and metadata.abi in profile.metadata_abis
    _check(
        checks,
        "transport.buffer_metadata",
        "pass"
        if metadata_ok
        else "unknown"
        if metadata.state is MetadataAbiState.ABSENT
        else "fail",
        metadata.abi if metadata.abi is not None else metadata.raw,
        profile.metadata_abis if profile is not None else "known diagnostic profile",
        f"Continuous buffer metadata ABI {metadata.abi} matches the profile"
        if metadata_ok
        else f"Continuous buffer metadata is {metadata.state.value} or unsupported",
    )
    raw_device_names = facts.get("device_names", ())
    device_names = (
        {str(value) for value in raw_device_names}
        if isinstance(raw_device_names, (tuple, list, set, frozenset))
        else set()
    )
    paired_rx = {"ad9361-phy", "cf-ad9361-lpc"} <= device_names
    _check(
        checks,
        "rf.paired_rx_device",
        "pass" if paired_rx else "fail",
        tuple(sorted(device_names)),
        ("ad9361-phy", "cf-ad9361-lpc"),
        "Paired-RX IIO devices are present"
        if paired_rx
        else "Paired-RX IIO devices are incomplete",
    )
    tandem_agc = "tandem-agc" in device_names
    tandem_expected = profile.tandem_agc_required if profile is not None else None
    tandem_ok = profile is not None and tandem_agc is tandem_expected
    _check(
        checks,
        "transport.tandem_agc",
        "pass" if tandem_ok else "unknown" if profile is None else "fail",
        tandem_agc,
        tandem_expected,
        (
            "Tandem AGC capability matches the profile"
            if tandem_ok
            else "Tandem AGC capability does not match the profile"
        ),
    )
    _check(
        checks,
        "firmware.qspi_boot_provenance",
        "unknown",
        None,
        "fresh trusted persistent-boot evidence",
        "Standalone USB IIOD inspection cannot prove QSPI boot provenance",
    )
    probed = None if setup_probe is None else setup_probe(device, firmware)
    _check(
        checks,
        "setup.uboot_ad9361_2r2t",
        "unknown" if probed is None else probed.status,
        None if probed is None else probed.actual,
        CANONICAL_UBOOT_SUMMARY,
        "Persistent U-Boot values require the authenticated setup inspector"
        if probed is None
        else probed.summary,
    )
    return _radio_result(
        device,
        usb_bus_device,
        interface,
        storage,
        checks,
        setup_repair=None if probed is None else probed.repair,
        firmware=firmware,
        model=model,
        phy=phy,
        diagnostic_profile_id=profile.profile_id if profile is not None else None,
        metadata_enabled=metadata.abi is not None,
        metadata_abi=metadata.abi,
        tandem_agc=tandem_agc,
    )


def _unknown_facts(checks: list[LocalDoctorCheck]) -> None:
    for code, expected in (
        ("identity.iio_serial", "same non-empty USB serial"),
        ("hardware.rev_c", "PlutoSDR Rev.C"),
        (
            "firmware.diagnostic_profile",
            tuple(item.firmware_version for item in DIAGNOSTIC_PROFILES),
        ),
        ("firmware.release_currency", UPGRADE_TARGET_PROFILE.firmware_version),
        ("rf.phy_model", "ad9361"),
        ("transport.buffer_metadata", "metadata ABI selected by a known profile"),
        ("rf.paired_rx_device", ("ad9361-phy", "cf-ad9361-lpc")),
        ("transport.tandem_agc", "capability selected by a known profile"),
        ("firmware.qspi_boot_provenance", "fresh trusted persistent-boot evidence"),
        ("setup.uboot_ad9361_2r2t", "canonical persistent U-Boot tuple"),
    ):
        _check(checks, code, "unknown", None, expected, "Fresh fact is unavailable")


def _usb_topology_checks(
    checks: list[LocalDoctorCheck],
    device: LocalUsbPluto,
) -> None:
    speed = device.speed_mbps
    _check(
        checks,
        "usb.negotiated_speed",
        "unknown" if speed is None else "pass" if speed >= 480 else "fail",
        speed,
        ">= 480 Mb/s (USB high speed)",
        "USB link negotiated high speed"
        if speed is not None and speed >= 480
        else "USB link speed is unavailable or below high speed",
    )
    _check(
        checks,
        "usb.controller_lineage",
        "pass" if device.root_controller_pci_address else "unknown",
        {
            "resolved_parent_path": device.resolved_parent_path,
            "direct_to_root_hub": device.direct_to_root_hub,
            "intermediate_hub_count": device.intermediate_hub_count,
            "pci_address": device.root_controller_pci_address,
            "vendor_id": device.root_controller_vendor_id,
            "device_id": device.root_controller_device_id,
        },
        "resolved USB parent path and root xHCI PCI controller",
        "USB controller lineage is resolved"
        if device.root_controller_pci_address
        else "USB controller lineage is unavailable",
    )
    _check(
        checks,
        "usb.power_budget",
        "pass" if device.advertised_max_power_ma is not None else "unknown",
        {
            "advertised_max_power_ma": device.advertised_max_power_ma,
            "runtime_status": device.runtime_power_status,
            "runtime_control": device.runtime_power_control,
        },
        "descriptor budget and runtime state (not measured voltage/current)",
        (
            f"Device advertises {device.advertised_max_power_ma} mA; this is not "
            "measured electrical consumption"
            if device.advertised_max_power_ma is not None
            else "USB descriptor power budget is unavailable"
        ),
    )
    faults = device.link_faults
    fault_count = 0 if faults is None else faults.error_count + faults.port_power_cycle_count
    disconnects = 0 if faults is None else faults.disconnect_count
    fault_status: CheckStatus = (
        "unknown"
        if faults is None or (fault_count == 0 and disconnects > 0)
        else "fail"
        if fault_count > 0
        else "pass"
    )
    _check(
        checks,
        "usb.recent_link_faults",
        fault_status,
        None if faults is None else faults.model_dump(mode="json"),
        "no recent port-scoped enumeration errors or power cycles",
        "Recent port-scoped USB errors need investigation"
        if fault_count > 0
        else "Recent disconnects may be intentional and need operator correlation"
        if disconnects > 0
        else "No recent port-scoped USB link faults were observed"
        if faults is not None
        else "Kernel journal is unavailable; link fault status is unknown",
    )


def _check(
    checks: list[LocalDoctorCheck],
    code: str,
    status: CheckStatus,
    actual: object,
    expected: object,
    summary: str,
) -> None:
    checks.append(LocalDoctorCheck(code, status, actual, expected, summary))


def _radio_result(
    device: LocalUsbPluto,
    usb_bus_device: str | None,
    interface: str | None,
    storage: str | None,
    checks: list[LocalDoctorCheck],
    *,
    setup_repair: SetupRepairRecord | None = None,
    firmware: str | None = None,
    model: str | None = None,
    phy: str | None = None,
    diagnostic_profile_id: str | None = None,
    metadata_enabled: bool | None = None,
    metadata_abi: int | None = None,
    tandem_agc: bool | None = None,
    error: str | None = None,
) -> LocalDoctorRadio:
    statuses = {check.status for check in checks}
    overall: CheckStatus = (
        "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
    )
    return LocalDoctorRadio(
        usb_sysfs_path=device.usb_path,
        usb_bus_device=usb_bus_device,
        serial=device.serial,
        usb_interface=interface,
        storage_partition=storage,
        firmware_version=firmware,
        model=model,
        phy_model=phy,
        diagnostic_profile_id=diagnostic_profile_id,
        metadata_enabled=metadata_enabled,
        metadata_abi=metadata_abi,
        tandem_agc=tandem_agc,
        overall=overall,
        checks=tuple(checks),
        error=error,
        setup_repair=setup_repair,
    )


def _host_libiio(probe: Callable[[], IioEnvironmentReport]) -> HostLibiioCheck | None:
    """Summarise host libiio health, degrading to None if the probe itself fails."""

    try:
        report = probe()
    except Exception:  # noqa: BLE001 - a probe failure must not fail the whole sweep
        return None
    return HostLibiioCheck(
        status=str(report.status),
        healthy=report.healthy,
        summary=report.message,
        remediation=report.remediation,
        libiio_version=report.libiio_version,
        backends=tuple(report.backends),
    )
