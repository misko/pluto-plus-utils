"""Profile-aware, read-only Pluto+ setup diagnostics.

The policy is deliberately shipped with the application rather than inferred from
lexical tag order.  Updating it is a reviewed release action; a doctor run never
downloads or mutates firmware.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from pluto_plus.diagnostic_profiles import (
    DIAGNOSTIC_PROFILES,
    MetadataAbiState,
    parse_metadata_abi,
    select_diagnostic_profile,
)
from pluto_plus.models import (
    DiagnosticProfileSummary,
    DoctorFinding,
    DoctorRemediation,
    DoctorReport,
    DoctorStatus,
    FirmwarePolicy,
    RadioSnapshot,
)

CANONICAL_UBOOT = {
    "attr_name": "compatible",
    "attr_val": "ad9361",
    "compatible": "ad9361",
    "mode": "2r2t",
}

CANONICAL_POLICY = FirmwarePolicy(
    profile_id="libiio-continuous-metadata",
    release_tag="v0.38-plutoplus-spf-libiio-metadata-v5",
    device_firmware="v0.38-plutoplus-spf-libiio-metadata-v5",
    asset_name="plutoplus-spf-libiio-metadata-v5-d7c87a9a2809-pluto.dfu",
    asset_sha256="948b46506febacb087f3955be86015e074f8c0e3370a9dfc6a942e735d97f882",
    release_url=(
        "https://github.com/misko/plutosdr-fw/releases/tag/v0.38-plutoplus-spf-libiio-metadata-v5"
    ),
    source_commit="d7c87a9a28094ee6f0b23cb47df9ff737b5a69d8",
    fit_body_sha256="ae8ee0dac655f1178d24d3d53a78ae44ccb21b4aaef9273c6416bdd6bef761d9",
    fit_body_size=12_743_859,
    hardware_qualified=True,
    published_at=datetime(2026, 8, 12, 17, 21, 7, tzinfo=UTC),
)

# This is a separately selected mutation target, not the canonical repair
# policy above.  Keeping the two objects distinct prevents read-only diagnostic
# recognition from silently authorizing a firmware write.
TANDEM_V6_DEVELOPMENT_POLICY = FirmwarePolicy(
    profile_id="libiio-metadata-v6-tandem-abi2-development",
    release_tag="tandem-agc-v2-ab79bb591a6e",
    device_firmware="v0.39-plutoplus-spf-libiio-metadata-v6-36-gab79b",
    asset_name="plutoplus-spf-tandem-agc-v2-ab79bb591a6e-pluto.dfu",
    asset_sha256="13106a19abbb36ec8950d5e37d50928c6af798efdb1259189a1a61ae9d75863f",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/32175110831",
    source_commit="ab79bb591a6e61361e2724a0f6673096bf5cb026",
    fit_body_sha256="5235ff23b1d31e169308ab6abb91523ed41a196fe72b3f0af395f25c36c958e9",
    fit_body_size=12_776_779,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 18, 19, 27, 12, tzinfo=UTC),
)


def diagnose_radio(
    snapshot: RadioSnapshot,
    facts: Mapping[str, Any] | None = None,
    *,
    firmware_helper_available: bool,
) -> DoctorReport:
    """Compare fresh passive observations with the selected standalone profile."""

    observed = dict(facts or {})
    findings: list[DoctorFinding] = []
    identity = snapshot.identity

    findings.append(
        _comparison(
            "identity.serial",
            identity.serial not in {"", "unattested"},
            "Radio serial is attested"
            if identity.serial != "unattested"
            else "Radio serial is not attested",
            identity.serial,
            "one stable non-empty hardware serial",
            "IIO context hw_serial, checked when the controller opened the radio",
        )
    )

    usb_path = identity.usb_path or _string(observed.get("usb_path"))
    if usb_path:
        findings.append(
            _comparison(
                "identity.usb_path",
                True,
                "Exact USB attachment is correlated",
                usb_path,
                "one serial-matched Pluto+ sysfs path",
                "host sysfs VID/PID/serial correlation",
            )
        )
    else:
        findings.append(
            DoctorFinding(
                code="identity.usb_path",
                status=DoctorStatus.WARN,
                summary="No exact local USB attachment is correlated",
                actual=None,
                expected="one serial-matched Pluto+ sysfs path before any mutation",
                evidence="network control alone is not a safe flashing identity",
                remediation=_usb_remediation(),
            )
        )

    firmware = identity.firmware_version
    diagnostic_profile = select_diagnostic_profile(firmware)
    findings.append(
        _comparison(
            "firmware.device_version",
            diagnostic_profile is not None,
            (
                f"Active firmware matches diagnostic profile {diagnostic_profile.profile_id}"
                if diagnostic_profile is not None
                else "Active firmware has no supported diagnostic profile"
            ),
            firmware,
            [profile.firmware_version for profile in DIAGNOSTIC_PROFILES],
            (
                "exact fresh IIO context fw_version; diagnostic compatibility does not "
                "authorize flashing or prove persistent QSPI"
            ),
            remediation=None if diagnostic_profile is not None else _firmware_remediation(),
            unknown=firmware is None,
        )
    )

    phy_model = _string(observed.get("phy_model"))
    findings.append(
        _comparison(
            "rf.phy_model",
            phy_model == "ad9361",
            "RF PHY identifies as AD9361"
            if phy_model == "ad9361"
            else "RF PHY is not canonical AD9361",
            phy_model,
            "ad9361",
            "ad9361-phy model attribute",
            remediation=_setup_remediation(),
            unknown=phy_model is None,
        )
    )

    scan_channels = _strings(observed.get("rx_scan_channels"))
    required_channels = ("voltage0", "voltage1", "voltage2", "voltage3")
    dual_rx = set(required_channels).issubset(scan_channels)
    findings.append(
        _comparison(
            "rf.dual_rx_scan",
            dual_rx,
            "Both complex receive channels are exposed"
            if dual_rx
            else "Dual-receiver scan layout is incomplete",
            sorted(scan_channels),
            list(required_channels),
            "cf-ad9361-lpc enabled scan elements; voltage0..3 are RX1 I/Q and RX2 I/Q",
            remediation=_setup_remediation(),
            unknown=not scan_channels,
        )
    )

    metadata_value = (
        observed.get("buffer_metadata_abi")
        if "buffer_metadata_abi" in observed
        else observed.get("buffer_metadata")
    )
    metadata = parse_metadata_abi(metadata_value)
    metadata_matches = (
        diagnostic_profile is not None and metadata.abi in diagnostic_profile.metadata_abis
    )
    findings.append(
        _comparison(
            "firmware.buffer_metadata",
            metadata_matches,
            (
                f"Frame metadata ABI {metadata.abi} matches the diagnostic profile"
                if metadata_matches
                else (
                    f"Frame metadata ABI {metadata.abi} is available but unsupported "
                    "by the diagnostic profile"
                    if metadata.state is MetadataAbiState.AVAILABLE
                    else f"Frame metadata capability is {metadata.state.value}"
                )
            ),
            metadata.abi if metadata.abi is not None else metadata.raw,
            diagnostic_profile.metadata_abis if diagnostic_profile is not None else "known profile",
            "exact IIO context iio,buffer-metadata ABI value",
            remediation=None if diagnostic_profile is not None else _firmware_remediation(),
            unknown=metadata.state is MetadataAbiState.ABSENT,
        )
    )

    tandem_agc = observed.get("tandem_agc") is True
    tandem_expected = diagnostic_profile.tandem_agc_required if diagnostic_profile else None
    findings.append(
        _comparison(
            "firmware.tandem_agc",
            diagnostic_profile is not None and tandem_agc is tandem_expected,
            (
                "Tandem AGC capability matches the diagnostic profile"
                if diagnostic_profile is not None and tandem_agc is tandem_expected
                else "Tandem AGC capability does not match the diagnostic profile"
            ),
            tandem_agc,
            tandem_expected,
            "presence of the read-only tandem-agc IIO capability device",
            unknown=diagnostic_profile is None,
        )
    )

    uboot = observed.get("uboot")
    if isinstance(uboot, Mapping):
        actual_uboot = {key: uboot.get(key) for key in CANONICAL_UBOOT}
        uboot_matches = actual_uboot == CANONICAL_UBOOT
        status = DoctorStatus.PASS if uboot_matches else DoctorStatus.FAIL
        summary = (
            "Persistent AD9361/2R2T U-Boot tuple is canonical"
            if uboot_matches
            else "Persistent AD9361/2R2T U-Boot tuple is not canonical"
        )
    else:
        actual_uboot = None
        status = DoctorStatus.UNKNOWN
        summary = "Persistent U-Boot tuple has not been read"
    findings.append(
        DoctorFinding(
            code="setup.uboot_2r2t",
            status=status,
            summary=summary,
            actual=actual_uboot,
            expected=CANONICAL_UBOOT,
            evidence=(
                "all four values must be read after a reboot; functional channels alone "
                "are insufficient"
            ),
            remediation=None if status is DoctorStatus.PASS else _setup_remediation(),
        )
    )

    boot_provenance = _string(observed.get("boot_provenance"))
    findings.append(
        DoctorFinding(
            code="firmware.boot_provenance",
            status=(
                DoctorStatus.PASS
                if boot_provenance == "qspi_cold_boot_verified"
                else DoctorStatus.UNKNOWN
            ),
            summary=(
                "Canonical firmware was verified after a full power cycle"
                if boot_provenance == "qspi_cold_boot_verified"
                else "Persistent QSPI firmware is not proven by the active version"
            ),
            actual=boot_provenance,
            expected="qspi_cold_boot_verified",
            evidence="a volatile RAM image can report the same /opt/VERSIONS and fw_version",
            remediation=(
                None if boot_provenance == "qspi_cold_boot_verified" else _power_cycle_remediation()
            ),
        )
    )

    findings.append(
        DoctorFinding(
            code="firmware.helper",
            status=(DoctorStatus.PASS if firmware_helper_available else DoctorStatus.WARN),
            summary=(
                "Guarded radio mutation helper is configured"
                if firmware_helper_available
                else "Guarded radio mutation helper is not configured"
            ),
            actual=firmware_helper_available,
            expected=True,
            evidence=(
                "mutations require an explicitly configured exact-radio executor and "
                "authenticated admin boundary"
            ),
            remediation=None if firmware_helper_available else _helper_remediation(),
        )
    )

    healthy = all(finding.status is DoctorStatus.PASS for finding in findings)
    return DoctorReport(
        radio_id=identity.radio_id,
        canonical_policy=CANONICAL_POLICY,
        diagnostic_profile=(
            DiagnosticProfileSummary(
                profile_id=diagnostic_profile.profile_id,
                firmware_version=diagnostic_profile.firmware_version,
                metadata_abis=diagnostic_profile.metadata_abis,
                tandem_agc_required=diagnostic_profile.tandem_agc_required,
                release_status=diagnostic_profile.release_status,
            )
            if diagnostic_profile is not None
            else None
        ),
        healthy=healthy,
        findings=tuple(findings),
    )


def _comparison(
    code: str,
    matches: bool,
    summary: str,
    actual: Any,
    expected: Any,
    evidence: str,
    *,
    remediation: DoctorRemediation | None = None,
    unknown: bool = False,
) -> DoctorFinding:
    status = (
        DoctorStatus.UNKNOWN if unknown else (DoctorStatus.PASS if matches else DoctorStatus.FAIL)
    )
    return DoctorFinding(
        code=code,
        status=status,
        summary=summary,
        actual=actual,
        expected=expected,
        evidence=evidence,
        remediation=None if status is DoctorStatus.PASS else remediation,
    )


def _firmware_remediation() -> DoctorRemediation:
    return DoctorRemediation(
        remediation_id="flash_canonical_firmware_mtd3",
        title="Qualify, then flash the canonical firmware partition",
        description=(
            "Verify the release DFU SHA-256, test it with volatile DFU, then create a separate "
            "persistent-QSPI plan. Only pluto.frm/mtd3 is writable; bootloader and environment "
            "images are forbidden."
        ),
        automatable=True,
        mutation=True,
        requires_privileged_helper=True,
        cli_hint=(
            "pluto firmware upload IMAGE.dfu; pluto firmware plan RADIO IMAGE_ID "
            "--mode volatile_dfu"
        ),
    )


def _setup_remediation() -> DoctorRemediation:
    return DoctorRemediation(
        remediation_id="provision_ad9361_2r2t",
        title="Provision the persistent AD9361/2R2T tuple",
        description=(
            "Back up the complete U-Boot environment, write only the four canonical values, "
            "reboot, re-attest the exact USB serial/path, reread all values, and prove voltage0..3."
        ),
        automatable=True,
        mutation=True,
        requires_privileged_helper=True,
        cli_hint="pluto setup plan RADIO; pluto setup execute PLAN_ID --token TOKEN",
    )


def _usb_remediation() -> DoctorRemediation:
    return DoctorRemediation(
        remediation_id="attach_exact_usb_radio",
        title="Attach and correlate the selected radio over USB",
        description=(
            "Match the network hw_serial to exactly one 0456:b673 sysfs device before planning."
        ),
    )


def _power_cycle_remediation() -> DoctorRemediation:
    return DoctorRemediation(
        remediation_id="power_cycle_and_attest",
        title="Cold-boot from QSPI and run doctor again",
        description=(
            "Remove power completely, reconnect the same serial/path, then reread firmware "
            "and setup facts."
        ),
        mutation=True,
    )


def _helper_remediation() -> DoctorRemediation:
    return DoctorRemediation(
        remediation_id="configure_privileged_helper",
        title="Configure a guarded exact-radio mutation helper",
        description=(
            "Configure an exact-radio executor plus authenticated admin policy before "
            "enabling setup or firmware changes."
        ),
    )


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any) -> set[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return set()
    return {item for item in value if isinstance(item, str)}
