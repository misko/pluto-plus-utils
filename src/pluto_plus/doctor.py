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
    SUPPORTED_AD936X_PHY_MODELS,
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

# attr_name/attr_val must stay unset.  The AD936x boot script on these boards guards
# its AD9364 branch with a malformed condition:
#
#     test ${compatible} = ad9364 || test -n ${attr_val} = ad9364
#
# U-Boot's test consumes "-n <value>" as a complete operator, then matches no operator
# at the trailing "= ad9364" and returns true unconditionally (u-boot cmd/test.c).  Any
# non-empty attr_val therefore fires that branch on every boot, stripping
# adi,2rx-2tx-mode-enable and running "setenv mode 1r1t; saveenv" -- reverting a 2R2T
# radio to 1R1T and persisting the revert.  compatible=ad9361 drives the AD9361
# override on its own through a separate, correctly formed branch.
CANONICAL_UBOOT: dict[str, str | None] = {
    "attr_name": None,
    "attr_val": None,
    "compatible": "ad9361",
    "mode": "2r2t",
}

CANONICAL_POLICY = FirmwarePolicy(
    profile_id="libiio-continuous-metadata",
    release_tag="v0.39-plutoplus-spf-libiio-metadata-v6",
    device_firmware="v0.39-plutoplus-spf-libiio-metadata-v6",
    asset_name="plutoplus-spf-libiio-metadata-v6-e3700cc72681-pluto.dfu",
    asset_sha256="8ffbb0bf0912285636ddbcf0b00e12deaca0f55612faf7d29efa067b22e61352",
    release_url=(
        "https://github.com/misko/plutosdr-fw/releases/tag/v0.39-plutoplus-spf-libiio-metadata-v6"
    ),
    source_commit="e3700cc7268132eb6baa4bc88d8f3320dc7148b9",
    fit_body_sha256="b23c90be6841255ee38b08bbe609b087d53bcef96ff4e94e40dbc4c72c0f0480",
    fit_body_size=12_762_675,
    hardware_qualified=True,
    published_at=datetime(2026, 8, 17, 17, 22, 3, tzinfo=UTC),
)

# This is a separately selected mutation target, not the canonical repair
# policy above.  Keeping the two objects distinct prevents read-only diagnostic
# recognition from silently authorizing a firmware write.
TANDEM_V6_DEVELOPMENT_POLICY = FirmwarePolicy(
    profile_id="libiio-metadata-v6-tandem-abi2-development",
    release_tag="tandem-agc-v2-7f812fe63c96",
    device_firmware="v0.39-plutoplus-spf-libiio-metadata-v6-35-g7f812",
    asset_name="plutoplus-spf-tandem-agc-v2-7f812fe63c96-pluto.dfu",
    asset_sha256="8e324b6ce77d657925355fcb4a17eb7392ec6a187a41e40c8fd63ccfba40caf0",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/32170709605",
    source_commit="7f812fe63c96eaf091550ab8804fd867dcb43fe2",
    fit_body_sha256="a3879aaa73cd69c5225c7f4775033868aac7414db576eb3545bfc9e29f31c70e",
    fit_body_size=12_776_899,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 18, 18, 39, 52, tzinfo=UTC),
)

# RAM-only successor to the initial tandem development image. It is deliberately
# not canonical or persistence-qualified; the standalone volatile-DFU command is
# the only automatic mutation path that should select this profile.
TANDEM_V6_LATCH_CLEAR_RAM_POLICY = FirmwarePolicy(
    profile_id="libiio-metadata-v6-tandem-latch-clear-ram",
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

# The exact same immutable bytes receive a distinct mutation identity only after
# passing the multi-board RAM-only hardware gate. Keeping this separate from the
# RAM profile prevents a diagnostic selection from silently authorizing QSPI.
TANDEM_V6_LATCH_CLEAR_PERSISTENT_POLICY = TANDEM_V6_LATCH_CLEAR_RAM_POLICY.model_copy(
    update={
        "profile_id": "libiio-metadata-v6-tandem-latch-clear-persistent-promotion",
        "hardware_qualified": True,
    }
)

# Exact final-version-stamped tandem v7 candidate from the trusted Kalman build.
# This successor includes the synchronous iiOD exclusive-buffer close barrier.
# This policy is deliberately RAM-only until all four physical radios pass the
# release matrix. A future persistent policy must be a separate reviewed object.
TANDEM_AGC_V7_RAM_POLICY = FirmwarePolicy(
    profile_id="tandem-agc-v7-release-ram",
    release_tag="v0.40-plutoplus-spf-tandem-agc-v7",
    device_firmware="v0.40-plutoplus-spf-tandem-agc-v7",
    asset_name="plutoplus-spf-tandem-agc-v2-e0049c2d0077-pluto.dfu",
    asset_sha256="4fe286f9756e3c721d5322ba9c18831f43ab4678c34bb9ef7f238cbb1236debe",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/32214045747",
    source_commit="e0049c2d0077770eeb1f6850b957878a373623d9",
    fit_body_sha256="4c19876d09082adfdbd255726e84be397eb4e18a4c0d96b9722d7d543c2ebae7",
    fit_body_size=12_776_823,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 19, 4, 32, 25, tzinfo=UTC),
)

# The same attested bytes receive a separate QSPI authorization only after the
# four-radio RAM matrix passed. Keeping this identity distinct preserves the
# rule that selecting the RAM diagnostic profile can never authorize a write.
TANDEM_AGC_V7_PERSISTENT_POLICY = TANDEM_AGC_V7_RAM_POLICY.model_copy(
    update={
        "profile_id": "tandem-agc-v7-release-persistent-promotion",
        "hardware_qualified": True,
    }
)

# Exact ABI-3 single-RX candidate produced by the trusted Kalman build. The
# sealed bundle passed the complete offline release gate, but these bytes have
# not yet passed the physical-radio matrix. Keeping only a RAM policy makes a
# power cycle the recovery path and prevents any command from selecting it for
# QSPI persistence before an explicit hardware promotion.
SINGLE_RX_METADATA_RC1_RAM_POLICY = FirmwarePolicy(
    profile_id="single-rx-metadata-rc1-ram",
    release_tag="plutoplus-spf-single-rx-metadata-rc1-c83345490234",
    device_firmware="v0.42-plutoplus-spf-single-rx-metadata-rc1",
    asset_name="plutoplus-spf-single-rx-metadata-rc1-c83345490234-pluto.dfu",
    asset_sha256="3d38a74234823937995e20c32099f61923284df50b530f1e39df1b72f5e80aaf",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/33121754593",
    source_commit="c833454902343843e4af7f3f6c97c40d4a809c90",
    fit_body_sha256="dff0c0f4d607beb5c5adc050e9cf6d2bbb09d1cd5c13a7c57a4771c2cbf17dab",
    fit_body_size=12_793_263,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 27, 22, 38, 52, tzinfo=UTC),
)

# Exact opt-in DDR burst candidate built from the RC32-based ABI-3 graph. The
# profile is intentionally RAM-only: its hash authorizes volatile DFU testing,
# never persistence. A separate promotion identity is required after the USB,
# IP, cancellation, and memory-reserve hardware matrix passes.
DDR_BURST_V1_RC1_RAM_POLICY = FirmwarePolicy(
    profile_id="ddr-burst-v1-rc1-ram",
    release_tag="ddr-burst-v1-rc1-fdbe3ffaed60",
    device_firmware="v0.42-plutoplus-spf-ddr-burst-v1-rc1",
    asset_name="plutoplus-spf-ddr-burst-v1-rc1-fdbe3ffaed60-pluto.dfu",
    asset_sha256="9024ed3c0ce38efeaf2e30dd71f903e2d65a234b90e7af175d3c196042dc6591",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/33145187461",
    source_commit="fdbe3ffaed604cc83f89252a10d2ec8b51b5be58",
    fit_body_sha256="b9ceebdbadf144e91be78c2b87aad30691f3ade068f91ad8ab61c72b1b4035d4",
    fit_body_size=12_796_131,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 28, 5, 34, 46, tzinfo=UTC),
)

# RC2 rebuilds the combined post-PR56 source graph with the reviewed Pluto HDL
# area strategy that keeps the widened RX DMAC inside the Z7010. The exact
# trusted-CI bytes remain RAM-only: selecting this profile can never authorize
# a persistent write, and a future promotion must use a distinct policy.
DDR_BURST_V1_RC2_RAM_POLICY = FirmwarePolicy(
    profile_id="ddr-burst-v1-rc2-ram",
    release_tag="ddr-burst-v1-rc2-b046b80fd280",
    device_firmware="v0.42-plutoplus-spf-ddr-burst-v1-rc2",
    asset_name="plutoplus-spf-ddr-burst-v1-rc2-b046b80fd280-pluto.dfu",
    asset_sha256="2164eed7450cfe8e29ea1e57ee1b556c06e912a4bbca6f186721f0ecc744d0b8",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/33157004273",
    source_commit="b046b80fd280dc827b8e0eef75374cda8bdf15a6",
    fit_body_sha256="8c06c17aecebb724e021470f43f31440ed850327ac7fd4d4b0238c5a3563eda7",
    fit_body_size=12_796_723,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 28, 9, 14, 1, tzinfo=UTC),
)

# RC3 retains the exact RC2 userspace/FPGA graph and adds the merged AXI-DMAC
# hardware-shutdown fence. The trusted bundle is release-eligible offline, but
# this identity remains RAM-only until abrupt-disconnect and multi-radio gates
# pass; no policy with the same source commit may authorize persistence.
DDR_BURST_V1_RC3_RAM_POLICY = FirmwarePolicy(
    profile_id="ddr-burst-v1-rc3-ram",
    release_tag="ddr-burst-v1-rc3-19abd4a4184b",
    device_firmware="v0.42-plutoplus-spf-ddr-burst-v1-rc3",
    asset_name="plutoplus-spf-ddr-burst-v1-rc3-19abd4a4184b-pluto.dfu",
    asset_sha256="18f0ce26e4c242f24fcacbd04e71b633e24ccf5b740332a263dc15e778a231fa",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/33163618434",
    source_commit="19abd4a4184b155153eaf1d1b7fd3b393bcb6ace",
    fit_body_sha256="0f46a47d41c994c71c4d58d409cfe73ec90b198a07553586a5188ae4321230f9",
    fit_body_size=12_796_875,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 28, 10, 51, 38, tzinfo=UTC),
)

# RC5 closes the high-to-low sample-rate recovery defect by resetting the RX
# timestamp FIFO, with the reset hold implemented as one SRL so the slice-full
# Z7010 still routes. The protected bundle and both checksum inventories pass,
# but these bytes remain RAM-only until the repeated disconnect and fleet gates
# complete; no profile with this identity may authorize persistence.
DDR_BURST_V1_RC5_RAM_POLICY = FirmwarePolicy(
    profile_id="ddr-burst-v1-rc5-ram",
    release_tag="ddr-burst-v1-rc5-58f382f69776",
    device_firmware="v0.42-plutoplus-spf-ddr-burst-v1-rc5",
    asset_name="plutoplus-spf-ddr-burst-v1-rc5-58f382f69776-pluto.dfu",
    asset_sha256="ba364191cdfd0eb17af81d952f92d69481c7e31fbcdd8baac79590eab8afe98c",
    release_url="https://github.com/misko/plutosdr-fw/actions/runs/33171059728",
    source_commit="58f382f69776f39b04eac9e289064d6e22edd433",
    fit_body_sha256="bd888473054b269643e94e599f835a71fad2ed8cb08f21258c5f418bfd380aab",
    fit_body_size=12_793_407,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 28, 12, 48, 35, tzinfo=UTC),
)

# Exact final-version-stamped DDR burst image from protected main run
# 33174605592. The release label does not transfer RC5's hardware evidence:
# these byte-distinct DFU/FIT objects remain RAM-only until they pass the final
# recovery and fleet matrix. A separate reviewed policy must authorize QSPI.
DDR_BURST_V1_RELEASE_RAM_POLICY = FirmwarePolicy(
    profile_id="ddr-burst-v1-release-ram",
    release_tag="v0.42-plutoplus-spf-ddr-burst-v1",
    device_firmware="v0.42-plutoplus-spf-ddr-burst-v1",
    asset_name="plutoplus-spf-ddr-burst-v1-a6b78df100f6-pluto.dfu",
    asset_sha256="47bb23ff1d498a5899c4503de33bc818aa908c567eab4e0fc535602ffa296877",
    release_url=(
        "https://github.com/misko/plutosdr-fw/releases/tag/"
        "v0.42-plutoplus-spf-ddr-burst-v1"
    ),
    source_commit="a6b78df100f67c1bcd2528e2fbc0c86b2a8ee2ba",
    fit_body_sha256="f40542a7b1a53f4f1b06a5733f068e7b69f1eddff7ab0eb46c0f37f9f37d295a",
    fit_body_size=12_793_395,
    hardware_qualified=False,
    published_at=datetime(2026, 8, 28, 13, 55, 32, tzinfo=UTC),
)

# The same exact final DFU/FIT receives a distinct QSPI authorization only
# after all five USB-attached radios passed RAM boot, RX0/RX1 abrupt-client
# recovery, final-safe checks, and the designated USB/IP maximum-burst matrix.
# Keeping the RAM identity separate prevents diagnostic selection from writing.
DDR_BURST_V1_RELEASE_PERSISTENT_POLICY = DDR_BURST_V1_RELEASE_RAM_POLICY.model_copy(
    update={
        "profile_id": "ddr-burst-v1-release-persistent-promotion",
        "hardware_qualified": True,
    }
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
    phy_supported = phy_model in SUPPORTED_AD936X_PHY_MODELS
    findings.append(
        _comparison(
            "rf.phy_model",
            phy_supported,
            "RF PHY identifies as a supported AD936x"
            if phy_supported
            else "RF PHY is not a supported AD936x",
            phy_model,
            SUPPORTED_AD936X_PHY_MODELS,
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
