"""Exact artifact and topology boundaries for v0.50 installation."""

import pytest

from pluto_plus import bootstrap_firmware as flash
from pluto_plus import doctor
from pluto_plus.diagnostic_profiles import select_diagnostic_profile


@pytest.mark.parametrize("single", [False, True])
@pytest.mark.parametrize("persistent", [False, True])
def test_counter_release_preserves_exact_artifact_and_mode_gates(single, persistent):
    policy = (
        doctor.COUNTER_RX_V1_1R1T_PERSISTENT_POLICY
        if persistent and single
        else doctor.COUNTER_RX_V1_1R1T_RAM_POLICY
        if single
        else doctor.COUNTER_RX_V1_RELEASE_PERSISTENT_POLICY
        if persistent
        else doctor.COUNTER_RX_V1_RELEASE_RAM_POLICY
    )
    profile = flash.STANDALONE_FLASH_PROFILES[policy.profile_id]
    baseline = flash.STANDALONE_FLASH_PROFILES[
        doctor.IQ_DIRECT_ASYNC_V4_RELEASE_PERSISTENT_POLICY.profile_id
    ]
    assert policy.asset_sha256 == "435a26369018e86ee66262b79c32895dbaaacef510a1efb71c566d6409555344"
    assert (
        policy.fit_body_sha256 == "a53efc46f3c65d1a15e5063374551d2daa3cb9d0df51257de53b6af80be39493"
    )
    assert policy.fit_body_size == 12829435
    assert policy.source_commit == "619ecedf23a3fd2103e1237d69db830e26d8959c"
    assert policy.hardware_qualified is persistent and profile.persistent_allowed is persistent
    layout = flash.SINGLE_RX_TX_CAPABLE_LAYOUT if single else flash.PAIRED_RX_TX_CAPABLE_LAYOUT
    assert profile.source_iio_layout == profile.return_iio_layout == layout
    caps = dict(profile.required_iio_capabilities)
    assert caps["iio,buffer-counter-metadata"] == "1"
    assert caps["iio,buffer-counter-metadata-topology-supported"] == ("1" if single else "0")
    assert set(baseline.required_iio_capabilities) <= set(profile.required_iio_capabilities)
    assert profile.ddr_burst_max_iq_bytes == baseline.ddr_burst_max_iq_bytes
    assert profile.ddr_ring_max_iq_bytes == baseline.ddr_ring_max_iq_bytes
    assert profile.iiod_rw_cpu_affinity == baseline.iiod_rw_cpu_affinity


def test_counter_release_is_known_without_version_prefix_inference():
    policy = doctor.COUNTER_RX_V1_RELEASE_PERSISTENT_POLICY
    assert doctor.PERSISTENT_UPGRADE_POLICY is policy
    assert doctor.require_setup_repair_policy(policy) is policy
    assert doctor.setup_repair_policy_for_firmware(policy.device_firmware) is policy
    assert doctor.setup_inspection_policy_for_firmware(policy.device_firmware) is policy
    assert doctor.IQ_DIRECT_ASYNC_V4_RELEASE_PERSISTENT_POLICY in doctor.SETUP_REPAIR_POLICIES
    profile = select_diagnostic_profile(policy.device_firmware)
    assert profile is not None and profile.metadata_abis == (3,)
    assert select_diagnostic_profile(policy.device_firmware + "-unreviewed") is None


@pytest.mark.parametrize(
    ("profile_id", "asset_sha256", "fit_sha256", "fit_size"),
    [
        (
            "feature-103-rc10-parent-ram",
            "435a26369018e86ee66262b79c32895dbaaacef510a1efb71c566d6409555344",
            "a53efc46f3c65d1a15e5063374551d2daa3cb9d0df51257de53b6af80be39493",
            12_829_435,
        ),
        (
            "feature-103-rc10-repack-ram",
            "42353c6d25d0dfa1692e2ef05c43736ebf7c2342b93bc1316a48a8d05bf6b769",
            "aed5b10e692bc683e04ef9c5d9cde0442f6bd5af4250cbdd7e52969eb5b54e42",
            12_828_795,
        ),
        (
            "feature-103-rc10-kernel-ram",
            "407bcf54c77a2237bde68b0b184674c6376ea8b29cc503ce1a5647dd1edfc50a",
            "79caea519d6f67f0b5521f45641c61956b20b86f9d003490a815f14cabd44518",
            12_831_827,
        ),
        (
            "feature-103-rc10-rx0-ram",
            "3b7ee6b229c64227d569a15744aedf7a50b549f36f328f4707c69df6a02e8477",
            "7ec535917eabffbd4b5689eda053e258d042e1c76325d31a0850c89ec2dc067d",
            12_832_079,
        ),
        (
            "feature-103-rc10-full-ram",
            "cdd25fcb2fa422d515500f0f144bae0c1d543405e1a0bdbd687b6a939950074a",
            "95760da77b70cefaf1ee9bb0d43c2d012846893f8edee8f50645c39c3c4daf5f",
            13_185_287,
        ),
    ],
)
def test_feature_103_candidate_is_exactly_ram_only(
    profile_id, asset_sha256, fit_sha256, fit_size
):
    profile = flash.STANDALONE_FLASH_PROFILES[profile_id]

    assert profile.persistent_allowed is False
    assert profile.policy.hardware_qualified is False
    assert profile.policy.asset_sha256 == asset_sha256
    assert profile.policy.fit_body_sha256 == fit_sha256
    assert profile.policy.fit_body_size == fit_size
    if profile_id not in {"feature-103-rc10-parent-ram", "feature-103-rc10-repack-ram"}:
        assert ("iio,adaptive-scan", "1") in profile.required_iio_capabilities
    if profile_id != "feature-103-rc10-parent-ram":
        assert not any(
            candidate.policy.asset_sha256 == profile.policy.asset_sha256
            and candidate.persistent_allowed
            for candidate in flash.STANDALONE_FLASH_PROFILES.values()
        )


@pytest.mark.parametrize("profile_id", ["feature-103-rc10-rx0-ram", "feature-103-rc10-full-ram"])
def test_feature_103_rx0_candidates_attest_physical_rx0_topology(profile_id: str) -> None:
    profile = flash.STANDALONE_FLASH_PROFILES[profile_id]
    capabilities = dict(profile.required_iio_capabilities)

    assert profile.source_iio_layout == flash.SINGLE_RX_TX_CAPABLE_LAYOUT
    assert profile.return_iio_layout == flash.SINGLE_RX_TX_CAPABLE_LAYOUT
    assert capabilities["iio,buffer-counter-metadata-topology-supported"] == "1"


def test_feature_103_rc1_through_rc9_are_quarantined() -> None:
    for revision in range(1, 10):
        assert f"feature-103-rc{revision}-ram" not in flash.STANDALONE_FLASH_PROFILES
