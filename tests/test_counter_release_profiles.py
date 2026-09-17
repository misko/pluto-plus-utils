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
    assert policy in doctor.SETUP_REPAIR_POLICIES
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
            "feature-103-rc12-parent-ram",
            "435a26369018e86ee66262b79c32895dbaaacef510a1efb71c566d6409555344",
            "a53efc46f3c65d1a15e5063374551d2daa3cb9d0df51257de53b6af80be39493",
            12_829_435,
        ),
        (
            "feature-103-rc12-repack-ram",
            "42353c6d25d0dfa1692e2ef05c43736ebf7c2342b93bc1316a48a8d05bf6b769",
            "aed5b10e692bc683e04ef9c5d9cde0442f6bd5af4250cbdd7e52969eb5b54e42",
            12_828_795,
        ),
        (
            "feature-103-rc12-kernel-ram",
            "407bcf54c77a2237bde68b0b184674c6376ea8b29cc503ce1a5647dd1edfc50a",
            "79caea519d6f67f0b5521f45641c61956b20b86f9d003490a815f14cabd44518",
            12_831_827,
        ),
        (
            "feature-103-rc12-rx0-ram",
            "3b7ee6b229c64227d569a15744aedf7a50b549f36f328f4707c69df6a02e8477",
            "7ec535917eabffbd4b5689eda053e258d042e1c76325d31a0850c89ec2dc067d",
            12_832_079,
        ),
        (
            "feature-103-rc12-full-ram",
            "9f401b3b1309db28d67e6b5380e6872f310ed1e2c3d9f073ee6d8aad5ac9fa05",
            "71b397ae007013b3b8ac6a017a4897f617e7db8be097708f61ff6aa0b15feac7",
            13_187_283,
        ),
        (
            "feature-103-rc13-full-ram",
            "1554cc43e2af0efe494eae570140adb57a2162b3cc7aa531e6f00dd9ca9b23f2",
            "a836a026f9e49572805c402ce24886b88beb23dbf12bbad5e7a1cb921f253c25",
            13_187_271,
        ),
        (
            "feature-103-rc14-full-ram",
            "99ae82e5e6a5eb4f02394463112e9d41fd90ff8343cbfbf95a4ec15e97853db1",
            "26db9c700ad5b2cf01a3a9fc841f847bc0d06f7a1660cbbd3f181dcc4bdf048e",
            13_200_115,
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
    if profile_id not in {"feature-103-rc12-parent-ram", "feature-103-rc12-repack-ram"}:
        assert ("iio,adaptive-scan", "1") in profile.required_iio_capabilities
    if profile_id != "feature-103-rc12-parent-ram":
        assert not any(
            candidate.policy.asset_sha256 == profile.policy.asset_sha256
            and candidate.persistent_allowed
            for candidate in flash.STANDALONE_FLASH_PROFILES.values()
        )


@pytest.mark.parametrize(
    "profile_id",
    [
        "feature-103-rc12-rx0-ram",
        "feature-103-rc12-full-ram",
        "feature-103-rc13-full-ram",
        "feature-103-rc14-full-ram",
    ],
)
def test_feature_103_rx0_candidates_attest_physical_rx0_topology(profile_id: str) -> None:
    profile = flash.STANDALONE_FLASH_PROFILES[profile_id]
    capabilities = dict(profile.required_iio_capabilities)

    assert profile.source_iio_layout == flash.SINGLE_RX_TX_CAPABLE_LAYOUT
    assert profile.return_iio_layout == flash.SINGLE_RX_TX_CAPABLE_LAYOUT
    assert capabilities["iio,buffer-counter-metadata-topology-supported"] == "1"


def test_feature_103_rc1_through_rc11_are_quarantined() -> None:
    for revision in range(1, 12):
        assert f"feature-103-rc{revision}-ram" not in flash.STANDALONE_FLASH_PROFILES
