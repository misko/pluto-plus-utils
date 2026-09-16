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
