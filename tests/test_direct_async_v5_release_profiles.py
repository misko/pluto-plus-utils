from __future__ import annotations

from pluto_plus import bootstrap_firmware, doctor
from pluto_plus.diagnostic_profiles import (
    IQ_DIRECT_ASYNC_V5_RELEASE_PROFILE,
    select_diagnostic_profile,
)


def test_v5_release_identity_and_persistent_authority_are_exact() -> None:
    ram = doctor.IQ_DIRECT_ASYNC_V5_RELEASE_RAM_POLICY
    persistent = doctor.IQ_DIRECT_ASYNC_V5_RELEASE_PERSISTENT_POLICY

    assert ram.source_commit == "b72773dd191a3df1d717886ac100d0dcbf3403e2"
    assert ram.asset_sha256 == (
        "feea70f42b104698dc2ca1b0abcc8e836bf86f25ba21c24bd92741f5cb6f5ace"
    )
    assert ram.fit_body_sha256 == (
        "d86df7226fd10fdebb7cc1166c264077e39698fcf3e33e57705e8eca7913bc38"
    )
    assert ram.fit_body_size == 12_829_587
    assert ram.hardware_qualified is False
    assert persistent.hardware_qualified is True
    assert doctor.PERSISTENT_UPGRADE_POLICY is persistent
    assert persistent in doctor.SETUP_REPAIR_POLICIES
    assert ram in doctor.SETUP_INSPECTION_POLICIES


def test_v5_profiles_require_the_decimal_peer_limit() -> None:
    for profile_id, persistent_allowed in (
        ("iq-direct-async-v5-candidate-ram", False),
        ("iq-direct-async-v5-release-ram", False),
        ("iq-direct-async-v5-release-persistent-promotion", True),
    ):
        profile = bootstrap_firmware.STANDALONE_FLASH_PROFILES[profile_id]
        assert profile.persistent_allowed is persistent_allowed
        assert ("iio,buffer-direct-async-max-frames", "8192") in (
            profile.required_iio_capabilities
        )


def test_v5_is_the_newest_diagnostic_release() -> None:
    selected = select_diagnostic_profile("v0.51-plutoplus-spf-iq-direct-async-v5")

    assert selected is IQ_DIRECT_ASYNC_V5_RELEASE_PROFILE
    assert selected.release_rank == 38
