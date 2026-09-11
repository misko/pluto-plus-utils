from dataclasses import replace

import pytest

from pluto_plus import bootstrap_firmware as b


def test_restore_keeps_exact_qualified_target_and_return_checks():
    standard = b.STANDALONE_FLASH_PROFILES["iq-direct-async-v4-release-persistent-promotion"]
    restore = b.STANDALONE_FLASH_PROFILES["iq-direct-async-v4-from-glrt-stripped-restore"]
    assert (
        replace(
            restore,
            policy=standard.policy,
            source_iio_layout=standard.source_iio_layout,
            allowed_before_firmwares=(),
        )
        == standard
    )
    assert restore.policy.model_dump(exclude={"profile_id"}) == standard.policy.model_dump(
        exclude={"profile_id"}
    )
    assert (
        restore.policy.asset_sha256
        == "f45524f4765d5743144703ff6f4541084ff1ab9b1ce20a77f3f6fa820a1f84b6"
    )
    b._require_allowed_before_firmware("glrt-native-exact-r60000000-stripped-v1", restore)
    with pytest.raises(b.BootstrapFirmwareError, match="source firmware"):
        b._require_allowed_before_firmware("some-other-rx-only-image", restore)


def test_source_layout_requires_glrt_and_rejects_rx_scan_or_tx_core():
    facts = {
        "device_names": ("ad9361-phy", "cf-ad9361-lpc", "starlink-glrt-iq"),
        "cf-ad9361-lpc,scan_channels": (),
    }

    def check(f):
        b._require_iio_layout_shape(
            f, b.GLRT_STRIPPED_RX_ONLY_LAYOUT, expected_tandem=False, transport="source"
        )

    check(facts)
    for changed in (
        {"device_names": ("ad9361-phy", "cf-ad9361-lpc")},
        {"device_names": (*facts["device_names"], "cf-ad9361-dds-core-lpc")},
        {"device_names": (*facts["device_names"], "tandem-agc")},
        {"cf-ad9361-lpc,scan_channels": ("voltage0", "voltage1")},
    ):
        with pytest.raises(b.BootstrapFirmwareError):
            check(facts | changed)


@pytest.mark.parametrize(
    "key,value",
    [
        ("all_buffer_enable", "1"),
        ("tx_hardwaregain_db", "-20"),
        ("tx_lo_powerdown", "0"),
        ("dds_present", "1"),
        ("root_marker_present", "0"),
        ("rx_dma_dt_state", "disabled"),
        ("tx_dma_dt_state", "enabled"),
        ("tandem_dt_state", "enabled"),
    ],
)
def test_glrt_source_readback_retains_tx_and_buffer_guards(key, value):
    fields = {
        "tx_hardwaregain_db": "-80",
        "tx_lo_powerdown": "1",
        "all_buffer_enable": "0",
        "tx_buffer_enable": "",
        "tx_scan_enable": "",
        "tx_dds_raw": "",
        "tx_dds_scale": "",
        "dds_present": "0",
        "tandem_present": "0",
        "root_marker_present": "1",
        "rx_dma_dt_state": "enabled",
        "dds_dt_state": "disabled",
        "tx_dma_dt_state": "disabled",
        "tandem_dt_state": "disabled",
    }
    b._require_remote_tx_safe(fields, b.GLRT_STRIPPED_RX_ONLY_LAYOUT)
    with pytest.raises(b.BootstrapFirmwareError, match="TX-safe"):
        b._require_remote_tx_safe(fields | {key: value}, b.GLRT_STRIPPED_RX_ONLY_LAYOUT)
