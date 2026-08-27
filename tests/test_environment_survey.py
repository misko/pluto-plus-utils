from __future__ import annotations

import hashlib
import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from pydantic import ValidationError

import pluto_plus.environment_survey as survey
from pluto_plus.environment_survey import (
    ADC_CLIP_THRESHOLD,
    ADC_FULL_SCALE,
    ANCHOR_CENTER_FREQUENCY_HZ,
    AUTHORIZING_BASELINE_FREQUENCIES_HZ,
    CAPTURE_PAYLOAD_BYTES,
    FAILURE_RESERVE_BYTES,
    FFT_SIZE,
    MANIFEST_ALLOWANCE_BYTES,
    MINIMUM_FREE_SPACE_BYTES,
    RAW_BYTES_PER_WINDOW,
    RAW_PAYLOAD_BYTES,
    RESERVED_SURVEY_SERIALS,
    SAMPLE_RATE_HZ,
    SAMPLES_PER_WINDOW,
    SPECTRAL_BYTES_PER_WINDOW,
    SPECTRAL_PAYLOAD_BYTES,
    STFT_FRAMES_PER_WINDOW,
    SURVEY_CENTER_FREQUENCIES_HZ,
    TOTAL_RETAINED_WINDOWS,
    EnvironmentSurveyEmitterInventory,
    EnvironmentSurveyError,
    EnvironmentSurveyExecutionError,
    EnvironmentSurveyManifest,
    EnvironmentSurveyParameters,
    EnvironmentSurveyPlan,
    EnvironmentSurveyReceipt,
    SurveyArtifactFile,
    SurveyArtifactIdentity,
    SurveyCenterEvidence,
    SurveyCleanup,
    SurveyEmitter,
    SurveyFrequencySpan,
    SurveyRuntimeIdentity,
    SurveyRxSettingsReadback,
    SurveyTemperatureReadback,
    SurveyWindowEvidence,
    TxStateObservation,
    build_environment_survey_fleet_selection,
    deterministic_spectrum,
    execute_environment_survey,
    make_tx_state_observation,
    prepare_environment_survey,
    verify_environment_survey_receipt,
)
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import GainMode, RadioSettings
from pluto_plus.release_candidate import load_private_contract, write_private_contract
from pluto_plus.release_candidate_linux import ToolSourceAttestation

SERIAL = "winbond-db6968136727402c"
TOPOLOGY = "3-7"
NOW = datetime(2026, 8, 27, 1, 0, tzinfo=UTC)
SOURCE = ToolSourceAttestation(repository="misko/pluto-plus-utils", commit="2" * 40)
VERSION = "0.1.0"
AP_START_HZ = 2_427_000_000
AP_STOP_HZ = 2_447_000_000


def _parameters() -> EnvironmentSurveyParameters:
    return EnvironmentSurveyParameters(
        occupied_2_4_spans_hz=(SurveyFrequencySpan(start_hz=AP_START_HZ, stop_hz=AP_STOP_HZ),),
    )


def _inventory() -> EnvironmentSurveyEmitterInventory:
    return EnvironmentSurveyEmitterInventory(
        schema="pluto-plus-utils.environment-survey-emitter-inventory.v1",
        state="worst-normal",
        emitters=(
            SurveyEmitter(
                emitter_id="internal-ap-24",
                band="2.4-ghz",
                channel="6",
                center_hz=2_437_000_000,
                occupied_start_hz=AP_START_HZ,
                occupied_stop_hz=AP_STOP_HZ,
                channel_width_hz=20_000_000,
                power_setting="normal",
                traffic_state="worst-normal",
            ),
            SurveyEmitter(
                emitter_id="internal-ap-5",
                band="5-ghz",
                channel="149",
                center_hz=5_745_000_000,
                occupied_start_hz=5_735_000_000,
                occupied_stop_hz=5_755_000_000,
                channel_width_hz=20_000_000,
                power_setting="normal",
                traffic_state="worst-normal",
            ),
        ),
    )


def _local(*, device_number: int = 29, serial: str = SERIAL) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=f"/sys/bus/usb/devices/{TOPOLOGY}",
        bus_number=3,
        device_number=device_number,
        product="PlutoSDR+",
        serial=serial,
        speed_mbps=480.0,
        interface_count=7,
    )


def _plan(tmp_path: Path) -> tuple[EnvironmentSurveyPlan, Path]:
    tmp_path.chmod(0o700)
    result_root = tmp_path / "results"
    result_root.mkdir(mode=0o700)
    plan_root = tmp_path / "plans"
    plan_root.mkdir(mode=0o700)
    inventory = _inventory()
    inventory_path = (plan_root / "emitter-inventory.json").absolute()
    inventory_identity = write_private_contract(inventory_path, inventory)
    plan = prepare_environment_survey(
        (_local(),),
        serial=SERIAL,
        usb_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
        output_root=result_root.absolute(),
        emitter_inventory_file=inventory_identity,
        emitter_inventory=inventory,
        parameters=_parameters(),
        tool_source=SOURCE,
        tool_version=VERSION,
        survey_id="1" * 32,
        created_at=NOW,
    )
    path = (plan_root / "plan.json").absolute()
    write_private_contract(path, plan)
    return plan, path


def _safe_state(*, observed_at: datetime = NOW) -> TxStateObservation:
    return make_tx_state_observation(
        observed_at=observed_at,
        tx_gain_db=(-80.0, -80.0),
        tx_buffer_enabled=False,
        tx_data_available=0,
        tx_scan_enabled=(False, False, False, False),
        dds_raw=(0,) * 8,
        dds_scale=(0.0,) * 8,
        dac_selectors=(3, 3, 3, 3),
        tandem_state=0,
        fifo_level=0,
        fault_flags=0,
        overflow_count=0,
    )


def _unsafe_state() -> TxStateObservation:
    return make_tx_state_observation(
        observed_at=NOW,
        tx_gain_db=(-10.0, -20.0),
        tx_buffer_enabled=True,
        tx_data_available=8,
        tx_scan_enabled=(True, False, False, False),
        dds_raw=(1,) + (0,) * 7,
        dds_scale=(0.5,) + (0.0,) * 7,
        dac_selectors=(0, 3, 3, 3),
        tandem_state=1,
        fifo_level=1,
        fault_flags=1,
        overflow_count=1,
    )


def _identity(path: str, byte_count: int) -> SurveyArtifactIdentity:
    return SurveyArtifactIdentity(relative_path=Path(path), bytes=byte_count, sha256="0" * 64)


def _artifact(kind: str, relative_root: Path) -> SurveyArtifactFile:
    if kind == "raw":
        return SurveyArtifactFile(
            identity=_identity(str(relative_root / "raw.ci16"), RAW_BYTES_PER_WINDOW),
            dtype="ci16_le",
            shape=(SAMPLES_PER_WINDOW, 2, 2),
        )
    if kind == "psd":
        return SurveyArtifactFile(
            identity=_identity(
                str(relative_root / "psd-density-dbfs-per-hz.f32le"), 2 * FFT_SIZE * 4
            ),
            dtype="float32_le",
            shape=(2, FFT_SIZE),
        )
    return SurveyArtifactFile(
        identity=_identity(
            str(relative_root / "stft-density-dbfs-per-hz.f32le"),
            2 * STFT_FRAMES_PER_WINDOW * FFT_SIZE * 4,
        ),
        dtype="float32_le",
        shape=(2, STFT_FRAMES_PER_WINDOW, FFT_SIZE),
    )


def _window(
    index: int,
    power: tuple[float, float],
    *,
    clips: tuple[int, int] = (0, 0),
    burst: tuple[bool, bool] = (False, False),
    relative_root: Path | None = None,
) -> SurveyWindowEvidence:
    root = relative_root or Path("test") / f"window-{index:03d}"
    linear = tuple(10.0 ** (value / 10.0) for value in power)
    return SurveyWindowEvidence(
        window_index=index,
        utc_ns=1_000_000_000 + index,
        raw_ci16=_artifact("raw", root),
        psd_density_dbfs_per_hz=_artifact("psd", root),
        stft_density_dbfs_per_hz=_artifact("stft", root),
        receiver_integrated_power_fs=linear,
        receiver_integrated_power_dbfs=power,
        receiver_clip_count=clips,
        receiver_burst=burst,
    )


def _center(
    role: str,
    center_index: int | None,
    frequency_hz: int,
    *,
    power_dbfs: float = -60.0,
    clips: tuple[int, int] = (0, 0),
) -> SurveyCenterEvidence:
    if role == "sweep":
        assert center_index is not None
        base = Path("sweep") / f"{center_index:03d}-{frequency_hz}"
    elif role == "authorizing_baseline":
        assert center_index is not None
        base = Path("baselines") / f"{center_index:03d}-{frequency_hz}"
    else:
        base = Path("anchors") / ("pre" if role == "pre_sweep_anchor" else "post")
    windows = tuple(
        _window(
            index,
            (power_dbfs, power_dbfs - 1.0),
            clips=clips,
            relative_root=base / f"window-{index:03d}",
        )
        for index in range(32)
    )
    p50_linear, p95_linear, p99_linear, p50, p95, p99, clip_count, occupancy, bursts = (
        survey._summarize_windows(windows)
    )
    corrected = tuple(
        window.model_copy(update={"receiver_burst": bursts[index]})
        for index, window in enumerate(windows)
    )
    settings = RadioSettings(
        center_frequency_hz=float(frequency_hz),
        sample_rate_hz=2_500_000.0,
        bandwidth_hz=1_500_000.0,
        gain_db=40.0,
        channels=(0, 1),
    )
    readback = SurveyRxSettingsReadback(
        center_frequency_hz=float(frequency_hz),
        sample_rate_hz=2_500_000.0,
        rf_bandwidth_hz=1_500_000.0,
        receiver_channels=(0, 1),
        receiver_gain_modes=(GainMode.MANUAL, GainMode.MANUAL),
        receiver_gain_db=(40.0, 40.0),
        sample_rate_source_channels=(0, 1),
        sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
        rf_bandwidth_source_channels=(0, 1),
        rf_bandwidth_source_values_hz=(1_500_000.0, 1_500_000.0),
    )
    temperature = SurveyTemperatureReadback(millidegrees_c=44_000)
    return SurveyCenterEvidence(
        capture_role=role,
        center_index=center_index,
        center_frequency_hz=frequency_hz,
        requested_settings=settings,
        actual_settings=readback,
        pre_capture_temperature=temperature,
        post_capture_settings=readback,
        post_capture_temperature=temperature,
        windows=corrected,
        receiver_p50_power_fs=p50_linear,
        receiver_p95_power_fs=p95_linear,
        receiver_p99_power_fs=p99_linear,
        receiver_p50_dbfs=p50,
        receiver_p95_dbfs=p95,
        receiver_p99_dbfs=p99,
        receiver_clip_count=clip_count,
        receiver_burst_occupancy=occupancy,
        worst_rx_p99_dbfs=max(p99),
        worst_rx_burst_occupancy=max(occupancy),
    )


class FakeSurveySession:
    def __init__(self, *, cleanup_failure: bool = False) -> None:
        self.calls: list[str] = []
        self.cleanup_failure = cleanup_failure
        self.original = SurveyRxSettingsReadback(
            center_frequency_hz=915_000_000.0,
            sample_rate_hz=2_500_000.0,
            rf_bandwidth_hz=2_500_000.0,
            receiver_channels=(0, 1),
            receiver_gain_modes=(GainMode.MANUAL, GainMode.MANUAL),
            receiver_gain_db=(39.9, 40.1),
            sample_rate_source_channels=(0, 1),
            sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
            rf_bandwidth_source_channels=(0, 1),
            rf_bandwidth_source_values_hz=(2_500_000.0, 2_500_000.0),
        )
        self.runtime = SurveyRuntimeIdentity(
            serial=SERIAL,
            usb_uri="usb:3.29.5",
            usb_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
            hardware_model="Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            firmware_version="v-survey-test",
            metadata_abi="frame-metadata-v2",
        )

    def observe_tx_state(self) -> TxStateObservation:
        self.calls.append("observe_pre")
        return _unsafe_state()

    def ensure_tx_safe(self) -> TxStateObservation:
        self.calls.append("ensure_mute")
        if self.cleanup_failure and self.calls.count("ensure_mute") >= 2:
            raise RuntimeError("planted cleanup mute failure")
        return _safe_state()

    def open_rx(self) -> TxStateObservation:
        self.calls.append("open_rx")
        return _safe_state()

    def read_rx_settings(self) -> SurveyRxSettingsReadback:
        self.calls.append("read_rx_settings")
        return self.original

    def apply_rx_settings(self, settings: RadioSettings) -> RadioSettings:
        raise AssertionError("capture was expected to be stubbed")

    def read_rx_block(self, sample_count: int) -> Any:
        raise AssertionError("capture was expected to be stubbed")

    def read_temperature(self) -> SurveyTemperatureReadback:
        return SurveyTemperatureReadback(millidegrees_c=44_000)

    def reset_rx_buffer(self) -> None:
        self.calls.append("reset_rx")

    def restore_rx_settings(self, settings: SurveyRxSettingsReadback) -> SurveyRxSettingsReadback:
        self.calls.append("restore_rx")
        return settings


class FakeSurveyBackend:
    def __init__(self, session: FakeSurveySession) -> None:
        self.session = session
        self.calls: list[str] = []

    @contextmanager
    def locked_session(self, target: Any) -> Iterator[FakeSurveySession]:
        assert target.serial == SERIAL
        self.calls.append("lock")
        try:
            yield self.session
        finally:
            self.calls.append("unlock")


class FailingReleaseBackend(FakeSurveyBackend):
    @contextmanager
    def locked_session(self, target: Any) -> Iterator[FakeSurveySession]:
        assert target.serial == SERIAL
        self.calls.append("lock")
        yield self.session
        self.calls.append("unlock")
        raise RuntimeError("planted session release failure")


def _stub_capture(
    _session: Any,
    _plan: EnvironmentSurveyPlan,
    _partial: Path,
    *,
    capture_role: str,
    center_index: int | None,
    center_frequency_hz: int,
) -> SurveyCenterEvidence:
    power = -70.0 if capture_role != "sweep" else -80.0 + (center_index or 0) / 10
    return _center(capture_role, center_index, center_frequency_hz, power_dbfs=power)


def test_frozen_grid_analysis_and_storage_contract() -> None:
    parameters = _parameters()

    assert tuple(range(2_400_000_000, 2_490_000_001, 1_000_000)) == SURVEY_CENTER_FREQUENCIES_HZ
    assert len(SURVEY_CENTER_FREQUENCIES_HZ) == 91
    assert parameters.anchor_center_frequency_hz == 2_445_000_000
    assert parameters.windows_per_center == parameters.anchor_windows == 32
    assert parameters.samples_per_window == 65_536
    assert parameters.stft_frames_per_window == 31
    assert parameters.authorizing_baseline_frequencies_hz == AUTHORIZING_BASELINE_FREQUENCIES_HZ
    assert TOTAL_RETAINED_WINDOWS == 3_104
    assert RAW_PAYLOAD_BYTES == 1_627_389_952
    assert SPECTRAL_PAYLOAD_BYTES == 3_254_779_904
    assert CAPTURE_PAYLOAD_BYTES == 4_882_169_856
    assert parameters.failure_reserve_bytes == FAILURE_RESERVE_BYTES == 67_108_864
    assert parameters.manifest_allowance_bytes == MANIFEST_ALLOWANCE_BYTES == 419_430_400
    assert MINIMUM_FREE_SPACE_BYTES == 5_368_709_120
    assert RAW_BYTES_PER_WINDOW == 524_288
    assert SPECTRAL_BYTES_PER_WINDOW == 1_048_576
    assert parameters.adc_full_scale == ADC_FULL_SCALE == 2_048.0
    assert parameters.adc_clip_threshold == ADC_CLIP_THRESHOLD == 2_047
    assert RESERVED_SURVEY_SERIALS == (
        "winbond-db6968136727402c",
        "1040007c4a94000211000b009186843ef2",
        "winbond-db620818a328172c",
        "104000bac4950008230026001b440a003a",
    )


def test_remaining_space_preserves_manifest_allowance_at_every_center(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    required = RAW_BYTES_PER_WINDOW + FAILURE_RESERVE_BYTES + MANIFEST_ALLOWANCE_BYTES
    monkeypatch.setattr(survey, "_available_free_space_bytes", lambda _path: required)
    survey._require_remaining_capture_space(
        tmp_path,
        remaining_payload_bytes=RAW_BYTES_PER_WINDOW,
        failure_reserve_bytes=FAILURE_RESERVE_BYTES,
        manifest_allowance_bytes=MANIFEST_ALLOWANCE_BYTES,
    )
    monkeypatch.setattr(survey, "_available_free_space_bytes", lambda _path: required - 1)
    with pytest.raises(EnvironmentSurveyError, match="manifest allowance"):
        survey._require_remaining_capture_space(
            tmp_path,
            remaining_payload_bytes=RAW_BYTES_PER_WINDOW,
            failure_reserve_bytes=FAILURE_RESERVE_BYTES,
            manifest_allowance_bytes=MANIFEST_ALLOWANCE_BYTES,
        )


def test_unknown_tx_buffer_data_or_scan_state_is_rejected() -> None:
    values = _safe_state().model_dump(exclude={"safe"})
    for field in ("tx_buffer_enabled", "tx_data_available", "tx_scan_enabled"):
        with pytest.raises(EnvironmentSurveyError, match="affirmative"):
            make_tx_state_observation(**{**values, field: None})


def test_ap_exclusion_uses_closed_candidate_and_expanded_ap_intervals() -> None:
    touching = EnvironmentSurveyParameters(
        occupied_2_4_spans_hz=(SurveyFrequencySpan(start_hz=2_401_500_000, stop_hz=2_402_000_000),),
    )
    separated_by_one_hz = EnvironmentSurveyParameters(
        occupied_2_4_spans_hz=(SurveyFrequencySpan(start_hz=2_401_500_001, stop_hz=2_402_000_000),),
    )

    assert 2_400_000_000 not in touching.control_candidates_hz
    assert 2_400_000_000 in separated_by_one_hz.control_candidates_hz
    assert all(value % 1_000_000 == 0 for value in touching.control_candidates_hz)
    with pytest.raises(ValidationError, match="strictly below"):
        EnvironmentSurveyParameters(
            occupied_2_4_spans_hz=(
                SurveyFrequencySpan(start_hz=2_440_000_000, stop_hz=2_440_000_000),
            ),
        )


def test_emitter_inventory_is_canonical_and_rejects_touching_closed_spans() -> None:
    first = _inventory().emitters[0]
    touching = SurveyEmitter(
        emitter_id="second-ap",
        band="2.4-ghz",
        channel="11",
        center_hz=2_457_000_000,
        occupied_start_hz=first.occupied_stop_hz,
        occupied_stop_hz=2_467_000_000,
        channel_width_hz=20_000_000,
        power_setting="normal",
        traffic_state="worst-normal",
    )
    with pytest.raises(ValidationError, match="must not touch or overlap"):
        EnvironmentSurveyEmitterInventory(
            schema="pluto-plus-utils.environment-survey-emitter-inventory.v1",
            state="worst-normal",
            emitters=(first, touching),
        )
    with pytest.raises(ValidationError, match="sorted unique emitter IDs"):
        EnvironmentSurveyEmitterInventory(
            schema="pluto-plus-utils.environment-survey-emitter-inventory.v1",
            state="worst-normal",
            emitters=(touching.model_copy(update={"occupied_start_hz": 2_448_000_000}), first),
        )


def test_parameter_contract_rejects_tampered_grid_or_analysis_constant() -> None:
    document = _parameters().model_dump(mode="json")
    document["sample_rate_hz"] = 2_499_999
    with pytest.raises(ValidationError, match="constants are frozen"):
        EnvironmentSurveyParameters.model_validate(document)

    document = _parameters().model_dump(mode="json")
    document["center_frequencies_hz"][0] = 2_399_000_000
    with pytest.raises(ValidationError, match="exact frozen"):
        EnvironmentSurveyParameters.model_validate(document)


def test_plan_is_passive_exact_private_and_binds_explicit_mute(tmp_path: Path) -> None:
    plan, path = _plan(tmp_path)

    assert load_private_contract(path, EnvironmentSurveyPlan) == plan
    assert plan.hardware_accessed is False
    assert plan.pluto_tx_authorized is False
    assert plan.ensure_mute_authorized is True
    assert plan.target.usb_uri == "usb:3.29.5"
    assert plan.parameters.occupied_2_4_spans_hz[0].start_hz == AP_START_HZ
    assert path.stat().st_mode & 0o777 == 0o600


def test_plan_rejects_ambiguous_serial_and_wrong_path(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    with pytest.raises(EnvironmentSurveyError, match="found 2"):
        inventory = _inventory()
        inventory_path = tmp_path / "inventory.json"
        inventory_identity = write_private_contract(inventory_path, inventory)
        prepare_environment_survey(
            (_local(), _local()),
            serial=SERIAL,
            usb_path=Path(f"/sys/bus/usb/devices/{TOPOLOGY}"),
            output_root=tmp_path.absolute(),
            emitter_inventory_file=inventory_identity,
            emitter_inventory=inventory,
            parameters=_parameters(),
            tool_source=SOURCE,
            tool_version=VERSION,
        )
    with pytest.raises(EnvironmentSurveyError, match="differs"):
        prepare_environment_survey(
            (_local(),),
            serial=SERIAL,
            usb_path=Path("/sys/bus/usb/devices/3-8"),
            output_root=tmp_path.absolute(),
            emitter_inventory_file=inventory_identity,
            emitter_inventory=inventory,
            parameters=_parameters(),
            tool_source=SOURCE,
            tool_version=VERSION,
        )


def test_periodic_hann_density_integration_and_clip_threshold_are_exact() -> None:
    parameters = _parameters()
    sample_index = np.arange(SAMPLES_PER_WINDOW, dtype=np.float64)
    bin_frequency = 164 * SAMPLE_RATE_HZ / FFT_SIZE
    tone = 1_000 * np.exp(2j * np.pi * bin_frequency * sample_index / SAMPLE_RATE_HZ)
    encoded = np.zeros((SAMPLES_PER_WINDOW, 2, 2), dtype="<i2")
    encoded[:, 0, 0] = np.rint(tone.real).astype("<i2")
    encoded[:, 0, 1] = np.rint(tone.imag).astype("<i2")
    encoded[:, 1] = encoded[:, 0]
    encoded[0, 0, 0] = 2_046
    encoded[0, 1, 1] = -2_046

    products = deterministic_spectrum(encoded, parameters)

    assert products.psd_density_dbfs_per_hz.shape == (2, 4_096)
    assert products.stft_density_dbfs_per_hz.shape == (2, 31, 4_096)
    assert products.psd_density_dbfs_per_hz.dtype == np.dtype("<f4")
    expected_dbfs = 20 * np.log10(1_000 / 2_048)
    assert products.receiver_integrated_power_dbfs == pytest.approx(
        (expected_dbfs, expected_dbfs), abs=0.01
    )
    assert products.receiver_clip_count == (0, 0)

    encoded[0, 0, 0] = 2_047
    encoded[0, 1, 1] = -2_047
    clipped = deterministic_spectrum(encoded, parameters)
    assert clipped.receiver_clip_count == (1, 1)

    with pytest.raises(ValueError, match="strictly positive"):
        deterministic_spectrum(np.zeros_like(encoded), parameters)


def test_block_settings_gate_is_exact_and_gain_tolerance_is_inclusive() -> None:
    requested = RadioSettings(
        center_frequency_hz=2_400_000_000,
        sample_rate_hz=2_500_000,
        bandwidth_hz=1_500_000,
        gain_mode=GainMode.MANUAL,
        gain_db=40.0,
        channels=(0, 1),
    )
    boundary = SurveyRxSettingsReadback(
        center_frequency_hz=2_400_000_002,
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=1_500_000,
        receiver_channels=(0, 1),
        receiver_gain_modes=(GainMode.MANUAL, GainMode.MANUAL),
        receiver_gain_db=(39.74, 40.26),
        sample_rate_source_channels=(0, 1),
        sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
        rf_bandwidth_source_channels=(0, 1),
        rf_bandwidth_source_values_hz=(1_500_000.0, 1_500_000.0),
    )

    survey._validate_survey_readback(requested, boundary)
    for changed in (
        {"center_frequency_hz": 2_400_000_002.01},
        {"sample_rate_hz": 2_500_001},
        {"rf_bandwidth_hz": 1_499_999},
        {"receiver_gain_modes": (GainMode.MANUAL, GainMode.SLOW_ATTACK)},
        {"receiver_gain_db": (39.739, 40.0)},
    ):
        with pytest.raises(ValueError, match="differs from the fixed request"):
            survey._validate_survey_readback(requested, boundary.model_copy(update=changed))


def test_cleanup_restore_rejects_tolerated_capture_drift_but_ignores_agc_gain() -> None:
    original = SurveyRxSettingsReadback(
        center_frequency_hz=915_000_000,
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=2_500_000,
        receiver_channels=(0, 1),
        receiver_gain_modes=(GainMode.MANUAL, GainMode.SLOW_ATTACK),
        receiver_gain_db=(39.9, 12.0),
        sample_rate_source_channels=(0, 1),
        sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
        rf_bandwidth_source_channels=(0, 1),
        rf_bandwidth_source_values_hz=(2_500_000.0, 2_500_000.0),
    )

    assert not survey._rx_settings_restored(
        original, original.model_copy(update={"center_frequency_hz": 915_000_001})
    )
    assert not survey._rx_settings_restored(
        original, original.model_copy(update={"receiver_gain_db": (40.15, 12.0)})
    )
    assert survey._rx_settings_restored(
        original, original.model_copy(update={"receiver_gain_db": (39.9, 27.0)})
    )


@pytest.mark.parametrize("channels", [(0,), (1,)])
def test_original_rx_snapshot_accepts_each_single_channel(channels: tuple[int, ...]) -> None:
    readback = SurveyRxSettingsReadback(
        center_frequency_hz=915_000_000,
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=2_500_000,
        receiver_channels=channels,
        receiver_gain_modes=(GainMode.MANUAL,),
        receiver_gain_db=(39.9,),
        sample_rate_source_channels=(0, 1),
        sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
        rf_bandwidth_source_channels=(0, 1),
        rf_bandwidth_source_values_hz=(2_500_000.0, 2_500_000.0),
    )

    assert readback.receiver_channels == channels


def test_capture_reads_settings_only_after_configure_and_after_last_window(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _ = _plan(tmp_path)
    events: list[str] = []
    readback = SurveyRxSettingsReadback(
        center_frequency_hz=SURVEY_CENTER_FREQUENCIES_HZ[0],
        sample_rate_hz=2_500_000,
        rf_bandwidth_hz=1_500_000,
        receiver_channels=(0, 1),
        receiver_gain_modes=(GainMode.MANUAL, GainMode.MANUAL),
        receiver_gain_db=(40.0, 40.0),
        sample_rate_source_channels=(0, 1),
        sample_rate_source_values_hz=(2_500_000.0, 2_500_000.0),
        rf_bandwidth_source_channels=(0, 1),
        rf_bandwidth_source_values_hz=(1_500_000.0, 1_500_000.0),
    )

    class CadenceSession:
        def apply_rx_settings(self, _settings: RadioSettings) -> SurveyRxSettingsReadback:
            events.append("configure_readback")
            return readback

        def read_rx_block(self, sample_count: int) -> SampleBlock:
            assert sample_count == SAMPLES_PER_WINDOW
            events.append("buffer")
            return SampleBlock(
                utc_ns=1,
                samples=np.zeros((2, SAMPLES_PER_WINDOW), dtype=np.complex64),
            )

        def read_survey_rx_settings(self) -> SurveyRxSettingsReadback:
            events.append("post_readback")
            return readback

        def read_temperature(self) -> SurveyTemperatureReadback:
            events.append("temperature")
            return SurveyTemperatureReadback(millidegrees_c=44_000)

    def retain(
        _block: SampleBlock,
        _plan_value: EnvironmentSurveyPlan,
        _partial: Path,
        *,
        capture_role: str,
        center_index: int | None,
        center_frequency_hz: int,
        window_index: int,
    ) -> survey._RetainedWindow:
        assert capture_role == "sweep"
        assert center_index == 0
        base = Path("sweep") / f"000-{center_frequency_hz}" / f"window-{window_index:03d}"
        survey._make_private_tree(_partial, base)
        return survey._RetainedWindow(
            window_index=window_index,
            utc_ns=1_000_000 + window_index,
            raw_ci16=_artifact("raw", base),
            psd_density_dbfs_per_hz=_artifact("psd", base),
            stft_density_dbfs_per_hz=_artifact("stft", base),
            receiver_integrated_power_fs=(1e-6, 1e-6),
            receiver_integrated_power_dbfs=(-60.0, -60.0),
            receiver_clip_count=(0, 0),
        )

    monkeypatch.setattr(survey, "_retain_window", retain)
    center = survey._capture_center(
        CadenceSession(),
        plan,
        tmp_path,
        capture_role="sweep",
        center_index=0,
        center_frequency_hz=SURVEY_CENTER_FREQUENCIES_HZ[0],
    )

    assert events == [
        "configure_readback",
        "temperature",
        *("buffer" for _ in range(34)),
        "post_readback",
        "temperature",
    ]
    assert center.actual_settings == readback
    assert center.post_capture_settings == readback


def test_center_failure_removes_all_unpublished_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _ = _plan(tmp_path)
    partial = tmp_path / "capture-partial"
    partial.mkdir(mode=0o700)
    readback = _center("sweep", 0, SURVEY_CENTER_FREQUENCIES_HZ[0]).actual_settings

    class Session:
        def apply_rx_settings(self, _settings: RadioSettings) -> SurveyRxSettingsReadback:
            return readback

        def read_temperature(self) -> SurveyTemperatureReadback:
            return SurveyTemperatureReadback(millidegrees_c=44_000)

        def read_rx_block(self, _sample_count: int) -> SampleBlock:
            return SampleBlock(
                utc_ns=1,
                samples=np.ones((2, SAMPLES_PER_WINDOW), dtype=np.complex64),
            )

        def read_survey_rx_settings(self) -> SurveyRxSettingsReadback:
            return readback

    retained = 0

    def fail_mid_center(
        _block: SampleBlock,
        _plan_value: EnvironmentSurveyPlan,
        staging: Path,
        *,
        center_frequency_hz: int,
        window_index: int,
        **_kwargs: object,
    ) -> survey._RetainedWindow:
        nonlocal retained
        retained += 1
        if retained == 3:
            raise RuntimeError("planted mid-center failure")
        base = Path("sweep") / f"000-{center_frequency_hz}" / f"window-{window_index:03d}"
        survey._make_private_tree(staging, base)
        return survey._RetainedWindow(
            window_index=window_index,
            utc_ns=window_index + 1,
            raw_ci16=_artifact("raw", base),
            psd_density_dbfs_per_hz=_artifact("psd", base),
            stft_density_dbfs_per_hz=_artifact("stft", base),
            receiver_integrated_power_fs=(1e-6, 1e-6),
            receiver_integrated_power_dbfs=(-60.0, -60.0),
            receiver_clip_count=(0, 0),
        )

    monkeypatch.setattr(survey, "_retain_window", fail_mid_center)
    with pytest.raises(RuntimeError, match="mid-center"):
        survey._capture_center(
            Session(),
            plan,
            partial,
            capture_role="sweep",
            center_index=0,
            center_frequency_hz=SURVEY_CENTER_FREQUENCIES_HZ[0],
        )
    assert tuple(partial.iterdir()) == ()


def test_post_rename_failure_removes_published_center(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, _ = _plan(tmp_path)
    partial = tmp_path / "capture-partial"
    partial.mkdir(mode=0o700)
    readback = _center("sweep", 0, SURVEY_CENTER_FREQUENCIES_HZ[0]).actual_settings

    class Session:
        def apply_rx_settings(self, _settings: RadioSettings) -> SurveyRxSettingsReadback:
            return readback

        def read_temperature(self) -> SurveyTemperatureReadback:
            return SurveyTemperatureReadback(millidegrees_c=44_000)

        def read_rx_block(self, _sample_count: int) -> SampleBlock:
            return SampleBlock(
                utc_ns=1,
                samples=np.ones((2, SAMPLES_PER_WINDOW), dtype=np.complex64),
            )

        def read_survey_rx_settings(self) -> SurveyRxSettingsReadback:
            return readback

    def retain(
        _block: SampleBlock,
        _plan_value: EnvironmentSurveyPlan,
        staging: Path,
        *,
        center_frequency_hz: int,
        window_index: int,
        **_kwargs: object,
    ) -> survey._RetainedWindow:
        base = Path("sweep") / f"000-{center_frequency_hz}" / f"window-{window_index:03d}"
        survey._make_private_tree(staging, base)
        return survey._RetainedWindow(
            window_index=window_index,
            utc_ns=window_index + 1,
            raw_ci16=_artifact("raw", base),
            psd_density_dbfs_per_hz=_artifact("psd", base),
            stft_density_dbfs_per_hz=_artifact("stft", base),
            receiver_integrated_power_fs=(1e-6, 1e-6),
            receiver_integrated_power_dbfs=(-60.0, -60.0),
            receiver_clip_count=(0, 0),
        )

    real_fsync = survey._fsync_directory
    failed = False

    def fail_first_post_rename(path: Path) -> None:
        nonlocal failed
        if not failed and path == partial / "sweep":
            failed = True
            raise OSError("planted post-rename fsync failure")
        real_fsync(path)

    monkeypatch.setattr(survey, "_retain_window", retain)
    monkeypatch.setattr(survey, "_fsync_directory", fail_first_post_rename)
    with pytest.raises(OSError, match="post-rename"):
        survey._capture_center(
            Session(),
            plan,
            partial,
            capture_role="sweep",
            center_index=0,
            center_frequency_hz=SURVEY_CENTER_FREQUENCIES_HZ[0],
        )
    assert tuple(partial.iterdir()) == ()


def test_exact_result_tree_rejects_undeclared_file(tmp_path: Path) -> None:
    tmp_path.chmod(0o700)
    survey._write_private_bytes(tmp_path / "manifest.json", b"{}\n")
    survey._write_private_bytes(tmp_path / "receipt.json", b"{}\n")
    survey._write_private_bytes(tmp_path / "orphan.bin", b"x")
    with pytest.raises(EnvironmentSurveyError, match="undeclared"):
        survey._verify_exact_result_tree(tmp_path, {Path("manifest.json"), Path("receipt.json")})


def test_percentiles_use_type7_linear_power_then_db_and_bursts_are_strict() -> None:
    initial = tuple(_window(index, (10.0 * np.log10(index + 1), -50.0)) for index in range(32))
    p50_linear, p95_linear, p99_linear, p50, p95, p99, clips, occupancy, bursts = (
        survey._summarize_windows(initial)
    )

    assert p50_linear == pytest.approx((16.5, 1e-5))
    assert p95_linear == pytest.approx((30.45, 1e-5))
    assert p99_linear == pytest.approx((31.69, 1e-5))
    assert p50 == pytest.approx((10.0 * np.log10(16.5), -50.0))
    assert p95 == pytest.approx((10.0 * np.log10(30.45), -50.0))
    assert p99 == pytest.approx((10.0 * np.log10(31.69), -50.0))
    assert clips == (0, 0)
    assert occupancy == pytest.approx((0.0, 0.0))
    assert not any(any(value) for value in bursts)

    threshold = 10.0 ** (6.0 / 10.0)
    burst_powers = [1.0] * 30 + [threshold, np.nextafter(threshold, np.inf)]
    burst_windows = tuple(
        _window(index, (10.0 * np.log10(value), -50.0)) for index, value in enumerate(burst_powers)
    )
    *_, burst_occupancy, burst_flags = survey._summarize_windows(burst_windows)
    assert burst_occupancy == pytest.approx((1 / 32, 0.0))
    assert burst_flags[-2:] == ((False, False), (True, False))


def test_json_metrics_reject_zero_or_nonfinite_integrated_power() -> None:
    with pytest.raises(ValidationError, match="strictly positive"):
        _window(0, (-np.inf, -50.0))
    with pytest.raises(ValidationError):
        _window(0, (np.nan, -50.0))


def test_objective_is_p99_then_occupancy_then_hz_and_excludes_clipping() -> None:
    parameters = _parameters()
    first, second, third = parameters.control_candidates_hz[:3]
    centers = (
        SurveyCenterEvidence.model_construct(
            center_frequency_hz=first,
            worst_rx_p99_dbfs=-40.0,
            worst_rx_burst_occupancy=0.2,
            receiver_clip_count=(0, 0),
        ),
        SurveyCenterEvidence.model_construct(
            center_frequency_hz=second,
            worst_rx_p99_dbfs=-40.0,
            worst_rx_burst_occupancy=0.1,
            receiver_clip_count=(0, 0),
        ),
        SurveyCenterEvidence.model_construct(
            center_frequency_hz=third,
            worst_rx_p99_dbfs=-41.0,
            worst_rx_burst_occupancy=0.9,
            receiver_clip_count=(0, 0),
        ),
    )

    assert survey._objective_ranking(parameters, centers) == (third, second, first)
    clipped = centers[2].model_copy(update={"receiver_clip_count": (1, 0)})
    assert survey._objective_ranking(parameters, (*centers[:2], clipped)) == (second, first)


def test_fleet_objective_uses_worst_of_all_four_radios_and_global_clip_gate() -> None:
    parameters = _parameters()
    first, second, third = parameters.control_candidates_hz[:3]
    manifests = []
    for radio_index in range(4):
        centers = []
        for center_hz in SURVEY_CENTER_FREQUENCIES_HZ:
            p99 = -35.0
            occupancy = 0.2
            clips = (0, 0)
            if center_hz == first:
                p99 = -90.0 if radio_index == 0 else -30.0
            elif center_hz == second:
                p99 = -40.0
                occupancy = 0.1
            elif center_hz == third:
                p99 = -50.0
                clips = (0, 1) if radio_index == 3 else (0, 0)
            centers.append(
                SurveyCenterEvidence.model_construct(
                    center_frequency_hz=center_hz,
                    receiver_p99_dbfs=(p99, p99 - 1.0),
                    receiver_burst_occupancy=(occupancy, occupancy / 2),
                    receiver_clip_count=clips,
                )
            )
        manifests.append(EnvironmentSurveyManifest.model_construct(centers=tuple(centers)))

    candidates = survey._fleet_candidates(tuple(manifests), parameters)
    by_hz = {candidate.center_frequency_hz: candidate for candidate in candidates}
    ranked = sorted(
        (candidate for candidate in candidates if candidate.eligible),
        key=lambda candidate: (
            candidate.worst_radio_rx_p99_dbfs,
            candidate.worst_radio_rx_burst_occupancy,
            candidate.center_frequency_hz,
        ),
    )

    assert by_hz[first].worst_radio_rx_p99_dbfs == -30.0
    assert by_hz[third].exclusion_reasons == ("clipping",)
    assert ranked[0].center_frequency_hz == second
    assert tuple(radio.serial for radio in by_hz[second].radios) == RESERVED_SURVEY_SERIALS


def test_fleet_builder_requires_exact_four_manifest_receipt_pairs() -> None:
    inventory = _inventory()
    with pytest.raises(EnvironmentSurveyError, match="exactly four"):
        build_environment_survey_fleet_selection(
            (),
            (),
            emitter_inventory_file=survey.FileIdentity(
                path=Path("/private/inventory.json"), bytes=1, sha256="0" * 64
            ),
            emitter_inventory=inventory,
            tool_source=SOURCE,
            tool_version=VERSION,
        )


def test_fleet_builder_binds_verified_pass_pairs_and_per_radio_baselines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    tmp_path.chmod(0o700)
    inventory = _inventory()
    inventory_identity = write_private_contract(tmp_path / "inventory.json", inventory)
    parameters = _parameters()
    selected_hz = parameters.control_candidates_hz[0]
    plans: dict[Path, EnvironmentSurveyPlan] = {}
    manifests: dict[Path, EnvironmentSurveyManifest] = {}
    receipts: dict[Path, EnvironmentSurveyReceipt] = {}
    identities: dict[Path, survey.FileIdentity] = {}
    manifest_paths: list[Path] = []
    receipt_paths: list[Path] = []
    for radio_index, serial in enumerate(RESERVED_SURVEY_SERIALS):
        plan_path = (tmp_path / f"plan-{radio_index}.json").absolute()
        manifest_path = (tmp_path / f"manifest-{radio_index}.json").absolute()
        receipt_path = (tmp_path / f"receipt-{radio_index}.json").absolute()
        plan_identity = survey.FileIdentity(
            path=plan_path, bytes=1, sha256=f"{radio_index + 1}" * 64
        )
        manifest_identity = survey.FileIdentity(
            path=manifest_path, bytes=1, sha256=f"{radio_index + 5}" * 64
        )
        receipt_identity = survey.FileIdentity(
            path=receipt_path, bytes=1, sha256=f"{radio_index + 9:x}" * 64
        )
        identities.update(
            {
                plan_path: plan_identity,
                manifest_path: manifest_identity,
                receipt_path: receipt_identity,
            }
        )
        centers = tuple(
            SurveyCenterEvidence.model_construct(
                capture_role="sweep",
                center_index=center_index,
                center_frequency_hz=center_hz,
                receiver_p50_power_fs=(1e-6, 8e-7),
                receiver_p95_power_fs=(2e-6, 1.8e-6),
                receiver_p99_power_fs=(3e-6, 2.8e-6),
                receiver_p50_dbfs=(-60.0, -60.96910013008056),
                receiver_p95_dbfs=(-56.98970004336019, -57.44727494896694),
                receiver_p99_dbfs=(
                    (-50.0 - radio_index / 10) if center_hz == selected_hz else -30.0,
                    (-51.0 - radio_index / 10) if center_hz == selected_hz else -31.0,
                ),
                receiver_clip_count=(0, 0),
                receiver_burst_occupancy=(0.125, 0.0625),
            )
            for center_index, center_hz in enumerate(SURVEY_CENTER_FREQUENCIES_HZ)
        )
        manifest = EnvironmentSurveyManifest.model_construct(
            capture_complete=True,
            qualified=True,
            parameters=parameters,
            centers=centers,
        )
        plan = EnvironmentSurveyPlan.model_construct(
            emitter_inventory=inventory,
            emitter_inventory_file=inventory_identity,
        )
        runtime = SurveyRuntimeIdentity(
            serial=serial,
            usb_uri=f"usb:3.{30 + radio_index}.5",
            usb_path=Path(f"/sys/bus/usb/devices/3-{7 + radio_index}"),
            hardware_model="Pluto+",
            firmware_version="rc21",
        )
        receipt = EnvironmentSurveyReceipt.model_construct(
            survey_id=f"{radio_index + 1}" * 32,
            outcome="pass",
            cleanup=SurveyCleanup(
                verified=True,
                rx_settings_restored=True,
                tx_safe=True,
            ),
            manifest=manifest_identity,
            plan=plan_identity,
            target=survey.EnvironmentSurveyTarget.model_construct(serial=serial),
            runtime=runtime,
            tool_repository=SOURCE.repository,
            tool_source_commit=SOURCE.commit,
            tool_version=VERSION,
        )
        plans[plan_path] = plan
        manifests[manifest_path] = manifest
        receipts[receipt_path] = receipt
        manifest_paths.append(manifest_path)
        receipt_paths.append(receipt_path)

    def load(path: Path, model: type[Any]) -> Any:
        if model is EnvironmentSurveyManifest:
            return manifests[path]
        if model is EnvironmentSurveyPlan:
            return plans[path]
        raise AssertionError(f"unexpected model {model}")

    monkeypatch.setattr(survey, "load_private_contract", load)
    monkeypatch.setattr(survey, "verify_environment_survey_receipt", lambda path: receipts[path])
    monkeypatch.setattr(survey, "model_file_identity", lambda path, _model: identities[path])

    selection = build_environment_survey_fleet_selection(
        tuple(manifest_paths),
        tuple(receipt_paths),
        emitter_inventory_file=inventory_identity,
        emitter_inventory=inventory,
        tool_source=SOURCE,
        tool_version=VERSION,
        created_at=NOW,
    )

    assert selection.selected_control_frequency_hz == selected_hz
    assert tuple(item.serial for item in selection.surveys) == RESERVED_SURVEY_SERIALS
    assert tuple(item.serial for item in selection.selected_radio_baselines) == (
        RESERVED_SURVEY_SERIALS
    )
    assert all(
        item.baseline.center_frequency_hz == selected_hz
        for item in selection.selected_radio_baselines
    )
    assert selection.receipts_and_artifacts_verified is True


def test_anchor_drift_is_inclusive_and_anchor_clipping_fails() -> None:
    pre = SurveyCenterEvidence.model_construct(
        capture_role="pre_sweep_anchor",
        receiver_p99_dbfs=(-50.0, -50.0),
        receiver_burst_occupancy=(0.0, 0.0),
        receiver_clip_count=(0, 0),
    )
    post = SurveyCenterEvidence.model_construct(
        capture_role="post_sweep_anchor",
        receiver_p99_dbfs=(-47.0, -53.0),
        receiver_burst_occupancy=(0.09375, 0.0),
        receiver_clip_count=(0, 0),
    )

    assert survey._measure_anchor_drift(pre, post).passed
    clipped = post.model_copy(update={"receiver_clip_count": (0, 1)})
    verdict = survey._measure_anchor_drift(pre, clipped)
    assert not verdict.passed
    assert verdict.anchor_clipping_detected


def test_wrong_confirmation_or_missing_mute_never_enters_backend(tmp_path: Path) -> None:
    plan, plan_path = _plan(tmp_path)
    backend = FakeSurveyBackend(FakeSurveySession())

    with pytest.raises(EnvironmentSurveyError, match="exact confirmation"):
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation="wrong",
            ensure_mute=True,
            backend=backend,
            tool_source=SOURCE,
            tool_version=VERSION,
        )
    with pytest.raises(EnvironmentSurveyError, match="explicit --ensure-mute"):
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation=plan.confirmation_phrase,
            ensure_mute=False,
            backend=backend,
            tool_source=SOURCE,
            tool_version=VERSION,
        )
    assert backend.calls == []


def test_replaced_plan_bytes_fail_digest_pin_before_backend(tmp_path: Path) -> None:
    plan, plan_path = _plan(tmp_path)
    approved_digest = hashlib.sha256(plan_path.read_bytes()).hexdigest()
    replacement = plan.model_copy(update={"created_at": datetime(2026, 8, 27, 1, 1, tzinfo=UTC)})
    plan_path.write_bytes(survey.canonical_json_bytes(replacement))
    backend = FakeSurveyBackend(FakeSurveySession())

    with pytest.raises(EnvironmentSurveyError, match="approved digest"):
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=approved_digest,
            confirmation=replacement.confirmation_phrase,
            ensure_mute=True,
            backend=backend,
            tool_source=SOURCE,
            tool_version=VERSION,
        )
    assert backend.calls == []


def test_free_space_gate_is_exact_and_precedes_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, plan_path = _plan(tmp_path)
    backend = FakeSurveyBackend(FakeSurveySession())
    monkeypatch.setattr(
        survey, "_available_free_space_bytes", lambda _path: MINIMUM_FREE_SPACE_BYTES - 1
    )

    with pytest.raises(EnvironmentSurveyError, match="requires at least"):
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation=plan.confirmation_phrase,
            ensure_mute=True,
            backend=backend,
            tool_source=SOURCE,
            tool_version=VERSION,
        )
    assert backend.calls == []


def test_execute_runs_anchor_grid_baselines_anchor_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, plan_path = _plan(tmp_path)
    session = FakeSurveySession()
    backend = FakeSurveyBackend(session)
    roles: list[tuple[str, int | None, int]] = []

    def capture(*args: Any, **kwargs: Any) -> SurveyCenterEvidence:
        roles.append(
            (kwargs["capture_role"], kwargs["center_index"], kwargs["center_frequency_hz"])
        )
        return _stub_capture(*args, **kwargs)

    monkeypatch.setattr(
        survey, "_available_free_space_bytes", lambda _path: MINIMUM_FREE_SPACE_BYTES
    )
    monkeypatch.setattr(survey, "_capture_center", capture)

    receipt, digest = execute_environment_survey(
        plan_path,
        expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
        confirmation=plan.confirmation_phrase,
        ensure_mute=True,
        backend=backend,
        tool_source=SOURCE,
        tool_version=VERSION,
    )

    assert receipt.outcome == "pass"
    assert receipt.free_space_bytes_before_hardware == MINIMUM_FREE_SPACE_BYTES
    assert receipt.anchor_drift is not None and receipt.anchor_drift.passed
    assert receipt.selected_control_frequency_hz == plan.parameters.control_candidates_hz[0]
    assert roles[0] == ("pre_sweep_anchor", None, ANCHOR_CENTER_FREQUENCY_HZ)
    assert roles[1:92] == [
        ("sweep", index, frequency) for index, frequency in enumerate(SURVEY_CENTER_FREQUENCIES_HZ)
    ]
    assert roles[92:96] == [
        ("authorizing_baseline", index, frequency)
        for index, frequency in enumerate(AUTHORIZING_BASELINE_FREQUENCIES_HZ)
    ]
    assert roles[-1] == ("post_sweep_anchor", None, ANCHOR_CENTER_FREQUENCY_HZ)
    assert session.calls[:4] == ["observe_pre", "ensure_mute", "open_rx", "read_rx_settings"]
    assert session.calls[-3:] == ["reset_rx", "restore_rx", "ensure_mute"]
    assert backend.calls == ["lock", "unlock"]
    receipt_path = plan.result_directory / "receipt.json"
    assert digest == hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    manifest = json.loads((plan.result_directory / "manifest.json").read_text())
    assert manifest["capture_complete"] is True
    assert manifest["qualified"] is True
    assert len(manifest["centers"]) == 91
    assert len(manifest["authorizing_baselines"]) == 4


def test_cleanup_failure_is_fail_closed_and_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, plan_path = _plan(tmp_path)
    monkeypatch.setattr(
        survey, "_available_free_space_bytes", lambda _path: MINIMUM_FREE_SPACE_BYTES
    )
    monkeypatch.setattr(survey, "_capture_center", _stub_capture)

    with pytest.raises(EnvironmentSurveyExecutionError) as captured:
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation=plan.confirmation_phrase,
            ensure_mute=True,
            backend=FakeSurveyBackend(FakeSurveySession(cleanup_failure=True)),
            tool_source=SOURCE,
            tool_version=VERSION,
        )

    receipt = load_private_contract(captured.value.receipt_path, EnvironmentSurveyReceipt)
    assert receipt.outcome == "failed"
    assert receipt.failure_phase == "cleanup"
    assert receipt.selected_control_frequency_hz is None
    assert not receipt.cleanup.verified
    assert any("planted cleanup mute failure" in value for value in receipt.cleanup.errors)


def test_failed_receipt_verifier_rejects_any_undeclared_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, plan_path = _plan(tmp_path)
    monkeypatch.setattr(
        survey, "_available_free_space_bytes", lambda _path: MINIMUM_FREE_SPACE_BYTES
    )

    def fail_capture(*_args: object, **_kwargs: object) -> SurveyCenterEvidence:
        raise RuntimeError("planted first-center failure")

    monkeypatch.setattr(survey, "_capture_center", fail_capture)
    with pytest.raises(EnvironmentSurveyExecutionError) as captured:
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation=plan.confirmation_phrase,
            ensure_mute=True,
            backend=FakeSurveyBackend(FakeSurveySession()),
            tool_source=SOURCE,
            tool_version=VERSION,
        )

    assert verify_environment_survey_receipt(captured.value.receipt_path).outcome == "failed"
    survey._write_private_bytes(captured.value.receipt_path.parent / "orphan.bin", b"x")
    with pytest.raises(EnvironmentSurveyError, match="undeclared"):
        verify_environment_survey_receipt(captured.value.receipt_path)


def test_radio_session_release_failure_is_cleanup_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, plan_path = _plan(tmp_path)
    monkeypatch.setattr(
        survey, "_available_free_space_bytes", lambda _path: MINIMUM_FREE_SPACE_BYTES
    )
    monkeypatch.setattr(survey, "_capture_center", _stub_capture)

    with pytest.raises(EnvironmentSurveyExecutionError) as captured:
        execute_environment_survey(
            plan_path,
            expected_plan_sha256=hashlib.sha256(plan_path.read_bytes()).hexdigest(),
            confirmation=plan.confirmation_phrase,
            ensure_mute=True,
            backend=FailingReleaseBackend(FakeSurveySession()),
            tool_source=SOURCE,
            tool_version=VERSION,
        )

    receipt = load_private_contract(captured.value.receipt_path, EnvironmentSurveyReceipt)
    assert receipt.outcome == "failed"
    assert receipt.failure_phase == "release_radio_session"
    assert not receipt.cleanup.verified
    assert any("planted session release failure" in value for value in receipt.cleanup.errors)
