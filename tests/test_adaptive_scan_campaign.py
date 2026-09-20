from __future__ import annotations

from contextlib import AbstractContextManager

import pytest

import pluto_plus.adaptive_scan_campaign as campaign
from pluto_plus.adaptive_scan import (
    ScanCapabilities,
    ScanOutcome,
    ScanSetup,
    ScanTarget,
    ScanTerminal,
    ScanVisit,
    TerminalState,
    VisitResult,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_detector import TargetMaskDetectorConfig
from pluto_plus.adaptive_scan_radio import (
    AdaptiveScanRadioPreparation,
    AdaptiveScanRadioRestoration,
)
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.hardware.iio import IioReceiverSettingsReadback
from pluto_plus.models import GainMode

SETTINGS = IioReceiverSettingsReadback(
    915_000_000.0, 10_000_000.0, 8_000_000.0, (0,), (GainMode.MANUAL,), (40.0,)
)


def _setup() -> ScanSetup:
    return ScanSetup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=8_000_000,
        duration_ms=1_000,
        dwell_ms=240,
        transition_budget_ms=10,
        maximum_revisit_ms=1_000,
        feedback_age_ms=1_000,
        application_delay_ms=1_000,
        decay_ms=5_000,
        maximum_boost=3,
        maximum_queue_bytes=200_000_000,
        maximum_queue_age_ms=5_000,
        maximum_queue_visits=50,
        analysis_digest=bytes(range(1, 33)),
        targets=(ScanTarget(1, 0, 2_400_000_000, 1, 0x12345678),),
    )


class Session(AbstractContextManager):
    def __init__(self, setup: ScanSetup) -> None:
        self.setup = setup
        self.terminal = None

    def visits(self):
        samples = self.setup.source_rate_hz * self.setup.dwell_ms // 1_000
        iq = bytes(samples * 4)
        record = ScanVisit(
            session=self.setup.session,
            generation=self.setup.generation,
            visit=0,
            selection_counter=0,
            transition_before=0,
            transition_after=100_000,
            valid_start=100_000,
            valid_end=100_000 + samples,
            frequency_hz=self.setup.targets[0].frequency_hz,
            iq_bytes=len(iq),
            missing_samples_before=0,
            analog_bandwidth_hz=self.setup.analog_bandwidth_hz,
            source_rate_hz=self.setup.source_rate_hz,
            target=0,
            profile=0,
            result=VisitResult.COMPLETE,
            eligible_mask=1,
            effective_weight=65_536,
            profile_crc32=self.setup.targets[0].profile_crc32,
        )
        yield AdaptiveScanVisit(record, iq)
        self.terminal = ScanTerminal(
            session=self.setup.session,
            generation=self.setup.generation,
            final_counter=record.valid_end,
            restore_before=record.valid_end,
            restore_after=record.valid_end + 1,
            planned=1,
            delivered=1,
            skipped=0,
            invalid=0,
            cancelled=0,
            iq_bytes=len(iq),
            state=TerminalState.COMPLETED,
            reason=1,
            error=0,
        )

    def submit_feedback(self, _feedback):
        raise AssertionError("shadow mode must not submit feedback")

    def __exit__(self, *_args):
        return None


class Client:
    def __init__(self, host: str) -> None:
        assert host == "192.168.1.18"

    def capabilities(self):
        return ScanCapabilities()

    def start(self, setup, *, samples_per_block):
        assert samples_per_block == 1_000_000
        return Session(setup)


def _install_lifecycle(monkeypatch, setup: ScanSetup, events: list[str]) -> None:
    preparation = AdaptiveScanRadioPreparation(
        uri="ip:192.168.1.18",
        serial="SERIAL_A",
        original=SETTINGS,
        configured=SETTINGS,
        original_kernel_buffers=4,
        configured_kernel_buffers=16,
        setup=setup,
        profile_words=((1,) * 16,),
    )

    def prepare(*_args, **_kwargs):
        events.append("prepare")
        return preparation

    def restore(value, **_kwargs):
        assert value is preparation
        events.append("restore")
        return AdaptiveScanRadioRestoration(SETTINGS, SETTINGS, 4, 4, True)

    monkeypatch.setattr(campaign, "prepare_adaptive_scan_radio", prepare)
    monkeypatch.setattr(campaign, "restore_adaptive_scan_radio", restore)


def test_campaign_joins_prepare_shadow_stream_metrics_and_restore(monkeypatch) -> None:
    events = []
    setup = _setup()
    _install_lifecycle(monkeypatch, setup, events)
    receipt = campaign.run_adaptive_scan_campaign(
        "ip:192.168.1.18",
        "SERIAL_A",
        setup,
        lambda _visit: ScanOutcome.ACTIVE,
        mode=AdaptiveScanMode.SHADOW,
        client_factory=Client,
    )
    assert events == ["prepare", "restore"]
    assert receipt.run.gate.passed
    assert receipt.restoration.fastlock_inactive


def test_campaign_restores_after_detector_failure(monkeypatch) -> None:
    events = []
    setup = _setup()
    _install_lifecycle(monkeypatch, setup, events)

    def fail(_visit):
        raise RuntimeError("detector failed")

    with pytest.raises(RuntimeError, match="detector failed"):
        campaign.run_adaptive_scan_campaign(
            "ip:192.168.1.18",
            "SERIAL_A",
            setup,
            fail,
            mode=AdaptiveScanMode.SHADOW,
            client_factory=Client,
        )
    assert events == ["prepare", "restore"]


def test_timing_sink_failure_still_restores_radio(monkeypatch) -> None:
    from pluto_plus.counter_utc import CounterUtcEvidence

    events = []
    setup = _setup()
    _install_lifecycle(monkeypatch, setup, events)

    class Collector:
        def __init__(self, *_args, **_kwargs):
            pass

        def start(self):
            events.append("timing-start")

        def stop(self):
            events.append("timing-stop")
            return CounterUtcEvidence(
                session=setup.session, generation=setup.generation, radio_serial="SERIAL_A"
            )

    def sink(_evidence):
        raise RuntimeError("evidence sink failed")

    monkeypatch.setattr(campaign, "CounterUtcCollector", Collector)
    with pytest.raises(RuntimeError, match="evidence sink failed"):
        campaign.run_adaptive_scan_campaign(
            "ip:192.168.1.18",
            "SERIAL_A",
            setup,
            lambda _: ScanOutcome.ACTIVE,
            mode=AdaptiveScanMode.SHADOW,
            client_factory=Client,
            counter_clock_sink=sink,
        )
    assert events == ["prepare", "timing-start", "timing-stop", "restore"]


@pytest.mark.parametrize("rate", [2_500_000, 10_000_000, 15_000_000, 20_000_000, 30_000_000])
def test_campaign_setup_builder_is_fixed_rate_and_profile_bounded(rate) -> None:
    setup = campaign.build_adaptive_scan_setup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=rate,
        analog_bandwidth_hz=8_000_000,
        duration_ms=300_000,
        dwell_ms=240,
        frequencies_hz=(959_687_500, 1_190_312_500),
        baseline_weights=(1, 1),
        analysis_digest=TargetMaskDetectorConfig((1,)).analysis_digest,
    )
    assert setup.source_rate_hz == rate
    assert setup.analog_bandwidth_hz == 8_000_000
    assert [target.profile for target in setup.targets] == [1, 2]
    assert all(target.profile_crc32 == 0 for target in setup.targets)


def test_campaign_setup_builder_preserves_dual_rx_request() -> None:
    setup = campaign.build_adaptive_scan_setup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_500_000,
        duration_ms=300_000,
        dwell_ms=120,
        frequencies_hz=(959_687_498, 1_209_687_498),
        baseline_weights=(1, 1),
        analysis_digest=b"x" * 32,
        rx_mask=3,
    )
    assert setup.rx_mask == 3


def test_campaign_rejects_2p5_without_the_appended_capability(monkeypatch) -> None:
    setup = campaign.build_adaptive_scan_setup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_500_000,
        duration_ms=30_000,
        dwell_ms=120,
        frequencies_hz=(959_687_500,),
        baseline_weights=(1,),
        analysis_digest=b"x" * 32,
    )

    class LegacyClient(Client):
        def capabilities(self):
            return ScanCapabilities(rate_mask=0x0F)

    with pytest.raises(ValueError, match="does not advertise"):
        campaign.run_adaptive_scan_campaign(
            "ip:192.168.1.18",
            "SERIAL_A",
            setup,
            lambda _visit: ScanOutcome.ACTIVE,
            mode=AdaptiveScanMode.SHADOW,
            client_factory=LegacyClient,
        )


def test_campaign_setup_builder_rejects_sixty_mss() -> None:
    with pytest.raises(ValueError, match="10/15/20/30"):
        campaign.build_adaptive_scan_setup(
            session=1,
            generation=2,
            seed=3,
            source_rate_hz=60_000_000,
            analog_bandwidth_hz=8_000_000,
            duration_ms=300_000,
            dwell_ms=240,
            frequencies_hz=(959_687_500, 1_190_312_500),
            baseline_weights=(1, 1),
            analysis_digest=TargetMaskDetectorConfig((1,)).analysis_digest,
        )


def test_setup_rejects_eighth_frequency_because_profile_zero_is_inactive() -> None:
    with pytest.raises(ValueError, match="one to seven"):
        campaign.build_adaptive_scan_setup(
            session=1,
            generation=2,
            seed=3,
            source_rate_hz=10_000_000,
            analog_bandwidth_hz=8_000_000,
            duration_ms=30_000,
            dwell_ms=240,
            frequencies_hz=tuple(900_000_000 + index * 10_000_000 for index in range(8)),
            baseline_weights=(1,) * 8,
            analysis_digest=b"x" * 32,
        )
