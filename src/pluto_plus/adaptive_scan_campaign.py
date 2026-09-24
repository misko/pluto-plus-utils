"""Bounded prepare/capture/restore lifecycle for feature-request #103."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable

from .adaptive_scan import (
    RUNTIME_VERSION,
    SUPPORTED_RATES,
    VARIABLE_DWELL_VERSION,
    ScanOutcome,
    ScanSetup,
    ScanTarget,
    ScanTerminal,
)
from .adaptive_scan_client import AdaptiveScanClient, AdaptiveScanVisit
from .adaptive_scan_radio import (
    AdaptiveScanRadioPreparation,
    AdaptiveScanRadioRestoration,
    RadioFactory,
    prepare_adaptive_scan_radio,
    restore_adaptive_scan_radio,
)
from .adaptive_scan_shadow import AdaptiveScanMode, ScannerRunReport, run_scanner_session
from .counter_utc import DEFAULT_TIMING_POLICY, CounterUtcEvidence, TimingPolicy
from .counter_utc_capture import CounterUtcCollector
from .models import GainMode
from .persistent_hop import require_physical_lan_uri

ClientFactory = Callable[[str], AdaptiveScanClient]
Detector = Callable[[AdaptiveScanVisit], ScanOutcome]
VisitSink = Callable[[AdaptiveScanVisit], None]
SessionClockSink = Callable[[int, int, int, int], None]

# The v1 firmware's original fixed-rate bits are 10/15/20/30 MS/s.  The
# issue-108 dual-RX extension adds the fifth bit for its 2.5 MS/s mode.
_RATE_CAPABILITY_BITS = {
    2_500_000: 1 << 4,
    10_000_000: 1 << 0,
    15_000_000: 1 << 1,
    20_000_000: 1 << 2,
    30_000_000: 1 << 3,
}


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanCampaignReceipt:
    uri: str
    serial: str
    preparation: AdaptiveScanRadioPreparation
    run: ScannerRunReport
    terminal: ScanTerminal
    restoration: AdaptiveScanRadioRestoration


def build_adaptive_scan_setup(
    *,
    session: int,
    generation: int,
    seed: int,
    source_rate_hz: int,
    analog_bandwidth_hz: int,
    duration_ms: int,
    dwell_ms: int,
    frequencies_hz: tuple[int, ...],
    baseline_weights: tuple[int, ...],
    analysis_digest: bytes,
    transition_budget_ms: int = 10,
    maximum_revisit_ms: int = 3_000,
    rx_mask: int = 1,
    variable_dwell: bool = False,
) -> ScanSetup:
    """Build the canonical bounded campaign setup before profile compilation."""

    # The AD9361 driver uses fastlock profile 0 as its inactive sentinel.
    # Hardware-backed sessions therefore use the seven recallable slots 1..7.
    if not 1 <= len(frequencies_hz) <= 7 or len(baseline_weights) != len(frequencies_hz):
        raise ValueError("campaign requires one to seven frequency/weight pairs")
    setup = ScanSetup(
        session=session,
        generation=generation,
        seed=seed,
        source_rate_hz=source_rate_hz,
        analog_bandwidth_hz=analog_bandwidth_hz,
        duration_ms=duration_ms,
        dwell_ms=dwell_ms,
        transition_budget_ms=transition_budget_ms,
        maximum_revisit_ms=maximum_revisit_ms,
        feedback_age_ms=1_000,
        application_delay_ms=1_000,
        decay_ms=5_000,
        maximum_boost=3,
        maximum_queue_bytes=200_000_000,
        maximum_queue_age_ms=5_000,
        maximum_queue_visits=50,
        analysis_digest=analysis_digest,
        targets=tuple(
            ScanTarget(
                channel=index,
                profile=index + 1,
                frequency_hz=frequency,
                baseline_weight=baseline_weights[index],
                profile_crc32=0,
            )
            for index, frequency in enumerate(frequencies_hz)
        ),
        rx_mask=rx_mask,
        protocol_version=(
            VARIABLE_DWELL_VERSION
            if variable_dwell
            else 1
            if source_rate_hz in SUPPORTED_RATES
            else RUNTIME_VERSION
        ),
    )
    setup.validate()
    return setup


def run_adaptive_scan_campaign(
    uri: str,
    serial: str,
    setup: ScanSetup,
    detector: Detector,
    *,
    mode: AdaptiveScanMode,
    manual_gain_db: float = 40.0,
    gain_mode: GainMode = GainMode.MANUAL,
    samples_per_block: int = 1_000_000,
    feedback_period_visits: int = 1,
    radio_factory: RadioFactory | None = None,
    client_factory: ClientFactory = AdaptiveScanClient,
    visit_sink: VisitSink | None = None,
    session_clock_sink: SessionClockSink | None = None,
    counter_clock_sink: Callable[[CounterUtcEvidence], None] | None = None,
    timing_policy: TimingPolicy = DEFAULT_TIMING_POLICY,
) -> AdaptiveScanCampaignReceipt:
    """Run one bounded campaign and always restore the pre-session host state."""

    selected_uri = require_physical_lan_uri(uri)
    host = selected_uri.removeprefix("ip:")
    setup.validate()
    discovery = client_factory(host)
    capabilities = (
        discovery.variable_dwell_capabilities()
        if setup.protocol_version == VARIABLE_DWELL_VERSION
        else discovery.runtime_capabilities()
        if setup.protocol_version == RUNTIME_VERSION
        else discovery.capabilities()
    )
    supported = (
        capabilities.protocol_version == RUNTIME_VERSION
        and capabilities.minimum_rate_hz <= setup.source_rate_hz <= capabilities.maximum_rate_hz
        if setup.protocol_version == RUNTIME_VERSION
        else bool(capabilities.rate_mask & _RATE_CAPABILITY_BITS[setup.source_rate_hz])
    )
    if not supported:
        raise ValueError(
            f"radio does not advertise adaptive-scan support for {setup.source_rate_hz} S/s"
        )
    if capabilities.rx_mask & setup.rx_mask != setup.rx_mask:
        raise ValueError(f"radio does not advertise adaptive-scan RX mask {setup.rx_mask:#x}")
    preparation = (
        prepare_adaptive_scan_radio(
            selected_uri,
            serial,
            setup,
            manual_gain_db=manual_gain_db,
            gain_mode=gain_mode,
        )
        if radio_factory is None
        else prepare_adaptive_scan_radio(
            selected_uri,
            serial,
            setup,
            manual_gain_db=manual_gain_db,
            gain_mode=gain_mode,
            radio_factory=radio_factory,
        )
    )
    run: ScannerRunReport | None = None
    restoration: AdaptiveScanRadioRestoration | None = None
    failure: BaseException | None = None
    collector: CounterUtcCollector | None = None
    try:
        client = client_factory(host)
        client.capabilities()
        begin_before_realtime_ns = time.time_ns()
        begin_before_monotonic_ns = time.monotonic_ns()
        with client.start(
            preparation.setup,
            samples_per_block=samples_per_block,
        ) as session:
            if counter_clock_sink is not None:
                collector = CounterUtcCollector(
                    AdaptiveScanClient(host, timeout_s=1.0),
                    preparation.setup,
                    serial,
                    policy=timing_policy,
                )
                collector.start()
            if session_clock_sink is not None:
                session_clock_sink(
                    begin_before_realtime_ns,
                    begin_before_monotonic_ns,
                    time.time_ns(),
                    time.monotonic_ns(),
                )
            run = run_scanner_session(
                session,
                detector,
                mode=mode,
                feedback_period_visits=feedback_period_visits,
                visit_observer=visit_sink,
            )
    except BaseException as error:
        failure = error
    finally:
        if collector is not None and counter_clock_sink is not None:
            try:
                counter_clock_sink(collector.stop())
            except BaseException as timing_error:
                if failure is None:
                    failure = timing_error
                else:
                    failure.add_note(f"timing evidence persistence failed: {timing_error!r}")
        try:
            restoration = (
                restore_adaptive_scan_radio(preparation)
                if radio_factory is None
                else restore_adaptive_scan_radio(
                    preparation,
                    radio_factory=radio_factory,
                )
            )
        except BaseException as cleanup:
            if failure is not None:
                failure.add_note(f"adaptive scan campaign restoration failed: {cleanup!r}")
            else:
                raise
    if failure is not None:
        raise failure
    if run is None or restoration is None:
        raise RuntimeError("adaptive scan campaign did not produce a complete receipt")
    if session.terminal is None:
        raise RuntimeError("adaptive scan campaign lost its terminal record")
    return AdaptiveScanCampaignReceipt(
        uri=selected_uri,
        serial=serial,
        preparation=preparation,
        run=run,
        terminal=session.terminal,
        restoration=restoration,
    )
