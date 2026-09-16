"""Bounded prepare/capture/restore lifecycle for feature-request #103."""

from __future__ import annotations

import dataclasses
from collections.abc import Callable

from .adaptive_scan import ScanOutcome, ScanSetup, ScanTarget
from .adaptive_scan_client import AdaptiveScanClient, AdaptiveScanVisit
from .adaptive_scan_radio import (
    AdaptiveScanRadioPreparation,
    AdaptiveScanRadioRestoration,
    RadioFactory,
    prepare_adaptive_scan_radio,
    restore_adaptive_scan_radio,
)
from .adaptive_scan_shadow import AdaptiveScanMode, ScannerRunReport, run_scanner_session
from .persistent_hop import require_physical_lan_uri

ClientFactory = Callable[[str], AdaptiveScanClient]
Detector = Callable[[AdaptiveScanVisit], ScanOutcome]


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanCampaignReceipt:
    uri: str
    serial: str
    preparation: AdaptiveScanRadioPreparation
    run: ScannerRunReport
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
) -> ScanSetup:
    """Build the canonical bounded campaign setup before profile compilation."""

    if not 1 <= len(frequencies_hz) <= 8 or len(baseline_weights) != len(frequencies_hz):
        raise ValueError("campaign requires one to eight frequency/weight pairs")
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
                profile=index,
                frequency_hz=frequency,
                baseline_weight=baseline_weights[index],
                profile_crc32=0,
            )
            for index, frequency in enumerate(frequencies_hz)
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
    samples_per_block: int = 1_000_000,
    feedback_period_visits: int = 1,
    radio_factory: RadioFactory | None = None,
    client_factory: ClientFactory = AdaptiveScanClient,
) -> AdaptiveScanCampaignReceipt:
    """Run one bounded campaign and always restore the pre-session host state."""

    selected_uri = require_physical_lan_uri(uri)
    host = selected_uri.removeprefix("ip:")
    preparation = (
        prepare_adaptive_scan_radio(
            selected_uri,
            serial,
            setup,
            manual_gain_db=manual_gain_db,
        )
        if radio_factory is None
        else prepare_adaptive_scan_radio(
            selected_uri,
            serial,
            setup,
            manual_gain_db=manual_gain_db,
            radio_factory=radio_factory,
        )
    )
    run: ScannerRunReport | None = None
    restoration: AdaptiveScanRadioRestoration | None = None
    failure: BaseException | None = None
    try:
        client = client_factory(host)
        client.capabilities()
        with client.start(
            preparation.setup,
            samples_per_block=samples_per_block,
        ) as session:
            run = run_scanner_session(
                session,
                detector,
                mode=mode,
                feedback_period_visits=feedback_period_visits,
            )
    except BaseException as error:
        failure = error
    finally:
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
    return AdaptiveScanCampaignReceipt(
        uri=selected_uri,
        serial=serial,
        preparation=preparation,
        run=run,
        restoration=restoration,
    )
