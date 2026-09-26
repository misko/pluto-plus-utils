"""Opt-in multirate adaptive-scan round trip of the Qin Starlink edge pilot."""

from __future__ import annotations

import dataclasses
import gc
import hashlib
import json
import os
import queue
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import pytest

from pluto_plus.adaptive_scan import ScanOutcome
from pluto_plus.adaptive_scan_campaign import (
    build_adaptive_scan_setup,
    run_adaptive_scan_campaign,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.direct_radio.samples import ci16_dual_rx
from pluto_plus.hardware.iio import _mute_transmit
from pluto_plus.starlink_pilot_loopback import (
    analyze_starlink_pilot_parity,
    cyclic_tx_waveform,
    measure_starlink_pilot_parity,
    qin_lower_edge_pilot_frame,
    receiver_has_starlink_pilot_glrt,
    require_counter_marker_free,
    starlink_pilot_parity_failures,
)

pytestmark = pytest.mark.hardware

RATE_BANDWIDTHS_HZ = (
    (2_500_000, 2_500_000),
    (5_000_000, 5_000_000),
    (7_500_000, 7_500_000),
    (10_000_000, 10_000_000),
)
DEFAULT_LO_HZ = 960_000_000
SECOND_SCAN_LO_HZ = 1_190_000_000
LONG_SCAN_RATES_HZ = (2_500_000, 10_000_000)
LONG_SCAN_DURATION_MS = 200_000
LONG_SCAN_OFFSETS_HZ = (0, 250_000_000, 500_000_000, 750_000_000)
AUTHORIZED_SERIALS = {
    "1040005e0b100007100010000bf33a5d4d",
    "1040007c4a94000211000b009186843ef2",
    "104000b29905000e17000800065934759d",
}


def _dac_selector_register(channel: int) -> int:
    return 0x0418 + channel * 0x40


def _dac_legacy_register(channel: int) -> int:
    return 0x0414 + channel * 0x40


def _write_selector(tx: Any, channel: int, selector: int) -> None:
    legacy = _dac_legacy_register(channel)
    tx.reg_write(legacy, int(tx.reg_read(legacy)) & ~1)
    register = _dac_selector_register(channel)
    tx.reg_write(register, selector)
    if int(tx.reg_read(register)) & 0xF != selector:
        pytest.fail(f"DAC channel {channel} did not retain selector {selector}")


class _DirectCyclicTx2:
    """Use the release-qualified libiio-v0 cyclic path for physical TX2."""

    def __init__(self, radio: Any, waveform: np.ndarray, tx_gain_db: float) -> None:
        self.radio = radio
        self.waveform = waveform
        self.tx_gain_db = tx_gain_db
        self.buffer: Any = None
        self.channel_states: list[tuple[Any, bool]] = []

    def arm(self) -> None:
        import iio

        _mute_transmit(self.radio)
        tx = self.radio._txdac
        enabled_ids = {"voltage2", "voltage3"}
        found: set[str] = set()
        for channel in tx.channels:
            if channel.scan_element:
                self.channel_states.append((channel, bool(channel.enabled)))
                channel.enabled = channel.id in enabled_ids
                if channel.enabled:
                    found.add(channel.id)
        if found != enabled_ids or int(tx.sample_size) != 4:
            pytest.fail(f"TX2-only DMA scan layout is invalid: {found}, {tx.sample_size}")
        words = np.empty((len(self.waveform), 2), dtype="<i2")
        words[:, 0] = np.real(self.waveform).astype("<i2")
        words[:, 1] = np.imag(self.waveform).astype("<i2")
        payload = bytearray(words.tobytes())
        self.buffer = iio.Buffer(tx, len(self.waveform), True)
        if len(self.buffer) != len(payload) or int(self.buffer.write(payload)) != len(payload):
            pytest.fail("TX2 cyclic DMA buffer length/write did not match the waveform")
        if bytes(self.buffer.read()) != bytes(payload):
            pytest.fail("TX2 cyclic DMA readback differs from the waveform")
        self.buffer.push()
        _write_selector(tx, 0, 3)
        _write_selector(tx, 1, 3)
        _write_selector(tx, 2, 2)
        _write_selector(tx, 3, 2)
        assert float(self.radio.tx_hardwaregain_chan0) <= -80.0
        self.radio.tx_hardwaregain_chan1 = self.tx_gain_db

    def close(self) -> None:
        self.radio.tx_hardwaregain_chan0 = -80.0
        self.radio.tx_hardwaregain_chan1 = -80.0
        for channel in range(4):
            _write_selector(self.radio._txdac, channel, 3)
        buffer = self.buffer
        self.buffer = None
        close = getattr(buffer, "close", None)
        if callable(close):
            close()
        buffer = None
        gc.collect()
        for channel, enabled in self.channel_states:
            channel.enabled = enabled
        self.channel_states.clear()


def _targets() -> tuple[tuple[str, str], ...]:
    raw = os.environ.get("PLUTO_ADAPTIVE_PILOT_TARGETS", "").strip()
    attenuation = os.environ.get("PLUTO_TX2_LOOPBACK_ATTENUATION_DB", "").strip()
    if not raw or not attenuation:
        pytest.skip(
            "set PLUTO_ADAPTIVE_PILOT_TARGETS=serial@ip:host and "
            "PLUTO_TX2_LOOPBACK_ATTENUATION_DB to authorize RF transmission"
        )
    try:
        attenuation_db = float(attenuation)
        tx_gain_db = float(os.environ.get("PLUTO_TX2_LOOPBACK_TX_GAIN_DB", "-50"))
    except ValueError:
        pytest.fail("TX2 attenuation and gain must be numeric")
    if not 0 <= attenuation_db <= 120 or not -80 <= tx_gain_db <= -10:
        pytest.fail("TX2 attenuation/gain is outside the bounded hardware-test range")
    if attenuation_db - tx_gain_db < 30:
        pytest.fail("TX2 loopback must provide at least 30 dB effective attenuation")

    targets: list[tuple[str, str]] = []
    for item in raw.split(","):
        try:
            serial, uri = (part.strip() for part in item.split("@", 1))
        except ValueError:
            pytest.fail("adaptive pilot targets must use serial@ip:host syntax")
        if serial not in AUTHORIZED_SERIALS or not uri.startswith("ip:"):
            pytest.fail("adaptive pilot target is outside the authorized radio/LAN set")
        targets.append((serial, uri))
    if not targets or len(targets) != len(set(targets)):
        pytest.fail("adaptive pilot targets must be nonempty and unique")
    return tuple(targets)


def _snapshot_tx(sdr: Any) -> dict[str, Any]:
    return {
        name: getattr(sdr, name)
        for name in (
            "tx_lo",
            "tx_rf_bandwidth",
            "tx_hardwaregain_chan0",
            "tx_hardwaregain_chan1",
        )
    }


def _restore_tx(sdr: Any, snapshot: dict[str, Any]) -> None:
    _mute_transmit(sdr)
    # The precondition below proves the saved gains are both muted. Restore
    # tuning while muted and deliberately leave DMA/DDS disabled.
    sdr.tx_lo = snapshot["tx_lo"]
    sdr.tx_rf_bandwidth = snapshot["tx_rf_bandwidth"]
    sdr.tx_hardwaregain_chan0 = snapshot["tx_hardwaregain_chan0"]
    sdr.tx_hardwaregain_chan1 = snapshot["tx_hardwaregain_chan1"]


def _write_report(path: str, payload: list[dict[str, Any]]) -> None:
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    temporary.replace(destination)


class _FullScanGlrtAnalyzer:
    """Analyze bounded dual-RX slices without delaying the IQ drain loop."""

    def __init__(self, sample_rate_hz: int, *, workers: int = 4) -> None:
        self.sample_rate_hz = sample_rate_hz
        self.frame_samples = round(sample_rate_hz / 750)
        self.jobs: queue.Queue[tuple[int, int, np.ndarray] | None] = queue.Queue(
            maxsize=64
        )
        self.rows: list[dict[str, Any]] = []
        self.errors: list[BaseException] = []
        self.dropped: list[int] = []
        self.complete_visits = 0
        self.finished = False
        self.threads = [
            threading.Thread(
                target=self._work,
                name=f"starlink-glrt-{index}",
                daemon=True,
            )
            for index in range(workers)
        ]
        for thread in self.threads:
            thread.start()

    def observe(self, visit: AdaptiveScanVisit) -> None:
        if not visit.iq:
            return
        self.complete_visits += 1
        require_counter_marker_free(visit.iq, valid_start=visit.record.valid_start)
        signal = ci16_dual_rx(visit.iq)
        # Keep queued GLRT work bounded well below one 120 ms visit.
        bounded = signal[:, : 8 * self.frame_samples].copy()
        try:
            self.jobs.put_nowait((visit.record.visit, visit.record.target, bounded))
        except queue.Full:
            self.dropped.append(visit.record.visit)

    def _work(self) -> None:
        while True:
            job = self.jobs.get()
            try:
                if job is None:
                    return
                visit, target, signal = job
                metrics = measure_starlink_pilot_parity(
                    signal, sample_rate_hz=self.sample_rate_hz
                )
                self.rows.append(
                    {
                        "visit": visit,
                        "target": target,
                        "glrt_detected": [
                            receiver_has_starlink_pilot_glrt(item)
                            for item in metrics.receivers
                        ],
                        "positive_gate_failures": list(
                            starlink_pilot_parity_failures(metrics)
                        ),
                        "pilot": dataclasses.asdict(metrics),
                    }
                )
            except BaseException as error:
                self.errors.append(error)
            finally:
                self.jobs.task_done()

    def finish(self) -> list[dict[str, Any]]:
        if self.finished:
            if self.errors:
                raise self.errors[0]
            if self.dropped:
                pytest.fail(f"GLRT analysis queue dropped visits: {self.dropped[:8]}")
            return self.rows
        for _thread in self.threads:
            self.jobs.put(None)
        self.jobs.join()
        for thread in self.threads:
            thread.join()
        self.finished = True
        if self.errors:
            raise self.errors[0]
        if self.dropped:
            pytest.fail(f"GLRT analysis queue dropped visits: {self.dropped[:8]}")
        if len(self.rows) != self.complete_visits:
            pytest.fail("GLRT result count does not match observed complete visits")
        self.rows.sort(key=lambda row: row["visit"])
        return self.rows


def test_qin_edge_pilot_round_trip_glrt_matches_rx0_and_rx1() -> None:
    """TX2 Qin pilot -> four-rate adaptive dual RX -> independent GLRT gates."""

    targets = _targets()
    lo_hz = int(os.environ.get("PLUTO_ADAPTIVE_PILOT_LO_HZ", str(DEFAULT_LO_HZ)))
    tx_gain_db = float(os.environ.get("PLUTO_TX2_LOOPBACK_TX_GAIN_DB", "-50"))
    protocol = int(os.environ.get("PLUTO_ADAPTIVE_PILOT_PROTOCOL", "3"))
    if protocol not in (1, 3):
        pytest.fail("adaptive pilot protocol must be 1 or 3")
    if not 900_000_000 <= lo_hz <= 1_100_000_000:
        pytest.fail("adaptive pilot RF frequency must remain in the authorized ~1 GHz band")

    import adi

    reports: list[dict[str, Any]] = []
    for serial, uri in targets:
        sdr = adi.ad9361(uri=uri)
        snapshot: dict[str, Any] | None = None
        try:
            assert sdr._ctx.attrs.get("hw_serial") == serial
            if float(sdr.tx_hardwaregain_chan0) > -80 or float(sdr.tx_hardwaregain_chan1) > -80:
                pytest.fail(f"{serial} was not muted before the hardware test")
            if sdr._ctrl.find_channel("voltage1", True) is None:
                pytest.fail(f"{serial} does not expose physical TX2")
            snapshot = _snapshot_tx(sdr)
            for sample_rate_hz, rf_bandwidth_hz in RATE_BANDWIDTHS_HZ:
                transmitter: _DirectCyclicTx2 | None = None
                try:
                    _mute_transmit(sdr)
                    sdr.tx_rf_bandwidth = rf_bandwidth_hz
                    sdr.tx_lo = lo_hz
                    waveform = cyclic_tx_waveform(sample_rate_hz)
                    transmitter = _DirectCyclicTx2(sdr, waveform, tx_gain_db)

                    def arm_tx2_after_session_start(
                        _session: Any,
                        radio: Any = sdr,
                        tx_samples: np.ndarray = waveform,
                        tx_fixture: _DirectCyclicTx2 = transmitter,
                    ) -> None:
                        # Both adaptive preparation and OPENM deliberately destroy TX
                        # buffers. Arm after the session owns its RX capture and before
                        # visit draining begins. TX1 remains at -80 dB throughout.
                        assert len(tx_samples) == len(tx_fixture.waveform)
                        assert radio is tx_fixture.radio
                        tx_fixture.arm()
                        time.sleep(0.25)

                    captured: list[AdaptiveScanVisit] = []

                    def retain_first_visit(
                        visit: AdaptiveScanVisit,
                        destination: list[AdaptiveScanVisit] = captured,
                    ) -> None:
                        if visit.record.target == 0 and not destination:
                            destination.append(visit)

                    digest = hashlib.sha256(
                        np.asarray(
                            qin_lower_edge_pilot_frame(sample_rate_hz), dtype="<c8"
                        ).tobytes()
                    ).digest()
                    setup = build_adaptive_scan_setup(
                        session=time.time_ns() & 0xFFFF_FFFF,
                        generation=1,
                        seed=0x51514E,
                        source_rate_hz=sample_rate_hz,
                        analog_bandwidth_hz=rf_bandwidth_hz,
                        duration_ms=1_200,
                        dwell_ms=120,
                        # Two distinct profiles are required to exercise Fast Lock's
                        # exit path. Target 0 contains the injected ~1 GHz pilot;
                        # target 1 reproduces an ordinary adaptive hop away and back.
                        frequencies_hz=(lo_hz, SECOND_SCAN_LO_HZ),
                        baseline_weights=(1, 1),
                        analysis_digest=digest,
                        rx_mask=3,
                        variable_dwell=protocol == 3,
                    )
                    receipt = run_adaptive_scan_campaign(
                        uri,
                        serial,
                        setup,
                        lambda _visit: ScanOutcome.ACTIVE,
                        mode=AdaptiveScanMode.ADAPTIVE,
                        manual_gain_db=30.0,
                        samples_per_block=1_000_000,
                        visit_sink=retain_first_visit,
                        session_hook=arm_tx2_after_session_start,
                    )
                    assert receipt.run.gate.passed
                    assert captured, "adaptive scan delivered no dual-RX visit"
                    require_counter_marker_free(
                        captured[0].iq, valid_start=captured[0].record.valid_start
                    )
                    signal = ci16_dual_rx(captured[0].iq)
                    # Analyze a bounded number of complete frames; the visit remains
                    # large enough to reproduce the 120 ms release scan geometry.
                    frame_samples = round(sample_rate_hz / 750)
                    metrics = analyze_starlink_pilot_parity(
                        signal[:, : 8 * frame_samples], sample_rate_hz=sample_rate_hz
                    )
                    reports.append(
                        {
                            "serial": serial,
                            "uri": uri,
                            "rf_lo_hz": lo_hz,
                            "rf_bandwidth_hz": rf_bandwidth_hz,
                            "sample_rate_hz": sample_rate_hz,
                            "rx_mask": 3,
                            "protocol_version": protocol,
                            "tx_channel": "TX2",
                            "tx_gain_db": tx_gain_db,
                            "adaptive_gate": dataclasses.asdict(receipt.run.gate),
                            "pilot": dataclasses.asdict(metrics),
                        }
                    )
                finally:
                    if transmitter is not None:
                        transmitter.close()
                    _mute_transmit(sdr)
                    assert float(sdr.tx_hardwaregain_chan0) <= -80.0
                    assert float(sdr.tx_hardwaregain_chan1) <= -80.0
        finally:
            try:
                _mute_transmit(sdr)
                assert float(sdr.tx_hardwaregain_chan0) <= -80.0
                assert float(sdr.tx_hardwaregain_chan1) <= -80.0
            finally:
                if snapshot is not None:
                    _restore_tx(sdr, snapshot)
                close_context = getattr(sdr._ctx, "close", None)
                if callable(close_context):
                    close_context()

    report_path = os.environ.get("PLUTO_ADAPTIVE_PILOT_REPORT", "").strip()
    if report_path:
        _write_report(report_path, reports)


def test_qin_edge_pilot_full_adaptive_scan_has_no_other_channel_glrt() -> None:
    """Run consecutive 200 s scans and classify every complete four-target visit."""

    targets = _targets()
    lo_hz = int(os.environ.get("PLUTO_ADAPTIVE_PILOT_LO_HZ", str(DEFAULT_LO_HZ)))
    tx_gain_db = float(os.environ.get("PLUTO_TX2_LOOPBACK_TX_GAIN_DB", "-50"))
    protocol = int(os.environ.get("PLUTO_ADAPTIVE_PILOT_PROTOCOL", "3"))
    if protocol != 3:
        pytest.fail("the full adaptive scan GLRT gate requires protocol 3")
    if not 900_000_000 <= lo_hz <= 1_100_000_000:
        pytest.fail("adaptive pilot RF frequency must remain in the authorized ~1 GHz band")
    frequencies_hz = tuple(lo_hz + offset for offset in LONG_SCAN_OFFSETS_HZ)

    import adi

    reports: list[dict[str, Any]] = []
    campaign_failures: list[str] = []
    for serial, uri in targets:
        sdr = adi.ad9361(uri=uri)
        snapshot: dict[str, Any] | None = None
        try:
            assert sdr._ctx.attrs.get("hw_serial") == serial
            if float(sdr.tx_hardwaregain_chan0) > -80 or float(sdr.tx_hardwaregain_chan1) > -80:
                pytest.fail(f"{serial} was not muted before the hardware test")
            if sdr._ctrl.find_channel("voltage1", True) is None:
                pytest.fail(f"{serial} does not expose physical TX2")
            snapshot = _snapshot_tx(sdr)
            for sample_rate_hz in LONG_SCAN_RATES_HZ:
                transmitter: _DirectCyclicTx2 | None = None
                analyzer: _FullScanGlrtAnalyzer | None = None
                rows: list[dict[str, Any]] | None = None
                try:
                    _mute_transmit(sdr)
                    sdr.tx_rf_bandwidth = sample_rate_hz
                    sdr.tx_lo = lo_hz
                    waveform = cyclic_tx_waveform(sample_rate_hz)
                    transmitter = _DirectCyclicTx2(sdr, waveform, tx_gain_db)

                    def arm_tx2_after_session_start(
                        _session: Any,
                        radio: Any = sdr,
                        tx_fixture: _DirectCyclicTx2 = transmitter,
                    ) -> None:
                        assert radio is tx_fixture.radio
                        tx_fixture.arm()
                        time.sleep(0.25)

                    analyzer = _FullScanGlrtAnalyzer(sample_rate_hz)
                    digest = hashlib.sha256(
                        np.asarray(
                            qin_lower_edge_pilot_frame(sample_rate_hz), dtype="<c8"
                        ).tobytes()
                    ).digest()
                    setup = build_adaptive_scan_setup(
                        session=time.time_ns() & 0xFFFF_FFFF,
                        generation=1,
                        seed=0x51514E,
                        source_rate_hz=sample_rate_hz,
                        analog_bandwidth_hz=sample_rate_hz,
                        duration_ms=LONG_SCAN_DURATION_MS,
                        dwell_ms=120,
                        frequencies_hz=frequencies_hz,
                        baseline_weights=(1, 1, 1, 1),
                        analysis_digest=digest,
                        maximum_revisit_ms=3_000,
                        rx_mask=3,
                        variable_dwell=True,
                    )
                    receipt = run_adaptive_scan_campaign(
                        uri,
                        serial,
                        setup,
                        lambda visit: (
                            ScanOutcome.ACTIVE
                            if visit.record.target == 0
                            else ScanOutcome.QUIET
                        ),
                        mode=AdaptiveScanMode.ADAPTIVE,
                        manual_gain_db=30.0,
                        samples_per_block=1_000_000,
                        classifier_queue_visits=50,
                        visit_sink=analyzer.observe,
                        session_hook=arm_tx2_after_session_start,
                    )
                    rows = analyzer.finish()
                    analyzer = None

                    if not receipt.run.gate.passed:
                        campaign_failures.append(
                            f"{sample_rate_hz}: adaptive delivery gate failed"
                        )
                    if receipt.run.classification_dropped:
                        campaign_failures.append(
                            f"{sample_rate_hz}: dropped "
                            f"{receipt.run.classification_dropped} classifications"
                        )
                    if len(rows) != receipt.run.metrics.delivered:
                        campaign_failures.append(
                            f"{sample_rate_hz}: analyzed {len(rows)} of "
                            f"{receipt.run.metrics.delivered} delivered visits"
                        )
                    target_rows = {
                        target: [row for row in rows if row["target"] == target]
                        for target in range(4)
                    }
                    positive_misses = [
                        row for row in target_rows[0] if row["glrt_detected"] != [True, True]
                    ]
                    quiet_false_positives = [
                        row
                        for target in range(1, 4)
                        for row in target_rows[target]
                        if row["glrt_detected"] != [False, False]
                    ]

                    reports.append(
                        {
                            "serial": serial,
                            "uri": uri,
                            "duration_ms": LONG_SCAN_DURATION_MS,
                            "sample_rate_hz": sample_rate_hz,
                            "rf_bandwidth_hz": sample_rate_hz,
                            "frequencies_hz": frequencies_hz,
                            "injected_target": 0,
                            "rx_mask": 3,
                            "protocol_version": protocol,
                            "tx_channel": "TX2",
                            "tx_gain_db": tx_gain_db,
                            "adaptive_gate": dataclasses.asdict(receipt.run.gate),
                            "adaptive_metrics": dataclasses.asdict(receipt.run.metrics),
                            "classification_dropped": receipt.run.classification_dropped,
                            "glrt_visit_counts": {
                                str(target): len(target_rows[target]) for target in range(4)
                            },
                            "visits": rows,
                        }
                    )
                    report_path = os.environ.get(
                        "PLUTO_ADAPTIVE_PILOT_LONG_REPORT", ""
                    ).strip()
                    if report_path:
                        _write_report(report_path, reports)
                    missing_targets = [
                        target
                        for target, target_results in target_rows.items()
                        if not target_results
                    ]
                    if missing_targets:
                        campaign_failures.append(
                            f"{sample_rate_hz}: targets delivered no IQ: {missing_targets}"
                        )
                    if positive_misses:
                        examples = [
                            (row["visit"], row["glrt_detected"])
                            for row in positive_misses[:10]
                        ]
                        campaign_failures.append(
                            f"{sample_rate_hz}: {len(positive_misses)} injected-target "
                            "visits did not detect on both receivers: "
                            f"{examples}"
                        )
                    if quiet_false_positives:
                        examples = [
                            (row["visit"], row["target"], row["glrt_detected"])
                            for row in quiet_false_positives[:10]
                        ]
                        campaign_failures.append(
                            f"{sample_rate_hz}: {len(quiet_false_positives)} quiet-target "
                            f"visits produced GLRT detections: {examples}"
                        )
                finally:
                    if analyzer is not None:
                        analyzer.finish()
                    if transmitter is not None:
                        transmitter.close()
                    _mute_transmit(sdr)
                    assert float(sdr.tx_hardwaregain_chan0) <= -80.0
                    assert float(sdr.tx_hardwaregain_chan1) <= -80.0
        finally:
            try:
                _mute_transmit(sdr)
                assert float(sdr.tx_hardwaregain_chan0) <= -80.0
                assert float(sdr.tx_hardwaregain_chan1) <= -80.0
            finally:
                if snapshot is not None:
                    _restore_tx(sdr, snapshot)
                close_context = getattr(sdr._ctx, "close", None)
                if callable(close_context):
                    close_context()

    report_path = os.environ.get("PLUTO_ADAPTIVE_PILOT_LONG_REPORT", "").strip()
    if report_path:
        _write_report(report_path, reports)
    if campaign_failures:
        pytest.fail("; ".join(campaign_failures))
