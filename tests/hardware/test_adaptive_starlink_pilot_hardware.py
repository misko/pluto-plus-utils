"""Opt-in 10 MS/s adaptive-scan round trip of the Qin Starlink edge pilot."""

from __future__ import annotations

import dataclasses
import gc
import hashlib
import json
import os
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
    qin_lower_edge_pilot_frame,
)

pytestmark = pytest.mark.hardware

SAMPLE_RATE_HZ = 10_000_000
RF_BANDWIDTH_HZ = 8_000_000
DEFAULT_LO_HZ = 960_000_000
SECOND_SCAN_LO_HZ = 1_190_000_000
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


def test_qin_edge_pilot_round_trip_glrt_matches_rx0_and_rx1() -> None:
    """TX2 Qin pilot -> 10 MS/s adaptive dual RX -> independent GLRT gates."""

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
        transmitter: _DirectCyclicTx2 | None = None
        try:
            assert sdr._ctx.attrs.get("hw_serial") == serial
            if float(sdr.tx_hardwaregain_chan0) > -80 or float(sdr.tx_hardwaregain_chan1) > -80:
                pytest.fail(f"{serial} was not muted before the hardware test")
            if sdr._ctrl.find_channel("voltage1", True) is None:
                pytest.fail(f"{serial} does not expose physical TX2")
            snapshot = _snapshot_tx(sdr)
            _mute_transmit(sdr)
            sdr.tx_rf_bandwidth = RF_BANDWIDTH_HZ
            sdr.tx_lo = lo_hz
            waveform = cyclic_tx_waveform(SAMPLE_RATE_HZ)
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
                visit: AdaptiveScanVisit, destination: list[AdaptiveScanVisit] = captured
            ) -> None:
                if visit.record.target == 0 and not destination:
                    destination.append(visit)

            digest = hashlib.sha256(
                np.asarray(
                    qin_lower_edge_pilot_frame(SAMPLE_RATE_HZ), dtype="<c8"
                ).tobytes()
            ).digest()
            setup = build_adaptive_scan_setup(
                session=time.time_ns() & 0xFFFF_FFFF,
                generation=1,
                seed=0x51514E,
                source_rate_hz=SAMPLE_RATE_HZ,
                analog_bandwidth_hz=RF_BANDWIDTH_HZ,
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
            signal = ci16_dual_rx(captured[0].iq)
            # Analyze a bounded number of complete frames; the visit remains
            # large enough to reproduce the 120 ms release scan geometry.
            frame_samples = round(SAMPLE_RATE_HZ / 750)
            metrics = analyze_starlink_pilot_parity(
                signal[:, : 8 * frame_samples], sample_rate_hz=SAMPLE_RATE_HZ
            )
            reports.append(
                {
                    "serial": serial,
                    "uri": uri,
                    "rf_lo_hz": lo_hz,
                    "sample_rate_hz": SAMPLE_RATE_HZ,
                    "rx_mask": 3,
                    "protocol_version": protocol,
                    "tx_channel": "TX2",
                    "tx_gain_db": tx_gain_db,
                    "adaptive_gate": dataclasses.asdict(receipt.run.gate),
                    "pilot": dataclasses.asdict(metrics),
                }
            )
        finally:
            try:
                if transmitter is not None:
                    transmitter.close()
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
