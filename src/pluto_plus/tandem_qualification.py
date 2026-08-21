"""Serial-scoped, fail-closed tandem-AGC hardware qualification."""

from __future__ import annotations

import errno
import gc
import json
import math
import os
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np

from pluto_plus.bootstrap_firmware import STANDALONE_FLASH_PROFILES
from pluto_plus.doctor import TANDEM_AGC_V8_RC1_RAM_POLICY
from pluto_plus.hardware.iio import _mute_transmit
from pluto_plus.inventory import scan_local_usb_plutos
from pluto_plus.tandem import (
    RadioMetadataV5,
    TandemEventDirection,
    TandemGainTable,
    TandemMode,
    TandemSessionRequestV1,
    TandemState,
)

SAMPLE_RATE_HZ = 3_000_000
SAMPLES_PER_CHANNEL = 65_536
RF_BANDWIDTH_HZ = 1_500_000
TONE_HZ = 100_000
TONE_SCALE = 0.25
AUTO_TONE_SCALE = 0.9
INITIAL_GAIN_DB = 30
ADC_FULL_SCALE = 2048.0
WATCHDOG_FAULT = 1 << 18
WATCHDOG_SETTLE_SECONDS = 6.5
QUALIFICATION_FREQUENCIES_HZ = (915_000_000, 2_450_000_000, 5_800_000_000)


class TandemQualificationError(RuntimeError):
    """A tandem qualification precondition or live invariant failed."""


@dataclass(frozen=True, slots=True)
class TandemQualificationPlan:
    profile_id: str
    serial: str
    usb_sysfs_path: str
    physical_attenuation_db: float
    strong_tx_gain_db: float
    weak_tx_gain_db: float
    effective_attenuation_db: float
    expected_firmware: str
    expected_metadata_abi: int
    frequencies_hz: tuple[int, ...]
    confirmation_phrase: str


class _MetadataReceiver:
    def __init__(self, sdr: Any, mode: TandemMode) -> None:
        self.sdr = sdr
        self.mode = mode
        self.buffer: Any | None = None

    def open(self) -> None:
        import iio

        metadata_buffer = getattr(iio, "MetadataBuffer", None)
        if metadata_buffer is None:
            raise TandemQualificationError(
                "loaded libiio Python binding lacks MetadataBuffer support"
            )
        self.sdr.rx_destroy_buffer()
        signal = np.asarray(self.sdr.rx())
        self.sdr.rx_destroy_buffer()
        if signal.shape != (2, SAMPLES_PER_CHANNEL) or not np.iscomplexobj(signal):
            raise TandemQualificationError("ordinary RX prime is not paired complex IQ")
        request = TandemSessionRequestV1(mode=self.mode).pack(SAMPLES_PER_CHANNEL)
        self.buffer = metadata_buffer(
            self.sdr._rxadc,
            SAMPLES_PER_CHANNEL,
            request,
            64 * 1024,
        )
        self.sdr._rxbuf = self.buffer

    def capture(self) -> tuple[np.ndarray, RadioMetadataV5]:
        if self.buffer is None:
            raise TandemQualificationError("metadata receiver is not open")
        for attempt in range(65):
            try:
                signal = np.vstack(self.sdr.rx()).astype(np.complex64, copy=False)
                break
            except OSError as error:
                if error.errno != errno.EAGAIN or attempt == 64:
                    raise
        raw = self.buffer.metadata
        if raw is None:
            raise TandemQualificationError("metadata refill returned no header")
        metadata = RadioMetadataV5.unpack(raw)
        if signal.shape != (2, SAMPLES_PER_CHANNEL):
            raise TandemQualificationError("metadata IQ shape is not paired")
        return signal, metadata

    def close(self) -> None:
        buffer = self.buffer
        self.buffer = None
        if getattr(self.sdr, "_rxbuf", None) is buffer:
            self.sdr._rxbuf = None
        close = getattr(buffer, "close", None)
        if callable(close):
            close()
        del buffer
        gc.collect()


def prepare_tandem_qualification(
    serial: str,
    usb_sysfs_path: Path,
    *,
    physical_attenuation_db: float,
    strong_tx_gain_db: float,
    weak_tx_gain_db: float,
    profile_id: str = TANDEM_AGC_V8_RC1_RAM_POLICY.profile_id,
) -> TandemQualificationPlan:
    """Prepare a read-only, exact-local-radio tandem qualification plan."""

    if not serial.strip():
        raise TandemQualificationError("serial must be non-empty")
    profile = STANDALONE_FLASH_PROFILES.get(profile_id)
    if profile is None:
        raise TandemQualificationError(
            f"unknown tandem qualification profile {profile_id!r}; expected one of "
            f"{sorted(STANDALONE_FLASH_PROFILES)}"
        )
    if not profile.tandem_agc or profile.metadata_abi != 2:
        raise TandemQualificationError(
            f"profile {profile_id!r} is not an ABI-2 tandem-AGC profile"
        )
    matches = [
        item
        for item in scan_local_usb_plutos()
        if item.serial == serial and item.usb_path == str(usb_sysfs_path)
    ]
    if len(matches) != 1:
        raise TandemQualificationError(
            "serial and USB path must identify exactly one attached local radio"
        )
    if physical_attenuation_db < 0 or not -80 <= strong_tx_gain_db <= 0:
        raise TandemQualificationError("attenuation/gain values are outside safe bounds")
    if not -80 <= weak_tx_gain_db < strong_tx_gain_db:
        raise TandemQualificationError("weak TX gain must be below the strongest TX gain")
    effective = physical_attenuation_db - strong_tx_gain_db
    if effective < 30:
        raise TandemQualificationError(
            f"unsafe loopback provides {effective:g} dB effective attenuation; 30 dB required"
        )
    phrase = f"QUALIFY TANDEM {serial} {physical_attenuation_db:g}DB"
    return TandemQualificationPlan(
        profile_id=profile_id,
        serial=serial,
        usb_sysfs_path=str(usb_sysfs_path),
        physical_attenuation_db=physical_attenuation_db,
        strong_tx_gain_db=strong_tx_gain_db,
        weak_tx_gain_db=weak_tx_gain_db,
        effective_attenuation_db=effective,
        expected_firmware=profile.policy.device_firmware,
        expected_metadata_abi=profile.metadata_abi,
        frequencies_hz=QUALIFICATION_FREQUENCIES_HZ,
        confirmation_phrase=phrase,
    )


def execute_tandem_qualification(
    plan: TandemQualificationPlan,
    *,
    confirmation: str,
    report_path: Path,
    include_watchdog: bool = True,
) -> dict[str, Any]:
    """Run HOLD, AUTO, and watchdog gates while guaranteeing TX cleanup."""

    if confirmation != plan.confirmation_phrase:
        raise TandemQualificationError(f"confirmation must be exactly {plan.confirmation_phrase!r}")
    fresh = prepare_tandem_qualification(
        plan.serial,
        Path(plan.usb_sysfs_path),
        physical_attenuation_db=plan.physical_attenuation_db,
        strong_tx_gain_db=plan.strong_tx_gain_db,
        weak_tx_gain_db=plan.weak_tx_gain_db,
        profile_id=plan.profile_id,
    )
    if fresh != plan:
        raise TandemQualificationError("qualification plan changed before execution")

    import adi
    import iio

    uris = [
        uri
        for uri, description in iio.scan_contexts().items()
        if uri.startswith("usb:") and f"serial={plan.serial}" in description
    ]
    if len(uris) != 1:
        raise TandemQualificationError(f"expected one serial-scoped USB IIO URI, got {uris}")
    sdr = adi.ad9361(uri=uris[0])
    receiver: _MetadataReceiver | None = None
    report: dict[str, Any] = {
        "schema_version": 2,
        "started_at_unix_ns": time.time_ns(),
        "plan": asdict(plan),
        "usb_uri": uris[0],
        "checks": {},
        "outcome": "started",
    }
    try:
        if sdr._ctx.attrs.get("hw_serial") != plan.serial:
            raise TandemQualificationError("opened IIO context has the wrong serial")
        if sdr._ctx.attrs.get("fw_version") != plan.expected_firmware:
            raise TandemQualificationError("radio firmware does not match the tandem profile")
        if sdr._ctx.attrs.get("iio,buffer-metadata") != str(plan.expected_metadata_abi):
            raise TandemQualificationError("radio metadata ABI does not match the plan")
        if sdr._ctx.find_device("tandem-agc") is None:
            raise TandemQualificationError("radio lacks the tandem-agc capability")
        _configure(sdr)
        report["checks"]["bands"] = []
        for frequency_hz in plan.frequencies_hz:
            gain_table = _expected_gain_table(frequency_hz)
            _configure_frequency(sdr, frequency_hz)
            band_report: dict[str, Any] = {
                "frequency_hz": frequency_hz,
                "expected_gain_table_id": int(gain_table),
            }
            report["checks"]["bands"].append(band_report)
            band_report["hold"] = _qualify_hold(sdr, gain_table)
            band_report["tone"] = _qualify_tone(sdr, plan.strong_tx_gain_db, frequency_hz)
            band_report["auto"] = _qualify_auto(sdr, plan, gain_table)
        if include_watchdog:
            report["checks"]["watchdog"] = _qualify_watchdog(sdr)
            report["checks"]["post_watchdog_hold"] = _qualify_hold(
                sdr, _expected_gain_table(plan.frequencies_hz[-1])
            )
        report["outcome"] = "pass"
    except BaseException as error:
        report["outcome"] = "fail"
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        try:
            if receiver is not None:
                receiver.close()
        finally:
            try:
                _mute_transmit(sdr)
                tandem = sdr._ctx.find_device("tandem-agc")
                report["final_safety"] = {
                    "tx1_gain_db": float(sdr.tx_hardwaregain_chan0),
                    "tx2_gain_db": float(sdr.tx_hardwaregain_chan1),
                    "tandem_state": int(tandem.attrs["state"].value) if tandem else None,
                    "fault_flags": int(tandem.attrs["fault_flags"].value) if tandem else None,
                    "overflow_count": (
                        int(tandem.attrs["overflow_count"].value) if tandem else None
                    ),
                }
            finally:
                report["finished_at_unix_ns"] = time.time_ns()
                _write_report(report_path, report)
                sdr.rx_destroy_buffer()
                sdr._ctx.close()
                del sdr
                gc.collect()
    return report


def _configure(sdr: Any) -> None:
    _mute_transmit(sdr)
    sdr.rx_enabled_channels = [0, 1]
    sdr.sample_rate = SAMPLE_RATE_HZ
    sdr.rx_rf_bandwidth = RF_BANDWIDTH_HZ
    sdr.tx_rf_bandwidth = RF_BANDWIDTH_HZ
    sdr.rx_buffer_size = SAMPLES_PER_CHANNEL
    sdr._rxadc.set_kernel_buffers_count(2)
    sdr.gain_control_mode_chan0 = "manual"
    sdr.gain_control_mode_chan1 = "manual"
    sdr.rx_hardwaregain_chan0 = INITIAL_GAIN_DB
    sdr.rx_hardwaregain_chan1 = INITIAL_GAIN_DB


def _configure_frequency(sdr: Any, frequency_hz: int) -> None:
    _mute_transmit(sdr)
    sdr.rx_destroy_buffer()
    sdr.rx_lo = frequency_hz
    sdr.tx_lo = frequency_hz
    if int(sdr.rx_lo) != frequency_hz or int(sdr.tx_lo) != frequency_hz:
        raise TandemQualificationError(f"radio did not tune both LOs to {frequency_hz}")


def _expected_gain_table(frequency_hz: int) -> TandemGainTable:
    if 200_000_000 <= frequency_hz <= 1_300_000_000:
        return TandemGainTable.MHZ_200_1300
    if 1_300_000_000 < frequency_hz <= 4_000_000_000:
        return TandemGainTable.MHZ_1300_4000
    if 4_000_000_000 < frequency_hz <= 6_000_000_000:
        return TandemGainTable.MHZ_4000_6000
    raise TandemQualificationError(
        f"frequency {frequency_hz} Hz is outside the qualified gain tables"
    )


def _temperature_summary(frames: list[RadioMetadataV5]) -> dict[str, int]:
    values = [
        frame.ad9361_temperature_mdeg_c
        for frame in frames
        if frame.ad9361_temperature_mdeg_c is not None
    ]
    if not values:
        raise TandemQualificationError("no valid cached AD9361 temperature")
    if any(not -40_000 <= value <= 125_000 for value in values):
        raise TandemQualificationError("AD9361 temperature is outside its physical range")
    return {
        "temperature_mdeg_c_min": min(values),
        "temperature_mdeg_c_max": max(values),
    }


def _qualify_hold(sdr: Any, expected_gain_table: TandemGainTable) -> dict[str, Any]:
    receiver = _MetadataReceiver(sdr, TandemMode.HOLD)
    receiver.open()
    try:
        frames = [receiver.capture()[1] for _ in range(2)]
        deadline = time.monotonic() + 2.0
        while not any(
            frame.ad9361_temperature_mdeg_c is not None for frame in frames
        ) and time.monotonic() < deadline:
            frames.append(receiver.capture()[1])
        if any(frame.tandem_state is not TandemState.ARMED_HOLD for frame in frames):
            raise TandemQualificationError("HOLD metadata does not report ARMED_HOLD")
        if any(frame.gain_events or frame.tandem_transition_count for frame in frames):
            raise TandemQualificationError("HOLD unexpectedly changed gain")
        if any(frame.gain_table_id is not expected_gain_table for frame in frames):
            raise TandemQualificationError("HOLD metadata reports the wrong gain table")
        try:
            sdr.rx_hardwaregain_chan0 = INITIAL_GAIN_DB + 1
        except OSError as error:
            if error.errno != errno.EBUSY:
                raise
        else:
            raise TandemQualificationError("HOLD did not own RX gain controls")
        epochs = {frame.ownership_epoch for frame in frames}
        if len(epochs) != 1:
            raise TandemQualificationError("HOLD ownership epoch changed")
        return {
            "frames": len(frames),
            "ownership_epoch": frames[0].ownership_epoch,
            "gain_table_id": int(frames[0].gain_table_id),
            **_temperature_summary(frames),
        }
    finally:
        receiver.close()


def _qualify_tone(sdr: Any, strong_tx_gain_db: float, frequency_hz: int) -> dict[str, Any]:
    _mute_transmit(sdr)
    sdr._ctrl.attrs["calib_mode"].value = "tx_quad"
    sdr.tx_hardwaregain_chan1 = strong_tx_gain_db
    sdr.dds_single_tone(TONE_HZ, TONE_SCALE, channel=1)
    time.sleep(0.25)
    signal = np.asarray(sdr.rx())[:, 1024:]
    sdr.rx_destroy_buffer()
    if signal.shape[0] != 2:
        raise TandemQualificationError("tone preflight did not capture both receivers")
    return _analyze_tone(signal, frequency_hz)


def _analyze_tone(signal: np.ndarray, frequency_hz: int) -> dict[str, Any]:
    signal = np.asarray(signal)
    if signal.ndim != 2 or signal.shape[0] != 2 or signal.shape[1] < 4096:
        raise TandemQualificationError("tone analysis requires two sufficiently long RX channels")
    sample_index = np.arange(signal.shape[1])
    window = np.hanning(signal.shape[1])
    spectra = np.fft.fft(signal * window, axis=1)
    frequencies = np.fft.fftfreq(signal.shape[1], 1 / SAMPLE_RATE_HZ)
    search = np.abs(np.abs(frequencies) - TONE_HZ) <= 25_000
    search_indices = np.flatnonzero(search)
    coarse_index = int(
        search_indices[np.argmax(np.sum(np.abs(spectra[:, search_indices]) ** 2, axis=0))]
    )
    bin_width = SAMPLE_RATE_HZ / signal.shape[1]
    trial_frequencies = np.linspace(
        frequencies[coarse_index] - bin_width,
        frequencies[coarse_index] + bin_width,
        41,
    )
    candidates = []
    for frequency in trial_frequencies:
        trial_reference = np.exp(-2j * np.pi * frequency * sample_index / SAMPLE_RATE_HZ)
        candidates.append(np.mean(signal * trial_reference, axis=1))
    selected = max(
        range(len(candidates)),
        key=lambda index: float(np.sum(np.abs(candidates[index]) ** 2)),
    )
    tone_frequency_hz = float(trial_frequencies[selected])
    reference = np.exp(-2j * np.pi * tone_frequency_hz * sample_index / SAMPLE_RATE_HZ)
    tones = candidates[selected]
    tone_power = np.abs(tones) ** 2
    residual = signal - tones[:, None] / reference[None, :]
    residual_power = np.mean(np.abs(residual) ** 2, axis=1)
    snr_db = 10 * np.log10(np.maximum(tone_power, 1e-12) / np.maximum(residual_power, 1e-12))
    tone_dbfs = 20 * np.log10(np.maximum(np.abs(tones), 1e-12) / ADC_FULL_SCALE)
    clipping = np.mean(
        (np.abs(signal.real) >= ADC_FULL_SCALE - 1) | (np.abs(signal.imag) >= ADC_FULL_SCALE - 1),
        axis=1,
    )
    coherence_denominator = math.sqrt(
        float(np.vdot(signal[0], signal[0]).real * np.vdot(signal[1], signal[1]).real)
    )
    coherence = (
        abs(np.vdot(signal[0], signal[1])) / coherence_denominator if coherence_denominator else 0.0
    )
    diagnostics = {
        "frequency_hz": frequency_hz,
        "tone_frequency_hz": tone_frequency_hz,
        "rx_channels": [
            {
                "channel": f"RX{index + 1}",
                "tone_dbfs": float(tone_dbfs[index]),
                "tone_snr_db": float(snr_db[index]),
                "clipping_fraction": float(clipping[index]),
            }
            for index in range(2)
        ],
        "cross_channel_coherence": coherence,
    }
    if np.any(snr_db < 6) or np.any(tone_dbfs < -75) or np.any(tone_dbfs > -3):
        raise TandemQualificationError(
            f"tone level or SNR is outside qualification bounds: {diagnostics}"
        )
    if np.any(clipping) or coherence < 0.98:
        raise TandemQualificationError(f"tone clipping/coherence gate failed: {diagnostics}")
    return diagnostics


def _qualify_auto(
    sdr: Any,
    plan: TandemQualificationPlan,
    expected_gain_table: TandemGainTable,
) -> dict[str, Any]:
    receiver = _MetadataReceiver(sdr, TandemMode.AUTO)
    sdr.dds_single_tone(TONE_HZ, AUTO_TONE_SCALE, channel=1)
    sdr.tx_hardwaregain_chan1 = plan.weak_tx_gain_db
    receiver.open()
    frames: list[RadioMetadataV5] = []
    attempts: list[dict[str, int]] = []
    try:
        for attempt in range(1, 4):
            start = len(frames)
            sdr.tx_hardwaregain_chan1 = plan.weak_tx_gain_db
            for _ in range(12):
                frames.append(receiver.capture()[1])
                time.sleep(0.02)
            sdr.tx_hardwaregain_chan1 = plan.strong_tx_gain_db
            for _ in range(24):
                frames.append(receiver.capture()[1])
                time.sleep(0.02)
            attempt_frames = frames[start:]
            attempt_events = [event for frame in attempt_frames for event in frame.gain_events]
            attempts.append(
                {
                    "attempt": attempt,
                    "events": len(attempt_events),
                    "first_transition_count": attempt_frames[0].tandem_transition_count,
                    "last_transition_count": attempt_frames[-1].tandem_transition_count,
                }
            )
            directions = {event.direction for frame in frames for event in frame.gain_events}
            if directions == {
                TandemEventDirection.INCREASE,
                TandemEventDirection.DECREASE,
            }:
                break
    finally:
        receiver.close()
    events = [event for frame in frames for event in frame.gain_events]
    directions = {event.direction for event in events}
    if directions != {TandemEventDirection.INCREASE, TandemEventDirection.DECREASE}:
        raise TandemQualificationError(
            "AUTO did not prove bidirectional control: "
            f"frequency_hz={int(sdr.rx_lo)} "
            f"directions={sorted(int(item) for item in directions)} attempts={attempts}"
        )
    if any(frame.tandem_state is not TandemState.ARMED_AUTO for frame in frames):
        raise TandemQualificationError("AUTO metadata does not report ARMED_AUTO")
    if any(frame.rx1_gain_index != frame.rx2_gain_index for frame in frames):
        raise TandemQualificationError("AUTO endpoint gains diverged")
    if any(frame.gain_table_id is not expected_gain_table for frame in frames):
        raise TandemQualificationError("AUTO metadata reports the wrong gain table")
    for previous, current in zip(events, events[1:], strict=False):
        delta = (current.event_sequence - previous.event_sequence) & 0xFFFFFFFF
        if not 1 <= delta < 1 << 31:
            raise TandemQualificationError("AUTO event sequence did not advance")
    return {
        "frames": len(frames),
        "events": len(events),
        "increase_events": sum(
            event.direction is TandemEventDirection.INCREASE for event in events
        ),
        "decrease_events": sum(
            event.direction is TandemEventDirection.DECREASE for event in events
        ),
        "first_transition_count": frames[0].tandem_transition_count,
        "last_transition_count": frames[-1].tandem_transition_count,
        "gain_table_id": int(frames[0].gain_table_id),
        "attempts": attempts,
        **_temperature_summary(frames),
    }


def _qualify_watchdog(sdr: Any) -> dict[str, Any]:
    _mute_transmit(sdr)
    receiver = _MetadataReceiver(sdr, TandemMode.HOLD)
    receiver.open()
    try:
        time.sleep(WATCHDOG_SETTLE_SECONDS)
        tandem = sdr._ctx.find_device("tandem-agc")
        state = int(tandem.attrs["state"].value)
        faults = int(tandem.attrs["fault_flags"].value)
        if state != int(TandemState.FAULTED) or not faults & WATCHDOG_FAULT:
            raise TandemQualificationError("stalled owner did not trigger watchdog rollback")
        sdr.rx_hardwaregain_chan0 = INITIAL_GAIN_DB + 1
        sdr.rx_hardwaregain_chan0 = INITIAL_GAIN_DB
        return {"state": state, "fault_flags": faults}
    finally:
        receiver.close()


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
