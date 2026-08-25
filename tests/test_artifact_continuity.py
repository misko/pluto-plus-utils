from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from pluto_plus.artifacts import CaptureWriter, verify_artifact
from pluto_plus.direct_radio.usb import MetadataFlags
from pluto_plus.hardware.base import SampleBlock, SampleBlockV2
from pluto_plus.models import RadioIdentity, RadioSettings, Transport


def _identity() -> RadioIdentity:
    return RadioIdentity(
        radio_id="radio-metadata",
        serial="serial-metadata",
        uri="fake:metadata",
        transport=Transport.FAKE,
    )


def _settings() -> RadioSettings:
    return RadioSettings(sample_rate_hz=1_000_000, bandwidth_hz=800_000)


def _block(
    buffer_sequence: int,
    first_sample_sequence: int,
    *,
    sample_count: int = 4,
    stream_id: int = 77,
    metadata_abi: int = 2,
    metadata_flags: int = int(
        MetadataFlags.SAMPLE_SEQUENCE_VALID
        | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
    ),
    missing_samples_before: int = 0,
) -> SampleBlockV2:
    timestamp = 10_000 + buffer_sequence * 100
    return SampleBlockV2(
        utc_ns=timestamp,
        samples=np.full((2, sample_count), 10 + 20j, dtype=np.complex64),
        stream_id=stream_id,
        buffer_sequence=buffer_sequence,
        first_sample_sequence=first_sample_sequence,
        metadata_flags=metadata_flags,
        metadata_abi=metadata_abi,
        missing_samples_before=missing_samples_before,
        sample_time_realtime_start_ns=timestamp,
        sample_time_realtime_end_ns=timestamp + sample_count,
        sample_time_monotonic_start_ns=timestamp + 1_000,
        sample_time_monotonic_end_ns=timestamp + 1_000 + sample_count,
        sample_time_uncertainty_ns=5,
    )


def _writer(tmp_path: Path) -> CaptureWriter:
    return CaptureWriter(
        tmp_path,
        radio=_identity(),
        settings=_settings(),
        label="continuous",
    )


def test_v2_capture_persists_a_complete_continuity_ledger(tmp_path) -> None:
    writer = _writer(tmp_path)
    writer.append(_block(0, 1_000, sample_count=3), _settings(), 0)
    writer.append(_block(1, 1_003, sample_count=4), _settings(), 0)
    writer.append(_block(2, 1_007, sample_count=2), _settings(), 0)

    artifact = writer.finalize()

    assert artifact.sample_count == 9
    assert verify_artifact(artifact)
    metadata = json.loads(
        (tmp_path / artifact.artifact_id / f"{artifact.artifact_id}.sigmf-meta").read_text()
    )
    continuity = metadata["pluto:continuity"]
    assert continuity == {
        "schema_version": 1,
        "metadata_abi": 2,
        "stream_id": 77,
        "block_count": 3,
        "total_samples": 9,
        "first_sample_sequence": 1_000,
        "last_sample_sequence_exclusive": 1_009,
        "sample_sequence_span": 9,
        "blocks": [
            {
                "sample_start": 0,
                "sample_count": 3,
                "utc_ns": 10_000,
                "metadata_abi": 2,
                "stream_id": 77,
                "buffer_sequence": 0,
                "first_sample_sequence": 1_000,
                "last_sample_sequence_exclusive": 1_003,
                "metadata_flags": int(
                    MetadataFlags.SAMPLE_SEQUENCE_VALID
                    | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
                ),
                "missing_samples_before": 0,
                "sample_time_realtime_start_ns": 10_000,
                "sample_time_realtime_end_ns": 10_003,
                "sample_time_monotonic_start_ns": 11_000,
                "sample_time_monotonic_end_ns": 11_003,
                "sample_time_uncertainty_ns": 5,
            },
            {
                "sample_start": 3,
                "sample_count": 4,
                "utc_ns": 10_100,
                "metadata_abi": 2,
                "stream_id": 77,
                "buffer_sequence": 1,
                "first_sample_sequence": 1_003,
                "last_sample_sequence_exclusive": 1_007,
                "metadata_flags": int(
                    MetadataFlags.SAMPLE_SEQUENCE_VALID
                    | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
                ),
                "missing_samples_before": 0,
                "sample_time_realtime_start_ns": 10_100,
                "sample_time_realtime_end_ns": 10_104,
                "sample_time_monotonic_start_ns": 11_100,
                "sample_time_monotonic_end_ns": 11_104,
                "sample_time_uncertainty_ns": 5,
            },
            {
                "sample_start": 7,
                "sample_count": 2,
                "utc_ns": 10_200,
                "metadata_abi": 2,
                "stream_id": 77,
                "buffer_sequence": 2,
                "first_sample_sequence": 1_007,
                "last_sample_sequence_exclusive": 1_009,
                "metadata_flags": int(
                    MetadataFlags.SAMPLE_SEQUENCE_VALID
                    | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
                ),
                "missing_samples_before": 0,
                "sample_time_realtime_start_ns": 10_200,
                "sample_time_realtime_end_ns": 10_202,
                "sample_time_monotonic_start_ns": 11_200,
                "sample_time_monotonic_end_ns": 11_202,
                "sample_time_uncertainty_ns": 5,
            },
        ],
    }


def test_legacy_capture_format_does_not_gain_a_continuity_claim(tmp_path) -> None:
    writer = _writer(tmp_path)
    writer.append(
        SampleBlock(utc_ns=1, samples=np.ones((2, 4), dtype=np.complex64)),
        _settings(),
        0,
    )

    artifact = writer.finalize()
    metadata = json.loads(
        (tmp_path / artifact.artifact_id / f"{artifact.artifact_id}.sigmf-meta").read_text()
    )

    assert "pluto:continuity" not in metadata


@pytest.mark.parametrize("v2_first", [False, True])
def test_writer_rejects_mixing_legacy_and_v2_blocks(tmp_path, *, v2_first: bool) -> None:
    writer = _writer(tmp_path)
    legacy = SampleBlock(utc_ns=1, samples=np.ones((2, 4), dtype=np.complex64))
    v2 = _block(0, 100)
    first, second = (v2, legacy) if v2_first else (legacy, v2)
    writer.append(first, _settings(), 0)

    with pytest.raises(ValueError, match="cannot be mixed"):
        writer.append(second, _settings(), 0)
    with pytest.raises(RuntimeError, match="cannot finalize discontinuous capture"):
        writer.finalize()


@pytest.mark.parametrize(
    ("second", "message"),
    [
        (_block(1, 104, stream_id=78), "stream_id changed"),
        (_block(2, 104), "buffer_sequence did not increment"),
        (_block(1, 105), "first_sample_sequence does not follow"),
        (_block(1, 104, metadata_abi=3), "metadata ABI is not supported"),
        (_block(1, 104, missing_samples_before=4), "missing samples"),
    ],
)
def test_writer_rejects_discontinuous_v2_blocks(tmp_path, second, message: str) -> None:
    writer = _writer(tmp_path)
    writer.append(_block(0, 100), _settings(), 0)

    with pytest.raises(ValueError, match=message):
        writer.append(second, _settings(), 0)
    with pytest.raises(RuntimeError, match="rejected a prior block"):
        writer.append(_block(1, 104), _settings(), 0)


@pytest.mark.parametrize(
    "failure_flag",
    [
        MetadataFlags.DEVICE_IIO_OVERFLOW,
        MetadataFlags.GAIN_READ_FAILED,
        MetadataFlags.FPGA_EVENT_OVERFLOW,
        MetadataFlags.RSSI_READ_FAILED,
        MetadataFlags.GAIN_OBSERVATION_OVERFLOW,
    ],
)
def test_writer_rejects_every_overflow_or_capture_failure_flag(
    tmp_path, failure_flag: MetadataFlags
) -> None:
    writer = _writer(tmp_path)
    flags = int(
        MetadataFlags.SAMPLE_SEQUENCE_VALID
        | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
        | failure_flag
    )

    with pytest.raises(ValueError, match="overflow or capture failure"):
        writer.append(_block(0, 100, metadata_flags=flags), _settings(), 0)


def test_writer_requires_a_reset_bounded_first_buffer(tmp_path) -> None:
    writer = _writer(tmp_path)

    with pytest.raises(ValueError, match="buffer sequence zero"):
        writer.append(_block(1, 100), _settings(), 0)


@pytest.mark.parametrize(
    ("block", "message"),
    [
        (_block(0, 100, metadata_abi=3), "ABI is not supported"),
        (_block(0, 100, metadata_flags=0), "lacks valid sample-sequence"),
        (
            _block(
                0,
                100,
                metadata_flags=int(MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID),
            ),
            "lacks valid sample-sequence",
        ),
    ],
)
def test_first_metadata_block_must_carry_independent_continuity_evidence(
    tmp_path: Path,
    block: SampleBlockV2,
    message: str,
) -> None:
    writer = _writer(tmp_path)

    with pytest.raises(ValueError, match=message):
        writer.append(block, _settings(), 0)


def test_persisted_count_is_the_iq_samples_per_channel(tmp_path) -> None:
    writer = _writer(tmp_path)
    block = _block(0, 100, sample_count=17)
    writer.append(block, _settings(), 0)

    artifact = writer.finalize()
    metadata = json.loads(
        (tmp_path / artifact.artifact_id / f"{artifact.artifact_id}.sigmf-meta").read_text()
    )

    assert block.sample_count == block.samples.shape[1] == 17
    assert metadata["pluto:continuity"]["blocks"][0]["sample_count"] == 17
