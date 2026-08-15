from __future__ import annotations

import json

import numpy as np

from pluto_plus.artifacts import CaptureWriter, complex_to_ci16, verify_artifact
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import RadioIdentity, RadioSettings, Transport


def _identity() -> RadioIdentity:
    return RadioIdentity(
        radio_id="radio-a",
        serial="serial-a",
        uri="fake:serial-a",
        transport=Transport.FAKE,
    )


def test_ci16_layout_is_sample_then_receiver_then_iq() -> None:
    samples = np.asarray([[1 + 2j, 3 + 4j], [5 + 6j, 7 + 8j]], dtype=np.complex64)
    encoded = complex_to_ci16(samples)
    np.testing.assert_array_equal(
        encoded,
        np.asarray([[[1, 2], [5, 6]], [[3, 4], [7, 8]]], dtype="<i2"),
    )


def test_capture_writer_atomically_publishes_verifiable_sigmf(tmp_path) -> None:
    settings = RadioSettings(sample_rate_hz=1_000_000, bandwidth_hz=1_000_000)
    writer = CaptureWriter(tmp_path, radio=_identity(), settings=settings, label="bench")
    writer.append(
        SampleBlock(utc_ns=1, samples=np.ones((2, 8), dtype=np.complex64) * (10 + 20j)),
        settings,
        0,
    )
    retuned = settings.model_copy(update={"center_frequency_hz": 916_000_000})
    writer.append(
        SampleBlock(utc_ns=2, samples=np.ones((2, 8), dtype=np.complex64) * (30 + 40j)),
        retuned,
        1,
    )

    artifact = writer.finalize()

    assert artifact.sample_count == 16
    assert artifact.receiver_count == 2
    assert verify_artifact(artifact)
    assert not (tmp_path / ".partial" / artifact.artifact_id).exists()
    metadata = json.loads(
        (tmp_path / artifact.artifact_id / f"{artifact.artifact_id}.sigmf-meta").read_text()
    )
    assert metadata["global"]["core:datatype"] == "ci16_le"
    assert [epoch["sample_start"] for epoch in metadata["captures"]] == [0, 8]


def test_failed_capture_never_appears_as_complete(tmp_path) -> None:
    writer = CaptureWriter(tmp_path, radio=_identity(), settings=RadioSettings(), label=None)
    artifact_id = writer.artifact_id
    failed = writer.fail(RuntimeError("injected"))

    assert failed == tmp_path / ".failed" / artifact_id
    assert not (tmp_path / artifact_id).exists()
    assert json.loads((failed / "failure.json").read_text())["message"] == "injected"
