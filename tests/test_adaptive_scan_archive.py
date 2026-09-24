from __future__ import annotations

import hashlib
import json

import zstandard as zstd

from pluto_plus.adaptive_scan import ScanTerminal, ScanVisit, TerminalState, VisitResult
from pluto_plus.adaptive_scan_archive import AdaptiveScanArchive
from pluto_plus.adaptive_scan_campaign import build_adaptive_scan_setup
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit


def test_archive_seals_exact_complete_iq(tmp_path):
    setup = build_adaptive_scan_setup(
        session=7,
        generation=8,
        seed=9,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=10_000_000,
        duration_ms=300_000,
        dwell_ms=120,
        frequencies_hz=(1_190_312_500,),
        baseline_weights=(1,),
        analysis_digest=b"x" * 32,
    )
    record = ScanVisit(
        session=7,
        generation=8,
        visit=0,
        target=0,
        profile=1,
        result=VisitResult.COMPLETE,
        frequency_hz=1_190_312_500,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=10_000_000,
        selection_counter=90,
        transition_before=100,
        transition_after=180,
        valid_start=200,
        valid_end=204,
        missing_samples_before=0,
        eligible_mask=1,
        effective_weight=1,
        profile_crc32=1,
        iq_bytes=16,
    )
    archive = AdaptiveScanArchive(tmp_path, "scan-test", setup)
    archive.append(AdaptiveScanVisit(record, bytes(range(16))))
    terminal = ScanTerminal(
        session=7,
        generation=8,
        planned=1,
        delivered=1,
        skipped=0,
        invalid=0,
        cancelled=0,
        final_counter=204,
        restore_before=205,
        restore_after=206,
        iq_bytes=16,
        state=TerminalState.COMPLETED,
        reason=0,
        error=0,
    )
    destination = archive.finish(terminal, {"run": "ok"})
    manifest = json.loads((destination / "manifest.json").read_text())
    item = manifest["visits"][0]["iq"]
    compressed = (destination / item["relative_path"]).read_bytes()
    assert zstd.ZstdDecompressor().decompress(compressed) == bytes(range(16))
    expected = "sha256:" + hashlib.sha256(bytes(range(16))).hexdigest()
    assert manifest["uncompressed_sha256"] == expected
    assert not (tmp_path / ".scan-test.partial").exists()


def test_dual_archive_declares_both_receivers_and_classifier(tmp_path):
    setup = build_adaptive_scan_setup(
        session=7,
        generation=8,
        seed=9,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_500_000,
        duration_ms=300_000,
        dwell_ms=120,
        frequencies_hz=(1_190_312_500,),
        baseline_weights=(1,),
        analysis_digest=b"x" * 32,
        rx_mask=3,
    )
    archive = AdaptiveScanArchive(tmp_path, "scan-dual", setup)
    terminal = ScanTerminal(
        session=7,
        generation=8,
        planned=0,
        delivered=0,
        skipped=0,
        invalid=0,
        cancelled=0,
        final_counter=0,
        restore_before=1,
        restore_after=2,
        iq_bytes=0,
        state=TerminalState.COMPLETED,
        reason=0,
        error=0,
    )

    destination = archive.finish(terminal, {"run": "ok"})
    manifest = json.loads((destination / "manifest.json").read_text())

    assert manifest["sample_layout"] == "sample_rx_iq_interleaved"
    assert manifest["physical_receivers"] == [0, 1]
    assert manifest["classifier_physical_receiver"] == 1
