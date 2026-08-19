# Signal-analysis provenance audit

Audit date: 2026-08-15. The audit was read-only and bounded to the sibling SDR
repositories under `/home/mouse9911/gits` at the revisions below.

| Repository | Revision | Relevant material inspected | Disposition |
|---|---|---|---|
| `leo-tracker-redux` | `292840bac9165317f67262895e1d5b1df5e74db0` | CI16 quality accounting in `src/leo_flow/analysis/recording/quality.py`; paired evidence in `detectors.py` | Conceptual requirements only. No repository-level license was tracked, so no code or fixtures were copied. |
| `spf` | `998bbfce88d1b68159642bebcba4a03785d17dae` | Dual-RX phase/coherence experiments and loopback quality tests; `tests/golden_windows_stats_v3p7.npz` | Not reused. No repository-level license was tracked; the golden file is also unrelated to raw CI16 analyzer truth. |
| `leo-tracker` | `b7d9ce2bc9beb3a5bb9eaf25432d9c03e1d15811` | Carrier, beacon, and IQ-evidence modules; six tracked firmware-acceptance NPZ captures | Not reused. No repository-level license was tracked, and the NPZ files contain hardware measurements rather than portable analyzer truth. |
| `plutosdr-fw` | `de830094a177daf4f577b60b9d3324b41f99ae58` | Top-level aggregate license and firmware tree | No analysis implementation or vector selected. Individual components have differing licenses. |

Two analyzers were implemented independently from standard DSP definitions:

- `quality` accumulates first and second moments of CI16 I/Q components. It
  reports RMS and AC power, DC magnitude, I/Q variance ratio and correlation,
  zero samples, and configurable clipping diagnostics. Its default clipping
  threshold is 2047 counts, matching a 12-bit signed Pluto sample; callers must
  override it for a differently scaled CI16 source.
- `dual_receiver` computes normalized complex cross-correlation over a bounded
  delay search. At the best delay it reports the least-squares complex gain,
  relative phase, residual-power fraction, ordinary coherence, and a conjugate
  coherence diagnostic. A positive delay means receiver B lags receiver A.
- `freq_ladder` was added later, also independently. It segments bursts from a
  per-frame SNR series, identifies each burst's rung from its duration against a
  published schedule, and fits `Df = a * f_IF + b * t + c` so the receiver clock
  error (slope) separates from the LNB local-oscillator error (intercept). Its
  numerical constants - a 35 dB detection threshold, 6 dB of hysteresis, a
  +/-300 kHz search window, and the +8.94 ppm / +94.0 kHz sanity values quoted in
  its tests - are measurements taken on this project's own bench, not values
  imported from another repository.

The tests generate deterministic tones, sparse clipped samples, and seeded
QPSK-like paired data in memory, then pass them through this repository's CI16
writer. Expected values come from the declared synthetic parameters; no sibling
source data or golden outputs are embedded.

Distribution checkpoint: this repository itself does not yet contain a
top-level license. A project license and any required notices should be chosen
before publishing binaries or source releases.
