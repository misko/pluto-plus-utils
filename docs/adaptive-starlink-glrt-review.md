# Adaptive Starlink GLRT review

This review pins the Standard adaptive analysis to
`misko/leo-tracker-reduxredux` `origin/main` commit
`aa43a2bd`. It covers the complete firmware-import-to-detector path for the
v0.58 adaptive rates 2.5, 5, 7.5, and 10 MS/s.

## Result

No GLRT correctness defect was found in the reviewed path. The v6 adaptive
analysis contract accepts all four rates. The firmware importer selects that
contract for protocol-three 5 and 7.5 MS/s archives and retains the compatible
variable-dwell contract for 2.5 and 10 MS/s.

The detector derives every sample count from the selected rate:

- a 20 ms acquisition/GLRT probe and 10 ms production stride;
- sample-rate-derived Qin templates and rounded per-frame starts;
- symbols 2 through 65 for the GLRT-64 decision;
- an exact Qin score and a symbol-rolled control score normalized by the same
  coherent ceiling;
- a five-cell fractional epoch refinement after the integer decision; and
- a 0.025 exact-minus-control margin gate.

The live decision requires a CFO-consistent pair of nonoverlapping probes on
one receiver, with an 8 kHz CFO agreement bound. This prevents one isolated
high score from becoming a detection.

## Independent replay

A deterministic synthetic Qin lower-edge pilot was passed through
`analyze_glrt64_dwell` at each supported rate using both receiver columns.
One probe was scheduled to isolate the numerical scorer, so the paired live
decision was deliberately not expected. Both columns recovered the pilot:

| Rate (MS/s) | RX0 exact | RX1 exact | RX0 margin | RX1 margin |
| ---: | ---: | ---: | ---: | ---: |
| 2.5 | 0.999981 | 0.999975 | 0.921808 | 0.921553 |
| 5.0 | 0.999991 | 0.999988 | 0.920824 | 0.921103 |
| 7.5 | 0.999993 | 0.999992 | 0.920890 | 0.921058 |
| 10.0 | 0.999995 | 0.999994 | 0.920934 | 0.920893 |

The rate-dependent rounded frame geometry exercised the direct-or-FFT GLRT
selection without changing the score definition. No fixed 10 MS/s sample
constant was found in the adaptive detector or fractional refinement path.

## Hardware relationship

The release hardware test intentionally uses a smaller independent GLRT
implementation. It sends the same published Qin lower-edge pilot through TX2,
captures adaptive dual-RX visits at all four rates, and compares RX0 with RX1.
Keeping this gate independent avoids making the release test pass merely
because it calls the production Standard implementation under review.
