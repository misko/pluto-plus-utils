# ADR 0002: atomic CI16 SigMF recordings

Status: accepted for v1

Each completed capture is a directory containing one `.sigmf-data` file and one
canonical `.sigmf-meta` document. IQ is little-endian signed 16-bit, ordered by
sample, then receiver, then I/Q component. This preserves native Pluto values
without a complex64 storage expansion.

Capture files are written below `.partial`, flushed and checksummed, and then
published with an atomic directory rename. A failure moves the incomplete tree
below `.failed`; it is never entered into the artifact catalog. Configuration
epochs record retuning or gain changes during an acquisition.
