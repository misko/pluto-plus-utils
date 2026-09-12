# Optional persistent-hop metadata extension

`iio_persistent_hop_client(..., metadata_extension=extension)` accepts the narrow
`pluto_plus.metadata_extension.PersistentHopMetadataExtension` port. It is
default-off and imports no detector or application storage implementation.

The extension is single-session state. Its owner supplies a new instance for
each acquisition; do not reuse one for a new session or generation.

1. `negotiate` receives the original validated tandem/HOPR request, context
   attributes, and public Python binding drain availability before OPEN. Return
   unchanged bytes for unsupported peers, or an explicitly negotiated wrapper.
   Negotiation exceptions are recorded and fall back before OPEN. There is no
   automatic second buffer or retry of an arbitrary failed OPEN.
2. `unwrap` returns the exact legacy metadata bytes before strict V6/HOPS/IQ
   parsing. Unrecoverable framing errors must raise; never guess IQ boundaries.
   Full envelope bytes travel separately in an unversioned transient wire block.
3. `consume` runs only after HOPS sequence/counter/tuning, stream generation, and
   IQ payload validation. It must remain bounded, do no blocking I/O, and retain
   no IQ or DMA buffers. Exceptions disable result consumption for that session,
   record an error, and leave valid capture running.
4. `finish` receives independently validated terminal status and a metadata-only
   drain callable before the receive buffer closes. It must bound attempts and
   use the existing finite IIO RPC timeout. No refill or synthetic IQ is allowed.
5. `fail` preserves an explicit unavailable state. Even failure-reporting
   exceptions cannot mask primary capture errors or change capture policy.

The extension owns sequence/provenance checks, delayed-result/source matching,
final inventory reconciliation, and its separate evidence contract. PPU retains
its existing immutable recording receipts. Unsupported drain is explicit; a
missing final result must not be reported as negative signal evidence.

Completion now verifies HOPT's last block sequence and end counter against the
actual delivered HOPS/IQ inventory, as cancellation already did. A forged or
stale terminal inventory cannot authorize a successful result drain.

Hardware-free component tests cover negotiation/fallback, unchanged IQ,
unwrapping, terminal ordering, cancellation, invalid source evidence, and
isolated detector/drain/failure-reporter exceptions. These are not live duty
or detector-specificity qualifications. New RF/deployment remains separately
authorized.
