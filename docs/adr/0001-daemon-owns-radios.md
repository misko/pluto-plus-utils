# ADR 0001: one daemon owns all radio contexts

Status: accepted

The CLI and web interface do not open libiio or direct-radio transports. They
call a versioned API hosted by `plutod`. The daemon creates one serialized
controller per stable radio identity.

This is required because a Pluto+ dual-RX acquisition is one hardware refill,
not two independently openable receiver streams. It also gives tuning, capture,
scan, recovery, and firmware operations one conflict and lifecycle model.

Local deployments bind to loopback by default. A Unix-domain HTTP transport is
supported by the CLI. Remote exposure requires a later authenticated deployment
profile and is not enabled implicitly.
