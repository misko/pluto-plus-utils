# Direct-radio transports

This package is a standalone implementation of the Pluto+ direct-radio wire
contracts and bounded host adapters. It provides strict USB v3
metadata/status/identity/time parsing, direct-IP v1 control messages and UDP
reassembly, finite USB/IP capture, and dual-RX CI16 sample conversion. Constants
and layouts were derived from the SPF direct-radio protocol implementation
reviewed on 2026-08-15; SPF is not a runtime dependency and no sibling source or
test vectors are copied.

`ip_transport.py` adds a finite-capture UDP client with request-ID matching,
peer checks, deadlines, bounded reassembly, and protocol-v3 frame validation.
`hardware.direct_ip.DirectIpRadioDevice` pairs it with a separately
serial-attested IIO control context, and `plutod --direct-ip HOST,SERIAL` exposes
that composition. The loopback gadget tests cover real socket I/O, reordered
fragments, CRC failure, timeout, and controller-compatible dual-RX samples.

`usb_transport.py` adds exact serial/physical-path discovery, lazy libusb
ownership, capability negotiation, orphan STOP/drain, bounded finite reads, and
STOP-on-exit. `hardware.direct_usb.DirectUsbRadioDevice` pairs it with the same
serial-attested IIO control context, and `plutod --direct-usb SERIAL` exposes the
composition. Fake-backend tests cover split bulk reads, CRC failure, cleanup,
sample conversion, and cross-wired serial refusal.

Both transports remain attached-radio pending for measured rate and reconnect
qualification. Callers must discard/restart a stream after `ProtocolError`; the
parser never scans for a plausible frame after corruption.
