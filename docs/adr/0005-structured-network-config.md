# ADR 0005: Network configuration is structured, backed up, and restart-separate

## Status

Accepted.

## Context

Pluto firmware presents `/opt/config.txt` through its mass-storage interface, but
the file is generated at boot from the persistent U-Boot environment. It contains
more than IP settings: deployments can include WLAN credentials and action fields
that reset configuration, enter DFU, or calibrate. An IP address is not a radio
identity, and changing the address of the SSH/IIO connection used by the daemon can
strand an in-flight request.

The application already has an explicit radio-administration enrollment that binds
one managed serial to a literal IP endpoint, pinned SSH host key, and private key.
Privileged Web/API operations already require an admin bearer over HTTPS, loopback,
or a Unix socket.

## Decision

1. Treat `config.txt` as a redacted observation, not as the persistence mechanism.
   The radio-side reader returns only a bounded view and replaces `pwd_wlan` with
   `<redacted>` before data crosses SSH.
2. Expose two structured targets: Ethernet LAN (`ipaddr_eth`, `netmask_eth`) and USB
   gadget (`ipaddr`, `ipaddr_host`, `netmask`). DHCP is supported only for Ethernet
   and is represented by deleting `ipaddr_eth`.
3. Validate canonical IPv4, private/link-local scope, a contiguous netmask, usable
   host addresses, and paired USB addresses in one subnet. No general file, U-Boot
   variable, remote path, password, action, or command input is accepted.
4. Planning freshly attests the enrolled serial and host key, reads a canonical
   digest of all five network values, computes only changed allowed keys, and issues an expiring
   one-time token with an exact human confirmation phrase.
5. Execution re-attests and rechecks the network-value digest before consuming the
   token. The fixed radio-side operation saves a complete private backup, applies
   all changes in one `fw_setenv -s` batch, syncs, and verifies persistent read-back.
   The daemon also stores a mode-0600 backup and durable receipt.
6. Do not reboot automatically. A successful receipt means
   `persisted_restart_required`, not that the running interface changed. The operator
   must first update the daemon's managed IIO endpoint and SSH enrollment when the
   Ethernet address will change, then restart through a separately reviewed action.
7. Discovery never grants administration. Reads as well as writes require the admin
   boundary because the redacted configuration still contains deployment topology.

## Consequences

- CLI and Web users can safely inspect current network settings, select DHCP or a
  static address, review an exact diff, and persist it without arbitrary radio access.
- A changed Ethernet address cannot silently disconnect the service mid-mutation.
- The operator retains an explicit deployment step between persistence and restart.
- Other `config.txt` fields require a separately designed typed workflow rather than
  being smuggled through this interface.
