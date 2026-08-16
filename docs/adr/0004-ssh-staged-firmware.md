# ADR 0004: SSH firmware updates stage one validated FRM

## Status

Accepted for an experimental, explicitly enrolled transport.

## Context

Some managed Pluto+ radios are reachable through network IIO and SSH but are not
attached to the daemon host through USB. The normal mass-storage and DFU firmware
executors therefore cannot update them. An IP address is not a durable hardware
identity, network discovery is not authorization, and a lost SSH connection does
not reveal whether a flash write completed.

Routine Pluto+ updates may replace only the Linux FIT firmware partition (`mtd3`).
Bootloader, U-Boot environment, full release archives, arbitrary remote commands,
and direct `/dev/mtd*` writes are outside this feature.

## Decision

Add a distinct `ssh_frm` transport with these boundaries:

1. A radio must be explicitly enrolled by exact hardware serial, literal network
   endpoint, and pinned SSH host key. Discovery never enrolls a radio.
2. The first version accepts only the hardware-qualified canonical release from
   the shipped policy manifest. Candidate qualification remains a USB volatile-DFU
   workflow.
3. Planning validates the source DFU/FRM, stages a content-addressed `pluto.frm`,
   and binds its hashes, the enrollment, current radio identity, expected firmware,
   expiration, and transport into a one-time plan.
4. Execution re-attests the remote serial, model, firmware, and SSH key immediately
   before mutation. The client can select neither a remote path nor a command.
5. The executor uploads to a plan-specific private temporary file, verifies its
   size and SHA-256 remotely, and invokes only the radio's fixed FRM updater.
6. Updater process status is not sufficient evidence. Output indicating failure is
   a failure even when the process exits zero, and the written FIT body must match
   the planned size and SHA-256 before reset.
7. Each authorized attempt has durable phase evidence. A connection loss after the
   updater starts has an `unknown` outcome and is never retried automatically.
8. Reconciliation is fresh and read-only. It re-attests identity, active firmware,
   and persistent image evidence without invoking the updater.
9. A changed post-reboot host key is never trusted automatically. It requires a
   separate authenticated enrollment reconciliation before another mutation.
10. Remote firmware routes use the existing admin boundary and are unavailable over
    non-loopback plaintext HTTP.

The successful online result is a verified persistent image and a same-radio soft
reboot into the expected firmware. It is not proof that all physical power sources
were removed; field acceptance retains a separate external power-cycle checkpoint.

## Execution phases

The plan exposes the stable phases `preflight`, `authorization`,
`controller_quiesced`, `remote_identity_attested`, `frm_staged`,
`persistent_write`, `mtd_verified`, `reboot_requested`, and
`post_update_attestation`. The executor evidence adds precise checkpoints such as
`update_frm_completed`, `qspi_fit_verified`, `reset_dispatched`, and
`tx_safe_after_reset`. A receipt records completed phases, the failure phase, and
whether reconciliation is required. The one-time token is consumed before
`controller_quiesced` and can never authorize a replay. An unresolved receipt is
also rechecked immediately before token consumption, so a previously issued plan
cannot bypass a later reconciliation lock.

## Consequences

- Network-only installed radios can receive a canonical firmware update without
  exposing a generic remote shell through the API or browser.
- Enrollment and credential deployment are explicit operational prerequisites.
- A network failure can require operator reconciliation even when the actual write
  succeeded.
- Recovery remains the documented USB `firmware.dfu` procedure when the radio no
  longer boots far enough for authenticated SSH.
