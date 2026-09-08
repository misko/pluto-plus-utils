# Volatile iiOD companion bundles

The existing `UserspaceIiodDeployment` accepts an optional absolute
`bundle_manifest_path`. Omission preserves the existing single-binary lifecycle.
The bundle does not enable GLRT, change ports, set a loader environment, open
another capture buffer, or install/flash anything. The caller still owns exact
radio selection, ownership locking, RF authorization and the capture lifetime.

This is useful when a userspace iiOD needs an acquisition SDK, worker, templates
and numerical libraries. The daemon and worker must be compiled with literal
paths/RPATH matching the manifest's `remote_directory`. The release builder must
audit their ELF dependencies; declaring a file in a manifest does not prove the
dynamic loader will use it. Core target libc/loader compatibility is a separate
preflight, not established by hashing the companion files.

## Manifest version 1

The manifest lives alongside its companion files in a trusted local directory.
It contains exactly:

- `schema_version`: integer `1`.
- `remote_directory`: `/tmp/ppu-iiod-bundle-` followed by 32 lowercase hex digits,
  chosen at build time and embedded in the binaries.
- `daemon_sha256` and `daemon_bytes`: the exact separately configured iiOD file.
- `files`: 1–16 entries, each with `name`, `sha256`, `bytes`, and boolean
  `executable`. Names are single safe basenames, not paths; `owner`, `iiod`,
  and the manifest's own basename are reserved.

Each file is at most 64 MiB; the daemon and companions total at most 128 MiB.
Local reads reject duplicate keys/names, unexpected fields, symlinks, hardlinks,
nonregular files, untrusted ownership, group/other writes, changed reads and
digest/size mismatches. Payloads are snapshotted before the daemon is uploaded.
The manifest is an operator-approved release input, **not a signed trust root**
and not a proof of detector sensitivity or qualified classification.

## Lifecycle and cleanup

The existing pinned SSH key/password, exact radio serial, healthy stock :30431
and unused alternate :30432 checks still run. The transport stages the daemon,
exclusively creates a private bundle directory and records the daemon session
nonce in `owner`. Existing directories are rejected, including another instance
of the same release. Each companion is uploaded without overwrite, checked for
exact size/SHA-256, and given mode 0700 (executable) or 0600. The complete
directory inventory and hashes are checked again immediately before startup.

The original lifecycle still verifies the daemon PID, start ticks, executable
path, bytes and hash. Companions are removed only after that lifecycle proves
the owned daemon is absent. Cleanup verifies directory ownership, nonce,
permissions, regular-file/link facts, exact contents and complete inventory
before removing only the enumerated paths and then the empty directory. There
is no archive extraction, arbitrary command API, recursive deletion, or write
under QNAP. A later session cannot clean a previous unresolved session's bundle.

Metadata checks use the fixed permission/link-count/numeric-uid fields from
`LC_ALL=C ls -ldn` plus the regular-file/symlink tests. They do not require the
optional BusyBox `stat` applet, which is absent on the tested radio image. Input
paths have already been restricted to canonical directories and safe basenames;
unexpected field output fails closed. Permissions and ownership requirements
are unchanged. A minimal-command regression test omits `stat` entirely.

Interrupted uploads with entirely missing files can be cleaned. A truncated,
changed or unexpected file causes cleanup to fail and **retain the directory**
for inspection. An unresolved process likewise retains its dependencies. Such
failures propagate through the existing cleanup error/notes; they are not
reported as successful rollback. No forced retry or deletion is attempted.

Published V1 daemon start/stop receipts remain unchanged and still enumerate
exactly three daemon files. The separate bundle manifest records companion
identities; do not interpret the three-path receipt as a companion inventory.

## Verification scope

`tests/test_userspace_iiod_bundle.py` exercises input validation, lifecycle
ordering, failed uploads/start/stop, session ownership, default-off behavior,
and real shell commands in an unprivileged local namespace. The shell fixture
substitutes only its test-owned path and expected uid, never invokes SSH and
never starts a radio daemon. Target BusyBox, loader, startup and unchanged live
duty require their own explicitly scoped tests. No test silently skips hardware.
