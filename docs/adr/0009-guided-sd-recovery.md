# ADR 0009: SD recovery has a narrow, evidence-bound boot-write authority

Status: accepted for the orchestration implementation; live profiles pending
hardware qualification.

Normal firmware deployment continues to protect boot regions. A nonbooting radio
requires a separately qualified external bootstrap before repairing those bytes.
Recovery uses the same physical interval validator with an exact operation plan;
there is no general recovery exemption or force flag.

The recovery planner reconstructs a complete expected image from an immutable
target backup, exact rollback FIT and target-specific historical boot provenance.
It emits only differing erase sectors, including preserved bytes outside each
payload. The executor independently rebuilds that authority before dispatch,
binds the current target/writer/geometry/flash, journals intent before each erase
and program, and checks the final complete physical image. It never reboots
automatically after an uncertain operation.

Resume examines actual current bytes and generates a linked successor plan;
progress counters do not authorize writes. A RAM trial must leave flash unchanged.
Persistent recovery requires separate QSPI cold-boot, identity, image, services,
settings and RF-inactivity evidence. Operator reports and machine observations
remain distinguishable.

PPU ships the host workflow. Firmware owns board-compatible bootstrap artifacts,
electrical instructions and qualified identity/boot recipes. The shipped incident recipe binds one exact flash UID and original image and
limits writes below 16 MiB. It records pending RAM/cold-boot acceptance explicitly
and requires those checks during the workflow; it does not grant general hardware
qualification. Diagnostic imports
are retained privately but cannot self-certify physical addressing or enable the
executor. Returning to an older Linux image does not inherit the SD writer's
qualification.
