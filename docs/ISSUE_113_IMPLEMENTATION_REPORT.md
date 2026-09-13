PPU #113 implementation, deployment and verification
===================================================

Implemented and deployed locally on 2026-09-13. This delivers conservative
host-side prevention and the SSH pre-reboot integrity boundary. Real hardware
qualification for extended addressing remains pending under firmware #99.

**Behavior delivered**

- One physical flash policy validates authoritative FIT bytes, observed partition
  roles/offsets/sizes, actual erase geometry, JEDEC capacity and the complete
  firmware/environment write footprint. It shares interval validation with the
  recovery work. The unqualified limit is physical `0x1000000`, independent of
  transport or vendor. The incident FIT is rejected with its actual and allowed
  sizes/ends before writing.
- Plans and final dispatch bind serial, boot ID, board/kernel/updater/tool
  evidence, image bytes, layout and policy/qualification content. The privileged
  helper and uncontrolled mass-storage updater refuse persistent execution.
- Both standalone SSH paths and the daemon SSH executor use the same locked
  session. It saves private protected-region and previous-FIT recovery evidence,
  rechecks the remote state and staged-file digest immediately before dispatch,
  and verifies FIT/protected bytes and the exact expected environment change
  before reboot. A 128 KiB environment may span multiple actual erase blocks.
- Corruption or incomplete verification prevents automatic reboot/reflash/retry.
  A dispatched but unverified deployment stays `unknown`; a definite integrity
  failure is recorded separately and cannot be cleared by FIT-only reconciliation.
- Concrete DFU runners inspect the exact-path complete RAM alternate inventory
  before download and refuse SF/ambiguous modes, including resume/lifecycle paths.
  No persistent DFU feature or ordinary force override was added.
- Reviewable qualification records require matching board, flash, layout,
  running writer and bootloader evidence, plus write and cold-boot evidence.
  The production registry is empty; synthetic tests alone cannot promote hardware.

The precise compatibility restrictions, recovery files and CLI inspection
semantics are documented in [FLASH_SAFETY.md](FLASH_SAFETY.md).

**Verification**

| Final release snapshot | Result |
|---|---|
| Python 3.11.16 full offline suite | 2,881 passed, 11 skipped |
| Python 3.12.14 full offline suite | 2,881 passed, 11 skipped |
| Python 3.13.15 full offline suite | 2,881 passed, 11 skipped |
| Ruff | Passed |
| mypy | Passed, 86 source files |
| Source distribution and wheel build | Passed |
| Clean wheel install | Passed |
| Tests against deployed package | 241 passed |
| Deployed daemon health, index, JavaScript, CSS | HTTP 200 |
| Deployed CLI to daemon radio listing | Passed using a fake radio |
| Deployed exact incident rejection | `flash_range_unqualified`, allowed FIT 14,680,064 bytes |

The skipped cases are the explicitly enabled browser/hardware lanes and a test
whose transmitter implementation is unavailable. One existing Starlette/httpx
deprecation warning remains. No real flash mutation or hardware qualification was
performed by this task.

The new regressions include exact incident/boundary values, FRM trailer exclusion,
erase rounding, mismatched qualification and stale plans, malformed observations,
environment CRC/semantic changes, disabled mutation routes and DFU mode checks.
A synthetic 32 MiB NOR demonstrates the false-positive logical FIT hash while
boot bytes are overwritten; both direct integrity verification and a complete
session reject that state. An isolated shell test executes the real final wrapper
and proves changed target reports, staged bytes and lock ownership do not invoke
the updater.

**Deployed artifacts**

The user-local commands are:

```text
/home/mouse9911/.local/bin/pluto
/home/mouse9911/.local/bin/plutod
```

They select the installed wheel code in:

```text
/home/mouse9911/.local/share/pluto-plus-utils/releases/issue-113-5fb4fce52cda/runtime
```

The command launchers use this host's existing Python and hardware dependencies
at `/home/mouse9911/gits/pluto-plus-utils/.venv/bin/python`. This keeps the deployed
code independent of the development checkout without replacing the environment
used by concurrent development. Retain that interpreter/environment for these
launchers. `uv run` inside the checkout remains the development workflow.

Wheel: `pluto_plus_utils-0.1.0-py3-none-any.whl`

SHA-256:
`5fb4fce52cdadfc05cbc223272d87fc61d7c5425c5e97e8ae3071ab618021948`

The same release directory retains the source distribution, source-file digest
manifest, all three full test logs, clean-install smoke result, deployed smoke
result and deployed test log. Source base is `4bc2ca6` with the recorded workspace
changes. Existing profile work was preserved. The concurrent #114 recovery feature
was excluded from this release, except for the reviewed interval helper now used
directly by the shared flash policy. Later #114 CLI edits remain in the development
checkout and do not change the installed release.

Only the user-local CLI was deployed. The existing LEO acquisition service was
not restarted; temporary verification daemons used fake radios and were stopped
cleanly. Remote-host deployment and independent physical/cold-boot qualification
are not implied by these results.

**Integration for remote main**

The #113 changes were isolated from the pre-existing detector-profile edits and
the concurrent #114 recovery implementation, then rebased onto remote main
`dd5f151`. The shared interval helper is included because the flash policy uses it.
On this integrated source, Python 3.11.16 reports **3,503 passed, 11 skipped**;
Ruff, mypy (93 source files), diff whitespace checks, and the wheel/source build
pass. The earlier three-version and deployed-wheel results above describe the
frozen local release; rebasing does not replace that installed release.
