"""Offline proposed stop receipts; no firmware admission, IIO or RF proof."""

from dataclasses import FrozenInstanceError, replace

import pytest

from pluto_plus.hardware.pss_stop import PssMapStopReceipt

SPAN = 1_280_000
MAX64 = (1 << 64) - 1


def words(*, start=1 << 40, generation=19, ticket=7, has_map=True):
    end = start + SPAN if has_map else 0
    start = start if has_map else 0
    return [0x50535354, 0x0001000C, 6 | (16 if has_map else 0), ticket, ticket,
            generation if has_map else 0, start & 0xFFFFFFFF, start >> 32,
            end & 0xFFFFFFFF, end >> 32, 0, 0]


def encode(values):
    return "PSST 1 12 " + " ".join(f"{value:08x}" for value in values) + "\n"


@pytest.mark.parametrize("start", [0, 1, (1 << 32) - 10, 1 << 40, MAX64 - SPAN])
@pytest.mark.parametrize("ticket", [1, 7, 0xFFFFFFFF])
def test_exact_terminal_candidate_bounds_and_ticket(start, ticket):
    raw = encode(words(start=start, ticket=ticket))
    receipt = PssMapStopReceipt.decode(raw)
    receipt.require_boundary_complete(expected_ticket=ticket)
    assert receipt.raw == raw and receipt.words == tuple(words(start=start, ticket=ticket))
    assert receipt.accepted_ticket == receipt.terminal_ticket == ticket
    assert receipt.terminal_generation == 19
    assert receipt.terminal_candidate_start == start
    assert receipt.terminal_candidate_end == start + SPAN
    assert receipt.has_map and receipt.terminal_valid and receipt.boundary_complete
    assert not receipt.pending and not receipt.failed and not receipt.acquisition_enabled
    assert receipt.failure_reasons == receipt.command_status == 0


def test_empty_history_can_stop_but_provides_no_observed_interval():
    receipt = PssMapStopReceipt.decode(encode(words(has_map=False)))
    receipt.require_boundary_complete(expected_ticket=7)
    assert not receipt.has_map
    assert receipt.terminal_generation == 0
    assert receipt.terminal_candidate_start == receipt.terminal_candidate_end == 0


@pytest.mark.parametrize("index,value", [
    (2, 1 | 32),  # pending request, producer running
    (2, 22 | 1),  # inconsistent pending + terminal: diagnostic only
    (2, 22 & ~2),  # invalidated terminal tuple after restart
    (2, 22 & ~4),  # terminal but not a completed boundary
    (2, 22 | 8),  # failure even with no reason bit
    (2, 22 | 32),  # boundary published but producer still enabled
    (3, 0), (3, 6), (4, 0), (4, 8),
    (5, 0), (5, 0xFFFFFFFF),
    (8, 123),  # not exactly one production map's candidate span
    *((10, 1 << bit) for bit in range(6)),  # retain every known failure cause
    *((11, code) for code in range(1, 6)),
])
def test_negative_or_inconsistent_semantics_retained_not_qualified(index, value):
    values = words()
    values[index] = value
    raw = encode(values)
    receipt = PssMapStopReceipt.decode(raw)
    assert receipt.raw == raw and receipt.words[index] == value
    with pytest.raises(ValueError):
        receipt.require_boundary_complete(expected_ticket=7)


def test_late_failure_keeps_terminal_tuple_but_revokes_success():
    initial = words()
    before = PssMapStopReceipt.decode(encode(initial))
    before.require_boundary_complete(expected_ticket=7)
    initial[2] |= 8
    initial[10] = 2
    after = PssMapStopReceipt.decode(encode(initial))
    assert after.words[3:10] == before.words[3:10]
    with pytest.raises(ValueError, match="failure"):
        after.require_boundary_complete(expected_ticket=7)
    # Immutable historical success cannot replace the caller's fresh receipt.
    assert before.failure_reasons == 0 and after.failure_reasons == 2


@pytest.mark.parametrize("index", [5, 6, 7, 8, 9])
def test_empty_history_rejects_nonzero_generation_or_any_coordinate_word(index):
    values = words(has_map=False)
    values[index] = 1
    receipt = PssMapStopReceipt.decode(encode(values))
    with pytest.raises(ValueError, match="empty publication history"):
        receipt.require_boundary_complete(expected_ticket=7)


def test_wrapped_end_is_retained_as_diagnostic_not_clamped():
    values = words(start=MAX64 - 100)
    values[9] &= 0xFFFFFFFF
    receipt = PssMapStopReceipt.decode(encode(values))
    assert receipt.terminal_candidate_start == MAX64 - 100
    assert receipt.terminal_candidate_end == SPAN - 101
    with pytest.raises(ValueError, match="bounds"):
        receipt.require_boundary_complete(expected_ticket=7)


@pytest.mark.parametrize("expected", [None, True, False, 0, -1, 1 << 32, 7.0, "7", 6, 8])
def test_expected_ticket_is_explicit_exact_nonzero_u32(expected):
    with pytest.raises(ValueError):
        PssMapStopReceipt.decode(encode(words())).require_boundary_complete(
            expected_ticket=expected)


@pytest.mark.parametrize("payload", [None, b"PSST 1 12", "", "x" * 513, "\u00e9",
                                     "PSST 2 12", "PSST 1 13"])
def test_bounded_ascii_and_exact_envelope(payload):
    with pytest.raises(ValueError):
        PssMapStopReceipt.decode(payload)


@pytest.mark.parametrize("index,value", [(0, 0), (1, 0x0002000C), (1, 0x0001000B),
                                        (2, 64), (10, 64), (11, 6)])
def test_unknown_magic_version_reserved_bits_and_command_codes_rejected(index, value):
    values = words()
    values[index] = value
    with pytest.raises(ValueError):
        PssMapStopReceipt.decode(encode(values))


@pytest.mark.parametrize("mutated", ["0000000A", "0x000007", "0000007", "000000007",
                                    "+0000007", "-0000001", "0000000g", "\x007"])
def test_word_lexical_grammar_is_strict(mutated):
    fields = encode(words()).split()
    fields[6] = mutated
    with pytest.raises(ValueError):
        PssMapStopReceipt.decode(" ".join(fields))


@pytest.mark.parametrize("change", [-1, 1])
def test_word_count_is_exact(change):
    fields = encode(words()).split()
    changed = fields[:change] if change < 0 else [*fields, "00000000"]
    with pytest.raises(ValueError):
        PssMapStopReceipt.decode(" ".join(changed))


def test_raw_whitespace_retained_and_construction_cannot_disagree():
    raw = " \t" + encode(words()).replace(" ", "\t") + "\n"
    receipt = PssMapStopReceipt.decode(raw)
    assert receipt.raw == raw
    receipt.require_boundary_complete(expected_ticket=7)
    with pytest.raises(FrozenInstanceError):
        receipt.raw = "different"
    with pytest.raises(ValueError, match="match"):
        replace(receipt, words=(0,) * 12)
    with pytest.raises(ValueError, match="match"):
        replace(receipt, words=list(receipt.words))
    booleans = list(receipt.words)
    booleans[10] = False
    with pytest.raises(ValueError, match="match"):
        replace(receipt, words=tuple(booleans))


def test_schema_decode_does_not_admit_new_firmware_abi():
    from pluto_plus.hardware.pss_iio import _map_contract

    assert _map_contract(15, False)[0] == 0x10001
    assert _map_contract(15, True)[0] == 0x10005
    # Accepted ticket zero is retained for reset-idle diagnostics, not invented success.
    receipt = PssMapStopReceipt.decode(encode([0x50535354, 0x0001000C] + [0] * 10))
    assert receipt.accepted_ticket == 0 and not receipt.terminal_valid
    with pytest.raises(ValueError):
        receipt.require_boundary_complete(expected_ticket=1)


def test_all_known_flag_failure_command_combinations():
    for flags in range(64):
        values = words(has_map=bool(flags & 16))
        values[2] = flags
        for reasons in range(64):
            values[10] = reasons
            for command in range(6):
                values[11] = command
                receipt = PssMapStopReceipt.decode(encode(values))
                if flags in (6, 22) and reasons == 0 and command == 0:
                    receipt.require_boundary_complete(expected_ticket=7)
                else:
                    with pytest.raises(ValueError):
                        receipt.require_boundary_complete(expected_ticket=7)


def test_exact_text_cap_and_last_unambiguous_generation():
    raw = encode(words(generation=0xFFFFFFFE)).ljust(512)
    receipt = PssMapStopReceipt.decode(raw)
    assert len(receipt.raw) == 512 and receipt.terminal_generation == 0xFFFFFFFE
    receipt.require_boundary_complete(expected_ticket=7)
    with pytest.raises(ValueError, match="bounded"):
        PssMapStopReceipt.decode(raw + " ")
