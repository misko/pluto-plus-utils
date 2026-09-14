"""Bounded inline FIT inspection, beyond the legacy container-only checks."""

from __future__ import annotations

import hashlib
import re
import struct
import zlib

from .contracts import FitContract, RecoveryError, digest


def _error(detail: str) -> RecoveryError:
    return RecoveryError("fit_invalid", detail)


def _string(data: bytes) -> str:
    if not data.endswith(b"\0") or b"\0" in data[:-1]:
        raise _error("expected a single terminated string")
    try:
        return data[:-1].decode("ascii")
    except UnicodeError as error:
        raise _error("invalid FIT string") from error


def nodes(data: bytes) -> dict[str, dict[str, bytes]]:
    """Parse a bounded v17 FDT with duplicate and structural checks."""
    if len(data) < 56:
        raise _error("truncated FDT")
    magic, total, structure, strings, reserve, version, compatible, _, ss, st = struct.unpack(
        ">10I", data[:40]
    )
    if magic != 0xD00DFEED or total != len(data) or version != 17 or compatible > 17:
        raise _error("unsupported FDT header")
    if (
        structure % 4
        or reserve % 8
        or not 40 <= structure < structure + st <= total
        or not 40 <= strings <= strings + ss <= total
        or reserve < 40
        or reserve + 16 > total
    ):
        raise _error("invalid FDT offsets")
    if structure < strings + ss and strings < structure + st:
        raise _error("overlapping FDT blocks")
    end_reserve = reserve
    while True:
        if end_reserve + 16 > total:
            raise _error("unterminated reservation map")
        address, size = struct.unpack_from(">QQ", data, end_reserve)
        end_reserve += 16
        if not address and not size:
            break
        # Recovery FIT artifacts have no host-applied memory reservation entries.
        raise _error("unsupported reservation map")
    if any(
        reserve < end and start < end_reserve
        for start, end in ((structure, structure + st), (strings, strings + ss))
    ):
        raise _error("reservation map overlaps data")
    result: dict[str, dict[str, bytes]] = {}
    stack: list[str] = []
    pos, limit = structure, structure + st
    while pos + 4 <= limit:
        token = int.from_bytes(data[pos : pos + 4], "big")
        pos += 4
        if token == 1:
            end = data.find(b"\0", pos, limit)
            if end < 0:
                raise _error("unterminated node")
            name = _string(data[pos : end + 1])
            if (stack and not re.fullmatch(r"[A-Za-z0-9_,@.+-]{1,128}", name)) or (
                not stack and (name or result)
            ):
                raise _error("invalid node name or second root")
            stack.append(name)
            if len(stack) > 32 or len(result) > 4096:
                raise _error("FDT nesting or node count exceeds bound")
            path = "/".join(stack) or "/"
            if path in result:
                raise _error("duplicate node")
            result[path] = {}
            pos = (end + 4) & ~3
        elif token == 2:
            if not stack:
                raise _error("unbalanced end node")
            stack.pop()
        elif token == 3:
            if not stack or pos + 8 > limit:
                raise _error("property outside node or truncated")
            size, nameoff = struct.unpack_from(">II", data, pos)
            pos += 8
            if pos + size > limit or nameoff >= ss:
                raise _error("property exceeds block")
            end = data.find(b"\0", strings + nameoff, strings + ss)
            if end < 0:
                raise _error("unterminated property name")
            name = _string(data[strings + nameoff : end + 1])
            props = result["/".join(stack) or "/"]
            if not name or name in props:
                raise _error("empty or duplicate property")
            props[name] = data[pos : pos + size]
            pos = (pos + size + 3) & ~3
        elif token == 4:
            continue
        elif token == 9:
            if stack or not result or any(data[pos:limit]):
                raise _error("incomplete FDT or trailing structure data")
            return result
        else:
            raise _error("unknown FDT token")
    raise _error("missing FDT end token")


def validate_fit(data: bytes, contract: FitContract, soc: str) -> None:
    if len(data) != contract.size or digest(data) != contract.sha256 or soc != contract.soc:
        raise _error("exact artifact or SoC differs from trusted contract")
    tree = nodes(data)
    config = tree.get(f"/configurations/{contract.configuration}")
    if config is None or "loadables" in config or "script" in config:
        raise _error("missing or unsupported selected configuration")
    if "kernel" not in config or "fdt" not in config:
        raise _error("selected configuration needs kernel and device tree")
    selected = tuple(
        _string(config[key]) for key in ("kernel", "fdt", "ramdisk", "fpga") if key in config
    )
    if len(set(selected)) != len(selected) or set(selected) != set(contract.components):
        raise _error("selected components differ from trusted manifest")
    allocations: list[tuple[int, int]] = []
    for name in selected:
        path = f"/images/{name}"
        props = tree.get(path, {})
        body = props.get("data")
        if not body or any(key in props for key in ("data-offset", "data-position", "data-size")):
            raise _error("only complete inline image data is supported")
        pinned = contract.component_sha256.get(name)
        if pinned is not None and digest(body) != pinned:
            raise _error("component differs from trusted SHA-256 pin")
        compression = _string(props.get("compression", b"none\0"))
        hashes = [
            values
            for child, values in tree.items()
            if child.startswith(path + "/") and child.count("/") == 3
        ]
        if not hashes and pinned is None:
            raise _error("component lacks integrity hash")
        for hashed in hashes:
            algorithm = _string(hashed.get("algo", b"\0"))
            if algorithm not in {"sha256", "sha1"} and not (algorithm == "md5" and pinned):
                raise _error("unsupported component hash/signature")
            expected = hashlib.new(algorithm, body, usedforsecurity=False).digest()
            if hashed.get("value") != expected:
                raise _error("component integrity hash differs")
        expanded_size = len(body)
        if compression == "gzip":
            claimed = contract.expanded_sizes.get(name)
            if claimed is None:
                raise _error("gzip component needs an exact expanded-size contract")
            decoder = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
            try:
                expanded = decoder.decompress(body, claimed + 1)
            except zlib.error as error:
                raise _error("invalid compressed component") from error
            if (
                len(expanded) != claimed
                or not decoder.eof
                or decoder.unused_data
                or decoder.unconsumed_tail
            ):
                raise _error("decompressed size or gzip stream differs")
            expanded_size = claimed
        elif compression != "none":
            raise _error("unsupported component compression")
        elif name in contract.expanded_sizes and contract.expanded_sizes[name] != len(body):
            raise _error("component expanded size differs")
        for key in ("load", "entry"):
            if key not in props:
                continue
            raw = props[key]
            if len(raw) not in (4, 8):
                raise _error("invalid load/entry address")
            address = int.from_bytes(raw, "big")
            end = address + (expanded_size if key == "load" else 1)
            if not contract.ram_start <= address < end <= contract.ram_end:
                raise _error("component load/entry exceeds qualified RAM")
            if key == "load":
                if any(address < b and a < end for a, b in allocations):
                    raise _error("component RAM allocations overlap")
                allocations.append((address, end))
