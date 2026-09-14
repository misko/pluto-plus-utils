"""Strict, immutable recovery evidence and operation contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Name = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]{1,128}$")]
Address = Annotated[StrictInt, Field(ge=0, le=128 * 1024 * 1024)]
Size = Annotated[StrictInt, Field(gt=0, le=128 * 1024 * 1024)]


class RecoveryError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        super().__init__(f"{code}: {detail}")


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def canonical(value: BaseModel | dict[str, object]) -> bytes:
    raw = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    return (json.dumps(raw, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Blob(Contract):
    sha256: Digest
    size: Size


class Region(Contract):
    name: Name
    start: Address
    size: Size
    erase_size: Size

    @property
    def end(self) -> int:
        return self.start + self.size

    @model_validator(mode="after")
    def aligned(self) -> Region:
        if self.start % self.erase_size or self.size % self.erase_size:
            raise ValueError("region must contain complete erase sectors")
        return self


class Geometry(Contract):
    capacity: Size
    regions: tuple[Region, ...]

    @model_validator(mode="after")
    def complete(self) -> Geometry:
        parts = sorted(self.regions, key=lambda p: p.start)
        if not parts or len({p.name for p in parts}) != len(parts):
            raise ValueError("missing or duplicate regions")
        if parts[0].start != 0 or parts[-1].end != self.capacity:
            raise ValueError("layout must cover physical flash")
        if any(a.end != b.start for a, b in zip(parts, parts[1:], strict=False)):
            raise ValueError("layout overlaps or has gaps")
        return self

    def region(self, name: str) -> Region:
        for region in self.regions:
            if region.name == name:
                return region
        raise RecoveryError("geometry_unknown", f"missing {name} region")


class Target(Contract):
    adapter: str = Field(min_length=1, max_length=512)
    topology: str = Field(min_length=1, max_length=512)
    uid: str | None = Field(default=None, max_length=256)
    serial: str | None = Field(default=None, max_length=128)
    board: Name
    soc: Name
    ddr_bytes: StrictInt = Field(gt=0, le=4 * 1024**3)
    jedec: Name


class Observation(Contract):
    target: Target
    geometry: Geometry
    bootstrap_sha256: Digest
    writer_sha256: Digest
    boot_epoch: Name
    qualification_id: Name
    transcript: Blob
    flash_protected: bool


class FitContract(Contract):
    sha256: Digest
    size: Size
    configuration: Name
    soc: Name
    components: tuple[Name, ...]
    ram_start: StrictInt = Field(ge=0)
    ram_end: StrictInt = Field(gt=0, le=4 * 1024**3)
    expected_firmware: str = Field(min_length=1, max_length=256)
    expected_layout: Name
    expanded_sizes: dict[Name, Size] = Field(default_factory=dict)
    component_sha256: dict[Name, Digest] = Field(default_factory=dict)


class Profile(Contract):
    schema_version: Literal[1] = 1
    profile_id: Name
    qualification_id: Name
    board: Name
    soc: Name
    ddr_bytes: StrictInt
    jedec: Name
    geometry: Geometry
    bootstrap_sha256: Digest
    writer_sha256: Digest
    read_limit: Size
    write_limit: Size
    read_evidence: Digest
    write_evidence: Digest
    cold_boot_evidence: Digest | None
    console_only_evidence: Digest
    ram_recipe_evidence: Digest | None
    support: Literal["qualified", "incident"] = "qualified"
    target_uid_sha256: Digest | None = None
    original_flash_sha256: Digest | None = None
    opaque_environment_padding: bool = False
    capture_address: StrictInt = Field(ge=0)
    compare_address: StrictInt = Field(ge=0)
    wiring_instructions: str = Field(min_length=1)
    boot_instructions: str = Field(min_length=1)
    environment_format: Literal["uboot-single-le-crc32-128k"]
    rollback: FitContract
    sd_files: dict[Name, Blob]

    @model_validator(mode="after")
    def bounds(self) -> Profile:
        if self.opaque_environment_padding and self.support != "incident":
            raise ValueError("opaque padding is supported only for a pinned incident environment")
        if self.support == "qualified" and (
            self.cold_boot_evidence is None or self.ram_recipe_evidence is None
        ):
            raise ValueError("qualified support requires completed hardware acceptance")
        if self.support == "incident" and (
            not self.target_uid_sha256
            or not self.original_flash_sha256
            or self.write_limit > 0x1000000
        ):
            raise ValueError("incident support requires an exact target, image and low-bank limit")
        capacity = self.geometry.capacity
        a, b = self.capture_address, self.compare_address
        if not (
            self.read_limit <= capacity
            and self.write_limit <= capacity
            and a + capacity <= self.ddr_bytes
            and b + capacity <= self.ddr_bytes
            and (a + capacity <= b or b + capacity <= a)
            and self.rollback.soc == self.soc
            and self.rollback.ram_start < self.rollback.ram_end <= self.ddr_bytes
        ):
            raise ValueError("invalid qualified flash/RAM bounds")
        return self

    @property
    def sha256(self) -> str:
        return digest(canonical(self))


class Provenance(Contract):
    target_uid: str = Field(min_length=1, max_length=256)
    historical_boot_sha256: Digest
    historical_record_sha256: Digest
    boot_source_sha256: Digest
    rollback_sha256: Digest
    boot_restore_start: Address
    boot_restore_size: Size


class HistoricalBoot(Contract):
    target_uid: str = Field(min_length=1, max_length=256)
    boot_sha256: Digest
    source_receipt_sha256: Digest


class Dispatch(Contract):
    plan_sha256: Digest
    start: Address
    size: Size
    payload_sha256: Digest


class Patch(Contract):
    kind: Literal["fit", "environment", "boot"]
    start: Address
    payload: Blob
    before_sha256: Digest


class Sector(Contract):
    kind: Literal["fit", "environment", "boot"]
    start: Address
    size: Size
    before_sha256: Digest
    after: Blob


class Plan(Contract):
    schema_version: Literal[1] = 1
    policy_version: str
    session_id: Name
    profile_sha256: Digest
    observation: Observation
    original: Blob
    current: Blob
    expected: Blob
    provenance: Provenance
    history: Blob
    boot_source: Blob
    patches: tuple[Patch, ...]
    sectors: tuple[Sector, ...]
    parent_plan: Digest | None = None

    @property
    def sha256(self) -> str:
        return digest(canonical(self))


class ReturnEvidence(Contract):
    target: Target
    fit_sha256: Digest
    firmware: str
    layout: str
    network_ok: bool
    iio_ok: bool
    rf_inactive: bool
    settings_ok: bool
    boot_source: Literal["sd", "ram", "qspi", "unknown"]
    reset_cause: Literal["power_on", "warm", "unknown"]
    boot_epoch: Name
    transcript: Blob
    operator_power_off: bool = False
    operator_sd_removed: bool = False


class Session(Contract):
    schema_version: Literal[1] = 1
    session_id: Name
    adapter: str
    profile_id: str | None = None


class Event(Contract):
    sequence: StrictInt = Field(ge=0)
    previous_sha256: Digest | None
    kind: Name
    data: dict[str, object]
