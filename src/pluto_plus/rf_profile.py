"""Explicit AD936x inventory, runtime, and support-policy contracts.

The live device-tree model identifies the selected Linux driver personality;
it does not prove which RFIC is physically fitted. These contracts keep
attested inventory, observed runtime configuration, and qualification policy
separate so none can silently stand in for another.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class _RfModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class PhysicalRfic(StrEnum):
    """A physically fitted RFIC; absence means it has not been attested."""

    AD9361 = "ad9361"
    AD9363 = "ad9363"


class PhysicalRficEvidenceKind(StrEnum):
    """How an inventory record established the fitted RFIC."""

    VISUAL_MARKING = "visual_marking"
    BILL_OF_MATERIALS = "bill_of_materials"
    MANUFACTURER_RECORD = "manufacturer_record"


class PhysicalRficAttestation(_RfModel):
    """Evidence-backed physical RFIC inventory; never derived from IIO."""

    schema_version: Literal[1] = 1
    physical_rfic: PhysicalRfic
    evidence_kind: PhysicalRficEvidenceKind
    evidence_reference: str = Field(min_length=1, max_length=1024)


class Ad936xDriverProfile(StrEnum):
    """Linux AD936x personality selected by the live device tree."""

    AD9361 = "ad9361"
    AD9363A = "ad9363a"
    AD9364 = "ad9364"


class Ad936xChannelMode(StrEnum):
    """RF-interface channel mode selected at boot."""

    ONE_RX_ONE_TX = "1r1t"
    TWO_RX_TWO_TX = "2r2t"


class ReceiverLayout(StrEnum):
    """Digital receive streams exposed by the loaded FPGA design."""

    SINGLE_STREAM = "single_stream"
    DUAL_STREAM = "dual_stream"


class RfConfiguration(_RfModel):
    """Neutral AD936x driver/interface/layout value used by facts or policy."""

    schema_version: Literal[1] = 1
    driver_profile: Ad936xDriverProfile
    channel_mode: Ad936xChannelMode
    receiver_layout: ReceiverLayout

    @model_validator(mode="after")
    def validate_layout(self) -> RfConfiguration:
        if (
            self.channel_mode is Ad936xChannelMode.ONE_RX_ONE_TX
            and self.receiver_layout is not ReceiverLayout.SINGLE_STREAM
        ):
            raise ValueError("1r1t mode exposes one digital receive stream")
        if (
            self.driver_profile is Ad936xDriverProfile.AD9364
            and self.channel_mode is not Ad936xChannelMode.ONE_RX_ONE_TX
        ):
            raise ValueError("the AD9364 driver profile requires 1r1t mode")
        return self


class RfSupportTier(StrEnum):
    """Evidence level assigned by an operating-profile policy."""

    UNVERIFIED = "unverified"
    DEVELOPMENT = "development"
    HARDWARE_QUALIFIED = "hardware_qualified"


class RfOperatingProfile(_RfModel):
    """Named setup policy, separate from observed radio identity and state."""

    schema_version: Literal[1] = 1
    profile_id: str = Field(min_length=1, max_length=128)
    target_configuration: RfConfiguration
    intended_physical_rfic: PhysicalRfic | None = None
    support_tier: RfSupportTier
    qualification_reference: str | None = Field(default=None, min_length=1, max_length=1024)

    @model_validator(mode="after")
    def validate_qualification(self) -> RfOperatingProfile:
        if (
            self.support_tier is RfSupportTier.HARDWARE_QUALIFIED
            and self.qualification_reference is None
        ):
            raise ValueError("hardware-qualified RF profiles require a qualification reference")
        return self
