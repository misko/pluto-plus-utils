"""Transport-independent physical intervals used at persistent write boundaries."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Interval:
    start: int
    end: int

    def __post_init__(self) -> None:
        if type(self.start) is not int or type(self.end) is not int:
            raise ValueError("flash intervals require integer byte addresses")
        if not 0 <= self.start < self.end <= 128 * 1024 * 1024:
            raise ValueError("invalid flash interval")

    def contains(self, other: "Interval") -> bool:
        return self.start <= other.start and other.end <= self.end

    def overlaps(self, other: "Interval") -> bool:
        return self.start < other.end and other.start < self.end


def validate_write_intervals(
    payload: Interval,
    footprint: Interval,
    *,
    destination: Interval,
    address_limit: int,
    protected: tuple[Interval, ...] = (),
) -> None:
    """Check both authoritative payload and complete erase/program effects."""
    if type(address_limit) is not int or not 0 < address_limit <= 128 * 1024 * 1024:
        raise ValueError("invalid qualified address limit")
    if not footprint.contains(payload) or not destination.contains(footprint):
        raise ValueError("payload/erase footprint exceeds destination")
    if footprint.end > address_limit:
        raise ValueError("payload/erase footprint exceeds qualified physical range")
    if any(footprint.overlaps(region) for region in protected):
        raise ValueError("erase footprint overlaps a protected region")
