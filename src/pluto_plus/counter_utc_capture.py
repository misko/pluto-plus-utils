"""Optional control-plane timing collection; never owns or cancels IQ capture."""

from __future__ import annotations

import csv
import math
import subprocess
import threading
import time
from collections.abc import Callable
from decimal import Decimal, InvalidOperation

from .adaptive_scan import ScanSetup
from .adaptive_scan_client import AdaptiveScanClient
from .counter_utc import (
    DEFAULT_TIMING_POLICY,
    CounterUtcEvidence,
    HostClock,
    TimeAnchor,
    TimingPolicy,
)


def chrony_bound(output: str, realtime_ns: int) -> tuple[str, int]:
    """chronyc -c tracking: offset + root dispersion + half root delay.

    Includes a conservative one-second ageing allowance at reported skew.
    The upstream reference being correct remains an explicit NTP assumption.
    """
    fields = next(csv.reader([output.strip()]))
    # Reference ID and address occupy separate CSV columns (unlike the
    # human-readable report's single "Reference ID" line).
    if len(fields) != 14 or fields[13] != "Normal" or not 0 < int(fields[2]) < 16:
        raise ValueError("chrony is not synchronized")
    if fields[0] in ("00000000", "0", "127.127.1.1", "7F7F0101"):
        raise ValueError("chrony source is not an external UTC reference")
    values = [Decimal(fields[i]) for i in (3, 4, 9, 10, 11)]
    if any(not x.is_finite() for x in values):
        raise ValueError("chrony returned nonfinite clock evidence")
    reference, offset, skew, delay, dispersion = values
    age = Decimal(realtime_ns) / 10**9 - reference
    if age < -1 or age > 1200 or min(skew, delay, dispersion) < 0:
        raise ValueError("chrony reference is stale or invalid")
    bound = abs(offset) + dispersion + delay / 2 + skew / 10**6
    return f"chrony:{fields[0]}:{fields[1]}:stratum-{fields[2]}", math.ceil(bound * 10**9)


def read_host_clock() -> HostClock:
    source, bound, reason = "unavailable", None, "chrony evidence unavailable"
    tracking_csv = None
    try:
        result = subprocess.run(
            ["chronyc", "-c", "tracking"], capture_output=True, text=True, timeout=0.5, check=True
        )
        tracking_csv = result.stdout.strip()
        source, bound = chrony_bound(tracking_csv, time.time_ns())
        reason = "chrony tracking bound; assumes a correct external reference"
    except (OSError, subprocess.SubprocessError, ValueError, InvalidOperation) as error:
        reason = str(error)
    before = time.monotonic_ns()
    realtime = time.time_ns()
    after = time.monotonic_ns()
    return HostClock(
        monotonic_before_ns=before,
        realtime_ns=realtime,
        monotonic_after_ns=after,
        source=source,
        utc_error_bound_ns=bound,
        reason=reason,
        tracking_csv=tracking_csv,
    )


class CounterUtcCollector:
    def __init__(
        self,
        client: AdaptiveScanClient,
        setup: ScanSetup,
        serial: str,
        *,
        policy: TimingPolicy = DEFAULT_TIMING_POLICY,
        clock: Callable[[], HostClock] = read_host_clock,
    ) -> None:
        self.client, self.setup, self.serial = client, setup, serial
        self.policy, self.clock = policy, clock
        self.anchors: list[TimeAnchor] = []
        self.errors: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="counter-utc", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> CounterUtcEvidence:
        self._stop.set()
        self._thread.join(timeout=5)
        if self._thread.is_alive():
            # All normal I/O has bounded timeouts. Never expose concurrently
            # mutable observations if a custom connector violates that contract.
            return CounterUtcEvidence(
                session=self.setup.session,
                generation=self.setup.generation,
                radio_serial=self.serial,
                policy=self.policy,
                errors=("timing collector timed out",),
            )
        return CounterUtcEvidence(
            session=self.setup.session,
            generation=self.setup.generation,
            radio_serial=self.serial,
            policy=self.policy,
            anchors=tuple(self.anchors),
            errors=tuple(self.errors),
        )

    def _run(self) -> None:
        try:
            if not self.client.supports_counter_time():
                self.errors.append("firmware does not support counter-time observations")
                return
            request = 0
            while not self._stop.is_set():
                request += 1
                try:
                    before = self.clock()
                    send = time.monotonic_ns()
                    observation = self.client.counter_time("cf-ad9361-lpc", self.setup, request)
                    receive = time.monotonic_ns()
                    after = self.clock()
                    if observation is not None:
                        self.anchors.append(
                            TimeAnchor(
                                observation=observation,
                                send_monotonic_ns=send,
                                receive_monotonic_ns=receive,
                                clock_before=before,
                                clock_after=after,
                            )
                        )
                except (OSError, RuntimeError, ValueError) as error:
                    self.errors.append(f"query {request}: {error}")
                if self._stop.wait(0.05 if request < 8 else 5):
                    break
        except (OSError, RuntimeError, ValueError) as error:
            self.errors.append(str(error))
