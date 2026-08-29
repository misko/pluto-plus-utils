"""Bounded Pluto data-plane probing and exact-radio iiOD recovery."""

from __future__ import annotations

import importlib
import re
import time
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from datetime import UTC, datetime
from types import ModuleType
from typing import Any, Literal, Protocol

import numpy as np
from pydantic import Field, model_validator

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import context_facts, resolve_iio_uri
from pluto_plus.hardware.iio_metadata import configure_iio_context_timeout
from pluto_plus.hardware.preflight import inspect_iio_environment
from pluto_plus.models import ApiModel

DEFAULT_DATA_PLANE_PROBE_SAMPLES = 65_536
WIRE_BYTES_PER_COMPLEX_SAMPLE = 4
SUPPORTED_FIRMWARE_CMA_BYTES = 64 * 1024 * 1024
MAX_SAFE_CMA_FRACTION = 0.5
MAX_SAFE_IIO_BUFFER_BYTES = round(SUPPORTED_FIRMWARE_CMA_BYTES * MAX_SAFE_CMA_FRACTION)
IIOD_RECOVERY_SCHEMA: Literal["pluto-plus-utils.iiod-recovery-receipt.v1"] = (
    "pluto-plus-utils.iiod-recovery-receipt.v1"
)
_SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


class DataPlaneRecoveryError(RadioConfigurationError):
    """The bounded probe or iiOD restart could not be verified."""


class RecoveryTransport(Protocol):
    def run(
        self,
        command: str,
        *,
        stdin: bytes | None = None,
        timeout_s: float = 15,
    ) -> str: ...


class DataPlaneProbe(ApiModel):
    status: Literal["pass", "fail"]
    serial: str = Field(min_length=1, max_length=128)
    uri: str = Field(min_length=1, max_length=512)
    samples_per_channel: int = Field(gt=0)
    receiver_count: int | None = Field(default=None, gt=0)
    wire_bytes: int | None = Field(default=None, gt=0)
    elapsed_ms: float = Field(ge=0)
    failure_kind: Literal["timeout", "identity", "environment", "invalid_data", "io"] | None = None
    error: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> DataPlaneProbe:
        if self.status == "pass" and (self.failure_kind is not None or self.error is not None):
            raise ValueError("passing data-plane probe cannot carry failure evidence")
        if self.status == "fail" and (self.failure_kind is None or self.error is None):
            raise ValueError("failed data-plane probe requires a failure kind and error")
        return self


class IiodRestartEvidence(ApiModel):
    serial: str = Field(min_length=1, max_length=128)
    previous_pid: int = Field(gt=0)
    replacement_pid: int = Field(gt=0)
    previous_start_ticks: int = Field(gt=0)
    replacement_start_ticks: int = Field(gt=0)
    active_rx_buffers_before: int = Field(ge=0)
    cma_total_bytes: int = Field(gt=0)
    cma_free_before_bytes: int = Field(ge=0)
    cma_free_after_bytes: int = Field(ge=0)


class DataPlaneRuntimeStatus(ApiModel):
    """Read-only radio runtime evidence around one bounded RX probe."""

    serial: str = Field(min_length=1, max_length=128)
    iiod_pid: int = Field(gt=0)
    iiod_start_ticks: int = Field(gt=0)
    iiod_generation: int = Field(gt=0)
    active_rx_buffers: int = Field(ge=0)
    rx_buffer_length: int | None = Field(default=None, ge=0)
    rx_data_available: int | None = Field(default=None, ge=0)
    rx_device_path: str = Field(min_length=1, max_length=1024)
    cma_total_bytes: int = Field(gt=0)
    cma_free_bytes: int = Field(ge=0)
    memory_total_bytes: int = Field(gt=0)
    memory_available_bytes: int = Field(ge=0)
    interrupt_total: int = Field(ge=0)
    fpga_devices: tuple[str, ...] = Field(max_length=64)
    dma_devices: tuple[str, ...] = Field(max_length=32)
    interrupt_lines: tuple[str, ...] = Field(max_length=64)
    kernel_events: tuple[str, ...] = Field(max_length=64)


class IiodRecoveryReceipt(ApiModel):
    schema_id: Literal["pluto-plus-utils.iiod-recovery-receipt.v1"] = Field(
        IIOD_RECOVERY_SCHEMA, alias="schema"
    )
    schema_version: Literal[1] = 1
    receipt_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    started_at: datetime
    finished_at: datetime
    serial: str = Field(min_length=1, max_length=128)
    uri: str = Field(min_length=1, max_length=512)
    ssh_host: str = Field(min_length=1, max_length=64)
    ssh_interface: str | None = Field(default=None, min_length=1, max_length=64)
    usb_sysfs_path: str | None = Field(default=None, min_length=1, max_length=512)
    known_hosts_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_probe: DataPlaneProbe
    restart: IiodRestartEvidence | None = None
    after_probe: DataPlaneProbe | None = None
    outcome: Literal["recovered", "failed"]
    error: str | None = None

    @model_validator(mode="after")
    def validate_outcome(self) -> IiodRecoveryReceipt:
        if self.finished_at < self.started_at:
            raise ValueError("recovery receipt cannot finish before it starts")
        if self.outcome == "recovered":
            if self.error is not None or self.restart is None or self.after_probe is None:
                raise ValueError("recovered receipt requires restart and post-probe evidence")
            if self.after_probe.status != "pass":
                raise ValueError("recovered receipt requires a passing post-restart probe")
        elif self.error is None:
            raise ValueError("failed recovery receipt requires an error")
        return self


def iio_buffer_wire_bytes(sample_count: int, receiver_count: int) -> int:
    """Return the contiguous IIO payload allocation for one RX buffer."""

    if sample_count <= 0:
        raise ValueError("sample_count must be positive")
    if receiver_count <= 0:
        raise ValueError("receiver_count must be positive")
    return sample_count * receiver_count * WIRE_BYTES_PER_COMPLEX_SAMPLE


def require_safe_iio_buffer(sample_count: int, receiver_count: int) -> int:
    """Reject single allocations above half of the supported firmware CMA pool."""

    requested = iio_buffer_wire_bytes(sample_count, receiver_count)
    if requested > MAX_SAFE_IIO_BUFFER_BYTES:
        raise DataPlaneRecoveryError(
            "single IIO RX buffer requests "
            f"{requested / (1024 * 1024):.1f} MiB, above the "
            f"{MAX_SAFE_IIO_BUFFER_BYTES / (1024 * 1024):.1f} MiB safety ceiling "
            "(50% of the supported firmware CMA pool); use repeated/streaming buffers"
        )
    return requested


def probe_iio_data_plane(
    uri: str,
    serial: str,
    *,
    samples_per_channel: int = DEFAULT_DATA_PLANE_PROBE_SAMPLES,
    adi_module: ModuleType | Any | None = None,
    iio_contexts: Mapping[str, str] | None = None,
) -> DataPlaneProbe:
    """Perform one exact-serial, bounded RX refill without changing RF settings."""

    if not _SERIAL_PATTERN.fullmatch(serial):
        raise ValueError("invalid radio serial")
    require_safe_iio_buffer(samples_per_channel, 2)
    started = time.perf_counter_ns()
    resolved_uri = uri
    device: Any | None = None
    receiver_count: int | None = None
    wire_bytes: int | None = None
    try:
        if adi_module is None:
            environment = inspect_iio_environment(
                require_usb=uri.strip().casefold().startswith("usb:")
            )
            if not environment.healthy:
                raise DataPlaneRecoveryError(
                    f"IIO environment preflight failed: {environment.actionable_message}"
                )
        module = adi_module or importlib.import_module("adi")
        resolved_uri = resolve_iio_uri(uri, serial, contexts=iio_contexts)
        device = module.ad9361(uri=resolved_uri)
        configure_iio_context_timeout(device.ctx)
        facts = context_facts(device.ctx)
        observed_serial = str(facts.get("serial") or "")
        if observed_serial != serial:
            raise DataPlaneRecoveryError(
                f"data-plane context attested serial {observed_serial!r}, expected {serial!r}"
            )
        channels = tuple(int(value) for value in device.rx_enabled_channels)
        if not channels:
            raise DataPlaneRecoveryError("data-plane context has no enabled RX channels")
        receiver_count = len(channels)
        wire_bytes = require_safe_iio_buffer(samples_per_channel, receiver_count)
        device.rx_destroy_buffer()
        device.rx_buffer_size = samples_per_channel
        values = np.asarray(device.rx())
        if receiver_count == 1 and values.ndim == 1:
            values = values[np.newaxis, :]
        expected_shape = (receiver_count, samples_per_channel)
        if values.ndim != 2 or values.shape != expected_shape:
            raise DataPlaneRecoveryError(
                f"data-plane refill returned {values.shape}, expected {expected_shape}"
            )
        device.rx_destroy_buffer()
    except Exception as error:
        return DataPlaneProbe(
            status="fail",
            serial=serial,
            uri=resolved_uri,
            samples_per_channel=samples_per_channel,
            receiver_count=receiver_count,
            wire_bytes=wire_bytes,
            elapsed_ms=(time.perf_counter_ns() - started) / 1_000_000,
            failure_kind=_probe_failure_kind(error),
            error=f"{type(error).__name__}: {error}",
        )
    finally:
        _release_probe_device(device)
    return DataPlaneProbe(
        status="pass",
        serial=serial,
        uri=resolved_uri,
        samples_per_channel=samples_per_channel,
        receiver_count=receiver_count,
        wire_bytes=wire_bytes,
        elapsed_ms=(time.perf_counter_ns() - started) / 1_000_000,
    )


def wait_for_iio_data_plane(
    uri: str,
    serial: str,
    *,
    timeout_s: float = 15,
    poll_interval_s: float = 0.5,
    probe: Callable[[str, str], DataPlaneProbe] | None = None,
) -> DataPlaneProbe:
    """Retry transient iiOD startup until one bounded refill passes or time expires."""

    if timeout_s <= 0 or poll_interval_s <= 0:
        raise ValueError("data-plane wait timeouts must be positive")
    selected_probe = probe or probe_iio_data_plane
    deadline = time.monotonic() + timeout_s
    last: DataPlaneProbe | None = None
    while time.monotonic() < deadline:
        last = selected_probe(uri, serial)
        if last.status == "pass":
            return last
        if last.failure_kind in {"identity", "environment"}:
            return last
        time.sleep(poll_interval_s)
    if last is None:
        return selected_probe(uri, serial)
    return last


def restart_attested_iiod(
    transport: RecoveryTransport,
    serial: str,
    *,
    timeout_s: float = 30,
) -> IiodRestartEvidence:
    """Restart only the iiOD serving the fixed, remotely attested radio serial."""

    if not _SERIAL_PATTERN.fullmatch(serial):
        raise ValueError("invalid radio serial")
    if timeout_s < 5 or timeout_s > 120:
        raise ValueError("iiOD recovery timeout must be between 5 and 120 seconds")
    output = transport.run(
        f"sh -s -- {serial} {round(timeout_s)}",
        stdin=_RESTART_IIOD_SCRIPT,
        timeout_s=timeout_s + 5,
    )
    fields = _parse_recovery_report(output)
    if fields.get("serial") != serial:
        raise DataPlaneRecoveryError("iiOD recovery returned a different radio serial")
    try:
        evidence = IiodRestartEvidence(
            serial=serial,
            previous_pid=int(fields["previous_pid"]),
            replacement_pid=int(fields["replacement_pid"]),
            previous_start_ticks=int(fields["previous_start_ticks"]),
            replacement_start_ticks=int(fields["replacement_start_ticks"]),
            active_rx_buffers_before=int(fields["active_rx_buffers_before"]),
            cma_total_bytes=int(fields["cma_total_kib"]) * 1024,
            cma_free_before_bytes=int(fields["cma_free_before_kib"]) * 1024,
            cma_free_after_bytes=int(fields["cma_free_after_kib"]) * 1024,
        )
    except (KeyError, ValueError) as error:
        raise DataPlaneRecoveryError("iiOD recovery report is incomplete or invalid") from error
    if (
        evidence.previous_pid == evidence.replacement_pid
        and evidence.previous_start_ticks == evidence.replacement_start_ticks
    ):
        raise DataPlaneRecoveryError("iiOD process identity did not change")
    return evidence


def inspect_data_plane_runtime(
    transport: RecoveryTransport,
    serial: str,
) -> DataPlaneRuntimeStatus:
    """Collect fixed process, buffer, CMA, DMA, IRQ, and kernel evidence."""

    if not _SERIAL_PATTERN.fullmatch(serial):
        raise ValueError("invalid radio serial")
    output = transport.run(
        f"sh -s -- {serial}",
        stdin=_INSPECT_DATA_PLANE_SCRIPT,
        timeout_s=20,
    )
    fields = _parse_recovery_report(output)
    if fields.get("serial") != serial:
        raise DataPlaneRecoveryError("data-plane status returned a different radio serial")
    try:
        return DataPlaneRuntimeStatus(
            serial=serial,
            iiod_pid=int(fields["iiod_pid"]),
            iiod_start_ticks=int(fields["iiod_start_ticks"]),
            iiod_generation=int(fields["iiod_generation"]),
            active_rx_buffers=int(fields["active_rx_buffers"]),
            rx_buffer_length=_optional_report_int(fields, "rx_buffer_length"),
            rx_data_available=_optional_report_int(fields, "rx_data_available"),
            rx_device_path=fields["rx_device_path"],
            cma_total_bytes=int(fields["cma_total_kib"]) * 1024,
            cma_free_bytes=int(fields["cma_free_kib"]) * 1024,
            memory_total_bytes=int(fields["memory_total_kib"]) * 1024,
            memory_available_bytes=int(fields["memory_available_kib"]) * 1024,
            interrupt_total=int(fields["interrupt_total"]),
            fpga_devices=_decode_hex_report_lines(
                fields, "fpga_devices_hex", maximum_bytes=8192
            ),
            dma_devices=_decode_hex_report_lines(
                fields, "dma_devices_hex", maximum_bytes=4096
            ),
            interrupt_lines=_decode_hex_report_lines(
                fields, "interrupt_lines_hex", maximum_bytes=16_384
            ),
            kernel_events=_decode_hex_report_lines(
                fields, "kernel_events_hex", maximum_bytes=16_384
            ),
        )
    except (KeyError, ValueError) as error:
        raise DataPlaneRecoveryError(
            "data-plane runtime report is incomplete or invalid"
        ) from error


def new_recovery_receipt_id() -> str:
    return uuid.uuid4().hex


def utc_now() -> datetime:
    return datetime.now(UTC)


def _release_probe_device(device: Any | None) -> None:
    if device is None:
        return
    with suppress(Exception):
        device.rx_destroy_buffer()
    context = getattr(device, "ctx", None)
    closer = getattr(context, "destroy", None) or getattr(context, "close", None)
    if callable(closer):
        with suppress(Exception):
            closer()


def _probe_failure_kind(
    error: Exception,
) -> Literal["timeout", "identity", "environment", "invalid_data", "io"]:
    if isinstance(error, TimeoutError) or (
        isinstance(error, OSError) and getattr(error, "errno", None) == 110
    ):
        return "timeout"
    if isinstance(error, ImportError):
        return "environment"
    message = str(error)
    if "IIO environment preflight failed" in message:
        return "environment"
    if "attested serial" in message:
        return "identity"
    if "refill returned" in message or "no enabled RX channels" in message:
        return "invalid_data"
    return "io"


def _parse_recovery_report(output: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in output.replace("\r", "").splitlines():
        if not line.startswith("PPU\t"):
            continue
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[1] or parts[1] in fields:
            raise DataPlaneRecoveryError("malformed or duplicate iiOD recovery report field")
        fields[parts[1]] = parts[2]
    return fields


def _optional_report_int(fields: Mapping[str, str], key: str) -> int | None:
    value = fields.get(key, "")
    return None if not value else int(value)


def _decode_hex_report_lines(
    fields: Mapping[str, str], key: str, *, maximum_bytes: int
) -> tuple[str, ...]:
    encoded = fields.get(key)
    if encoded is None:
        raise ValueError(f"remote report omitted {key}")
    try:
        decoded = bytes.fromhex(encoded)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError(f"remote report contained invalid {key}") from error
    if len(decoded) > maximum_bytes or "\x00" in text:
        raise ValueError(f"remote report exceeded the {key} limit")
    return tuple(line for line in text.splitlines() if line)


_INSPECT_DATA_PLANE_SCRIPT = rb"""set -eu
serial_expected="$1"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
[ "$serial" = "$serial_expected" ]
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
emit_hex() { encoded=$(printf '%s' "$2" | od -An -tx1 | tr -d ' \n'); emit "$1" "$encoded"; }
pid_file=/var/run/iiod-child.pid
[ -r "$pid_file" ]
iiod_pid=$(cat "$pid_file")
case "$iiod_pid" in ''|*[!0-9]*) exit 21;; esac
[ -r "/proc/$iiod_pid/stat" ]
iiod_start_ticks=$(awk '{print $22}' "/proc/$iiod_pid/stat")
iiod_generation=$(cat /run/iiod-generation)
rx_device=''
rx_count=0
for candidate in /sys/bus/iio/devices/iio:device*; do
  [ "$(cat "$candidate/name" 2>/dev/null || true)" = cf-ad9361-lpc ] || continue
  rx_device="$candidate"
  rx_count=$((rx_count + 1))
done
[ "$rx_count" -eq 1 ]
rx_device_path=$(readlink -f "$rx_device")
rx_bus_path=$(dirname "$(dirname "$rx_device_path")")
read_optional() { [ -r "$1" ] && cat "$1" || true; }
active_rx_buffers=$(read_optional "$rx_device/buffer/enable")
[ -n "$active_rx_buffers" ] || active_rx_buffers=0
rx_buffer_length=$(read_optional "$rx_device/buffer/length")
rx_data_available=$(read_optional "$rx_device/buffer/data_available")
cma_total_kib=$(awk '$1 == "CmaTotal:" {print $2; exit}' /proc/meminfo)
cma_free_kib=$(awk '$1 == "CmaFree:" {print $2; exit}' /proc/meminfo)
memory_total_kib=$(awk '$1 == "MemTotal:" {print $2; exit}' /proc/meminfo)
memory_available_kib=$(awk '$1 == "MemAvailable:" {print $2; exit}' /proc/meminfo)
interrupt_total=$(awk '$1 == "intr" {print $2; exit}' /proc/stat)
fpga_devices=$(for candidate in "$rx_bus_path"/*; do
  printf '%s\n' "$candidate"
done)
dma_devices=$(for candidate in "$rx_bus_path"/*; do
  name=${candidate##*/}
  compatible=''
  [ ! -r "$candidate/of_node/compatible" ] \
    || compatible=$(tr '\000' '\n' <"$candidate/of_node/compatible")
  case "$name:$compatible" in *dma*) printf '%s\n' "$candidate";; esac
done)
interrupt_lines=$(cat /proc/interrupts)
kernel_events=$(dmesg | grep -Ei 'dma|cf-ad9361|iio|timeout|overflow' | tail -40 || true)
emit serial "$serial"
emit iiod_pid "$iiod_pid"
emit iiod_start_ticks "$iiod_start_ticks"
emit iiod_generation "$iiod_generation"
emit active_rx_buffers "$active_rx_buffers"
emit rx_buffer_length "$rx_buffer_length"
emit rx_data_available "$rx_data_available"
emit rx_device_path "$rx_device_path"
emit cma_total_kib "$cma_total_kib"
emit cma_free_kib "$cma_free_kib"
emit memory_total_kib "$memory_total_kib"
emit memory_available_kib "$memory_available_kib"
emit interrupt_total "$interrupt_total"
emit_hex fpga_devices_hex "$fpga_devices"
emit_hex dma_devices_hex "$dma_devices"
emit_hex interrupt_lines_hex "$interrupt_lines"
emit_hex kernel_events_hex "$kernel_events"
"""


_RESTART_IIOD_SCRIPT = rb"""set -eu
serial_expected="$1"
timeout_s="$2"
serial=$(cat /sys/kernel/config/usb_gadget/composite_gadget/strings/0x409/serialnumber)
[ "$serial" = "$serial_expected" ]
emit() { printf 'PPU\t%s\t%s\n' "$1" "$2"; }
pid_file=/var/run/iiod-child.pid
[ -r "$pid_file" ]
previous_pid=$(cat "$pid_file")
case "$previous_pid" in ''|*[!0-9]*) exit 21;; esac
[ -r "/proc/$previous_pid/stat" ]
previous_start_ticks=$(awk '{print $22}' "/proc/$previous_pid/stat")
active_rx_buffers_before=0
for rx_device in /sys/bus/iio/devices/iio:device*; do
  [ "$(cat "$rx_device/name" 2>/dev/null || true)" = cf-ad9361-lpc ] || continue
  value="$rx_device/buffer/enable"
  [ -e "$value" ] || continue
  active_rx_buffers_before=$((active_rx_buffers_before + $(cat "$value")))
done
cma_total_kib=$(awk '$1 == "CmaTotal:" {print $2; exit}' /proc/meminfo)
cma_free_before_kib=$(awk '$1 == "CmaFree:" {print $2; exit}' /proc/meminfo)
[ -n "$cma_total_kib" ]
[ -n "$cma_free_before_kib" ]
kill "$previous_pid"
replacement_pid=''
replacement_start_ticks=''
elapsed=0
while [ "$elapsed" -lt "$timeout_s" ]; do
  candidate=$(cat "$pid_file" 2>/dev/null || true)
  case "$candidate" in ''|*[!0-9]*) candidate='';; esac
  if [ -n "$candidate" ] && [ -r "/proc/$candidate/stat" ]; then
    candidate_start=$(awk '{print $22}' "/proc/$candidate/stat")
    if [ "$candidate" != "$previous_pid" ] || \
       [ "$candidate_start" != "$previous_start_ticks" ]; then
      replacement_pid="$candidate"
      replacement_start_ticks="$candidate_start"
      break
    fi
  fi
  sleep 1
  elapsed=$((elapsed + 1))
done
[ -n "$replacement_pid" ]
cma_free_after_kib=$(awk '$1 == "CmaFree:" {print $2; exit}' /proc/meminfo)
emit serial "$serial"
emit previous_pid "$previous_pid"
emit replacement_pid "$replacement_pid"
emit previous_start_ticks "$previous_start_ticks"
emit replacement_start_ticks "$replacement_start_ticks"
emit active_rx_buffers_before "$active_rx_buffers_before"
emit cma_total_kib "$cma_total_kib"
emit cma_free_before_kib "$cma_free_before_kib"
emit cma_free_after_kib "$cma_free_after_kib"
"""
