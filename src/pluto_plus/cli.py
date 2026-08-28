"""Command-line client and daemon launcher for Pluto+ control."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import asdict, dataclass
from importlib import import_module
from ipaddress import ip_address
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

import httpx
import typer

from pluto_plus.fastlock import (
    DEFAULT_DWELL_US,
    DEFAULT_HOPS_PER_MODE,
    DEFAULT_LOWER_FREQUENCY_HZ,
    DEFAULT_LOWER_PROFILE,
    DEFAULT_MAX_SECONDS,
    DEFAULT_PROFILE_SETTLE_MS,
    DEFAULT_UPPER_FREQUENCY_HZ,
    DEFAULT_UPPER_PROFILE,
    MAX_HOPS_PER_MODE,
    MAX_SECONDS,
    FastLockProbeError,
    FastLockProbeReport,
    prepare_usb_fastlock_probe,
    run_usb_fastlock_probe,
    write_fastlock_report,
)
from pluto_plus.hardware.preflight import IioEnvironmentReport, inspect_iio_environment
from pluto_plus.inventory import (
    LocalUsbPluto,
    RadioInventoryReport,
    build_radio_inventory,
    local_ipv4_discovery_networks,
    scan_local_usb_plutos,
)
from pluto_plus.ladder import (
    DEFAULT_RATE_LADDER,
    LADDER_CHANNEL_SELECTIONS,
    LadderReport,
    parse_rate_ladder,
    run_iio_ladder,
)
from pluto_plus.metadata_ladder import (
    DEFAULT_METADATA_SAMPLE_LADDER,
    METADATA_CHANNEL_SELECTIONS,
    parse_metadata_sample_ladder,
    run_metadata_continuity_ladder,
)
from pluto_plus.metadata_soak import (
    MAX_SLOTS,
    MetadataSoakError,
    SshMetadataHealthProbe,
    execute_metadata_soak,
    prepare_metadata_soak,
    run_live_metadata_slot,
)
from pluto_plus.setup_helper import BoundSshTransport

DEFAULT_ENDPOINT = "http://127.0.0.1:8765"
DEFAULT_STATE_ROOT = Path(os.environ.get("PLUTO_STATE_ROOT", "./pluto-state"))
_SOURCE_REPOSITORY = Path(__file__).resolve().parents[2]
DEFAULT_TOOL_REPOSITORY = (
    _SOURCE_REPOSITORY if (_SOURCE_REPOSITORY / ".git").is_dir() else Path.cwd()
)
DEFAULT_BOOTSTRAP_RECEIPTS = Path.home() / ".local/state/pluto-plus-utils/bootstrap-receipts"
DEFAULT_QUALIFICATION_REPORTS = Path.home() / ".local/state/pluto-plus-utils/qualification-reports"
DEFAULT_LOCAL_REBOOT_RECEIPTS = Path.home() / ".local/state/pluto-plus-utils/reboot-receipts"
DEFAULT_RAM_BOOT_RECEIPTS = Path.home() / ".local/state/pluto-plus-utils/ram-boot-receipts"
DEFAULT_METADATA_SOAK_REPORTS = Path.home() / ".local/state/pluto-plus-utils/metadata-soak-reports"
DEFAULT_FASTLOCK_REPORTS = Path.home() / ".local/state/pluto-plus-utils/fastlock-reports"
DEFAULT_HOST_ISOLATION_RECEIPTS = (
    Path.home() / ".local/state/pluto-plus-utils/host-isolation-receipts"
)
DEFAULT_SETUP_RECEIPTS = Path.home() / ".local/state/pluto-plus-utils/setup-receipts"
DEFAULT_NETWORK_CONFIG_RECEIPTS = (
    Path.home() / ".local/state/pluto-plus-utils/network-config-receipts"
)
DEFAULT_DATA_PLANE_RECOVERY_RECEIPTS = (
    Path.home() / ".local/state/pluto-plus-utils/data-plane-recovery-receipts"
)
DEFAULT_ENVIRONMENT_SURVEY_REPORTS = (
    Path.home() / ".local/state/pluto-plus-utils/environment-surveys"
)
API_PREFIX = "api/v1"

app = typer.Typer(
    no_args_is_help=True,
    help="Inspect Pluto+ radios directly and control them through plutod.",
)
radio_app = typer.Typer(no_args_is_help=True, help="Inspect and configure radios.")
settings_app = typer.Typer(no_args_is_help=True, help="Read or update radio settings.")
stream_app = typer.Typer(no_args_is_help=True, help="Manage live radio streams.")
capture_app = typer.Typer(no_args_is_help=True, help="Create persistent IQ captures.")
job_app = typer.Typer(no_args_is_help=True, help="Inspect stream and capture jobs.")
artifact_app = typer.Typer(no_args_is_help=True, help="Inspect captured artifacts.")
scan_app = typer.Typer(no_args_is_help=True, help="Run exclusive frequency scans.")
firmware_app = typer.Typer(no_args_is_help=True, help="Plan and execute guarded firmware updates.")
candidate_ram_app = typer.Typer(
    no_args_is_help=True,
    help="Plan, execute, and verify local release-candidate RAM deployments.",
)
comparator_ram_app = typer.Typer(
    no_args_is_help=True,
    help="Plan, execute, and verify the immutable approved-v7 comparator RAM boot.",
)
environment_survey_app = typer.Typer(
    no_args_is_help=True,
    help="Plan, execute, and verify exact-USB RX-only RF environment surveys.",
)
setup_app = typer.Typer(
    no_args_is_help=True, help="Plan and execute guarded canonical AD9361/2R2T setup."
)
config_app = typer.Typer(
    no_args_is_help=True,
    help="Read redacted config.txt and plan validated static-IP changes.",
)

app.add_typer(radio_app, name="radio")
radio_app.add_typer(settings_app, name="settings")
app.add_typer(stream_app, name="stream")
app.add_typer(capture_app, name="capture")
app.add_typer(job_app, name="job")
app.add_typer(artifact_app, name="artifact")
app.add_typer(scan_app, name="scan")
app.add_typer(firmware_app, name="firmware")
firmware_app.add_typer(candidate_ram_app, name="candidate-ram")
firmware_app.add_typer(comparator_ram_app, name="comparator-ram")
app.add_typer(environment_survey_app, name="environment-survey")
app.add_typer(setup_app, name="setup")
app.add_typer(config_app, name="config")


@dataclass
class _Context:
    endpoint: str
    admin_token: str | None = None
    client: ApiClient | None = None


@dataclass(frozen=True, slots=True)
class _SshFirmwareEnrollmentConfig:
    serial: str
    host: str
    known_hosts_file: Path
    private_key_file: Path


class ApiClient:
    """Small synchronous client for the versioned plutod HTTP API."""

    def __init__(self, endpoint: str, *, admin_token: str | None = None) -> None:
        self._client = (
            self._new_client(endpoint)
            if admin_token is None
            else self._new_client(endpoint, admin_token=admin_token)
        )

    @staticmethod
    def _new_client(endpoint: str, *, admin_token: str | None = None) -> httpx.Client:
        endpoint = endpoint.strip().rstrip("/")
        headers = {} if admin_token is None else {"Authorization": f"Bearer {admin_token}"}
        if endpoint.startswith("unix://"):
            socket_path = endpoint.removeprefix("unix://")
            if not socket_path.startswith("/"):
                _fail("invalid_endpoint", "Unix socket endpoint must use an absolute path", 2)
            transport = httpx.HTTPTransport(uds=socket_path)
            return httpx.Client(
                base_url=f"http://plutod/{API_PREFIX}/",
                transport=transport,
                timeout=30,
                headers=headers,
            )

        parsed = urlsplit(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            _fail(
                "invalid_endpoint",
                "endpoint must be an HTTP(S) URL or unix:///absolute/path.sock",
                2,
            )
        if admin_token is not None and parsed.scheme == "http":
            hostname = parsed.hostname or ""
            try:
                loopback = ip_address(hostname).is_loopback
            except ValueError:
                loopback = hostname.lower() == "localhost"
            if not loopback:
                _fail(
                    "admin_secure_transport_required",
                    "refusing to send an admin bearer token over non-loopback HTTP; "
                    "use HTTPS, an SSH tunnel, or a Unix socket",
                    2,
                )
        base_url = (
            endpoint
            if parsed.path.rstrip("/").endswith(f"/{API_PREFIX}")
            else (f"{endpoint}/{API_PREFIX}")
        )
        return httpx.Client(base_url=f"{base_url}/", timeout=30, headers=headers)

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any = None,
        content: bytes | None = None,
    ) -> Any:
        try:
            response = self._client.request(
                method,
                path.lstrip("/"),
                json=json_body,
                content=content,
            )
        except httpx.RequestError as error:
            _fail("daemon_unavailable", str(error), 3)

        if response.is_error:
            code = "http_error"
            message = f"plutod returned HTTP {response.status_code}"
            try:
                payload = response.json()
                detail = payload.get("error", payload) if isinstance(payload, dict) else {}
                if isinstance(detail, dict):
                    code = str(detail.get("code", code))
                    message = str(detail.get("message", detail.get("detail", message)))
            except ValueError:
                if response.text.strip():
                    message = response.text.strip()
            _fail(code, message, 4 if response.status_code < 500 else 5)

        if response.status_code == 204 or not response.content:
            return {}
        try:
            return response.json()
        except ValueError:
            _fail("invalid_daemon_response", "plutod returned invalid JSON", 5)


@app.callback()
def main(
    ctx: typer.Context,
    endpoint: str = typer.Option(
        DEFAULT_ENDPOINT,
        "--endpoint",
        envvar="PLUTO_ENDPOINT",
        help="plutod origin or unix:///absolute/path.sock.",
    ),
    admin_token_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--admin-token-file",
        envvar="PLUTO_ADMIN_TOKEN_FILE",
        help="Private file containing the bearer token for privileged API calls.",
    ),
) -> None:
    """Control Pluto+ radios through a single owning daemon."""
    ctx.obj = _Context(
        endpoint=endpoint,
        admin_token=(
            None if admin_token_file is None else _read_admin_token_file(admin_token_file)
        ),
    )


def _api(ctx: typer.Context) -> ApiClient:
    state = ctx.ensure_object(_Context)
    if state.client is None:
        state.client = ApiClient(state.endpoint, admin_token=state.admin_token)
        ctx.call_on_close(state.client.close)
    return state.client


def _emit(payload: Any) -> None:
    typer.echo(json.dumps(payload, indent=2, sort_keys=True))


def _inventory_table(report: Any) -> str:
    if not isinstance(report, dict) or not isinstance(report.get("records"), list):
        _fail("invalid_daemon_response", "plutod returned an invalid inventory report", 5)
    columns = (
        ("CLASS", "class"),
        ("SERIAL", "serial"),
        ("STATE", "state"),
        ("IP / URI", "endpoint"),
        ("FIRMWARE", "firmware"),
        ("USB", "usb"),
        ("USB LINK", "usb_link"),
        ("POWER BUDGET", "power"),
        ("CONTROLLER", "controller"),
        ("TERMINAL", "terminal"),
        ("HOST NET", "host_net"),
        ("STORAGE", "storage"),
        ("MODEL / NOTES", "details"),
    )
    rows: list[dict[str, str]] = []
    class_labels = {
        "confirmed_pluto_plus": "Pluto+",
        "daemon_attested_pluto": "Pluto",
        "network_attested_pluto": "Pluto",
        "pluto_class_ambiguous": "Ambiguous",
        "simulated": "Simulated",
    }
    for item in report["records"]:
        if not isinstance(item, dict):
            _fail("invalid_daemon_response", "inventory contains a malformed record", 5)
        interfaces = item.get("host_network_interfaces") or []
        host_network = []
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            addresses = interface.get("ipv4_addresses") or []
            address_text = ",".join(str(value) for value in addresses) or "no-ip"
            host_network.append(f"{interface.get('name', '?')}={address_text}")
        notes = [str(value) for value in (item.get("notes") or [])]
        fault_summary = item.get("usb_link_faults")
        if isinstance(fault_summary, dict):
            errors = int(fault_summary.get("error_count") or 0)
            disconnects = int(fault_summary.get("disconnect_count") or 0)
            cycles = int(fault_summary.get("port_power_cycle_count") or 0)
            if errors or disconnects or cycles:
                notes.append(
                    "recent port log: "
                    f"{errors} error(s), {disconnects} disconnect(s), {cycles} power cycle(s)"
                )
        model = str(item.get("model") or "—")
        details = model if not notes else f"{model}; {'; '.join(notes)}"
        usb_parts = [
            str(value) for value in (item.get("usb_bus_device"), item.get("usb_path")) if value
        ]
        speed = item.get("usb_speed_mbps")
        speed_text = "—" if speed is None else f"{float(speed):g} Mb/s"
        usb_version = item.get("usb_spec_version")
        direct = item.get("usb_direct_to_root_hub")
        topology = "direct" if direct is True else "via hub" if direct is False else "unknown path"
        link_text = f"{speed_text}; USB {usb_version or '?'}; {topology}"
        advertised_power = item.get("usb_advertised_max_power_ma")
        runtime_status = item.get("usb_runtime_power_status") or "unknown"
        runtime_control = item.get("usb_runtime_power_control") or "unknown"
        power_text = (
            "—"
            if item.get("usb_path") is None
            else (
                f"{advertised_power} mA advertised; {runtime_status}/{runtime_control}"
                if advertised_power is not None
                else f"unknown advertised; {runtime_status}/{runtime_control}"
            )
        )
        controller_address = item.get("usb_root_controller_pci_address")
        controller_vendor = item.get("usb_root_controller_vendor_id")
        controller_device = item.get("usb_root_controller_device_id")
        controller_text = (
            "—"
            if controller_address is None
            else f"{controller_address} {controller_vendor or '????'}:{controller_device or '????'}"
        )
        managed = "managed" if item.get("managed") else "unmanaged"
        rows.append(
            {
                "class": class_labels.get(
                    str(item.get("classification")), str(item.get("classification") or "—")
                ),
                "serial": str(item.get("serial") or "<blank>"),
                "state": f"{item.get('state', 'unknown')}/{managed}",
                "endpoint": str(item.get("radio_ip") or item.get("iio_uri") or "—"),
                "firmware": str(item.get("firmware_version") or "unknown"),
                "usb": " ".join(usb_parts) or "—",
                "usb_link": link_text if usb_parts else "—",
                "power": power_text,
                "controller": controller_text,
                "terminal": ",".join(str(value) for value in (item.get("terminal_devices") or []))
                or "—",
                "host_net": ",".join(host_network) or "—",
                "storage": ",".join(str(value) for value in (item.get("storage_devices") or []))
                or "—",
                "details": details,
            }
        )
    if not rows:
        return "No Pluto radios found."
    widths = {key: max(len(title), *(len(row[key]) for row in rows)) for title, key in columns}
    header = "  ".join(title.ljust(widths[key]) for title, key in columns)
    separator = "  ".join("-" * widths[key] for _title, key in columns)
    body = ["  ".join(row[key].ljust(widths[key]) for _title, key in columns) for row in rows]
    footer = "USB power values are descriptor budgets, not measured voltage or current."
    return "\n".join((header, separator, *body, "", footer))


def _ladder_table(report: LadderReport) -> str:
    columns = (
        ("RATE", "rate"),
        ("OFFERED", "offered"),
        ("ACHIEVED", "achieved"),
        ("TRANSFER/MIN", "per_minute"),
        ("EFFECTIVE", "effective"),
        ("DELIVERY", "delivery"),
        ("P50", "p50"),
        ("P95", "p95"),
        ("RESULT", "result"),
    )
    rows = [
        {
            "rate": f"{cell.sample_rate_hz / 1_000_000:g} MS/s",
            "offered": f"{cell.offered_payload_mbps:.2f} MB/s",
            "achieved": f"{cell.achieved_payload_mbps:.2f} MB/s",
            "per_minute": f"{cell.transferred_mb_per_minute:.0f} MB/min",
            "effective": f"{cell.delivered_sample_rate_sps / 1_000_000:.3f} MS/s",
            "delivery": f"{cell.delivery_fraction * 100:.1f}%",
            "p50": f"{cell.latency_p50_ms:.1f} ms",
            "p95": f"{cell.latency_p95_ms:.1f} ms",
            "result": "kept pace" if cell.kept_pace else "link-limited",
        }
        for cell in report.cells
    ]
    rows.extend(
        {
            "rate": f"{failure.sample_rate_hz / 1_000_000:g} MS/s",
            "offered": "—",
            "achieved": "—",
            "per_minute": "—",
            "effective": "—",
            "delivery": "—",
            "p50": "—",
            "p95": "—",
            "result": f"ERROR: {failure.message}",
        }
        for failure in report.failures
    )
    widths = {key: max(len(title), *(len(row[key]) for row in rows)) for title, key in columns}
    header = "  ".join(title.ljust(widths[key]) for title, key in columns)
    separator = "  ".join("-" * widths[key] for _title, key in columns)
    body = ["  ".join(row[key].ljust(widths[key]) for _title, key in columns) for row in rows]
    identity = (
        f"Radio {report.serial} · {report.uri} · {report.model} · "
        f"firmware {report.firmware_version or 'unknown'} · "
        f"kernel buffers {report.kernel_buffers} "
        f"({report.kernel_buffer_configuration_basis.replace('_', ' ')})"
    )
    restore = "Original RX settings restored: yes"
    return "\n".join((identity, header, separator, *body, restore, report.continuity_claim))


def _fastlock_table(report: FastLockProbeReport, report_path: Path) -> str:
    ordinary = report.ordinary_timing
    fastlock = report.fastlock_timing
    lines = (
        f"Radio {report.identity.serial} · {report.identity.uri} · "
        f"firmware {report.identity.firmware_version or 'unknown'}",
        (
            "Ordinary LO write: "
            f"median {ordinary.median_us:.1f} us · p95 {ordinary.p95_us:.1f} us · "
            f"max {ordinary.maximum_us:.1f} us"
        ),
        (
            "Fast Lock recall:  "
            f"median {fastlock.median_us:.1f} us · p95 {fastlock.p95_us:.1f} us · "
            f"max {fastlock.maximum_us:.1f} us"
        ),
        f"Median speedup: {report.median_speedup:.2f}x",
        "Original RX settings restored: yes",
        "TX muted and verified: yes",
        f"Report: {report_path}",
        report.latency_claim,
        report.continuity_claim,
    )
    return "\n".join(lines)


def _environment_table(report: IioEnvironmentReport) -> str:
    values: list[tuple[str, str]] = [
        ("Status", report.status.value),
        ("Ready", "yes" if report.healthy else "no"),
        ("Python", report.python_executable),
        ("pyadi-iio", report.pyadi_path or "not found"),
        ("pylibiio", report.pylibiio_path or "not found"),
        (
            "Native libiio",
            report.native_libiio_path or report.native_libiio_candidate or "not found",
        ),
        ("libiio version", report.libiio_version or "unavailable"),
        ("Backends", ", ".join(report.backends) or "none"),
        ("Message", report.message),
    ]
    if report.underlying_error:
        values.append(("Underlying error", report.underlying_error))
    if report.remediation:
        values.append(("Remediation", report.remediation))
    width = max(len(label) for label, _value in values)
    return "\n".join(f"{label.ljust(width)}  {value}" for label, value in values)


def _fail(code: str, message: str, exit_code: int) -> NoReturn:
    typer.echo(json.dumps({"error": {"code": code, "message": message}}, sort_keys=True), err=True)
    raise typer.Exit(exit_code)


def _read_admin_token_file(path: Path) -> str:
    token = _read_private_text_file(path, label="admin token")
    if len(token) < 32 or any(character.isspace() for character in token):
        _fail(
            "invalid_admin_token_file",
            "admin token must contain at least 32 non-space characters",
            2,
        )
    return token


def _read_private_text_file(path: Path, *, label: str) -> str:
    encoded = _read_private_file_bytes(path, label=label, maximum_bytes=4096)
    try:
        value = encoded.decode("utf-8").rstrip("\r\n")
    except UnicodeDecodeError:
        _fail("invalid_private_file", f"{label} must be UTF-8", 2)
    if not value or "\x00" in value or "\n" in value or "\r" in value:
        _fail("invalid_private_file", f"{label} must contain one non-empty line", 2)
    return value


def _read_private_file_bytes(path: Path, *, label: str, maximum_bytes: int) -> bytes:
    if not path.is_absolute():
        _fail("invalid_private_file", f"{label} file must be an absolute path", 2)
    try:
        metadata = path.lstat()
    except OSError as error:
        _fail("invalid_private_file", str(error), 2)
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        _fail("invalid_private_file", f"{label} file must be a regular file", 2)
    if metadata.st_mode & 0o077:
        _fail(
            "invalid_private_file",
            f"{label} file must not be accessible by group or other users",
            2,
        )
    try:
        encoded = path.read_bytes()
    except OSError as error:
        _fail("invalid_private_file", str(error), 2)
    if not encoded or len(encoded) > maximum_bytes:
        _fail("invalid_private_file", f"{label} file is empty or too large", 2)
    return encoded


def _private_usb_host(value: str) -> str:
    try:
        address = ip_address(value)
    except ValueError:
        _fail("invalid_setup_host", "setup USB host must be a literal IP address", 2)
    if address.is_global or address.is_loopback or address.is_multicast or address.is_unspecified:
        _fail(
            "invalid_setup_host",
            "setup USB host must be a private or link-local unicast address",
            2,
        )
    return str(address)


def _read_ssh_firmware_enrollment(path: Path) -> _SshFirmwareEnrollmentConfig:
    encoded = _read_private_file_bytes(
        path, label="SSH firmware enrollment", maximum_bytes=64 * 1024
    )
    if stat.S_IMODE(path.lstat().st_mode) != 0o600:
        _fail(
            "invalid_ssh_firmware_enrollment",
            "SSH firmware enrollment file mode must be exactly 0600",
            2,
        )
    try:
        document = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail("invalid_ssh_firmware_enrollment", f"invalid JSON: {error}", 2)
    if not isinstance(document, dict):
        _fail("invalid_ssh_firmware_enrollment", "enrollment must be a JSON object", 2)
    expected_keys = {
        "serial",
        "host",
        "username",
        "known_hosts_file",
        "private_key_file",
    }
    if set(document) != expected_keys:
        _fail(
            "invalid_ssh_firmware_enrollment",
            "enrollment must contain only serial, host, username, known_hosts_file, "
            "and private_key_file",
            2,
        )
    serial = document["serial"]
    if not isinstance(serial, str) or not serial or serial.strip() != serial:
        _fail("invalid_ssh_firmware_enrollment", "serial must be one exact value", 2)
    if document["username"] != "root":
        _fail("invalid_ssh_firmware_enrollment", "username must be exactly root", 2)
    host_value = document["host"]
    if not isinstance(host_value, str):
        _fail("invalid_ssh_firmware_enrollment", "host must be a literal IP", 2)
    try:
        address = ip_address(host_value)
    except ValueError:
        _fail("invalid_ssh_firmware_enrollment", "host must be a literal IP", 2)
    if address.is_global or address.is_loopback or address.is_multicast or address.is_unspecified:
        _fail(
            "invalid_ssh_firmware_enrollment",
            "host must be a private or link-local unicast IP",
            2,
        )
    if not isinstance(document["known_hosts_file"], str) or not isinstance(
        document["private_key_file"], str
    ):
        _fail(
            "invalid_ssh_firmware_enrollment",
            "credential file paths must be strings",
            2,
        )
    known_hosts_file = Path(document["known_hosts_file"])
    private_key_file = Path(document["private_key_file"])
    _read_private_file_bytes(
        known_hosts_file, label="SSH firmware known-hosts", maximum_bytes=1024 * 1024
    )
    _read_private_file_bytes(
        private_key_file, label="SSH firmware private key", maximum_bytes=1024 * 1024
    )
    if any(
        stat.S_IMODE(path.lstat().st_mode) != 0o600 for path in (known_hosts_file, private_key_file)
    ):
        _fail(
            "invalid_ssh_firmware_enrollment",
            "SSH firmware credential file modes must be exactly 0600",
            2,
        )
    return _SshFirmwareEnrollmentConfig(
        serial=serial,
        host=str(address),
        known_hosts_file=known_hosts_file,
        private_key_file=private_key_file,
    )


@radio_app.command("list")
def radio_list(ctx: typer.Context) -> None:
    """List radios known to plutod."""
    _emit(_api(ctx).request("GET", "radios"))


@radio_app.command("inventory")
def radio_inventory(
    ctx: typer.Context,
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json."
    ),
    network: bool = typer.Option(
        False,
        "--network",
        help="Also scan bounded private/link-local networks attached to this host.",
    ),
    network_cidr: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--network-cidr",
        help="Also scan this exact bounded IPv4 CIDR (repeatable).",
    ),
    daemon: bool = typer.Option(
        False,
        "--daemon",
        help="Query plutod instead of performing standalone discovery.",
    ),
) -> None:
    """Print a standalone local USB and optional network radio inventory."""

    normalized = output_format.strip().lower()
    if normalized not in {"json", "table"}:
        _fail("invalid_inventory_format", "inventory format must be table or json", 2)
    requested_networks = list(network_cidr or [])
    if daemon and (network or requested_networks):
        _fail(
            "incompatible_inventory_options",
            "--daemon cannot be combined with --network or --network-cidr",
            2,
        )
    if daemon:
        report: Any = _api(ctx).request("GET", "inventory")
    else:
        local_devices = scan_local_usb_plutos()
        if network:
            usb_network_interfaces = {
                interface.name
                for device in local_devices
                for interface in device.host_network_interfaces
            }
            requested_networks.extend(
                local_ipv4_discovery_networks(
                    exclude_interfaces=usb_network_interfaces,
                )
            )
        report = _standalone_radio_inventory(
            requested_networks,
            local_devices=local_devices,
        ).model_dump(mode="json")
    if normalized == "json":
        _emit(report)
    else:
        typer.echo(_inventory_table(report))


def _standalone_radio_inventory(
    networks: list[str],
    *,
    local_devices: tuple[LocalUsbPluto, ...] | None = None,
) -> RadioInventoryReport:
    snapshots: tuple[Any, ...] = ()
    if networks:
        _managed, snapshots = _network_iio_inventory(list(dict.fromkeys(networks)), [])
    return build_radio_inventory(
        snapshots,
        scan_local_usb_plutos() if local_devices is None else local_devices,
        snapshot_origin="standalone",
    )


@radio_app.command("reboot-local")
def radio_reboot_local(
    serial: str = typer.Argument(..., help="Exact stable serial of the local USB radio."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct /sys/bus/usb/devices path for the selected radio.",
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ...,
        "--ssh-known-hosts-file",
        help="Previously enrolled private known_hosts file for this exact radio.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Private radio password file; otherwise execution prompts without echo.",
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help=(
            "Literal private IPv4 address; 192.168.2.1 uses the exact USB route, "
            "other addresses use the normal LAN route."
        ),
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Dispatch the guarded reboot; omission produces a read-only plan.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase REBOOT <serial>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_LOCAL_REBOOT_RECEIPTS,
        "--receipt-directory",
        help="Private directory for durable local reboot receipts.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing local Pluto NICs/routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="With isolation execution, exact phrase ISOLATE USB SSH <interface>.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Plan or execute one serial/path-scoped local USB reboot."""

    from pluto_plus.host_isolation import (
        HostIsolationError,
        HostIsolationExecutionError,
        execute_usb_ssh_isolated,
        prepare_usb_ssh_isolation,
    )
    from pluto_plus.ip_firmware import UsbSshRouteObservation
    from pluto_plus.local_reboot import (
        FixedSshLocalRebootTransport,
        LocalRebootError,
        LocalRebootExecutionError,
        execute_local_reboot,
        prepare_local_reboot,
    )
    from pluto_plus.setup_helper import BoundSshTransport

    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    isolation_plan = None
    route_checker_override: Callable[[str, str], UsbSshRouteObservation] | None = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if ssh_host != "192.168.2.1":
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        local_devices = scan_local_usb_plutos()
        selected_matches = [
            item
            for item in local_devices
            if item.serial == serial and item.usb_path == str(usb_sysfs_path)
        ]
        if len(selected_matches) != 1 or len(selected_matches[0].host_network_interfaces) != 1:
            _fail("host_isolation_identity_unavailable", "selected USB radio is ambiguous", 4)
        pluto_interfaces = tuple(
            interface.name for item in local_devices for interface in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                selected_matches[0].host_network_interfaces[0].name,
                ssh_host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        anticipated_route = UsbSshRouteObservation(
            interface_addresses=(
                (isolation_plan.selected_interface, isolation_plan.selected_addresses),
            ),
            destination_routes=((isolation_plan.selected_interface, "192.168.2.0/24"),),
        )

        def anticipated_checker(interface: str, host: str) -> UsbSshRouteObservation:
            return anticipated_route

        route_checker_override = anticipated_checker
    try:
        prepare_options: dict[str, Any] = {}
        if route_checker_override is not None:
            prepare_options["route_checker"] = route_checker_override
        plan = prepare_local_reboot(
            serial,
            usb_sysfs_path,
            ssh_host=ssh_host,
            known_hosts_file=selected_known_hosts,
            **prepare_options,
        )
    except (LocalRebootError, OSError, ValueError) as error:
        _fail("local_reboot_preflight_failed", str(error), 4)
    if not execute:
        environment = inspect_iio_environment()
        _emit(
            {
                "mode": "dry_run",
                "will_reboot": False,
                "plan": asdict(plan),
                "host_isolation": (None if isolation_plan is None else asdict(isolation_plan)),
                "host_environment": environment.model_dump(mode="json"),
                "next_command": (
                    f"repeat with --execute and --confirm {json.dumps(plan.confirmation_phrase)}"
                ),
            }
        )
        return
    if confirmation != plan.confirmation_phrase:
        _fail(
            "local_reboot_confirmation_required",
            f"--execute requires --confirm {plan.confirmation_phrase!r}",
            2,
        )
    if isolation_plan is not None and isolation_confirmation != isolation_plan.confirmation_phrase:
        _fail(
            "host_isolation_confirmation_required",
            f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
            2,
        )
    if not plan.raw_usb_write_access:
        _fail(
            "local_reboot_usb_permission_denied",
            f"raw USB node {plan.runtime_usb_device_node} is not writable; install "
            "packaging/udev/70-pluto-plus-utils.rules and reconnect before execution",
            4,
        )
    environment = inspect_iio_environment()
    if not environment.healthy:
        _fail("local_reboot_environment_failed", environment.actionable_message, 5)
    if ssh_password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        try:
            password = (
                _read_private_file_bytes(
                    ssh_password_file,
                    label="radio SSH password",
                    maximum_bytes=4096,
                )
                .decode("utf-8")
                .strip()
            )
        except UnicodeDecodeError:
            _fail("invalid_private_file", "radio SSH password must be UTF-8", 2)

    def reboot_action() -> Any:
        ssh = BoundSshTransport(
            host=plan.ssh_host,
            interface=(plan.usb_interface if plan.ssh_route_mode == "usb_gadget" else None),
            password=password,
            known_hosts_file=selected_known_hosts,
        )
        return execute_local_reboot(
            plan,
            confirmation=confirmation or "",
            transport=FixedSshLocalRebootTransport(ssh),
            known_hosts_file=selected_known_hosts,
            receipt_directory=receipt_directory.expanduser().resolve(),
        )

    try:
        isolation_receipt = None
        if isolation_plan is None:
            receipt = reboot_action()
        else:
            receipt, isolation_receipt = execute_usb_ssh_isolated(
                isolation_plan,
                confirmation=isolation_confirmation or "",
                receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                action=reboot_action,
                pluto_interfaces=pluto_interfaces,
            )
    except HostIsolationExecutionError as error:
        _emit({"host_isolation": asdict(error.receipt)})
        raise typer.Exit(5) from error
    except HostIsolationError as error:
        _fail("host_isolation_failed", str(error), 4)
    except LocalRebootExecutionError as error:
        _emit(asdict(error.receipt))
        raise typer.Exit(5) from error
    except (LocalRebootError, OSError, ValueError) as error:
        _fail("local_reboot_failed", str(error), 4)
    if isolation_receipt is None:
        _emit(asdict(receipt))
    else:
        _emit({"host_isolation": asdict(isolation_receipt), "result": asdict(receipt)})


@radio_app.command("reboot-lan")
def radio_reboot_lan(
    serial: str = typer.Argument(..., help="Exact serial of the LAN radio with detached USB."),
    ssh_host: str = typer.Option(
        ...,
        "--ssh-host",
        help="Exact canonical private LAN IPv4; the shared USB address is rejected.",
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ...,
        "--ssh-known-hosts-file",
        help="Private known_hosts pinned to this exact LAN endpoint.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Private one-line root password file; otherwise prompt without echo.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Mute TX, dispatch the reboot, and verify the exact serial returns over USB.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase REBOOT LAN <serial>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_LOCAL_REBOOT_RECEIPTS,
        "--receipt-directory",
        help="Private directory for the durable LAN reboot receipt.",
    ),
    timeout_s: float = typer.Option(
        60,
        "--timeout",
        min=5,
        max=300,
        help="Seconds to wait for the exact serial to return over local USB.",
    ),
) -> None:
    """Guardedly reboot one LAN-attested radio whose USB gadget is absent."""

    from pluto_plus.lan_reboot import (
        LanRebootError,
        LanRebootExecutionError,
        execute_lan_reboot,
        prepare_lan_reboot,
    )
    from pluto_plus.local_reboot import FixedSshLocalRebootTransport

    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    password = (
        typer.prompt("Radio SSH password", hide_input=True)
        if ssh_password_file is None
        else _read_private_text_file(
            ssh_password_file.expanduser().absolute(), label="radio SSH password"
        )
    )
    transport = FixedSshLocalRebootTransport(
        BoundSshTransport(
            host=ssh_host,
            interface=None,
            password=password,
            known_hosts_file=selected_known_hosts,
        )
    )
    try:
        plan = prepare_lan_reboot(
            serial,
            ssh_host=ssh_host,
            known_hosts_file=selected_known_hosts,
            transport=transport,
        )
    except (LanRebootError, OSError, ValueError) as error:
        _fail("lan_reboot_preflight_failed", str(error), 4)
    if not execute:
        _emit(
            {
                "mode": "dry_run",
                "will_reboot": False,
                "plan": asdict(plan),
                "next_command": (
                    f"repeat with --execute and --confirm {json.dumps(plan.confirmation_phrase)}"
                ),
            }
        )
        return
    if confirmation != plan.confirmation_phrase:
        _fail(
            "lan_reboot_confirmation_required",
            f"--execute requires --confirm {plan.confirmation_phrase!r}",
            2,
        )
    try:
        receipt = execute_lan_reboot(
            plan,
            confirmation=confirmation or "",
            transport=transport,
            known_hosts_file=selected_known_hosts,
            receipt_directory=receipt_directory.expanduser().absolute(),
            timeout_s=timeout_s,
        )
    except LanRebootExecutionError as error:
        _emit(asdict(error.receipt))
        raise typer.Exit(5) from error
    except (LanRebootError, OSError, ValueError) as error:
        _fail("lan_reboot_failed", str(error), 4)
    _emit(asdict(receipt))


@app.command("environment")
def environment_preflight(
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json."
    ),
) -> None:
    """Check host pyadi/libiio/USB readiness without opening a radio."""

    normalized_format = output_format.strip().lower()
    if normalized_format not in {"table", "json"}:
        _fail("invalid_environment_format", "environment format must be table or json", 2)
    report = inspect_iio_environment()
    if normalized_format == "json":
        _emit(report.model_dump(mode="json"))
    else:
        typer.echo(_environment_table(report))
    if not report.healthy:
        raise typer.Exit(5)


@radio_app.command("ladder")
def radio_ladder(
    target: str = typer.Argument(
        ...,
        help="USB serial when --transport=usb, or a literal IPv4 address when using IP.",
    ),
    transport: str = typer.Option(
        "usb", "--transport", "-t", help="Standard libiio transport: usb or ip."
    ),
    expect_serial: str | None = typer.Option(
        None,
        "--expect-serial",
        help="Require this exact radio serial (required for IP).",
    ),
    rates: str = typer.Option(
        DEFAULT_RATE_LADDER,
        "--rates",
        help="Strictly increasing comma-separated Hz/K/M/G sample-rate rungs.",
    ),
    channels: str = typer.Option(
        "dual",
        "--channels",
        help="Canonical receive layout: rx0, rx1, or dual.",
    ),
    samples: int = typer.Option(
        262_144,
        "--samples",
        min=16_384,
        max=4_194_304,
        help="Samples per channel in each receive frame.",
    ),
    frames: int = typer.Option(
        12, "--frames", min=1, max=100, help="Timed frames captured at each rung."
    ),
    warmup_frames: int = typer.Option(
        2,
        "--warmup-frames",
        min=0,
        max=20,
        help="Discarded frames before timing each rung.",
    ),
    kernel_buffers: int = typer.Option(
        8,
        "--kernel-buffers",
        min=1,
        max=64,
        help="Explicit libiio RX kernel-buffer count.",
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json."
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--report",
        help="Absent-only private canonical JSON report path beneath an owned mode-0700 parent.",
    ),
    usb_sysfs_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--usb-sysfs-path",
        help="Exact local USB sysfs node anchoring an isolated IP transport.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing Pluto NICs/routes around an IP ladder.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for durable host-isolation receipts.",
    ),
) -> None:
    """Directly ladder-test RX0, RX1, or dual USB/IP throughput without plutod."""

    normalized_transport = transport.strip().lower()
    uri: str
    serial: str | None
    if normalized_transport == "usb":
        if expect_serial is not None and expect_serial != target:
            _fail(
                "radio_identity_mismatch",
                "for USB, TARGET is the serial and must equal --expect-serial",
                2,
            )
        uri = "usb:"
        serial = target
    elif normalized_transport == "ip":
        candidate = target.removeprefix("ip:")
        try:
            address = ip_address(candidate)
        except ValueError:
            _fail("invalid_radio_target", "IP ladder target must be a literal IP address", 2)
        if address.version != 4:
            _fail("invalid_radio_target", "IP ladder currently supports IPv4 targets", 2)
        if expect_serial is None:
            _fail("missing_radio_identity", "IP ladder requires --expect-serial", 2)
        uri = f"ip:{address}"
        serial = expect_serial
    else:
        _fail("invalid_ladder_transport", "ladder transport must be usb or ip", 2)

    isolation_plan = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if normalized_transport != "ip" or usb_sysfs_path is None:
            _fail(
                "host_isolation_target_required",
                "throughput ladder route isolation requires IP transport and --usb-sysfs-path",
                2,
            )
        from pluto_plus.host_isolation import HostIsolationError, prepare_usb_ssh_isolation

        local_devices = scan_local_usb_plutos()
        selected = [
            item
            for item in local_devices
            if item.serial == serial and item.usb_path == str(usb_sysfs_path)
        ]
        if len(selected) != 1 or len(selected[0].host_network_interfaces) != 1:
            _fail("host_isolation_identity_unavailable", "selected USB radio is ambiguous", 4)
        pluto_interfaces = tuple(
            interface.name for item in local_devices for interface in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                selected[0].host_network_interfaces[0].name,
                uri.removeprefix("ip:"),
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
                2,
            )

    normalized_format = output_format.strip().lower()
    if normalized_format not in {"table", "json"}:
        _fail("invalid_ladder_format", "ladder format must be table or json", 2)
    normalized_channels = channels.strip().lower()
    if normalized_channels not in LADDER_CHANNEL_SELECTIONS:
        _fail("ladder_failed", "channels must be rx0, rx1, or dual", 5)
    try:
        parsed_rates = parse_rate_ladder(rates)
    except ValueError as error:
        _fail("ladder_failed", str(error), 5)
    environment = inspect_iio_environment(require_usb=normalized_transport == "usb")
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)

    def ladder_action() -> Any:
        return run_iio_ladder(
            uri=uri,
            serial=serial,
            rates_hz=parsed_rates,
            channels=LADDER_CHANNEL_SELECTIONS[normalized_channels],
            samples_per_channel=samples,
            frames=frames,
            warmup_frames=warmup_frames,
            kernel_buffers=kernel_buffers,
        )

    try:
        isolation_receipt = None
        if isolation_plan is None:
            report = ladder_action()
        else:
            from pluto_plus.host_isolation import (
                HostIsolationError,
                HostIsolationExecutionError,
                execute_usb_ssh_isolated,
            )

            try:
                report, isolation_receipt = execute_usb_ssh_isolated(
                    isolation_plan,
                    confirmation=isolation_confirmation or "",
                    receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                    action=ladder_action,
                    pluto_interfaces=pluto_interfaces,
                )
            except HostIsolationExecutionError as error:
                _emit({"host_isolation": asdict(error.receipt)})
                raise typer.Exit(5) from error
            except HostIsolationError as error:
                _fail("host_isolation_failed", str(error), 4)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        _fail("ladder_failed", str(error), 5)
    if report_path is not None:
        from pluto_plus.release_candidate import (
            ReleaseCandidateContractError,
            write_private_contract,
        )

        try:
            write_private_contract(report_path.expanduser().absolute(), report)
        except (OSError, ReleaseCandidateContractError) as error:
            _fail("ladder_report_failed", str(error), 5)
    if normalized_format == "json":
        payload = report.model_dump(mode="json")
        _emit(
            payload
            if isolation_receipt is None
            else {"host_isolation": asdict(isolation_receipt), "result": payload}
        )
    else:
        typer.echo(_ladder_table(report))
        if isolation_receipt is not None:
            typer.echo(f"Host isolation receipt: {isolation_receipt.receipt_path}")
        if report_path is not None:
            typer.echo(f"Report: {report_path.expanduser().absolute()}")
    if report.failures:
        raise typer.Exit(5)


@radio_app.command("metadata-ladder")
def radio_metadata_ladder(
    target: str = typer.Argument(
        ...,
        help="USB serial when --transport=usb, or a literal IPv4 address when using IP.",
    ),
    transport: str = typer.Option(
        "usb", "--transport", "-t", help="Metadata libiio transport: usb or ip."
    ),
    expect_serial: str | None = typer.Option(
        None,
        "--expect-serial",
        help="Require this exact radio serial (required for IP).",
    ),
    sample_rate_hz: int = typer.Option(
        5_000_000,
        "--sample-rate-hz",
        min=1,
        help="Exact native sample rate used for every refill-size rung.",
    ),
    rf_bandwidth_hz: int = typer.Option(
        5_000_000,
        "--rf-bandwidth-hz",
        min=1,
        help="Exact analog RF bandwidth; must not exceed the sample rate.",
    ),
    metadata_abi: int = typer.Option(
        1,
        "--metadata-abi",
        min=1,
        max=3,
        help="Exact release-local and radio metadata ABI to attest.",
    ),
    channels: str = typer.Option(
        "dual",
        "--channels",
        help="Canonical receive layout: rx0, rx1, or dual (single RX requires ABI 3).",
    ),
    samples: str = typer.Option(
        DEFAULT_METADATA_SAMPLE_LADDER,
        "--samples",
        help="Strictly descending comma-separated samples/channel rungs.",
    ),
    frames: int = typer.Option(
        6,
        "--frames",
        min=2,
        max=32,
        help="Counter-observed metadata frames requested at each rung.",
    ),
    kernel_buffers: int = typer.Option(
        4,
        "--kernel-buffers",
        min=4,
        max=64,
        help="Explicit RX kernel-buffer count; at least four are required.",
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--report",
        help="Absent-only private canonical JSON report path beneath an owned mode-0700 parent.",
    ),
    usb_sysfs_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--usb-sysfs-path",
        help="Exact local USB sysfs node anchoring an isolated IP transport.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing Pluto NICs/routes around an IP ladder.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for durable host-isolation receipts.",
    ),
) -> None:
    """Find the largest refill preserving FPGA-counter continuity."""

    normalized_transport = transport.strip().lower()
    uri: str
    serial: str
    if normalized_transport == "usb":
        if expect_serial is not None and expect_serial != target:
            _fail(
                "radio_identity_mismatch",
                "for USB, TARGET is the serial and must equal --expect-serial",
                2,
            )
        uri = "usb:"
        serial = target
    elif normalized_transport == "ip":
        candidate = target.removeprefix("ip:")
        try:
            address = ip_address(candidate)
        except ValueError:
            _fail(
                "invalid_radio_target",
                "IP metadata ladder target must be a literal IP address",
                2,
            )
        if address.version != 4:
            _fail(
                "invalid_radio_target",
                "IP metadata ladder currently supports IPv4 targets",
                2,
            )
        if expect_serial is None:
            _fail(
                "missing_radio_identity",
                "IP metadata ladder requires --expect-serial",
                2,
            )
        uri = f"ip:{address}"
        serial = expect_serial
    else:
        _fail(
            "invalid_metadata_ladder_transport",
            "metadata ladder transport must be usb or ip",
            2,
        )
    isolation_plan = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if normalized_transport != "ip" or usb_sysfs_path is None:
            _fail(
                "host_isolation_target_required",
                "metadata ladder route isolation requires IP transport and --usb-sysfs-path",
                2,
            )
        from pluto_plus.host_isolation import HostIsolationError, prepare_usb_ssh_isolation

        local_devices = scan_local_usb_plutos()
        selected = [
            item
            for item in local_devices
            if item.serial == serial and item.usb_path == str(usb_sysfs_path)
        ]
        if len(selected) != 1 or len(selected[0].host_network_interfaces) != 1:
            _fail("host_isolation_identity_unavailable", "selected USB radio is ambiguous", 4)
        pluto_interfaces = tuple(
            interface.name for item in local_devices for interface in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                selected[0].host_network_interfaces[0].name,
                uri.removeprefix("ip:"),
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
                2,
            )
    try:
        parsed_samples = parse_metadata_sample_ladder(samples)
    except ValueError as error:
        _fail("metadata_ladder_failed", str(error), 5)
    environment = inspect_iio_environment(require_usb=normalized_transport == "usb")
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    normalized_channels = channels.strip().lower()
    if metadata_abi not in {1, 2, 3}:
        _fail("metadata_ladder_failed", "metadata ABI must be 1, 2, or 3", 5)
    if normalized_channels not in METADATA_CHANNEL_SELECTIONS:
        _fail("metadata_ladder_failed", "channels must be rx0, rx1, or dual", 5)

    def ladder_action() -> Any:
        return run_metadata_continuity_ladder(
            uri=uri,
            serial=serial,
            sample_rate_hz=sample_rate_hz,
            rf_bandwidth_hz=rf_bandwidth_hz,
            metadata_abi=cast(Any, metadata_abi),
            channels=METADATA_CHANNEL_SELECTIONS[cast(Any, normalized_channels)],
            samples_per_channel=parsed_samples,
            frames=frames,
            kernel_buffers=kernel_buffers,
        )

    try:
        isolation_receipt = None
        if isolation_plan is None:
            report = ladder_action()
        else:
            from pluto_plus.host_isolation import (
                HostIsolationError,
                HostIsolationExecutionError,
                execute_usb_ssh_isolated,
            )

            try:
                report, isolation_receipt = execute_usb_ssh_isolated(
                    isolation_plan,
                    confirmation=isolation_confirmation or "",
                    receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                    action=ladder_action,
                    pluto_interfaces=pluto_interfaces,
                )
            except HostIsolationExecutionError as error:
                _emit({"host_isolation": asdict(error.receipt)})
                raise typer.Exit(5) from error
            except HostIsolationError as error:
                _fail("host_isolation_failed", str(error), 4)
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        _fail("metadata_ladder_failed", str(error), 5)
    if report_path is not None:
        from pluto_plus.release_candidate import (
            ReleaseCandidateContractError,
            write_private_contract,
        )

        try:
            write_private_contract(report_path.expanduser().absolute(), report)
        except (OSError, ReleaseCandidateContractError) as error:
            _fail("metadata_ladder_report_failed", str(error), 5)
    payload = report.model_dump(mode="json")
    _emit(
        payload
        if isolation_receipt is None
        else {"host_isolation": asdict(isolation_receipt), "result": payload}
    )
    if report.failures or report.largest_passing_samples_per_channel is None:
        raise typer.Exit(5)


@radio_app.command("fastlock-probe")
def radio_fastlock_probe(
    serial: str = typer.Argument(..., help="Exact serial of one locally attached USB Pluto+."),
    lower_hz: int = typer.Option(
        DEFAULT_LOWER_FREQUENCY_HZ,
        "--lower-hz",
        min=70_000_000,
        max=6_000_000_000,
        help="Lower RX-LO frequency in Hz.",
    ),
    upper_hz: int = typer.Option(
        DEFAULT_UPPER_FREQUENCY_HZ,
        "--upper-hz",
        min=70_000_000,
        max=6_000_000_000,
        help="Upper RX-LO frequency in Hz.",
    ),
    hops: int = typer.Option(
        DEFAULT_HOPS_PER_MODE,
        "--hops",
        min=2,
        max=MAX_HOPS_PER_MODE,
        help="Even hop count for each of ordinary tuning and Fast Lock.",
    ),
    dwell_us: int = typer.Option(
        DEFAULT_DWELL_US,
        "--dwell-us",
        min=0,
        max=1_000_000,
        help="Host dwell after each control-plane hop.",
    ),
    profile_settle_ms: int = typer.Option(
        DEFAULT_PROFILE_SETTLE_MS,
        "--profile-settle-ms",
        min=0,
        max=1_000,
        help="Settle time before storing each volatile synthesizer profile.",
    ),
    lower_profile: int = typer.Option(DEFAULT_LOWER_PROFILE, "--lower-profile", min=0, max=7),
    upper_profile: int = typer.Option(DEFAULT_UPPER_PROFILE, "--upper-profile", min=0, max=7),
    max_seconds: int = typer.Option(
        DEFAULT_MAX_SECONDS,
        "--max-seconds",
        min=1,
        max=MAX_SECONDS,
        help=(
            "Cooperative operation budget checked around every dwell; the finite IIO timeout "
            "also bounds a stalled USB call, and the maximum is five minutes."
        ),
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None, "--report", help="Durable atomic JSON timing/restoration receipt."
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table or json."
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Run the bounded live USB workload, asserting the selected radio is idle.",
    ),
    confirmation: str | None = typer.Option(
        None, "--confirm", help="With --execute, the exact phrase printed by the dry run."
    ),
) -> None:
    """Compare ordinary RX tuning with AD9361 Fast Lock on one exact local USB radio."""

    normalized_format = output_format.strip().lower()
    if normalized_format not in {"table", "json"}:
        _fail("invalid_fastlock_format", "Fast Lock format must be table or json", 2)
    try:
        plan = prepare_usb_fastlock_probe(
            serial,
            lower_frequency_hz=lower_hz,
            upper_frequency_hz=upper_hz,
            lower_profile=lower_profile,
            upper_profile=upper_profile,
            hops_per_mode=hops,
            dwell_us=dwell_us,
            profile_settle_ms=profile_settle_ms,
            max_seconds=max_seconds,
        )
    except (FastLockProbeError, ValueError) as error:
        _fail("fastlock_plan_failed", str(error), 2)
    selected_report = (
        DEFAULT_FASTLOCK_REPORTS / f"fastlock-{plan.serial}-{time.time_ns()}.json"
        if report_path is None
        else report_path.expanduser().resolve()
    )
    if not execute:
        _emit(
            {
                "execute": False,
                "plan": plan.model_dump(mode="json"),
                "confirmation_phrase": plan.expected_confirmation,
                "report_path": str(selected_report),
            }
        )
        return
    if confirmation != plan.expected_confirmation:
        _fail(
            "fastlock_confirmation_required",
            f"--confirm must be exactly {plan.expected_confirmation!r}",
            2,
        )
    environment = inspect_iio_environment(require_usb=True)
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    try:
        report = run_usb_fastlock_probe(plan)
        write_fastlock_report(selected_report, report)
    except (FastLockProbeError, ImportError, OSError, RuntimeError, ValueError) as error:
        _fail("fastlock_probe_failed", str(error), 5)
    if normalized_format == "json":
        _emit(
            {
                "report": report.model_dump(mode="json"),
                "report_path": str(selected_report),
            }
        )
    else:
        typer.echo(_fastlock_table(report, selected_report))


@radio_app.command("soak-metadata")
def radio_soak_metadata(
    target: str = typer.Argument(..., help="Literal private IPv4 address of one radio."),
    expect_serial: str = typer.Option(
        ..., "--expect-serial", help="Require this exact radio serial over IIO and SSH."
    ),
    slots: int = typer.Option(
        9,
        "--slots",
        min=1,
        max=MAX_SLOTS,
        help="Bounded context slots; the full long-soak maximum is 936.",
    ),
    profile_id: str = typer.Option(
        "tandem-agc-v7-release-ram",
        "--profile",
        help="Exact immutable ABI-2/3 tandem firmware profile.",
    ),
    ssh_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-known-hosts-file",
        help="Private known_hosts file pinned to this exact radio and endpoint.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Optional private one-line radio password file; otherwise prompt.",
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None, "--report", help="Durable atomic JSON report path."
    ),
    execute: bool = typer.Option(False, "--execute", help="Run the bounded live workload."),
    confirmation: str | None = typer.Option(
        None, "--confirm", help="With --execute, the exact phrase printed by the dry run."
    ),
) -> None:
    """Soak repeated ABI-2/3 metadata context/retune/buffer lifecycles."""

    try:
        plan = prepare_metadata_soak(
            target,
            expect_serial,
            slots=slots,
            profile_id=profile_id,
        )
    except MetadataSoakError as error:
        _fail("metadata_soak_plan_failed", str(error), 2)
    selected_report = (
        DEFAULT_METADATA_SOAK_REPORTS / f"metadata-{plan.serial}-{time.time_ns()}.json"
        if report_path is None
        else report_path.expanduser().resolve()
    )
    if not execute:
        _emit(
            {
                "execute": False,
                "plan": plan.model_dump(mode="json"),
                "confirmation_phrase": plan.confirmation_phrase,
                "report_path": str(selected_report),
            }
        )
        return
    if confirmation != plan.confirmation_phrase:
        _fail(
            "metadata_soak_confirmation_required",
            f"--confirm must be exactly {plan.confirmation_phrase!r}",
            2,
        )
    if ssh_known_hosts_file is None:
        _fail(
            "metadata_soak_known_hosts_required",
            "--execute requires --ssh-known-hosts-file",
            2,
        )
    if selected_report.exists():
        _fail(
            "metadata_soak_report_exists",
            "refusing to replace an existing metadata soak report",
            2,
        )
    selected_known_hosts = ssh_known_hosts_file.expanduser().resolve()
    _read_private_file_bytes(
        selected_known_hosts,
        label="metadata soak SSH known-hosts",
        maximum_bytes=1024 * 1024,
    )
    password = (
        typer.prompt("Radio root password", hide_input=True)
        if ssh_password_file is None
        else _read_private_text_file(
            ssh_password_file.expanduser().resolve(), label="metadata soak SSH password"
        )
    )
    environment = inspect_iio_environment()
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    try:
        transport = BoundSshTransport(
            host=plan.target,
            interface=None,
            password=password,
            known_hosts_file=selected_known_hosts,
        )
        probe = SshMetadataHealthProbe(transport, serial=plan.serial)
        report = execute_metadata_soak(
            plan,
            report_path=selected_report,
            health_probe=probe,
            slot_runner=run_live_metadata_slot,
        )
    except (ImportError, MetadataSoakError, OSError, RuntimeError, ValueError) as error:
        _fail("metadata_soak_failed", str(error), 5)
    _emit(report.model_dump(mode="json"))


@radio_app.command("qualify-tandem")
def radio_qualify_tandem(
    serial: str = typer.Argument(..., help="Exact serial of one USB-attached local radio."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct USB sysfs node correlated with the serial.",
    ),
    attenuation_db: float = typer.Option(
        ...,
        "--attenuation-db",
        help="Declared physical attenuation on each TX2-to-RX loopback path.",
    ),
    strong_tx_gain_db: float = typer.Option(
        -10.0,
        "--strong-tx-gain-db",
        help="Strongest bounded TX2 hardware gain used by AUTO qualification.",
    ),
    weak_tx_gain_db: float = typer.Option(
        -60.0,
        "--weak-tx-gain-db",
        help="Weak TX2 hardware gain used by AUTO qualification.",
    ),
    profile_id: str = typer.Option(
        "tandem-agc-v7-release-ram",
        "--profile",
        help="Exact immutable ABI-2/3 tandem firmware profile to qualify.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Enable the bounded TX2 stimulus and run qualification.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, the exact phrase printed by the dry run.",
    ),
    report_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--report",
        help="Durable JSON report path.",
    ),
    watchdog: bool = typer.Option(
        True,
        "--watchdog/--no-watchdog",
        help="Include the 6.5-second stalled-owner rollback gate.",
    ),
) -> None:
    """Qualify three-band tandem HOLD/AUTO/watchdog on one TX2 loopback."""

    from pluto_plus.tandem_qualification import (
        execute_tandem_qualification,
        prepare_tandem_qualification,
    )

    try:
        plan = prepare_tandem_qualification(
            serial,
            usb_sysfs_path,
            physical_attenuation_db=attenuation_db,
            strong_tx_gain_db=strong_tx_gain_db,
            weak_tx_gain_db=weak_tx_gain_db,
            profile_id=profile_id,
        )
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        _fail("tandem_qualification_failed", str(error), 5)
    selected_report = report_path or (
        DEFAULT_QUALIFICATION_REPORTS / f"tandem-{serial}-{time.time_ns()}.json"
    )
    if not execute:
        _emit(
            {
                "mode": "dry_run",
                "will_enable_tx2": False,
                "plan": asdict(plan),
                "report_path": str(selected_report.expanduser().resolve()),
                "next_command": (
                    f"repeat with --execute and --confirm {json.dumps(plan.confirmation_phrase)}"
                ),
            }
        )
        return
    environment = inspect_iio_environment(require_usb=True)
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    if confirmation is None:
        _fail(
            "tandem_confirmation_required",
            f"--execute requires --confirm {plan.confirmation_phrase!r}",
            2,
        )
    try:
        report = execute_tandem_qualification(
            plan,
            confirmation=confirmation,
            report_path=selected_report,
            include_watchdog=watchdog,
        )
    except (ImportError, OSError, RuntimeError, ValueError) as error:
        _fail("tandem_qualification_failed", str(error), 5)
    _emit({"report_path": str(selected_report.expanduser().resolve()), "report": report})


@radio_app.command("status")
def radio_status(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Show identity, state, capabilities, and current settings."""
    _emit(_api(ctx).request("GET", f"radios/{radio_id}"))


@radio_app.command("recover")
def radio_recover(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    data_plane: bool = typer.Option(
        False,
        "--data-plane",
        help="Probe a wedged data plane and restart its attested iiOD over SSH.",
    ),
    usb_sysfs_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--usb-sysfs-path",
        help="Optional exact local USB node; otherwise derive it from SERIAL.",
    ),
    ssh_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-known-hosts-file",
        help="Private known_hosts pinned to the exact recovery endpoint.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Optional private one-line root password file; otherwise prompt on execution.",
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help="Literal private SSH IPv4; 192.168.2.1 uses the exact USB interface.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Restart iiOD only after the bounded pre-probe confirms a timeout.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase RESTART IIOD <serial>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_DATA_PLANE_RECOVERY_RECEIPTS,
        "--receipt-directory",
        help="Private directory for the durable recovery receipt.",
    ),
) -> None:
    """Recover controller resources, or explicitly repair a wedged iiOD data plane."""

    if not data_plane:
        local_options = (
            usb_sysfs_path,
            ssh_known_hosts_file,
            ssh_password_file,
            confirmation,
        )
        if execute or any(value is not None for value in local_options):
            _fail(
                "data_plane_recovery_flag_required",
                "local SSH recovery options require --data-plane",
                2,
            )
        _emit(_api(ctx).request("POST", f"radios/{radio_id}/recover"))
        return
    _recover_data_plane(
        radio_id,
        usb_sysfs_path=usb_sysfs_path,
        ssh_known_hosts_file=ssh_known_hosts_file,
        ssh_password_file=ssh_password_file,
        ssh_host=ssh_host,
        execute=execute,
        confirmation=confirmation,
        receipt_directory=receipt_directory,
    )


@radio_app.command("data-plane-status")
def radio_data_plane_status(
    serial: str = typer.Argument(..., help="Exact serial of the network radio."),
    ssh_host: str = typer.Option(
        ...,
        "--ssh-host",
        help="Exact private LAN IPv4 used for both pinned SSH and the IIO probe.",
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ...,
        "--ssh-known-hosts-file",
        help="Private known_hosts pinned to this exact LAN endpoint.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Private one-line root password file; otherwise prompt without echo.",
    ),
    probe: bool = typer.Option(
        False,
        "--probe",
        help="Bracket one bounded two-receiver LAN refill with runtime snapshots.",
    ),
) -> None:
    """Read exact-radio IIOD, IIO-buffer, DMA, IRQ, and kernel runtime evidence."""

    from pluto_plus.data_plane import (
        DataPlaneRecoveryError,
        inspect_data_plane_runtime,
        probe_iio_data_plane,
    )
    from pluto_plus.setup_helper import SetupHelperError

    try:
        address = ip_address(ssh_host)
    except ValueError:
        _fail("invalid_data_plane_status_host", "--ssh-host must be a literal IPv4", 2)
    if address.version != 4 or not address.is_private or str(address) != ssh_host:
        _fail(
            "invalid_data_plane_status_host",
            "--ssh-host must be a canonical private IPv4",
            2,
        )
    if ssh_host == "192.168.2.1":
        _fail(
            "invalid_data_plane_status_host",
            "data-plane status currently requires a unique LAN endpoint, not shared USB SSH",
            2,
        )
    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    _read_private_file_bytes(
        selected_known_hosts,
        label="data-plane status known-hosts",
        maximum_bytes=1024 * 1024,
    )
    password = (
        typer.prompt("Radio SSH password", hide_input=True)
        if ssh_password_file is None
        else _read_private_text_file(
            ssh_password_file.expanduser().absolute(), label="radio SSH password"
        )
    )
    try:
        transport = BoundSshTransport(
            host=ssh_host,
            interface=None,
            password=password,
            known_hosts_file=selected_known_hosts,
        )
        before = inspect_data_plane_runtime(transport, serial)
        bounded_probe = (
            probe_iio_data_plane(f"ip:{ssh_host}", serial) if probe else None
        )
        after = inspect_data_plane_runtime(transport, serial) if probe else None
    except (DataPlaneRecoveryError, SetupHelperError, OSError, ValueError) as error:
        _fail("data_plane_status_failed", str(error), 4)
    _emit(
        {
            "before": before.model_dump(mode="json"),
            "probe": None if bounded_probe is None else bounded_probe.model_dump(mode="json"),
            "after": None if after is None else after.model_dump(mode="json"),
        }
    )


def _recover_data_plane(
    serial: str,
    *,
    usb_sysfs_path: Path | None,
    ssh_known_hosts_file: Path | None,
    ssh_password_file: Path | None,
    ssh_host: str,
    execute: bool,
    confirmation: str | None,
    receipt_directory: Path,
) -> None:
    from pluto_plus.data_plane import (
        IIOD_RECOVERY_SCHEMA,
        IiodRecoveryReceipt,
        new_recovery_receipt_id,
        probe_iio_data_plane,
        restart_attested_iiod,
        utc_now,
        wait_for_iio_data_plane,
    )
    from pluto_plus.release_candidate import (
        ReleaseCandidateContractError,
        write_private_contract,
    )

    try:
        ssh_address = ip_address(ssh_host)
    except ValueError:
        _fail("invalid_data_plane_recovery_host", "--ssh-host must be a literal IPv4", 2)
    if ssh_address.version != 4 or not ssh_address.is_private:
        _fail("invalid_data_plane_recovery_host", "--ssh-host must be a private IPv4", 2)
    ssh_host = str(ssh_address)
    if ssh_known_hosts_file is None:
        _fail(
            "data_plane_recovery_trust_required",
            "--data-plane requires --ssh-known-hosts-file",
            2,
        )
    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    known_hosts_bytes = _read_private_file_bytes(
        selected_known_hosts,
        label="data-plane recovery known-hosts",
        maximum_bytes=1024 * 1024,
    )
    local_matches = [
        device
        for device in scan_local_usb_plutos()
        if device.serial == serial
        and (usb_sysfs_path is None or device.usb_path == str(usb_sysfs_path))
    ]
    selected_usb: LocalUsbPluto | None = None
    interface: str | None = None
    probe_uri: str
    if ssh_host == "192.168.2.1":
        if len(local_matches) != 1:
            _fail(
                "data_plane_recovery_target_ambiguous",
                f"expected one local USB radio with serial {serial!r}, found {len(local_matches)}",
                4,
            )
        selected_usb = local_matches[0]
        if len(selected_usb.host_network_interfaces) != 1:
            _fail(
                "data_plane_recovery_target_ambiguous",
                "selected USB radio does not expose one exact host network interface",
                4,
            )
        interface = selected_usb.host_network_interfaces[0].name
        probe_uri = "usb:"
    else:
        if usb_sysfs_path is not None and len(local_matches) != 1:
            _fail(
                "data_plane_recovery_target_ambiguous",
                "the requested USB path does not match one local radio with the expected serial",
                4,
            )
        selected_usb = local_matches[0] if len(local_matches) == 1 else None
        probe_uri = f"ip:{ssh_host}"
    environment = inspect_iio_environment(require_usb=probe_uri == "usb:")
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    before = probe_iio_data_plane(probe_uri, serial)
    confirmation_phrase = f"RESTART IIOD {serial}"
    dry_run = {
        "mode": "dry_run",
        "serial": serial,
        "ssh_host": ssh_host,
        "ssh_interface": interface,
        "usb_sysfs_path": None if selected_usb is None else selected_usb.usb_path,
        "before_probe": before.model_dump(mode="json"),
        "will_restart_iiod": False,
        "eligible_for_restart": before.failure_kind == "timeout",
        "next_command": (
            None
            if before.status == "pass" or before.failure_kind != "timeout"
            else f"repeat with --execute and --confirm {json.dumps(confirmation_phrase)}"
        ),
    }
    if not execute:
        _emit(dry_run)
        return
    if before.status == "pass":
        _emit({**dry_run, "mode": "already_healthy"})
        return
    if before.failure_kind != "timeout":
        _fail(
            "data_plane_recovery_not_eligible",
            "iiOD restart is allowed only for a bounded RX timeout; "
            f"probe failed as {before.failure_kind}: {before.error}",
            4,
        )
    if confirmation != confirmation_phrase:
        _fail(
            "data_plane_recovery_confirmation_required",
            f"--execute requires --confirm {confirmation_phrase!r}",
            2,
        )
    if ssh_password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        password = _read_private_text_file(
            ssh_password_file.expanduser().absolute(), label="radio SSH password"
        )

    receipt_id = new_recovery_receipt_id()
    started_at = utc_now()
    restart = None
    after = None
    error_text: str | None = None
    try:
        transport = BoundSshTransport(
            host=ssh_host,
            interface=interface,
            password=password,
            known_hosts_file=selected_known_hosts,
        )
        restart = restart_attested_iiod(transport, serial)
        after = wait_for_iio_data_plane(probe_uri, serial)
        if after.status != "pass":
            raise RuntimeError(f"post-restart data-plane probe failed: {after.error}")
    except Exception as error:
        error_text = f"{type(error).__name__}: {error}"
    receipt = IiodRecoveryReceipt(
        schema=IIOD_RECOVERY_SCHEMA,
        receipt_id=receipt_id,
        started_at=started_at,
        finished_at=utc_now(),
        serial=serial,
        uri=probe_uri,
        ssh_host=ssh_host,
        ssh_interface=interface,
        usb_sysfs_path=None if selected_usb is None else selected_usb.usb_path,
        known_hosts_sha256=hashlib.sha256(known_hosts_bytes).hexdigest(),
        before_probe=before,
        restart=restart,
        after_probe=after,
        outcome="recovered" if error_text is None else "failed",
        error=error_text,
    )
    selected_directory = receipt_directory.expanduser().absolute()
    try:
        selected_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory_state = selected_directory.lstat()
        if (
            not stat.S_ISDIR(directory_state.st_mode)
            or selected_directory.is_symlink()
            or directory_state.st_uid != os.getuid()
            or stat.S_IMODE(directory_state.st_mode) != 0o700
        ):
            raise OSError("receipt directory must be an owned mode-0700 real directory")
        identity = write_private_contract(selected_directory / f"{receipt_id}.json", receipt)
    except (OSError, ReleaseCandidateContractError) as error:
        _fail("data_plane_recovery_receipt_failed", str(error), 5)
    payload = {
        "receipt": receipt.model_dump(mode="json", by_alias=True),
        "receipt_path": str(identity.path),
        "receipt_sha256": identity.sha256,
    }
    if error_text is not None:
        _emit(payload)
        raise typer.Exit(5)
    _emit(payload)


@config_app.command("status")
def config_status(ctx: typer.Context) -> None:
    """Show whether exact-radio config administration is available."""

    _emit(_api(ctx).request("GET", "network-config"))


@config_app.command("show")
def config_show(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Read structured network settings and password-redacted config.txt."""

    _emit(_api(ctx).request("GET", f"radios/{radio_id}/config"))


def _standalone_network_plan_payload(plan: Any) -> dict[str, Any]:
    return {
        "plan_id": plan.plan_id,
        "created_at": plan.created_at.isoformat(),
        "expires_at": plan.expires_at.isoformat(),
        "identity": plan.identity.model_dump(mode="json"),
        "before": plan.before.model_dump(mode="json"),
        "interface": plan.interface.value,
        "mode": plan.mode.value,
        "address": plan.address,
        "netmask": plan.netmask,
        "host_address": plan.host_address,
        "changes": plan.changes,
        "confirmation": plan.confirmation,
        "endpoint_after_restart": plan.endpoint_after_restart,
        "restart_required": plan.restart_required,
    }


def _standalone_network_receipt_payload(receipt: Any) -> dict[str, Any]:
    payload = asdict(receipt)
    payload["started_at"] = receipt.started_at.isoformat()
    payload["finished_at"] = receipt.finished_at.isoformat()
    payload["identity"] = receipt.identity.model_dump(mode="json")
    payload["interface"] = receipt.interface.value
    payload["mode"] = receipt.mode.value
    payload["changes"] = receipt.changes
    return payload


@config_app.command("bootstrap-ethernet")
def config_bootstrap_ethernet(
    serial: str = typer.Argument(..., help="Exact stable serial of the local USB radio."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct /sys/bus/usb/devices path for the selected radio.",
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ...,
        "--ssh-known-hosts-file",
        help="Previously enrolled private known_hosts file for this exact USB endpoint.",
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Private radio password file; otherwise execution prompts without echo.",
    ),
    mode: str = typer.Option("static", "--mode", help="Ethernet mode: static or dhcp."),
    address: str | None = typer.Option(None, "--address", help="Static Ethernet IPv4."),
    netmask: str | None = typer.Option(
        None, "--netmask", help="Static dotted-decimal Ethernet netmask."
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Persist the validated Ethernet variables; omission only inspects and plans.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, the exact SET STATIC IP ... or SET DHCP ... phrase.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_NETWORK_CONFIG_RECEIPTS,
        "--receipt-directory",
        help="Private directory for network-config receipts and environment backups.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing Pluto USB routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Inspect or persist Ethernet settings through one exact USB-attached radio."""

    from pluto_plus.host_isolation import (
        HostIsolationError,
        HostIsolationExecutionError,
        execute_usb_ssh_isolated,
        prepare_usb_ssh_isolation,
    )
    from pluto_plus.ip_firmware import (
        IpFirmwareError,
        SshNetworkConfigBackend,
        pinned_ssh_host_key_fingerprint,
    )
    from pluto_plus.network_config import (
        NetworkAddressMode,
        NetworkConfigError,
        NetworkConfigExecutionError,
        NetworkConfigIdentity,
        NetworkConfigManager,
        NetworkInterface,
    )
    from pluto_plus.setup_helper import SetupHelperError

    endpoint = "192.168.2.1"
    local_devices = scan_local_usb_plutos()
    selected = [
        item
        for item in local_devices
        if item.serial == serial and item.usb_path == str(usb_sysfs_path)
    ]
    if len(selected) != 1 or len(selected[0].host_network_interfaces) != 1:
        _fail(
            "network_bootstrap_identity_unavailable",
            "serial and USB path must identify one radio with one network interface",
            4,
        )
    interface = selected[0].host_network_interfaces[0].name
    pluto_interfaces = tuple(
        network.name for item in local_devices for network in item.host_network_interfaces
    )
    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    _read_private_file_bytes(
        selected_known_hosts,
        label="radio SSH known-hosts",
        maximum_bytes=1024 * 1024,
    )
    try:
        fingerprint = pinned_ssh_host_key_fingerprint(selected_known_hosts, endpoint)
        selected_mode = NetworkAddressMode(mode)
    except ValueError as error:
        _fail("network_bootstrap_preflight_failed", str(error), 2)

    isolation_plan = None
    if isolate_usb_route:
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                interface,
                endpoint,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
                2,
            )

    if ssh_password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        password = _read_private_text_file(
            ssh_password_file.expanduser().absolute(), label="radio SSH password"
        )

    failed_receipt: dict[str, Any] | None = None

    def configure_action() -> tuple[Any, Any | None]:
        nonlocal failed_receipt
        ssh = BoundSshTransport(
            host=endpoint,
            interface=interface,
            password=password,
            known_hosts_file=selected_known_hosts,
            route_preflight=(None if isolation_plan is None else lambda: None),
        )
        backend = SshNetworkConfigBackend(
            endpoint=endpoint,
            host_key_fingerprint=fingerprint,
            command_runner=ssh.run,
        )
        manager = NetworkConfigManager(
            identity=NetworkConfigIdentity(
                serial=serial,
                endpoint=endpoint,
                host_key_fingerprint=fingerprint,
            ),
            backend=backend,
            receipt_directory=receipt_directory.expanduser().absolute(),
        )
        planned = manager.create_plan(
            interface=NetworkInterface.ETHERNET,
            mode=selected_mode,
            address=address,
            netmask=netmask,
            host_address=None,
        )
        if not execute:
            return planned.plan, None
        if confirmation != planned.plan.confirmation:
            raise NetworkConfigError(f"--execute requires --confirm {planned.plan.confirmation!r}")
        try:
            receipt = manager.execute(
                planned.plan,
                planned.confirmation_token,
                confirmation or "",
            )
        except NetworkConfigExecutionError as error:
            failed_receipt = _standalone_network_receipt_payload(error.receipt)
            raise
        return planned.plan, receipt

    isolation_receipt = None
    try:
        if isolation_plan is None:
            plan, receipt = configure_action()
        else:
            (plan, receipt), isolation_receipt = execute_usb_ssh_isolated(
                isolation_plan,
                confirmation=isolation_confirmation or "",
                receipt_directory=isolation_receipt_directory.expanduser().absolute(),
                action=configure_action,
                pluto_interfaces=pluto_interfaces,
            )
    except HostIsolationExecutionError as error:
        payload: dict[str, Any] = {"host_isolation": asdict(error.receipt)}
        if failed_receipt is not None:
            payload["network_config"] = failed_receipt
        _emit(payload)
        raise typer.Exit(5) from error
    except HostIsolationError as error:
        _fail("host_isolation_failed", str(error), 4)
    except NetworkConfigExecutionError as error:
        _emit(_standalone_network_receipt_payload(error.receipt))
        raise typer.Exit(5) from error
    except (IpFirmwareError, NetworkConfigError, SetupHelperError, OSError, ValueError) as error:
        _fail("network_bootstrap_failed", str(error), 4)

    isolation_payload = None if isolation_receipt is None else asdict(isolation_receipt)
    if receipt is None:
        _emit(
            {
                "mode": "dry_run",
                "will_persist": False,
                "will_restart": False,
                "plan": _standalone_network_plan_payload(plan),
                "host_isolation": isolation_payload,
                "next_step": (
                    f"repeat with --execute and --confirm {json.dumps(plan.confirmation)}; "
                    "restart remains a separate guarded action"
                ),
            }
        )
        return
    result = _standalone_network_receipt_payload(receipt)
    _emit(
        result
        if isolation_payload is None
        else {"host_isolation": isolation_payload, "result": result}
    )


@config_app.command("plan")
def config_plan(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    interface: str = typer.Option("ethernet", "--interface"),
    mode: str = typer.Option("static", "--mode"),
    address: str | None = typer.Option(None, "--address"),
    netmask: str | None = typer.Option(None, "--netmask"),
    host_address: str | None = typer.Option(None, "--host-address"),
) -> None:
    """Create a short-lived structured network configuration plan."""

    _emit(
        _api(ctx).request(
            "POST",
            f"radios/{radio_id}/config/plans",
            json_body={
                "interface": interface,
                "mode": mode,
                "address": address,
                "netmask": netmask,
                "host_address": host_address,
            },
        )
    )


@config_app.command("execute")
def config_execute(
    ctx: typer.Context,
    plan_id: str = typer.Argument(...),
    token: str = typer.Option(..., "--token"),
    operator_confirmation: str = typer.Option(..., "--operator-confirmation"),
) -> None:
    """Persist one exact plan; restart remains a separate operator action."""

    _emit(
        _api(ctx).request(
            "POST",
            "network-config/executions",
            json_body={
                "plan_id": plan_id,
                "confirmation_token": token,
                "operator_confirmation": operator_confirmation,
            },
        )
    )


@config_app.command("receipt-list")
def config_receipt_list(ctx: typer.Context) -> None:
    """List durable network-configuration mutation receipts."""

    _emit(_api(ctx).request("GET", "network-config/receipts"))


def _remediation_offers(payload: dict[str, Any]) -> list[tuple[str, str]]:
    """Collect (headline, command) for findings doctor can hand the operator a fix for.

    Doctor cannot obtain a firmware image -- nothing in this project downloads
    release assets -- so a firmware offer prints the exact guarded sequence rather
    than pretending it can flash on its own.
    """

    offers: list[tuple[str, str]] = []
    host = payload.get("host_libiio")
    if isinstance(host, dict) and host.get("healthy") is False:
        offers.append(
            (
                f"Host libiio is not usable ({host.get('status')}): {host.get('summary')}",
                str(host.get("remediation") or "scripts/install_native_libiio.sh"),
            )
        )
    for radio in payload.get("radios", []):
        stale = next(
            (
                check
                for check in radio.get("checks", [])
                if check.get("code") == "firmware.release_currency"
                and check.get("status") == "fail"
            ),
            None,
        )
        if stale is None:
            continue
        offers.append(
            (
                f"{radio.get('serial')} runs {stale.get('actual')}; "
                f"{stale.get('expected')} is the newest qualified release",
                (
                    f"pluto firmware upload <{stale.get('expected')}.dfu>; "
                    f"pluto firmware flash <IMAGE> "
                    f"--usb-sysfs-path {radio.get('usb_sysfs_path')} --execute --confirm ..."
                ),
            )
        )
    return offers


def _offer_remediations(offers: list[tuple[str, str]], *, assume_yes: bool) -> None:
    """Show each fix after an explicit yes; stay silent when not interactive."""

    if not offers:
        return
    if not assume_yes and not sys.stdin.isatty():
        typer.echo(
            f"\n{len(offers)} finding(s) have a known remediation. "
            "Rerun interactively, or pass --yes, to see the exact commands."
        )
        return
    for headline, command in offers:
        typer.echo(f"\n{headline}")
        if not assume_yes and not typer.confirm("Show the exact fix?", default=False):
            continue
        typer.echo(f"  {command}")


def _build_setup_probe(
    *,
    known_hosts_file: Path | None,
    password_file: Path | None,
    host: str,
    receipt_directory: Path,
    usb_sysfs_path: Path | None,
    repair: bool,
) -> Callable[[Any, str | None], Any] | None:
    """Build the credentialed persistent-tuple probe, or None to stay read-only.

    Without an enrolled known_hosts file there is no attested way to reach the
    radio, so doctor keeps its existing read-only behaviour and cannot mutate.
    """

    if known_hosts_file is None:
        return None
    if usb_sysfs_path is None:
        _fail(
            "setup_probe_target_required",
            "--setup-known-hosts-file requires --usb-sysfs-path: the pinned host key and the "
            "private endpoint each address exactly one radio",
            2,
        )
    from pluto_plus.setup_repair import SetupCredentials, probe_and_repair, ssh_manager_factory

    selected_known_hosts = known_hosts_file.expanduser().absolute()
    _read_private_file_bytes(
        selected_known_hosts, label="setup SSH known-hosts", maximum_bytes=1024 * 1024
    )
    if password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        password = _read_private_text_file(
            password_file.expanduser().absolute(), label="radio SSH password"
        )

    def probe(device: Any, firmware: str | None) -> Any:
        if not device.serial:
            from pluto_plus.setup_repair import SetupProbeOutcome

            return SetupProbeOutcome(
                status="unknown",
                actual=None,
                summary="Persistent tuple needs one stable USB serial to bind an identity",
            )
        interfaces = device.host_network_interfaces
        return probe_and_repair(
            serial=device.serial,
            usb_sysfs_path=device.usb_path,
            firmware_version=firmware,
            manager_factory=ssh_manager_factory(
                SetupCredentials(
                    host=host,
                    password=password,
                    known_hosts_file=selected_known_hosts,
                    receipt_directory=receipt_directory.expanduser().absolute(),
                    state_root=receipt_directory.expanduser().absolute().parent,
                    interface=(
                        interfaces[0].name
                        if host == "192.168.2.1" and len(interfaces) == 1
                        else None
                    ),
                )
            ),
            repair=repair,
        )

    return probe


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    radio_id: str | None = typer.Argument(None),
    usb_sysfs_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--usb-sysfs-path",
        help="Inspect one exact locally attached USB Pluto without plutod.",
    ),
    daemon: bool = typer.Option(
        False,
        "--daemon",
        help="Use plutod for all-radio doctor instead of standalone local USB inspection.",
    ),
    probe_data_plane: bool = typer.Option(
        False,
        "--probe-data-plane",
        help=(
            "Open one 64 Ki-sample RX buffer on the exact --usb-sysfs-path and report "
            "iiOD data-plane health."
        ),
    ),
    output_format: str = typer.Option(
        "table", "--format", "-f", help="Standalone output format: table or json."
    ),
    setup_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--setup-known-hosts-file",
        help=(
            "Enrolled private known_hosts pinned to this exact radio. Supplying it lets "
            "doctor read the persistent U-Boot tuple instead of reporting it unknown."
        ),
    ),
    setup_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--setup-password-file",
        help="Private radio root password file; prompts when omitted.",
    ),
    setup_host: str = typer.Option(
        "192.168.2.1", "--setup-host", help="Literal private IPv4 endpoint for the radio."
    ),
    setup_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_SETUP_RECEIPTS,
        "--setup-receipt-directory",
        help="Private directory for setup repair receipts.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing Pluto NICs/routes around the setup probe.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for durable host-isolation receipts.",
    ),
    yes: bool = typer.Option(
        False,
        "--yes",
        "-y",
        help="Assume yes for remediation prompts; required when stdin is not a TTY.",
    ),
    fix: bool = typer.Option(
        True,
        "--fix/--no-fix",
        help=(
            "Repair a non-canonical persistent U-Boot tuple through the guarded setup "
            "transaction. Requires --setup-known-hosts-file; --no-fix reports only."
        ),
    ),
) -> None:
    """Check local USB radios directly, or one managed radio through plutod."""

    if radio_id is not None or daemon:
        if usb_sysfs_path is not None or probe_data_plane or isolate_usb_route:
            _fail(
                "incompatible_doctor_options",
                "local USB probe options cannot be combined with a daemon radio ID or --daemon",
                2,
            )
        path = "doctor" if radio_id is None else f"radios/{radio_id}/doctor"
        _emit(_api(ctx).request("GET", path))
        return
    normalized = output_format.strip().lower()
    if normalized not in {"table", "json"}:
        _fail("invalid_doctor_format", "doctor format must be table or json", 2)
    from pluto_plus.local_doctor import diagnose_local_usb_radios

    if probe_data_plane and usb_sysfs_path is None:
        _fail(
            "data_plane_probe_target_required",
            "--probe-data-plane requires one exact --usb-sysfs-path",
            2,
        )

    isolation_plan = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if usb_sysfs_path is None or setup_known_hosts_file is None:
            _fail(
                "host_isolation_target_required",
                "doctor route isolation requires --usb-sysfs-path and "
                "--setup-known-hosts-file",
                2,
            )
        if setup_host != "192.168.2.1":
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        from pluto_plus.host_isolation import HostIsolationError, prepare_usb_ssh_isolation

        local_devices = scan_local_usb_plutos()
        selected = [item for item in local_devices if item.usb_path == str(usb_sysfs_path)]
        if len(selected) != 1 or len(selected[0].host_network_interfaces) != 1:
            _fail("host_isolation_identity_unavailable", "selected USB radio is ambiguous", 4)
        pluto_interfaces = tuple(
            interface.name for item in local_devices for interface in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                selected[0].host_network_interfaces[0].name,
                setup_host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly "
                f"{isolation_plan.confirmation_phrase!r}",
                2,
            )

    setup_probe = _build_setup_probe(
        known_hosts_file=setup_known_hosts_file,
        password_file=setup_password_file,
        host=setup_host,
        receipt_directory=setup_receipt_directory,
        usb_sysfs_path=usb_sysfs_path,
        repair=fix,
    )

    def doctor_action() -> Any:
        doctor_options: dict[str, Any] = {"setup_probe": setup_probe}
        if probe_data_plane:
            from pluto_plus.data_plane import probe_iio_data_plane

            def active_probe(device: LocalUsbPluto) -> Any:
                if device.serial is None:
                    raise ValueError("selected USB radio has no stable serial")
                return probe_iio_data_plane("usb:", device.serial)

            doctor_options["data_plane_probe"] = active_probe
        return diagnose_local_usb_radios(usb_sysfs_path, **doctor_options)

    isolation_receipt = None
    try:
        if isolation_plan is None:
            report = doctor_action()
        else:
            from pluto_plus.host_isolation import (
                HostIsolationError,
                HostIsolationExecutionError,
                execute_usb_ssh_isolated,
            )

            try:
                report, isolation_receipt = execute_usb_ssh_isolated(
                    isolation_plan,
                    confirmation=isolation_confirmation or "",
                    receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                    action=doctor_action,
                    pluto_interfaces=pluto_interfaces,
                )
            except HostIsolationExecutionError as error:
                _emit({"host_isolation": asdict(error.receipt)})
                raise typer.Exit(5) from error
            except HostIsolationError as error:
                _fail("host_isolation_failed", str(error), 4)
    except ValueError as error:
        _fail("local_doctor_target_not_found", str(error), 4)
    payload = asdict(report)
    if isolation_receipt is not None:
        payload["host_isolation"] = asdict(isolation_receipt)
    if normalized == "json":
        _emit(payload)
        return
    typer.echo(_local_doctor_table(payload))
    _offer_remediations(_remediation_offers(payload), assume_yes=yes)


def _local_doctor_table(report: dict[str, Any]) -> str:
    rows: list[dict[str, str]] = []
    for radio in report.get("radios", []):
        checks = radio.get("checks", [])
        failed = [item["code"] for item in checks if item.get("status") == "fail"]
        unknown = [item["code"] for item in checks if item.get("status") == "unknown"]
        notes = []
        if failed:
            notes.append("FAIL: " + ",".join(failed))
        if unknown:
            notes.append("UNKNOWN: " + ",".join(unknown))
        if radio.get("error"):
            notes.append(str(radio["error"]))
        repair = radio.get("setup_repair")
        if isinstance(repair, dict) and repair.get("attempted"):
            applied = ", ".join(
                f"{key} delete" if value is None else f"{key}={value}"
                for key, value in repair.get("changes") or ()
            )
            if repair.get("succeeded"):
                notes.append(f"REPAIRED setup ({applied}); receipt {repair.get('receipt_id')}")
            else:
                notes.append(f"REPAIR FAILED ({applied}): {repair.get('error')}")
        rows.append(
            {
                "USB": " ".join(
                    value
                    for value in (
                        str(radio.get("usb_bus_device") or ""),
                        str(radio.get("usb_sysfs_path") or ""),
                    )
                    if value
                ),
                "SERIAL": str(radio.get("serial") or "<blank>"),
                "FW": str(radio.get("firmware_version") or "unknown"),
                "PROFILE": str(radio.get("diagnostic_profile_id") or "unsupported"),
                "PHY": str(radio.get("phy_model") or "unknown"),
                "METADATA": (
                    f"ABI {radio['metadata_abi']}"
                    if radio.get("metadata_abi") is not None
                    else "unknown"
                ),
                "TANDEM": (
                    "yes"
                    if radio.get("tandem_agc") is True
                    else "no"
                    if radio.get("tandem_agc") is False
                    else "unknown"
                ),
                "RESULT": str(radio.get("overall") or "unknown").upper(),
                "DETAILS": "; ".join(notes) or "all observable checks passed",
            }
        )
    columns = ("USB", "SERIAL", "FW", "PROFILE", "PHY", "METADATA", "TANDEM", "RESULT", "DETAILS")
    return _text_table(rows, columns)


def _text_table(rows: list[dict[str, str]], columns: tuple[str, ...]) -> str:
    widths = {
        column: max([len(column), *(len(row.get(column, "")) for row in rows)])
        for column in columns
    }
    header = "  ".join(column.ljust(widths[column]) for column in columns)
    separator = "  ".join("-" * widths[column] for column in columns)
    body = [
        "  ".join(row.get(column, "").ljust(widths[column]) for column in columns) for row in rows
    ]
    return "\n".join((header, separator, *body))


@settings_app.command("get")
def settings_get(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Show the requested and hardware-read-back settings."""
    _emit(_api(ctx).request("GET", f"radios/{radio_id}/settings"))


@settings_app.command("set")
def settings_set(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    expected_revision: int | None = typer.Option(None, "--expected-revision", min=0),
    center_frequency_hz: float | None = typer.Option(None, "--frequency", min=1),
    sample_rate_hz: float | None = typer.Option(None, "--sample-rate", min=1),
    bandwidth_hz: float | None = typer.Option(None, "--bandwidth", min=1),
    gain_mode: str | None = typer.Option(None, "--gain-mode"),
    gain_db: float | None = typer.Option(None, "--gain", min=-10, max=80),
    channels: str | None = typer.Option(None, "--channels", help="Comma-separated RX channels."),
) -> None:
    """Atomically update settings with optimistic revision checking."""
    client = _api(ctx)
    if expected_revision is None:
        snapshot = client.request("GET", f"radios/{radio_id}")
        try:
            expected_revision = int(snapshot["revision"])
        except (KeyError, TypeError, ValueError):
            _fail("invalid_daemon_response", "radio status did not contain a revision", 5)

    body: dict[str, Any] = {"expected_revision": expected_revision}
    optional_values = {
        "center_frequency_hz": center_frequency_hz,
        "sample_rate_hz": sample_rate_hz,
        "bandwidth_hz": bandwidth_hz,
        "gain_mode": gain_mode,
        "gain_db": gain_db,
    }
    body.update({key: value for key, value in optional_values.items() if value is not None})
    if channels is not None:
        try:
            body["channels"] = [
                int(value.strip()) for value in channels.split(",") if value.strip()
            ]
        except ValueError:
            _fail("invalid_channels", "channels must be comma-separated integers", 2)
        if not body["channels"]:
            _fail("invalid_channels", "at least one channel is required", 2)
    if len(body) == 1:
        _fail("empty_settings_patch", "specify at least one setting to update", 2)
    _emit(client.request("PATCH", f"radios/{radio_id}/settings", json_body=body))


def _stream_body(
    duration_s: float | None,
    sample_count: int | None,
    block_size: int,
    fft_size: int,
    persist: bool,
    label: str | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "block_size": block_size,
        "fft_size": fft_size,
        "persist": persist,
    }
    if duration_s is not None:
        body["duration_s"] = duration_s
    if sample_count is not None:
        body["sample_count"] = sample_count
    if label is not None:
        body["label"] = label
    return body


@stream_app.command("start")
def stream_start(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    duration_s: float | None = typer.Option(None, "--duration", min=0.000001),
    sample_count: int | None = typer.Option(None, "--samples", min=1),
    block_size: int = typer.Option(65_536, "--block-size", min=1_024, max=1_048_576),
    fft_size: int = typer.Option(4_096, "--fft-size", min=256, max=65_536),
    persist: bool = typer.Option(False, "--persist"),
    label: str | None = typer.Option(None, "--label"),
) -> None:
    """Start a live stream, optionally bounded or persisted."""
    if duration_s is not None and sample_count is not None:
        _fail("invalid_bounds", "--duration and --samples are mutually exclusive", 2)
    body = _stream_body(duration_s, sample_count, block_size, fft_size, persist, label)
    _emit(_api(ctx).request("POST", f"radios/{radio_id}/streams", json_body=body))


@stream_app.command("stop")
def stream_stop(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Stop the radio's current stream."""
    _emit(_api(ctx).request("DELETE", f"radios/{radio_id}/streams/current"))


@capture_app.command("start")
def capture_start(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    duration_s: float | None = typer.Option(None, "--duration", min=0.000001),
    sample_count: int | None = typer.Option(None, "--samples", min=1),
    block_size: int = typer.Option(65_536, "--block-size", min=1_024, max=1_048_576),
    fft_size: int = typer.Option(4_096, "--fft-size", min=256, max=65_536),
    label: str | None = typer.Option(None, "--label"),
) -> None:
    """Start a bounded, persistent IQ capture."""
    if (duration_s is None) == (sample_count is None):
        _fail("invalid_bounds", "specify exactly one of --duration or --samples", 2)
    body = _stream_body(duration_s, sample_count, block_size, fft_size, True, label)
    _emit(_api(ctx).request("POST", f"radios/{radio_id}/streams", json_body=body))


@job_app.command("status")
def job_status(ctx: typer.Context, job_id: str = typer.Argument(...)) -> None:
    """Show a stream or capture job."""
    _emit(_api(ctx).request("GET", f"jobs/{job_id}"))


@job_app.command("list")
def job_list(ctx: typer.Context, radio_id: str | None = typer.Option(None, "--radio")) -> None:
    """List stream and capture jobs."""
    path = "jobs" if radio_id is None else f"jobs?radio_id={radio_id}"
    _emit(_api(ctx).request("GET", path))


@artifact_app.command("list")
def artifact_list(ctx: typer.Context) -> None:
    """List immutable capture artifacts."""
    _emit(_api(ctx).request("GET", "artifacts"))


@scan_app.command("start")
def scan_start(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    start_frequency_hz: float = typer.Option(..., "--start", min=1),
    stop_frequency_hz: float = typer.Option(..., "--stop", min=1),
    step_hz: float = typer.Option(..., "--step", min=1),
    sample_rate_hz: float = typer.Option(2_500_000, "--sample-rate", min=1),
    bandwidth_hz: float = typer.Option(2_500_000, "--bandwidth", min=1),
    gain_mode: str = typer.Option("manual", "--gain-mode"),
    gain_db: float | None = typer.Option(40.0, "--gain", min=-10, max=80),
    samples_per_frequency: int = typer.Option(16_384, "--samples", min=1_024),
    fft_size: int = typer.Option(4_096, "--fft-size", min=256),
    settle_buffers: int = typer.Option(1, "--settle-buffers", min=0, max=16),
) -> None:
    """Start a bounded sweep and restore the prior settings afterward."""
    body = {
        "start_frequency_hz": start_frequency_hz,
        "stop_frequency_hz": stop_frequency_hz,
        "step_hz": step_hz,
        "sample_rate_hz": sample_rate_hz,
        "bandwidth_hz": bandwidth_hz,
        "gain_mode": gain_mode,
        "gain_db": gain_db if gain_mode == "manual" else None,
        "samples_per_frequency": samples_per_frequency,
        "fft_size": fft_size,
        "settle_buffers": settle_buffers,
    }
    _emit(_api(ctx).request("POST", f"radios/{radio_id}/scans", json_body=body))


@scan_app.command("stop")
def scan_stop(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Cancel the current scan and restore the prior settings."""
    _emit(_api(ctx).request("DELETE", f"radios/{radio_id}/scans/current"))


@scan_app.command("status")
def scan_status(ctx: typer.Context, job_id: str = typer.Argument(...)) -> None:
    """Show a frequency-scan job."""
    _emit(_api(ctx).request("GET", f"scan-jobs/{job_id}"))


@scan_app.command("list")
def scan_list(ctx: typer.Context) -> None:
    """List completed scan results."""
    _emit(_api(ctx).request("GET", "scans"))


@scan_app.command("result")
def scan_result(ctx: typer.Context, scan_id: str = typer.Argument(...)) -> None:
    """Show one completed scan result."""
    _emit(_api(ctx).request("GET", f"scans/{scan_id}"))


@firmware_app.command("status")
def firmware_status(ctx: typer.Context) -> None:
    """Show whether the daemon has an explicitly configured firmware executor."""
    _emit(_api(ctx).request("GET", "firmware"))


@firmware_app.command("inspect")
def firmware_inspect(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Show the radio's attested identity, capabilities, and current firmware."""
    client = _api(ctx)
    _emit(
        {
            "firmware_service": client.request("GET", "firmware"),
            "radio": client.request("GET", f"radios/{radio_id}"),
        }
    )


@firmware_app.command("upload")
def firmware_upload(
    ctx: typer.Context,
    image: Path = typer.Argument(...),  # noqa: B008
) -> None:
    """Upload a DFU or firmware-only FRM into content-addressed staging."""
    if not image.is_file():
        _fail("firmware_image_not_found", f"firmware image does not exist: {image}", 2)
    try:
        data = image.read_bytes()
    except OSError as error:
        _fail("firmware_image_unreadable", str(error), 2)
    _emit(
        _api(ctx).request(
            "POST",
            f"firmware/images?{httpx.QueryParams({'filename': image.name})}",
            content=data,
        )
    )


@firmware_app.command("image-list")
def firmware_image_list(ctx: typer.Context) -> None:
    """List staged firmware images."""
    _emit(_api(ctx).request("GET", "firmware/images"))


@firmware_app.command("plan")
def firmware_plan(
    ctx: typer.Context,
    radio_id: str = typer.Argument(...),
    image_id: str = typer.Argument(...),
    mode: str = typer.Option("volatile_dfu", "--mode"),
    transport: str = typer.Option("usb", "--transport", help="usb or ssh"),
    expected_version: str | None = typer.Option(None, "--expected-version"),
) -> None:
    """Create an expiring identity/hash-bound plan and one-time token."""
    normalized_transport = "ssh_frm" if transport == "ssh" else transport
    if normalized_transport not in {"usb", "ssh_frm"}:
        _fail("invalid_firmware_transport", "--transport must be usb or ssh", 2)
    if normalized_transport == "ssh_frm" and mode != "persistent_qspi":
        _fail(
            "invalid_firmware_mode",
            "SSH firmware transport requires --mode persistent_qspi",
            2,
        )
    body = {"image_id": image_id, "mode": mode}
    if normalized_transport != "usb":
        body["transport"] = normalized_transport
    if expected_version is not None:
        body["expected_firmware_version"] = expected_version
    _emit(
        _api(ctx).request(
            "POST",
            (
                f"radios/{radio_id}/doctor/firmware-plans"
                if normalized_transport == "ssh_frm"
                else f"radios/{radio_id}/firmware/plans"
            ),
            json_body=body,
        )
    )


@firmware_app.command("execute")
def firmware_execute(
    ctx: typer.Context,
    plan_id: str = typer.Argument(...),
    confirmation_token: str = typer.Option(..., "--token", prompt=True, hide_input=True),
    operator_confirmation: str | None = typer.Option(
        None,
        "--operator-confirmation",
        help="For ssh_frm, exact phrase FLASH <serial>.",
    ),
) -> None:
    """Consume a plan's one-time token and perform its exact operation."""
    body = {"plan_id": plan_id, "confirmation_token": confirmation_token}
    if operator_confirmation is not None:
        body["operator_confirmation"] = operator_confirmation
    _emit(
        _api(ctx).request(
            "POST",
            "firmware/executions",
            json_body=body,
        )
    )


@firmware_app.command("receipt-list")
def firmware_receipt_list(ctx: typer.Context) -> None:
    """List receipts for authorized firmware attempts in this daemon lifetime."""
    _emit(_api(ctx).request("GET", "firmware/receipts"))


@firmware_app.command("reconcile")
def firmware_reconcile(ctx: typer.Context, receipt_id: str = typer.Argument(...)) -> None:
    """Read-only re-attest an uncertain firmware attempt; never retry it."""

    _emit(_api(ctx).request("POST", f"firmware/receipts/{receipt_id}/reconcile", json_body={}))


@firmware_app.command("reconcile-local")
def firmware_reconcile_local(
    receipt_id: str = typer.Argument(..., help="Exact standalone flash receipt ID."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ..., "--usb-sysfs-path", help="Exact direct USB sysfs node recorded by the receipt."
    ),
    profile: str = typer.Option(
        ..., "--profile", help="Exact immutable persistent profile recorded by the receipt."
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ..., "--ssh-known-hosts-file", help="Pinned known_hosts for the exact returned radio."
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None, "--ssh-password-file", help="Optional private password file; otherwise prompt."
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help="Literal private endpoint; non-default addresses use the LAN route.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_BOOTSTRAP_RECEIPTS,
        "--receipt-directory",
        help="Private directory containing the standalone receipt.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing local Pluto NICs/routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Read-only re-attest an uncertain standalone flash; never retry it."""

    from pluto_plus.bootstrap_firmware import (
        BootstrapFirmwareError,
        BoundSshBootstrapTransport,
        reconcile_usb_flash_receipt,
    )
    from pluto_plus.host_isolation import (
        HostIsolationError,
        HostIsolationExecutionError,
        execute_usb_ssh_isolated,
        prepare_usb_ssh_isolation,
    )

    interface = None
    local_devices: tuple[LocalUsbPluto, ...] = ()
    if ssh_host == "192.168.2.1":
        local_devices = scan_local_usb_plutos()
        selected_matches = [
            item
            for item in local_devices
            if item.usb_path == str(usb_sysfs_path) and len(item.host_network_interfaces) == 1
        ]
        if len(selected_matches) != 1:
            _fail(
                "standalone_reconciliation_identity_unavailable",
                "USB path must identify one radio with one network interface",
                4,
            )
        interface = selected_matches[0].host_network_interfaces[0].name
    isolation_plan = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if ssh_host != "192.168.2.1" or interface is None:
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        pluto_interfaces = tuple(
            network.name for item in local_devices for network in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                interface,
                ssh_host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
                2,
            )
    if ssh_password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        try:
            password = (
                _read_private_file_bytes(
                    ssh_password_file,
                    label="radio SSH password",
                    maximum_bytes=4096,
                )
                .decode("utf-8")
                .strip()
            )
        except UnicodeDecodeError:
            _fail("invalid_private_file", "radio SSH password must be UTF-8", 2)

    def reconcile_action() -> Any:
        try:
            transport = BoundSshBootstrapTransport(
                interface=interface,
                password=password,
                known_hosts_file=ssh_known_hosts_file.expanduser().resolve(),
                host=ssh_host,
            )
            return reconcile_usb_flash_receipt(
                receipt_id,
                receipt_directory=receipt_directory.expanduser().resolve(),
                usb_sysfs_path=usb_sysfs_path,
                mutation_profile_id=profile,
                transport=transport,
            )
        except (BootstrapFirmwareError, OSError, ValueError) as error:
            raise BootstrapFirmwareError(str(error)) from error

    try:
        isolation_receipt = None
        if isolation_plan is None:
            result = reconcile_action()
        else:
            result, isolation_receipt = execute_usb_ssh_isolated(
                isolation_plan,
                confirmation=isolation_confirmation or "",
                receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                action=reconcile_action,
                pluto_interfaces=pluto_interfaces,
            )
    except HostIsolationExecutionError as error:
        _emit({"host_isolation": asdict(error.receipt)})
        raise typer.Exit(5) from error
    except HostIsolationError as error:
        _fail("host_isolation_failed", str(error), 4)
    except (BootstrapFirmwareError, OSError, ValueError) as error:
        _fail("standalone_reconciliation_failed", str(error), 4)
    if isolation_receipt is None:
        _emit(asdict(result))
    else:
        _emit({"host_isolation": asdict(isolation_receipt), "result": asdict(result)})


@firmware_app.command("enroll-lan-ssh")
def firmware_enroll_lan_ssh(
    serial: str = typer.Argument(..., help="Exact serial expected at the LAN endpoint."),
    host: str = typer.Option(..., "--host", help="Exact private LAN IPv4 endpoint."),
    known_hosts_file: Path = typer.Option(  # noqa: B008
        ..., "--known-hosts-file", help="New private serial-specific known_hosts file."
    ),
    profile: str = typer.Option(
        ...,
        "--profile",
        help="Immutable metadata firmware/capability profile required from IIOD.",
    ),
    execute: bool = typer.Option(False, "--execute", help="Perform explicit LAN TOFU."),
    use_default_password: bool = typer.Option(
        False,
        "--use-default-password",
        help="Acknowledge use of the Pluto factory-default root password for enrollment.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase TRUST LAN SSH <serial> <host>.",
    ),
) -> None:
    """Pin one LAN SSH key after read-only IIOD identity attestation."""

    from pluto_plus.bootstrap_firmware import (
        BootstrapFirmwareError,
        execute_lan_ssh_host_key_enrollment,
        prepare_lan_ssh_host_key_enrollment,
    )

    try:
        plan = prepare_lan_ssh_host_key_enrollment(
            serial=serial,
            host=host,
            known_hosts_file=known_hosts_file,
            profile_id=profile,
        )
    except (BootstrapFirmwareError, OSError, ValueError) as error:
        _fail("lan_ssh_identity_attestation_failed", str(error), 4)
    if not execute:
        _emit(
            {
                "mode": "dry_run",
                "will_trust_host_key": False,
                "warning": "explicit LAN TOFU is weaker than USB-anchored enrollment",
                "plan": asdict(plan),
            }
        )
        return
    if confirmation != plan.confirmation_phrase:
        _fail(
            "lan_ssh_confirmation_required",
            f"--confirm must be exactly {plan.confirmation_phrase!r}",
            2,
        )
    if not use_default_password:
        _fail(
            "lan_ssh_default_password_authorization_required",
            "--execute requires explicit --use-default-password authorization",
            2,
        )
    try:
        result = execute_lan_ssh_host_key_enrollment(
            plan,
            confirmation=confirmation,
        )
    except (BootstrapFirmwareError, OSError, ValueError) as error:
        _fail("lan_ssh_enrollment_failed", str(error), 4)
    _emit(result)


@firmware_app.command("enroll-usb-ssh")
def firmware_enroll_usb_ssh(
    serial: str = typer.Argument(..., help="Exact serial of one USB-attached local radio."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ..., "--usb-sysfs-path", help="Exact direct USB sysfs node for the serial."
    ),
    known_hosts_file: Path = typer.Option(  # noqa: B008
        ..., "--known-hosts-file", help="New private serial-specific known_hosts file."
    ),
    execute: bool = typer.Option(False, "--execute", help="Perform the bounded enrollment."),
    confirmation: str | None = typer.Option(
        None, "--confirm", help="With --execute, exact phrase TRUST USB SSH <serial>."
    ),
    password_file: Path | None = typer.Option(  # noqa: B008
        None, "--password-file", help="Optional private password file; otherwise prompt."
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help="Literal private IPv4 endpoint; non-default addresses use the LAN route.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing local Pluto NICs/routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="With isolation execution, exact phrase ISOLATE USB SSH <interface>.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Pin an SSH host key after USB-selected remote serial attestation."""

    phrase = f"TRUST USB SSH {serial}"
    local_devices = scan_local_usb_plutos()
    matches = [
        item
        for item in local_devices
        if item.serial == serial and item.usb_path == str(usb_sysfs_path)
    ]
    if len(matches) != 1 or len(matches[0].host_network_interfaces) != 1:
        _fail(
            "usb_ssh_identity_unavailable",
            "serial/path must identify one local radio with one USB network interface",
            4,
        )
    plan = {
        "serial": serial,
        "usb_sysfs_path": str(usb_sysfs_path),
        "usb_interface": matches[0].host_network_interfaces[0].name,
        "known_hosts_file": str(known_hosts_file.expanduser().resolve()),
        "ssh_host": ssh_host,
        "confirmation_phrase": phrase,
    }
    isolation_plan = None
    pluto_interfaces = tuple(
        interface.name for item in local_devices for interface in item.host_network_interfaces
    )
    if isolate_usb_route:
        if ssh_host != "192.168.2.1":
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        from pluto_plus.host_isolation import HostIsolationError, prepare_usb_ssh_isolation

        try:
            isolation_plan = prepare_usb_ssh_isolation(
                matches[0].host_network_interfaces[0].name,
                ssh_host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
    if not execute:
        _emit(
            {
                "mode": "dry_run",
                "will_trust_host_key": False,
                "plan": plan,
                "host_isolation": (None if isolation_plan is None else asdict(isolation_plan)),
            }
        )
        return
    if confirmation != phrase:
        _fail("usb_ssh_confirmation_required", f"--confirm must be exactly {phrase!r}", 2)
    if isolation_plan is not None and isolation_confirmation != isolation_plan.confirmation_phrase:
        _fail(
            "host_isolation_confirmation_required",
            f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
            2,
        )
    if password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        try:
            password = (
                _read_private_file_bytes(
                    password_file,
                    label="radio SSH password",
                    maximum_bytes=4096,
                )
                .decode("utf-8")
                .strip()
            )
        except UnicodeDecodeError:
            _fail("invalid_private_file", "radio SSH password must be UTF-8", 2)
    from pluto_plus.bootstrap_firmware import (
        BootstrapFirmwareError,
        enroll_bound_usb_ssh_host_key,
    )

    def enrollment_action() -> dict[str, str]:
        return enroll_bound_usb_ssh_host_key(
            serial=serial,
            usb_sysfs_path=usb_sysfs_path,
            known_hosts_file=known_hosts_file,
            password=password,
            host=ssh_host,
        )

    try:
        isolation_receipt = None
        if isolation_plan is None:
            result = enrollment_action()
        else:
            from pluto_plus.host_isolation import (
                HostIsolationError,
                HostIsolationExecutionError,
                execute_usb_ssh_isolated,
            )

            try:
                result, isolation_receipt = execute_usb_ssh_isolated(
                    isolation_plan,
                    confirmation=isolation_confirmation or "",
                    receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                    action=enrollment_action,
                    pluto_interfaces=pluto_interfaces,
                )
            except HostIsolationExecutionError as error:
                _emit({"host_isolation": asdict(error.receipt)})
                raise typer.Exit(5) from error
            except HostIsolationError as error:
                _fail("host_isolation_failed", str(error), 4)
    except (BootstrapFirmwareError, OSError, ValueError) as error:
        _fail("usb_ssh_enrollment_failed", str(error), 4)
    if isolation_receipt is None:
        _emit(result)
    else:
        _emit({"host_isolation": asdict(isolation_receipt), "result": result})


@firmware_app.command("flash")
def firmware_flash_usb(
    image: Path = typer.Argument(...),  # noqa: B008
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct runtime USB node for one serial-attested Pluto.",
    ),
    profile: str = typer.Option(
        "libiio-continuous-metadata",
        "--profile",
        help="Exact standalone mutation profile; never inferred from the image.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Perform the planned write; omission is a read-only dry run.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase FLASH <serial>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_BOOTSTRAP_RECEIPTS,
        "--receipt-directory",
        help="Private directory for durable standalone flash receipts.",
    ),
    transport: str = typer.Option(
        "mass-storage", "--transport", help="Execution transport: mass-storage or ssh."
    ),
    ssh_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None, "--ssh-known-hosts-file", help="Pinned mode-private known_hosts for bound SSH."
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None, "--ssh-password-file", help="Optional mode-private password file; otherwise prompt."
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help="Literal private IPv4 endpoint; non-default addresses use the LAN route.",
    ),
    return_timeout_s: float = typer.Option(
        180,
        "--return-timeout",
        min=30,
        max=1800,
        help="Seconds to wait for the exact radio to return after flashing.",
    ),
) -> None:
    """Flash one exact qualified profile onto a serial-attested local USB Pluto."""

    _standalone_usb_flash(
        image,
        usb_sysfs_path,
        execute=execute,
        confirmation=confirmation,
        receipt_directory=receipt_directory,
        force_blank_serial=False,
        transport=transport,
        ssh_known_hosts_file=ssh_known_hosts_file,
        ssh_password_file=ssh_password_file,
        ssh_host=ssh_host,
        return_timeout_s=return_timeout_s,
        mutation_profile_id=profile,
    )


@environment_survey_app.command("plan")
def environment_survey_plan(
    serial: str = typer.Option(..., "--serial", help="Exact local runtime USB serial."),
    usb_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-path",
        help="Exact direct /sys/bus/usb/devices topology path for that serial.",
    ),
    emitter_inventory: Path = typer.Option(  # noqa: B008
        ...,
        "--emitter-inventory",
        help="Private canonical worst-normal Wi-Fi emitter inventory JSON.",
    ),
    emitter_inventory_sha256: str = typer.Option(
        ...,
        "--emitter-inventory-sha256",
        help="Expected lowercase SHA-256 of the exact canonical emitter inventory bytes.",
    ),
    result_root: Path = typer.Option(  # noqa: B008
        DEFAULT_ENVIRONMENT_SURVEY_REPORTS,
        "--result-root",
        help="Existing owned mode-0700 parent for raw, PSD, STFT, manifest, and receipt.",
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", help="Absent private survey-plan JSON output."
    ),
    ensure_mute: bool = typer.Option(
        False,
        "--ensure-mute",
        help="Authorize only the complete fail-closed TX mute before RX surveying.",
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout whose exact commit is bound into the plan.",
    ),
) -> None:
    """Create a passive exact-USB survey plan; never open IIO or touch the radio."""

    import pluto_plus.environment_survey as survey_source
    from pluto_plus import __version__
    from pluto_plus.environment_survey import (
        EnvironmentSurveyEmitterInventory,
        EnvironmentSurveyError,
        EnvironmentSurveyParameters,
        prepare_environment_survey,
        project_occupied_2_4_spans,
    )
    from pluto_plus.release_candidate import (
        ReleaseCandidateContractError,
        load_private_contract,
        model_file_identity,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import attest_clean_tool_repository

    if not ensure_mute:
        _fail(
            "environment_survey_mute_not_authorized",
            "plan creation requires explicit --ensure-mute authority",
            2,
        )
    if (
        len(emitter_inventory_sha256) != 64
        or emitter_inventory_sha256 != emitter_inventory_sha256.lower()
        or any(value not in "0123456789abcdef" for value in emitter_inventory_sha256)
    ):
        _fail(
            "environment_survey_inventory_digest_invalid",
            "--emitter-inventory-sha256 must be exactly 64 lowercase hexadecimal characters",
            2,
        )
    try:
        inventory_path = emitter_inventory.expanduser().absolute()
        inventory = load_private_contract(inventory_path, EnvironmentSurveyEmitterInventory)
        inventory_identity = model_file_identity(inventory_path, inventory)
        if inventory_identity.sha256 != emitter_inventory_sha256:
            raise EnvironmentSurveyError("emitter inventory SHA-256 differs from the CLI pin")
        parameters = EnvironmentSurveyParameters(
            occupied_2_4_spans_hz=project_occupied_2_4_spans(inventory),
        )
        source = attest_clean_tool_repository(
            tool_repository.expanduser().absolute(),
            imported_source_files=(Path(__file__), Path(survey_source.__file__)),
        )
        plan = prepare_environment_survey(
            scan_local_usb_plutos(),
            serial=serial,
            usb_path=usb_path.expanduser().absolute(),
            output_root=result_root.expanduser().absolute(),
            emitter_inventory_file=inventory_identity,
            emitter_inventory=inventory,
            parameters=parameters,
            tool_source=source,
            tool_version=__version__,
        )
        identity = write_private_contract(output.expanduser().absolute(), plan)
    except (
        OSError,
        ValueError,
        EnvironmentSurveyError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("environment_survey_plan_failed", str(error), 4)
    _emit(
        {
            "mode": "passive_plan",
            "hardware_accessed": False,
            "pluto_tx_authorized": False,
            "ssh_authorized": False,
            "route_mutation_authorized": False,
            "firmware_mutation_authorized": False,
            "plan": plan.model_dump(mode="json", by_alias=True),
            "output": str(identity.path),
            "sha256": identity.sha256,
            "next_command": (
                "pluto environment-survey execute --plan "
                f"{identity.path} --expected-plan-sha256 {identity.sha256} "
                "--ensure-mute --confirm "
                f"{json.dumps(plan.confirmation_phrase)}"
            ),
        }
    )


@environment_survey_app.command("execute")
def environment_survey_execute(
    plan: Path = typer.Option(  # noqa: B008
        ..., "--plan", help="Private plan produced by environment-survey plan."
    ),
    expected_plan_sha256: str = typer.Option(
        ...,
        "--expected-plan-sha256",
        help="Exact lowercase SHA-256 printed when the approved plan was created.",
    ),
    confirmation: str = typer.Option(
        ..., "--confirm", help="Exact serial- and survey-specific phrase printed by plan."
    ),
    ensure_mute: bool = typer.Option(
        False,
        "--ensure-mute",
        help="Explicitly apply and verify the complete TX mute before and after RX capture.",
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Same clean checkout and commit bound into the retained plan.",
    ),
) -> None:
    """Run one local USB-IIO RX survey with no SSH, route, firmware, QSPI, or TX."""

    import pluto_plus.environment_survey as survey_source
    import pluto_plus.environment_survey_linux as survey_linux_source
    from pluto_plus import __version__
    from pluto_plus.environment_survey import (
        EnvironmentSurveyError,
        EnvironmentSurveyExecutionError,
        execute_environment_survey,
    )
    from pluto_plus.environment_survey_linux import LinuxEnvironmentSurveyBackend
    from pluto_plus.release_candidate import ReleaseCandidateContractError
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import attest_clean_tool_repository

    environment = inspect_iio_environment(require_usb=True)
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    try:
        if (
            len(expected_plan_sha256) != 64
            or expected_plan_sha256 != expected_plan_sha256.lower()
            or any(value not in "0123456789abcdef" for value in expected_plan_sha256)
        ):
            raise EnvironmentSurveyError(
                "--expected-plan-sha256 must be exactly 64 lowercase hexadecimal characters"
            )
        source = attest_clean_tool_repository(
            tool_repository.expanduser().absolute(),
            imported_source_files=(
                Path(__file__),
                Path(survey_source.__file__),
                Path(survey_linux_source.__file__),
            ),
        )
        receipt, digest = execute_environment_survey(
            plan.expanduser().absolute(),
            expected_plan_sha256=expected_plan_sha256,
            confirmation=confirmation,
            ensure_mute=ensure_mute,
            backend=LinuxEnvironmentSurveyBackend(),
            tool_source=source,
            tool_version=__version__,
        )
    except EnvironmentSurveyExecutionError as error:
        _fail(
            "environment_survey_execute_failed",
            f"{error}; durable receipt={error.receipt_path} sha256={error.receipt_sha256}",
            5,
        )
    except (
        OSError,
        ValueError,
        EnvironmentSurveyError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("environment_survey_execute_failed", str(error), 5)
    _emit(
        {
            "outcome": receipt.outcome,
            "selected_control_frequency_hz": receipt.selected_control_frequency_hz,
            "receipt": str(receipt.manifest.path.parent / "receipt.json"),
            "receipt_sha256": digest,
            "manifest": str(receipt.manifest.path),
            "pluto_tx_enabled": False,
        }
    )


@environment_survey_app.command("receipt-verify")
def environment_survey_receipt_verify(
    receipt: Path = typer.Argument(...),  # noqa: B008
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout bound into the receipt.",
    ),
) -> None:
    """Verify the plan, manifest, and every retained raw/PSD/STFT SHA-256."""

    import pluto_plus.environment_survey as survey_source
    from pluto_plus import __version__
    from pluto_plus.environment_survey import (
        EnvironmentSurveyError,
        verify_environment_survey_receipt,
    )
    from pluto_plus.release_candidate import ReleaseCandidateContractError
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import attest_clean_tool_repository

    try:
        source = attest_clean_tool_repository(
            tool_repository.expanduser().absolute(),
            imported_source_files=(Path(__file__), Path(survey_source.__file__)),
        )
        verified = verify_environment_survey_receipt(receipt.expanduser().absolute())
        if (
            verified.tool_repository != source.repository
            or verified.tool_source_commit != source.commit
            or verified.tool_version != __version__
        ):
            raise EnvironmentSurveyError(
                "receipt tool source differs from the executing attested package"
            )
    except (
        OSError,
        ValueError,
        EnvironmentSurveyError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("environment_survey_receipt_invalid", str(error), 4)
    _emit(
        {
            "verdict": "pass",
            "outcome": verified.outcome,
            "serial": verified.target.serial,
            "selected_control_frequency_hz": verified.selected_control_frequency_hz,
            "receipt": str(receipt.expanduser().absolute()),
        }
    )


@environment_survey_app.command("fleet-select")
def environment_survey_fleet_select(
    manifests: list[Path] = typer.Option(  # noqa: B008
        ..., "--manifest", help="Manifest path, repeated exactly four times in reserved order."
    ),
    receipts: list[Path] = typer.Option(  # noqa: B008
        ..., "--receipt", help="Matching PASS receipt, repeated exactly four times."
    ),
    emitter_inventory: Path = typer.Option(  # noqa: B008
        ..., "--emitter-inventory", help="Exact private worst-normal emitter inventory."
    ),
    emitter_inventory_sha256: str = typer.Option(
        ..., "--emitter-inventory-sha256", help="Pinned lowercase inventory SHA-256."
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", help="Absent private fleet-selection JSON output."
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout matching all four surveys.",
    ),
) -> None:
    """Deep-verify four surveys and select one global quiet 2.4 GHz center."""

    import pluto_plus.environment_survey as survey_source
    from pluto_plus import __version__
    from pluto_plus.environment_survey import (
        EnvironmentSurveyEmitterInventory,
        EnvironmentSurveyError,
        build_environment_survey_fleet_selection,
    )
    from pluto_plus.release_candidate import (
        ReleaseCandidateContractError,
        load_private_contract,
        model_file_identity,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import attest_clean_tool_repository

    if (
        len(emitter_inventory_sha256) != 64
        or emitter_inventory_sha256 != emitter_inventory_sha256.lower()
        or any(value not in "0123456789abcdef" for value in emitter_inventory_sha256)
    ):
        _fail(
            "environment_survey_inventory_digest_invalid",
            "--emitter-inventory-sha256 must be exactly 64 lowercase hexadecimal characters",
            2,
        )
    try:
        inventory_path = emitter_inventory.expanduser().absolute()
        inventory = load_private_contract(inventory_path, EnvironmentSurveyEmitterInventory)
        inventory_identity = model_file_identity(inventory_path, inventory)
        if inventory_identity.sha256 != emitter_inventory_sha256:
            raise EnvironmentSurveyError("emitter inventory SHA-256 differs from the CLI pin")
        source = attest_clean_tool_repository(
            tool_repository.expanduser().absolute(),
            imported_source_files=(Path(__file__), Path(survey_source.__file__)),
        )
        selection = build_environment_survey_fleet_selection(
            tuple(path.expanduser().absolute() for path in manifests),
            tuple(path.expanduser().absolute() for path in receipts),
            emitter_inventory_file=inventory_identity,
            emitter_inventory=inventory,
            tool_source=source,
            tool_version=__version__,
        )
        identity = write_private_contract(output.expanduser().absolute(), selection)
    except (
        OSError,
        ValueError,
        EnvironmentSurveyError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("environment_survey_fleet_selection_failed", str(error), 4)
    _emit(
        {
            "verdict": "pass",
            "selected_control_frequency_hz": selection.selected_control_frequency_hz,
            "output": str(identity.path),
            "sha256": identity.sha256,
            "receipts_and_artifacts_verified": True,
        }
    )


@environment_survey_app.command("fleet-verify")
def environment_survey_fleet_verify(
    selection: Path = typer.Argument(...),  # noqa: B008
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout bound into the fleet selection.",
    ),
) -> None:
    """Reverify a fleet selection from all four receipts and retained artifacts."""

    import pluto_plus.environment_survey as survey_source
    from pluto_plus import __version__
    from pluto_plus.environment_survey import (
        EnvironmentSurveyError,
        verify_environment_survey_fleet_selection,
    )
    from pluto_plus.release_candidate import ReleaseCandidateContractError
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import attest_clean_tool_repository

    try:
        source = attest_clean_tool_repository(
            tool_repository.expanduser().absolute(),
            imported_source_files=(Path(__file__), Path(survey_source.__file__)),
        )
        verified = verify_environment_survey_fleet_selection(
            selection.expanduser().absolute(),
            tool_source=source,
            tool_version=__version__,
        )
    except (
        OSError,
        ValueError,
        EnvironmentSurveyError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("environment_survey_fleet_selection_invalid", str(error), 4)
    _emit(
        {
            "verdict": "pass",
            "selected_control_frequency_hz": verified.selected_control_frequency_hz,
            "selection": str(selection.expanduser().absolute()),
            "receipts_and_artifacts_verified": True,
        }
    )


@comparator_ram_app.command("plan")
def firmware_comparator_ram_plan(
    retained_bundle: Path = typer.Option(  # noqa: B008
        ..., "--retained-bundle", help="Exact retained approved-v7 build bundle."
    ),
    dfu: Path = typer.Option(  # noqa: B008
        ..., "--dfu", help="Exact retained approved-v7 DFU beside the build bundle."
    ),
    usb_inventory: Path = typer.Option(  # noqa: B008
        ..., "--usb-inventory", help="Private strict inventory from candidate-ram inventory."
    ),
    serial: str = typer.Option(..., "--serial", help="Exact pilot USB serial."),
    expected_current_firmware: str = typer.Option(
        ..., "--expected-current-firmware", help="Exact preboot firmware version."
    ),
    expected_current_hardware_model: str = typer.Option(
        ..., "--expected-current-hardware-model", help="Exact preboot Pluto+ hardware model."
    ),
    expected_current_metadata_abi: str = typer.Option(
        ..., "--expected-current-metadata-abi", help="Exact preboot frame-metadata ABI."
    ),
    expected_current_capability: list[str] = typer.Option(  # noqa: B008
        ...,
        "--expected-current-capability",
        help="Exact sorted preboot capability; repeat for each capability.",
    ),
    receipt: Path = typer.Option(  # noqa: B008
        ..., "--receipt", help="Absent serial-scoped comparator receipt output."
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", help="Absent mode-private comparator plan output."
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout to bind into the comparator plan.",
    ),
    validity_seconds: int = typer.Option(
        900,
        "--validity-seconds",
        min=60,
        max=1800,
        help="Bounded file-only plan approval window.",
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1", "--ssh-host", help="Private USB-gadget SSH endpoint."
    ),
) -> None:
    """Create a native approved-v7 comparator plan without opening hardware."""

    import uuid
    from datetime import UTC, datetime, timedelta

    import pluto_plus.comparator_ram as comparator_source
    from pluto_plus import __version__
    from pluto_plus.comparator_ram import (
        ComparatorRamError,
        attest_comparator_tool_repository,
        prepare_comparator_ram_plan,
    )
    from pluto_plus.release_candidate import (
        ExpectedRuntime,
        ReleaseCandidateContractError,
        ReleaseUsbInventory,
        load_private_contract,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError

    try:
        inventory_path = usb_inventory.expanduser().absolute()
        inventory = load_private_contract(inventory_path, ReleaseUsbInventory)
        repository = tool_repository.expanduser().absolute()
        tool = attest_comparator_tool_repository(
            repository,
            version=__version__,
            wrapper_path=Path(comparator_source.__file__).absolute(),
        )
        created = datetime.now(UTC)
        plan = prepare_comparator_ram_plan(
            inventory,
            inventory_path=inventory_path,
            retained_bundle_path=retained_bundle.expanduser().absolute(),
            dfu_path=dfu.expanduser().absolute(),
            serial=serial,
            expected_current_runtime=ExpectedRuntime(
                firmware_version=expected_current_firmware,
                hardware_model=expected_current_hardware_model,
                metadata_abi=expected_current_metadata_abi,
                capabilities=tuple(expected_current_capability),
            ),
            receipt_path=receipt.expanduser().absolute(),
            tool=tool,
            created_at=created,
            expires_at=created + timedelta(seconds=validity_seconds),
            plan_id=uuid.uuid4().hex,
            ssh_host=ssh_host,
        )
        identity = write_private_contract(output.expanduser().absolute(), plan)
    except (
        OSError,
        ValueError,
        ComparatorRamError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("comparator_ram_plan_failed", str(error), 4)
    _emit(
        {
            "mode": "offline_plan",
            "hardware_accessed": False,
            "will_write_qspi": False,
            "will_load_volatile_ram": False,
            "plan": plan.model_dump(mode="json", by_alias=True),
            "output": str(identity.path),
            "sha256": identity.sha256,
            "next_command": (
                "pluto firmware comparator-ram execute --plan "
                f"{identity.path} --expected-plan-sha256 {identity.sha256} "
                "--ssh-password-file <private-file> "
                f"--confirm {json.dumps(plan.confirmation_phrase)}"
            ),
        }
    )


@comparator_ram_app.command("execute")
def firmware_comparator_ram_execute(
    plan: Path = typer.Option(  # noqa: B008
        ..., "--plan", help="Private plan produced by comparator-ram plan."
    ),
    expected_plan_sha256: str = typer.Option(
        ..., "--expected-plan-sha256", help="Exact reviewed comparator plan SHA-256."
    ),
    ssh_password_file: Path = typer.Option(  # noqa: B008
        ..., "--ssh-password-file", help="Owned mode-0600 one-line radio password file."
    ),
    confirmation: str = typer.Option(
        ..., "--confirm", help="Exact COMPARATOR RAM BOOT <serial> phrase."
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Same clean checkout bound into the comparator plan.",
    ),
    state_root: Path = typer.Option(  # noqa: B008
        DEFAULT_STATE_ROOT,
        "--state-root",
        help="Private state root used for shared and maintenance locks.",
    ),
    timeout_s: float = typer.Option(
        45.0, "--timeout", min=5.0, max=600.0, help="Per-transition wait timeout."
    ),
) -> None:
    """RAM-boot the exact approved-v7 comparator without persistent authority."""

    import pluto_plus.comparator_ram as comparator_source
    from pluto_plus import __version__
    from pluto_plus.comparator_ram import (
        ComparatorRamError,
        ComparatorRamPlan,
        attest_comparator_tool_repository,
        execute_comparator_ram,
    )
    from pluto_plus.release_candidate import ReleaseCandidateContractError, load_private_contract
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError
    from pluto_plus.release_candidate_linux import LinuxReleaseCandidateBackend

    environment = inspect_iio_environment(require_usb=True)
    if not environment.healthy:
        _fail(environment.status.value, environment.actionable_message, 5)
    planned: ComparatorRamPlan | None = None
    try:
        selected_plan = plan.expanduser().absolute()
        planned = load_private_contract(selected_plan, ComparatorRamPlan)
        tool = attest_comparator_tool_repository(
            tool_repository.expanduser().absolute(),
            version=__version__,
            wrapper_path=Path(comparator_source.__file__).absolute(),
        )
        backend = LinuxReleaseCandidateBackend(
            state_root=state_root.expanduser().absolute(), timeout_s=timeout_s
        )
        receipt, digest = execute_comparator_ram(
            selected_plan,
            expected_plan_sha256=expected_plan_sha256,
            password_path=ssh_password_file.expanduser().absolute(),
            confirmation=confirmation,
            backend=backend,
            tool=tool,
            timeout_s=timeout_s,
        )
    except (
        OSError,
        ValueError,
        ComparatorRamError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        detail = ""
        if isinstance(error, ComparatorRamError) and error.receipt is not None:
            path = planned.receipt_path if planned is not None else "unknown"
            detail = (
                f"; durable {error.receipt.outcome} receipt={path} sha256={error.receipt_sha256}"
            )
        _fail("comparator_ram_execute_failed", f"{error}{detail}", 5)
    _emit(
        {
            "outcome": receipt.outcome,
            "receipt": receipt.model_dump(mode="json", by_alias=True),
            "receipt_path": str(planned.receipt_path),
            "receipt_sha256": digest,
            "persistent_write": False,
        }
    )


@comparator_ram_app.command("receipt-verify")
def firmware_comparator_ram_receipt_verify(
    receipt: Path = typer.Argument(...),  # noqa: B008
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout bound into the comparator plan.",
    ),
) -> None:
    """Deep-replay a native comparator receipt and every retained input."""

    import pluto_plus.comparator_ram as comparator_source
    from pluto_plus import __version__
    from pluto_plus.comparator_ram import (
        ComparatorRamError,
        attest_comparator_tool_repository,
        verify_comparator_ram_receipt,
    )
    from pluto_plus.release_candidate import ReleaseCandidateContractError
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError

    try:
        tool = attest_comparator_tool_repository(
            tool_repository.expanduser().absolute(),
            version=__version__,
            wrapper_path=Path(comparator_source.__file__).absolute(),
        )
        selected = receipt.expanduser().absolute()
        verified = verify_comparator_ram_receipt(selected, tool=tool)
    except (
        OSError,
        ValueError,
        ComparatorRamError,
        ReleaseCandidateContractError,
        ReleaseCandidateLifecycleError,
    ) as error:
        _fail("comparator_ram_receipt_invalid", str(error), 4)
    _emit(
        {
            "verdict": "pass",
            "outcome": verified.outcome,
            "receipt": str(selected),
            "serial": verified.target.serial,
            "profile": verified.artifact.profile_id,
            "persistent_write": False,
        }
    )


@candidate_ram_app.command("inventory")
def firmware_candidate_ram_inventory(
    output: Path = typer.Option(  # noqa: B008
        ...,
        "--output",
        help="Absent mode-private output for the strict USB inventory.",
    ),
    serial: str | None = typer.Option(
        None,
        "--serial",
        help=(
            "Restrict the retained inventory to exactly one matching USB runtime; "
            "the selected device must still pass every Pluto+ release check."
        ),
    ),
) -> None:
    """Capture strict runtime USB topology without opening IIO, SSH, or DFU."""

    from datetime import UTC, datetime

    from pluto_plus.release_candidate import (
        build_release_usb_inventory,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError

    try:
        scanned = scan_local_usb_plutos()
        selected = scanned
        if serial is not None:
            if not serial or serial.strip() != serial:
                raise ValueError("release USB inventory serial filter is not exact")
            selected = tuple(device for device in scanned if device.serial == serial)
            if len(selected) != 1:
                raise ValueError(
                    "release USB inventory requires exactly one runtime matching --serial"
                )
        inventory = build_release_usb_inventory(
            selected, created_at=datetime.now(UTC)
        )
        identity = write_private_contract(output.expanduser().absolute(), inventory)
    except (OSError, ValueError, ReleaseCandidateLifecycleError) as error:
        _fail("candidate_ram_inventory_failed", str(error), 4)
    _emit(
        {
            "mode": "read_only_usb_inventory",
            "hardware_accessed": False,
            "scanned_device_count": len(scanned),
            "device_count": len(inventory.devices),
            "serial_filter": serial,
            "output": str(identity.path),
            "sha256": identity.sha256,
        }
    )


@candidate_ram_app.command("plan")
def firmware_candidate_ram_plan(
    candidate_plan: Path = typer.Option(  # noqa: B008
        ..., "--candidate-plan", help="Private release-candidate plan from the firmware repo."
    ),
    usb_inventory: Path = typer.Option(  # noqa: B008
        ..., "--usb-inventory", help="Private inventory produced by candidate-ram inventory."
    ),
    serial: str = typer.Option(..., "--serial", help="Exact target USB serial."),
    expected_current_firmware: str = typer.Option(
        ...,
        "--expected-current-firmware",
        help="Exact firmware expected before this RAM transition.",
    ),
    receipt: Path = typer.Option(  # noqa: B008
        ..., "--receipt", help="Absent serial-scoped output for the eventual execution receipt."
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", help="Absent mode-private per-radio operation-plan output."
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1", "--ssh-host", help="Private USB-gadget SSH endpoint."
    ),
) -> None:
    """Create a per-radio operation plan using retained files only."""

    import uuid
    from datetime import UTC, datetime

    from pluto_plus.release_candidate import (
        ReleaseCandidatePlan,
        ReleaseUsbInventory,
        build_operation_plan,
        load_private_contract,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError

    try:
        candidate_path = candidate_plan.expanduser().absolute()
        inventory_path = usb_inventory.expanduser().absolute()
        candidate = load_private_contract(candidate_path, ReleaseCandidatePlan)
        inventory = load_private_contract(inventory_path, ReleaseUsbInventory)
        operation = build_operation_plan(
            candidate,
            inventory,
            candidate_path=candidate_path,
            inventory_path=inventory_path,
            serial=serial,
            expected_current_firmware=expected_current_firmware,
            receipt_path=receipt.expanduser().absolute(),
            plan_id=uuid.uuid4().hex,
            created_at=datetime.now(UTC),
            ssh_host=ssh_host,
        )
        identity = write_private_contract(output.expanduser().absolute(), operation)
    except (OSError, ValueError, ReleaseCandidateLifecycleError) as error:
        _fail("candidate_ram_plan_failed", str(error), 4)
    _emit(
        {
            "mode": "offline_plan",
            "hardware_accessed": False,
            "will_write_qspi": False,
            "will_load_volatile_ram": False,
            "operation_plan": operation.model_dump(mode="json", by_alias=True),
            "output": str(identity.path),
            "sha256": identity.sha256,
            "next_command": (
                "pluto firmware candidate-ram execute --operation-plan "
                f"{identity.path} --ssh-password-file <private-file> "
                f"--confirm {json.dumps(operation.confirmation_phrase)}"
            ),
        }
    )


@candidate_ram_app.command("execute")
def firmware_candidate_ram_execute(
    operation_plan: Path = typer.Option(  # noqa: B008
        ..., "--operation-plan", help="Private operation plan produced by candidate-ram plan."
    ),
    ssh_password_file: Path = typer.Option(  # noqa: B008
        ..., "--ssh-password-file", help="Owned mode-0600 one-line radio password file."
    ),
    confirmation: str = typer.Option(
        ..., "--confirm", help="Exact serial-specific phrase printed by candidate-ram plan."
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout whose commit is retained in the receipt.",
    ),
    state_root: Path = typer.Option(  # noqa: B008
        DEFAULT_STATE_ROOT,
        "--state-root",
        help="Private daemon state root used for exclusive maintenance locking.",
    ),
    timeout_s: float = typer.Option(
        45.0, "--timeout", min=5.0, max=600.0, help="Per-transition wait timeout."
    ),
) -> None:
    """RAM-boot one exact candidate with no host-key or persistent-write authority."""

    from pluto_plus import __version__
    from pluto_plus.release_candidate import (
        ReleaseCandidateOperationPlan,
        load_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import (
        ReleaseCandidateLifecycleError,
        execute_candidate_ram,
    )
    from pluto_plus.release_candidate_linux import (
        LinuxReleaseCandidateBackend,
        attest_clean_tool_repository,
    )

    try:
        selected_operation = operation_plan.expanduser().absolute()
        planned = load_private_contract(selected_operation, ReleaseCandidateOperationPlan)
        repository = tool_repository.expanduser().absolute()
        source = attest_clean_tool_repository(repository)
        backend = LinuxReleaseCandidateBackend(
            state_root=state_root.expanduser().absolute(), timeout_s=timeout_s
        )
        receipt, digest = execute_candidate_ram(
            selected_operation,
            password_path=ssh_password_file.expanduser().absolute(),
            confirmation=confirmation,
            backend=backend,
            tool_repository=source.repository,
            tool_version=__version__,
            tool_source_commit=source.commit,
            timeout_s=timeout_s,
        )
    except (OSError, ValueError, ReleaseCandidateLifecycleError) as error:
        detail = ""
        if isinstance(error, ReleaseCandidateLifecycleError) and error.receipt is not None:
            detail = (
                f"; durable {error.receipt.outcome} receipt={planned.receipt_path} "
                f"sha256={error.receipt_sha256}"
            )
        _fail("candidate_ram_execute_failed", f"{error}{detail}", 5)
    _emit(
        {
            "outcome": receipt.outcome,
            "receipt": receipt.model_dump(mode="json", by_alias=True),
            "receipt_path": str(planned.receipt_path),
            "receipt_sha256": digest,
        }
    )


@candidate_ram_app.command("receipt-verify")
def firmware_candidate_ram_receipt_verify(
    receipt: Path = typer.Argument(...),  # noqa: B008
) -> None:
    """Replay a durable receipt against its exact candidate and operation plans."""

    from pluto_plus.release_candidate import (
        ReleaseCandidateOperationPlan,
        ReleaseCandidatePlan,
        ReleaseCandidateRamReceipt,
        load_private_contract,
        validate_contract_bundle,
    )
    from pluto_plus.release_candidate_lifecycle import ReleaseCandidateLifecycleError

    try:
        selected = receipt.expanduser().absolute()
        value = load_private_contract(selected, ReleaseCandidateRamReceipt)
        operation = load_private_contract(value.operation_plan.path, ReleaseCandidateOperationPlan)
        candidate = load_private_contract(value.candidate_plan.path, ReleaseCandidatePlan)
        validate_contract_bundle(
            candidate,
            operation,
            value,
            candidate_path=value.candidate_plan.path,
            operation_path=value.operation_plan.path,
        )
    except (OSError, ValueError, ReleaseCandidateLifecycleError) as error:
        _fail("candidate_ram_receipt_invalid", str(error), 4)
    _emit(
        {
            "verdict": "pass",
            "outcome": value.outcome,
            "receipt": str(selected),
            "serial": value.target.serial,
            "candidate_firmware": value.expected_firmware,
        }
    )


@candidate_ram_app.command("recover")
def firmware_candidate_ram_recover(
    receipt: Path = typer.Argument(...),  # noqa: B008
    ssh_password_file: Path = typer.Option(  # noqa: B008
        ..., "--ssh-password-file", help="Owned mode-0600 one-line radio password file."
    ),
    confirmation: str = typer.Option(
        ..., "--confirm", help="Exact phrase RECOVER RELEASE CANDIDATE <serial>."
    ),
    expected_return_firmware: str = typer.Option(
        ...,
        "--expected-return-firmware",
        help="Exact firmware expected after returning to or finding the safe runtime.",
    ),
    output: Path = typer.Option(  # noqa: B008
        ..., "--output", help="Absent private recovery-receipt output."
    ),
    tool_repository: Path = typer.Option(  # noqa: B008
        DEFAULT_TOOL_REPOSITORY,
        "--tool-repository",
        help="Clean pluto-plus-utils checkout whose commit performs recovery.",
    ),
    state_root: Path = typer.Option(  # noqa: B008
        DEFAULT_STATE_ROOT,
        "--state-root",
        help="Private daemon state root used for exclusive maintenance locking.",
    ),
    timeout_s: float = typer.Option(
        45.0, "--timeout", min=5.0, max=600.0, help="Per-recovery wait timeout."
    ),
) -> None:
    """Return one exact unknown candidate DFU transition to a safe runtime."""

    import uuid
    from datetime import UTC, datetime

    from pluto_plus import __version__
    from pluto_plus.release_candidate import (
        RECOVERY_RECEIPT_SCHEMA,
        CleanupReceipt,
        ReleaseCandidateOperationPlan,
        ReleaseCandidatePlan,
        ReleaseCandidateRamReceipt,
        ReleaseCandidateRecoveryReceipt,
        load_private_contract,
        model_file_identity,
        validate_contract_bundle,
        write_private_contract,
    )
    from pluto_plus.release_candidate_lifecycle import (
        ReleaseCandidateLifecycleError,
        validate_password_file,
    )
    from pluto_plus.release_candidate_linux import (
        LinuxReleaseCandidateBackend,
        attest_clean_tool_repository,
    )

    try:
        selected_receipt = receipt.expanduser().absolute()
        unknown = load_private_contract(selected_receipt, ReleaseCandidateRamReceipt)
        operation = load_private_contract(
            unknown.operation_plan.path, ReleaseCandidateOperationPlan
        )
        candidate = load_private_contract(unknown.candidate_plan.path, ReleaseCandidatePlan)
        validate_contract_bundle(
            candidate,
            operation,
            unknown,
            candidate_path=unknown.candidate_plan.path,
            operation_path=unknown.operation_plan.path,
        )
        if selected_receipt != operation.receipt_path:
            raise ReleaseCandidateLifecycleError(
                "unknown receipt path differs from its operation plan"
            )
        if (
            unknown.outcome != "unknown"
            or unknown.pre_runtime is None
            or unknown.cleanup.verified
            or not unknown.host_route.release_verified
            or unknown.transition.persistent_write
        ):
            raise ReleaseCandidateLifecycleError(
                "recovery requires one route-released unknown RAM receipt"
            )
        expected_confirmation = f"RECOVER RELEASE CANDIDATE {unknown.target.serial}"
        if confirmation != expected_confirmation:
            raise ReleaseCandidateLifecycleError(
                f"recovery requires exact confirmation {expected_confirmation!r}"
            )
        password = validate_password_file(ssh_password_file.expanduser().absolute())
        try:
            password.path.relative_to(candidate.artifact_index.path.parent)
        except ValueError:
            pass
        else:
            raise ReleaseCandidateLifecycleError(
                "SSH password file must be outside the candidate archive"
            )
        source = attest_clean_tool_repository(tool_repository.expanduser().absolute())
        backend = LinuxReleaseCandidateBackend(
            state_root=state_root.expanduser().absolute(), timeout_s=timeout_s
        )
        if (
            unknown.transition.download_completed
            and expected_return_firmware != candidate.expected_runtime.firmware_version
        ):
            raise ReleaseCandidateLifecycleError(
                "a completed candidate download must recover to the candidate firmware"
            )
        started_at = datetime.now(UTC)
        with backend.transaction_locks(unknown.target, operation.ssh_host):
            recovered, route, detached = backend.recover_unknown_runtime(
                unknown.target,
                pre_runtime=unknown.pre_runtime,
                expected_firmware=expected_return_firmware,
                password=password,
                ssh_host=operation.ssh_host,
                timeout_s=timeout_s,
            )
        recovery = ReleaseCandidateRecoveryReceipt(
            schema=RECOVERY_RECEIPT_SCHEMA,
            recovery_id=uuid.uuid4().hex,
            started_at=started_at,
            completed_at=datetime.now(UTC),
            tool_repository=source.repository,
            tool_version=__version__,
            tool_source_commit=source.commit,
            source_receipt=model_file_identity(selected_receipt, unknown),
            operation_plan=unknown.operation_plan,
            candidate_plan=unknown.candidate_plan,
            target=unknown.target,
            pre_runtime=unknown.pre_runtime,
            recovered_runtime=recovered,
            expected_return_firmware=expected_return_firmware,
            host_route=route,
            recovery_action="dfu-detach-e" if detached else "runtime-attestation",
            dfu_detach_completed=detached,
            persistent_write=False,
            qspi_unchanged=True,
            cleanup=CleanupReceipt(verified=True),
        )
        identity = write_private_contract(output.expanduser().absolute(), recovery)
    except (OSError, ValueError, ReleaseCandidateLifecycleError) as error:
        _fail("candidate_ram_recovery_failed", str(error), 5)
    _emit(
        {
            "outcome": "pass",
            "recovery_receipt": str(identity.path),
            "recovery_receipt_sha256": identity.sha256,
            "serial": recovery.target.serial,
            "firmware_version": recovery.recovered_runtime.firmware_version,
            "qspi_unchanged": recovery.qspi_unchanged,
            "route_release_verified": recovery.host_route.release_verified,
        }
    )


@firmware_app.command("ram-boot")
def firmware_ram_boot(
    image: Path = typer.Argument(...),  # noqa: B008
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct runtime USB sysfs node for one stable serial.",
    ),
    profile: str = typer.Option(
        ...,
        "--profile",
        help="Exact immutable RAM-boot profile; never inferred from image bytes.",
    ),
    ssh_known_hosts_file: Path = typer.Option(  # noqa: B008
        ...,
        "--ssh-known-hosts-file",
        help="Private pinned known_hosts file for the selected radio.",
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help=(
            "Private literal SSH endpoint used only to enter DFU; non-default "
            "addresses use the normal LAN route."
        ),
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--ssh-password-file",
        help="Private radio password file; otherwise execution prompts without echo.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Load the image into volatile RAM; omission produces a read-only plan.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase RAM BOOT <serial>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_RAM_BOOT_RECEIPTS,
        "--receipt-directory",
        help="Private directory for durable RAM-boot receipts.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing local Pluto NICs/routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="With isolation execution, exact phrase ISOLATE USB SSH <interface>.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Load one exact qualified DFU into RAM without writing QSPI."""

    from pluto_plus.bootstrap_firmware import (
        BootstrapFirmwareError,
        BoundSshBootstrapTransport,
    )
    from pluto_plus.host_isolation import (
        HostIsolationError,
        HostIsolationExecutionError,
        execute_usb_ssh_isolated,
        prepare_usb_ssh_isolation,
    )
    from pluto_plus.volatile_firmware import (
        SshRamBootTransition,
        VolatileFirmwareError,
        execute_ram_boot_plan,
        prepare_ram_boot_plan,
    )

    selected_known_hosts = ssh_known_hosts_file.expanduser().absolute()
    try:
        plan = prepare_ram_boot_plan(
            image,
            usb_sysfs_path,
            profile_id=profile,
            transition_host=ssh_host,
            known_hosts_file=selected_known_hosts,
        )
    except (VolatileFirmwareError, OSError, ValueError) as error:
        _fail("ram_boot_preflight_failed", str(error), 4)
    isolation_plan = None
    pluto_interfaces: tuple[str, ...] = ()
    if isolate_usb_route:
        if ssh_host != "192.168.2.1":
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        local_devices = scan_local_usb_plutos()
        selected_matches = [
            item
            for item in local_devices
            if item.serial == plan.serial and item.usb_path == plan.usb_sysfs_path
        ]
        if len(selected_matches) != 1 or len(selected_matches[0].host_network_interfaces) != 1:
            _fail("host_isolation_identity_unavailable", "selected USB radio is ambiguous", 4)
        if selected_matches[0].host_network_interfaces[0].name != plan.usb_interface:
            _fail("host_isolation_identity_changed", "selected USB interface changed", 4)
        pluto_interfaces = tuple(
            interface.name for item in local_devices for interface in item.host_network_interfaces
        )
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                plan.usb_interface,
                ssh_host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
    if not execute:
        environment = inspect_iio_environment()
        _emit(
            {
                "mode": "dry_run",
                "will_write_qspi": False,
                "will_load_volatile_ram": False,
                "plan": asdict(plan),
                "host_isolation": (None if isolation_plan is None else asdict(isolation_plan)),
                "host_environment": environment.model_dump(mode="json"),
                "next_command": (
                    f"repeat with --execute and --confirm {json.dumps(plan.confirmation_phrase)}"
                ),
            }
        )
        return
    if confirmation != plan.confirmation_phrase:
        _fail(
            "ram_boot_confirmation_required",
            f"--execute requires --confirm {plan.confirmation_phrase!r}",
            2,
        )
    if isolation_plan is not None and isolation_confirmation != isolation_plan.confirmation_phrase:
        _fail(
            "host_isolation_confirmation_required",
            f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
            2,
        )
    if not plan.raw_usb_write_access:
        _fail(
            "ram_boot_usb_permission_denied",
            f"raw USB node {plan.runtime_usb_device_node} is not writable; install "
            "packaging/udev/70-pluto-plus-utils.rules and reconnect before execution",
            4,
        )
    environment = inspect_iio_environment()
    if not environment.healthy:
        _fail("ram_boot_environment_failed", environment.actionable_message, 5)
    if ssh_password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        try:
            password = (
                _read_private_file_bytes(
                    ssh_password_file,
                    label="radio SSH password",
                    maximum_bytes=4096,
                )
                .decode("utf-8")
                .strip()
            )
        except UnicodeDecodeError:
            _fail("invalid_private_file", "radio SSH password must be UTF-8", 2)
    def ram_boot_action() -> Any:
        ssh = BoundSshBootstrapTransport(
            interface=(plan.usb_interface if plan.transition_route_mode == "usb_gadget" else None),
            password=password,
            known_hosts_file=selected_known_hosts,
            host=plan.transition_host,
        )
        return execute_ram_boot_plan(
            plan,
            confirmation=confirmation,
            known_hosts_file=selected_known_hosts,
            transition=SshRamBootTransition(ssh),
            receipt_directory=receipt_directory.expanduser().resolve(),
        )

    try:
        isolation_receipt = None
        if isolation_plan is None:
            result = ram_boot_action()
        else:
            result, isolation_receipt = execute_usb_ssh_isolated(
                isolation_plan,
                confirmation=isolation_confirmation or "",
                receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                action=ram_boot_action,
                pluto_interfaces=pluto_interfaces,
            )
    except HostIsolationExecutionError as error:
        _emit({"host_isolation": asdict(error.receipt)})
        raise typer.Exit(5) from error
    except HostIsolationError as error:
        _fail("host_isolation_failed", str(error), 4)
    except (VolatileFirmwareError, BootstrapFirmwareError, OSError, ValueError) as error:
        _fail("ram_boot_failed", str(error), 4)
    if isolation_receipt is None:
        _emit(asdict(result))
    else:
        _emit({"host_isolation": asdict(isolation_receipt), "result": asdict(result)})
    if result.outcome != "success":
        raise typer.Exit(5)


@firmware_app.command("ram-resume")
def firmware_ram_resume(
    receipt: Path = typer.Argument(...),  # noqa: B008
    confirmation: str = typer.Option(
        ...,
        "--confirm",
        help="Exact phrase RESUME RAM BOOT <source-receipt-id>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_RAM_BOOT_RECEIPTS,
        "--receipt-directory",
        help="Private directory for the recovery receipt.",
    ),
) -> None:
    """Resume an exact guarded RAM boot that stopped at the DFU boundary."""

    from pluto_plus.volatile_firmware import VolatileFirmwareError, resume_ram_boot_receipt

    environment = inspect_iio_environment()
    if not environment.healthy:
        _fail("ram_resume_environment_failed", environment.actionable_message, 5)
    try:
        result = resume_ram_boot_receipt(
            receipt.expanduser().absolute(),
            confirmation=confirmation,
            receipt_directory=receipt_directory.expanduser().resolve(),
        )
    except (VolatileFirmwareError, OSError, ValueError) as error:
        _fail("ram_resume_failed", str(error), 4)
    _emit(asdict(result))
    if result.outcome != "success":
        raise typer.Exit(5)


@firmware_app.command("bootstrap-usb")
@firmware_app.command("force-flash-usb")
@firmware_app.command("force-flash")
def firmware_force_flash_usb(
    image: Path = typer.Argument(...),  # noqa: B008
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ...,
        "--usb-sysfs-path",
        help="Exact direct runtime USB node for one blank-serial Pluto.",
    ),
    execute: bool = typer.Option(
        False,
        "--execute",
        help="Perform the planned write; omission is a read-only dry run.",
    ),
    confirmation: str | None = typer.Option(
        None,
        "--confirm",
        help="With --execute, exact phrase BOOTSTRAP <usb-port>.",
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_BOOTSTRAP_RECEIPTS,
        "--receipt-directory",
        help="Private directory for durable bootstrap receipts.",
    ),
    transport: str = typer.Option(
        "mass-storage", "--transport", help="Execution transport: mass-storage or ssh."
    ),
    ssh_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None, "--ssh-known-hosts-file", help="Pinned mode-private known_hosts for bound SSH."
    ),
    ssh_password_file: Path | None = typer.Option(  # noqa: B008
        None, "--ssh-password-file", help="Optional mode-private password file; otherwise prompt."
    ),
    ssh_host: str = typer.Option(
        "192.168.2.1",
        "--ssh-host",
        help="Literal private IPv4 endpoint; non-default addresses use the LAN route.",
    ),
    return_timeout_s: float = typer.Option(
        180,
        "--return-timeout",
        min=30,
        max=1800,
        help="Seconds to wait for the exact radio to return after flashing.",
    ),
) -> None:
    """Bootstrap canonical firmware onto one path-bound blank-serial Pluto."""

    _standalone_usb_flash(
        image,
        usb_sysfs_path,
        execute=execute,
        confirmation=confirmation,
        receipt_directory=receipt_directory,
        force_blank_serial=True,
        transport=transport,
        ssh_known_hosts_file=ssh_known_hosts_file,
        ssh_password_file=ssh_password_file,
        ssh_host=ssh_host,
        return_timeout_s=return_timeout_s,
        mutation_profile_id="libiio-continuous-metadata",
    )


def _standalone_usb_flash(
    image: Path,
    usb_sysfs_path: Path,
    *,
    execute: bool,
    confirmation: str | None,
    receipt_directory: Path,
    force_blank_serial: bool,
    transport: str,
    ssh_known_hosts_file: Path | None,
    ssh_password_file: Path | None,
    ssh_host: str,
    return_timeout_s: float,
    mutation_profile_id: str,
) -> None:
    """Plan or execute one canonical local USB firmware operation."""

    from pluto_plus.bootstrap_firmware import (
        BootstrapFirmwareError,
        BoundSshBootstrapTransport,
        UdisksFailure,
        execute_usb_flash_plan,
        execute_usb_flash_plan_ssh,
        prepare_usb_flash_plan,
    )

    normalized_transport = transport.strip().lower()
    if normalized_transport not in {"mass-storage", "ssh"}:
        _fail(
            "invalid_standalone_flash_transport",
            "--transport must be mass-storage or ssh",
            2,
        )
    if normalized_transport == "mass-storage" and (
        ssh_known_hosts_file is not None
        or ssh_password_file is not None
        or ssh_host != "192.168.2.1"
    ):
        _fail(
            "incompatible_standalone_flash_options",
            "SSH credential options require --transport ssh",
            2,
        )

    try:
        plan, frm = prepare_usb_flash_plan(
            image,
            usb_sysfs_path,
            force_blank_serial=force_blank_serial,
            mutation_profile_id=mutation_profile_id,
        )
        if not execute:
            _emit(
                {
                    "mode": "dry_run",
                    "will_write": False,
                    "plan": asdict(plan),
                    "next_command": (
                        "repeat with --execute and "
                        f"--confirm {json.dumps(plan.confirmation_phrase)}"
                    ),
                }
            )
            return
        if confirmation is None:
            _fail(
                "bootstrap_confirmation_required",
                f"--execute requires --confirm {plan.confirmation_phrase!r}",
                2,
            )
        if normalized_transport == "mass-storage":
            result = execute_usb_flash_plan(
                plan,
                frm,
                confirmation=confirmation,
                receipt_directory=receipt_directory.expanduser().resolve(),
                return_timeout_s=return_timeout_s,
            )
        else:
            if ssh_known_hosts_file is None:
                _fail(
                    "ssh_known_hosts_required",
                    "--transport ssh requires --ssh-known-hosts-file",
                    2,
                )
            if ssh_password_file is None:
                password = typer.prompt("Radio SSH password", hide_input=True)
            else:
                try:
                    password = (
                        _read_private_file_bytes(
                            ssh_password_file,
                            label="radio SSH password",
                            maximum_bytes=4096,
                        )
                        .decode("utf-8")
                        .strip()
                    )
                except UnicodeDecodeError:
                    _fail("invalid_private_file", "radio SSH password must be UTF-8", 2)
            ssh_transport = BoundSshBootstrapTransport(
                interface=(plan.usb_interface if ssh_host == "192.168.2.1" else None),
                password=password,
                known_hosts_file=ssh_known_hosts_file.expanduser().resolve(),
                host=ssh_host,
            )
            result = execute_usb_flash_plan_ssh(
                plan,
                frm,
                confirmation=confirmation,
                receipt_directory=receipt_directory.expanduser().resolve(),
                transport=ssh_transport,
                return_timeout_s=return_timeout_s,
            )
    except UdisksFailure as error:
        _fail(f"bootstrap_udisks_{error.classification}", str(error), 4)
    except (BootstrapFirmwareError, ValueError) as error:
        _fail("bootstrap_firmware_failed", str(error), 4)
    _emit(asdict(result))
    if result.outcome != "success":
        raise typer.Exit(5)


@setup_app.command("status")
def setup_status(ctx: typer.Context) -> None:
    """Show whether guarded canonical setup is explicitly available."""

    _emit(_api(ctx).request("GET", "setup"))


@setup_app.command("plan")
def setup_plan(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Create an expiring identity/environment-bound canonical setup plan."""

    _emit(
        _api(ctx).request(
            "POST",
            f"radios/{radio_id}/doctor/setup-plans",
            json_body={},
        )
    )


@setup_app.command("execute")
def setup_execute(
    ctx: typer.Context,
    plan_id: str = typer.Argument(...),
    confirmation_token: str = typer.Option(..., "--token", prompt=True, hide_input=True),
) -> None:
    """Consume a setup plan token and execute its immutable changes once."""

    _emit(
        _api(ctx).request(
            "POST",
            "setup/executions",
            json_body={
                "plan_id": plan_id,
                "confirmation_token": confirmation_token,
            },
        )
    )


@setup_app.command("receipt-list")
def setup_receipt_list(ctx: typer.Context) -> None:
    """List durable canonical-setup receipts."""

    _emit(_api(ctx).request("GET", "setup/receipts"))


@setup_app.command("reconcile-local")
def setup_reconcile_local(
    receipt_id: str = typer.Argument(..., help="Exact uncertain setup receipt ID."),
    serial: str = typer.Option(..., "--serial", help="Exact USB serial recorded by the receipt."),
    usb_sysfs_path: Path = typer.Option(  # noqa: B008
        ..., "--usb-sysfs-path", help="Exact direct USB path recorded by the receipt."
    ),
    firmware: str = typer.Option(
        ..., "--firmware", help="Exact active firmware identity recorded by the receipt."
    ),
    known_hosts_file: Path = typer.Option(  # noqa: B008
        ..., "--known-hosts-file", help="Current pinned known_hosts for the exact radio."
    ),
    password_file: Path | None = typer.Option(  # noqa: B008
        None, "--password-file", help="Private radio password file; otherwise prompt."
    ),
    host: str = typer.Option(
        "192.168.2.1", "--host", help="Literal private SSH endpoint for the radio."
    ),
    receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_SETUP_RECEIPTS,
        "--receipt-directory",
        help="Private directory containing the uncertain setup receipt.",
    ),
    isolate_usb_route: bool = typer.Option(
        False,
        "--isolate-usb-route",
        help="Temporarily isolate competing local Pluto NICs/routes with a durable receipt.",
    ),
    isolation_confirmation: str | None = typer.Option(
        None,
        "--isolation-confirm",
        help="Exact phrase ISOLATE USB SSH <interface> for temporary route isolation.",
    ),
    isolation_receipt_directory: Path = typer.Option(  # noqa: B008
        DEFAULT_HOST_ISOLATION_RECEIPTS,
        "--isolation-receipt-directory",
        help="Private directory for host-isolation receipts.",
    ),
) -> None:
    """Read-only re-attest an uncertain local setup receipt; never retry it."""

    from pluto_plus.host_isolation import (
        HostIsolationError,
        HostIsolationExecutionError,
        execute_usb_ssh_isolated,
        prepare_usb_ssh_isolation,
    )
    from pluto_plus.setup import SetupError, SetupIdentity
    from pluto_plus.setup_helper import SetupHelperError
    from pluto_plus.setup_repair import SetupCredentials, ssh_manager_factory

    try:
        identity = SetupIdentity(
            serial=serial,
            usb_sysfs_path=str(usb_sysfs_path),
            observed_firmware=firmware,
        )
    except ValueError as error:
        _fail("setup_reconciliation_identity_invalid", str(error), 2)
    local_devices = scan_local_usb_plutos()
    matches = [
        item
        for item in local_devices
        if item.serial == serial and item.usb_path == str(usb_sysfs_path)
    ]
    if len(matches) != 1 or len(matches[0].host_network_interfaces) != 1:
        _fail(
            "setup_reconciliation_identity_unavailable",
            "serial/path must identify one local radio with one USB network interface",
            4,
        )
    interface = matches[0].host_network_interfaces[0].name if host == "192.168.2.1" else None
    isolation_plan = None
    pluto_interfaces = tuple(
        network.name for item in local_devices for network in item.host_network_interfaces
    )
    if isolate_usb_route:
        if host != "192.168.2.1" or interface is None:
            _fail("host_isolation_invalid", "USB route isolation requires 192.168.2.1", 2)
        try:
            isolation_plan = prepare_usb_ssh_isolation(
                interface,
                host,
                pluto_interfaces=pluto_interfaces,
            )
        except HostIsolationError as error:
            _fail("host_isolation_preflight_failed", str(error), 4)
        if isolation_confirmation != isolation_plan.confirmation_phrase:
            _fail(
                "host_isolation_confirmation_required",
                f"--isolation-confirm must be exactly {isolation_plan.confirmation_phrase!r}",
                2,
            )
    selected_known_hosts = known_hosts_file.expanduser().absolute()
    _read_private_file_bytes(
        selected_known_hosts, label="setup SSH known-hosts", maximum_bytes=1024 * 1024
    )
    if password_file is None:
        password = typer.prompt("Radio SSH password", hide_input=True)
    else:
        password = _read_private_text_file(
            password_file.expanduser().absolute(), label="radio SSH password"
        )
    selected_receipts = receipt_directory.expanduser().absolute()

    def reconcile_action() -> Any:
        manager = ssh_manager_factory(
            SetupCredentials(
                host=host,
                password=password,
                known_hosts_file=selected_known_hosts,
                receipt_directory=selected_receipts,
                state_root=selected_receipts.parent,
                interface=interface,
            )
        )(identity)
        return manager.reconcile(receipt_id)

    try:
        isolation_receipt = None
        if isolation_plan is None:
            receipt = reconcile_action()
        else:
            receipt, isolation_receipt = execute_usb_ssh_isolated(
                isolation_plan,
                confirmation=isolation_confirmation or "",
                receipt_directory=isolation_receipt_directory.expanduser().resolve(),
                action=reconcile_action,
                pluto_interfaces=pluto_interfaces,
            )
    except HostIsolationExecutionError as error:
        _emit({"host_isolation": asdict(error.receipt)})
        raise typer.Exit(5) from error
    except HostIsolationError as error:
        _fail("host_isolation_failed", str(error), 4)
    except (SetupError, SetupHelperError, OSError, ValueError) as error:
        _fail("setup_reconciliation_failed", str(error), 4)
    payload = asdict(receipt)
    if isolation_receipt is not None:
        payload = {"host_isolation": asdict(isolation_receipt), "result": payload}
    _emit(payload)


@app.command("analyze")
def analyze(
    ctx: typer.Context,
    artifact_id: str = typer.Argument(...),
    analyzer: str = typer.Option("spectrum", "--analyzer"),
    parameters: str = typer.Option("{}", "--parameters", help="Analyzer parameters as JSON."),
) -> None:
    """Run an analyzer against an immutable capture artifact."""
    try:
        decoded = json.loads(parameters)
    except json.JSONDecodeError as error:
        _fail("invalid_parameters", f"parameters are not valid JSON: {error.msg}", 2)
    if not isinstance(decoded, dict):
        _fail("invalid_parameters", "parameters must decode to a JSON object", 2)
    body = {"artifact_id": artifact_id, "analyzer": analyzer, "parameters": decoded}
    _emit(_api(ctx).request("POST", "analyses", json_body=body))


def _discover_production_devices() -> tuple[Any, ...]:
    """Lazy extension seam: importing the CLI never imports hardware libraries."""
    try:
        discovery = import_module("pluto_plus.hardware.discovery")
    except (ImportError, ModuleNotFoundError):
        _fail(
            "hardware_discovery_unavailable",
            "production discovery is not installed; install the hardware extra",
            2,
        )
    return tuple(discovery.discover_devices())


def _append_hardware_without_explicit_duplicates(
    explicit: list[Any], discovered: tuple[Any, ...]
) -> None:
    """Let an explicit transport selection override broad hardware discovery."""

    explicit_ids = {str(device.identity.radio_id) for device in explicit}
    explicit.extend(
        device for device in discovered if str(device.identity.radio_id) not in explicit_ids
    )


def _direct_ip_devices(specifications: list[str]) -> tuple[Any, ...]:
    """Compose explicit host/serial direct-IP targets without eager native imports."""

    from pluto_plus.direct_radio.ip_transport import DirectIpTransport
    from pluto_plus.hardware.direct_ip import DirectIpRadioDevice
    from pluto_plus.hardware.iio import IioRadioDevice

    devices: list[Any] = []
    for specification in specifications:
        parts = [part.strip() for part in specification.split(",")]
        if len(parts) != 2 or not all(parts):
            _fail(
                "invalid_direct_ip",
                "--direct-ip must be HOST,SERIAL with both values non-empty",
                2,
            )
        host, serial = parts
        control = IioRadioDevice(f"ip:{host}", serial=serial, radio_id=serial)
        devices.append(DirectIpRadioDevice(control, DirectIpTransport(host)))
    return tuple(devices)


def _direct_usb_devices(serials: list[str]) -> tuple[Any, ...]:
    """Compose exact-serial direct-USB capture targets with lazy native imports."""

    from pluto_plus.direct_radio.usb_transport import DirectUsbTransport
    from pluto_plus.hardware.direct_usb import DirectUsbRadioDevice
    from pluto_plus.hardware.iio import IioRadioDevice

    devices: list[Any] = []
    for raw_serial in serials:
        serial = raw_serial.strip()
        if not serial or serial != raw_serial:
            _fail(
                "invalid_direct_usb",
                "--direct-usb must be one non-empty exact serial without surrounding spaces",
                2,
            )
        control = IioRadioDevice("usb:", serial=serial, radio_id=serial)
        devices.append(DirectUsbRadioDevice(control, DirectUsbTransport(serial=serial)))
    return tuple(devices)


def _iio_ip_devices(specifications: list[str]) -> tuple[Any, ...]:
    """Compose explicit standard libiio network targets, optionally serial-pinned."""

    from pluto_plus.hardware.iio import IioRadioDevice

    devices: list[Any] = []
    for specification in specifications:
        parts = [part.strip() for part in specification.split(",")]
        if len(parts) not in {1, 2} or not all(parts) or specification != ",".join(parts):
            _fail(
                "invalid_iio_ip",
                "--iio-ip must be HOST or HOST,SERIAL without surrounding spaces",
                2,
            )
        host = parts[0]
        serial = parts[1] if len(parts) == 2 else None
        devices.append(
            IioRadioDevice(
                f"ip:{host}",
                serial=serial,
                radio_id=serial or host,
            )
        )
    return tuple(devices)


def _network_iio_inventory(
    networks: list[str], managed_serials: list[str]
) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
    """Discover network Plutos read-only and promote only selected serials."""

    from pluto_plus.hardware.discovery import discover_network_iio
    from pluto_plus.models import (
        RadioCapabilities,
        RadioIdentity,
        RadioSettings,
        RadioSnapshot,
        RadioState,
        Transport,
    )

    if len(managed_serials) != len(set(managed_serials)) or any(
        not serial or serial.strip() != serial for serial in managed_serials
    ):
        _fail(
            "invalid_managed_iio_serial",
            "--manage-discovered-iio must be unique exact serials without whitespace",
            2,
        )
    try:
        observations = discover_network_iio(networks)
    except ValueError as error:
        _fail("invalid_iio_network_discovery", str(error), 2)
    by_serial = {observation.serial: observation for observation in observations}
    missing = sorted(set(managed_serials) - set(by_serial))
    if missing:
        _fail(
            "managed_iio_serial_not_discovered",
            f"requested managed network IIO serials were not discovered: {missing}",
            2,
        )
    managed = tuple(by_serial[serial].device() for serial in managed_serials)
    passive = tuple(
        RadioSnapshot(
            identity=RadioIdentity(
                radio_id=observation.serial,
                serial=observation.serial,
                uri=f"ip:{observation.host}",
                transport=Transport.IIO_IP,
                model=observation.model,
                firmware_version=observation.firmware_version,
            ),
            capabilities=RadioCapabilities(
                receiver_channels=(0, 1),
                supports_live_tuning=False,
            ),
            managed=False,
            state=RadioState.OFFLINE,
            revision=0,
            requested_settings=RadioSettings(),
            actual_settings=RadioSettings(),
            last_error="Discovered read-only; not owned by this daemon",
        )
        for observation in observations
        if observation.serial not in managed_serials
    )
    return managed, passive


@app.command("serve")
def serve(
    state_root: Path = typer.Option(DEFAULT_STATE_ROOT, "--state-root"),  # noqa: B008
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8765, "--port", min=1, max=65_535),
    uds: Path | None = typer.Option(  # noqa: B008
        None, "--uds", help="Bind an absolute Unix socket path."
    ),
    fake_radio: list[str] | None = typer.Option(  # noqa: B008
        None, "--fake-radio", help="Add a deterministic fake radio by serial (repeatable)."
    ),
    direct_ip: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--direct-ip",
        help="Add an explicit direct-IP HOST,SERIAL target (repeatable).",
    ),
    direct_usb: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--direct-usb",
        help="Add an exact-serial direct-USB capture target (repeatable).",
    ),
    iio_ip: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--iio-ip",
        help="Add a standard network-IIO HOST or HOST,SERIAL target (repeatable).",
    ),
    discover_iio_network: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--discover-iio-network",
        help="Read-only inventory scan of a bounded IPv4 CIDR (repeatable).",
    ),
    manage_discovered_iio: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--manage-discovered-iio",
        help="Exact discovered serial this daemon may open and control (repeatable).",
    ),
    hardware: bool = typer.Option(False, "--hardware", help="Discover production radios."),
    firmware_helper_socket: Path | None = typer.Option(  # noqa: B008
        None,
        "--firmware-helper-socket",
        help="Protected absolute Unix socket for the site-specific privileged helper.",
    ),
    ssh_firmware_enrollment: list[Path] | None = typer.Option(  # noqa: B008
        None,
        "--ssh-radio-admin-enrollment",
        "--ssh-firmware-enrollment",
        help=(
            "Private exact-radio pinned-SSH enrollment for canonical firmware and "
            "structured config.txt administration (repeatable)."
        ),
    ),
    admin_token_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--admin-token-file",
        help="Private bearer-token file required before privileged HTTP routes are usable.",
    ),
    admin_allowed_origin: list[str] | None = typer.Option(  # noqa: B008
        None,
        "--admin-allowed-origin",
        help="Exact browser origin allowed to call privileged routes (repeatable).",
    ),
    enable_canonical_setup: bool = typer.Option(
        False,
        "--enable-canonical-setup",
        help="Explicitly enable one exact-radio AD9361/2R2T setup executor.",
    ),
    setup_serial: str | None = typer.Option(
        None, "--setup-serial", help="Exact serial of the sole setup target."
    ),
    setup_usb_sysfs_path: Path | None = typer.Option(  # noqa: B008
        None,
        "--setup-usb-sysfs-path",
        help="Exact direct USB sysfs node of the sole setup target.",
    ),
    setup_usb_interface: str | None = typer.Option(
        None,
        "--setup-usb-interface",
        help="USB network interface physically below the selected sysfs node.",
    ),
    setup_usb_host: str | None = typer.Option(
        None,
        "--setup-usb-host",
        help="Literal private/link-local Pluto USB SSH address.",
    ),
    setup_password_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--setup-password-file",
        help="Private mode-0600 file containing the selected radio root password.",
    ),
    setup_known_hosts_file: Path | None = typer.Option(  # noqa: B008
        None,
        "--setup-known-hosts-file",
        help="Private mode-0600 file pinning the selected radio SSH host key.",
    ),
    log_level: str = typer.Option("info", "--log-level"),
) -> None:
    """Run plutod with fake radios and/or lazily discovered hardware."""
    # These imports intentionally stay inside the command so ordinary clients need no server stack.
    import uvicorn

    from pluto_plus.api import create_app
    from pluto_plus.hardware.fake import FakeRadioDevice
    from pluto_plus.service import PlutoService

    admin_policy = None
    allowed_origins = admin_allowed_origin or []
    if admin_token_file is None and allowed_origins:
        _fail(
            "admin_authentication_unavailable",
            "--admin-allowed-origin requires --admin-token-file",
            2,
        )
    if admin_token_file is not None:
        from pluto_plus.admin import AdminMutationPolicy

        try:
            admin_policy = AdminMutationPolicy(
                token=_read_admin_token_file(admin_token_file),
                allowed_origins=allowed_origins,
            )
        except ValueError as error:
            _fail("invalid_admin_authentication", str(error), 2)

    direct_specifications = direct_ip or []
    direct_usb_serials = direct_usb or []
    iio_ip_specifications = iio_ip or []
    discovery_networks = discover_iio_network or []
    managed_discovered_serials = manage_discovered_iio or []
    if managed_discovered_serials and not discovery_networks:
        _fail(
            "iio_network_discovery_unavailable",
            "--manage-discovered-iio requires --discover-iio-network",
            2,
        )
    serials = (
        fake_radio
        if fake_radio is not None
        else (
            ["fake-001"]
            if (
                not hardware
                and not direct_specifications
                and not direct_usb_serials
                and not iio_ip_specifications
                and not discovery_networks
            )
            else []
        )
    )
    devices: list[Any] = [FakeRadioDevice(serial=serial) for serial in serials]
    devices.extend(_direct_ip_devices(direct_specifications))
    devices.extend(_direct_usb_devices(direct_usb_serials))
    devices.extend(_iio_ip_devices(iio_ip_specifications))
    discovered_radios: tuple[Any, ...] = ()
    if discovery_networks:
        managed_network_devices, discovered_radios = _network_iio_inventory(
            discovery_networks, managed_discovered_serials
        )
        devices.extend(managed_network_devices)
    if hardware:
        _append_hardware_without_explicit_duplicates(devices, _discover_production_devices())
    if not devices and not discovered_radios:
        _fail("no_radios", "no fake radios requested and no hardware radios discovered", 2)

    ssh_enrollments = tuple(
        _read_ssh_firmware_enrollment(path) for path in (ssh_firmware_enrollment or [])
    )
    if ssh_enrollments and admin_policy is None:
        _fail(
            "admin_authentication_unavailable",
            "SSH firmware enrollment requires --admin-token-file",
            2,
        )
    if len({item.serial for item in ssh_enrollments}) != len(ssh_enrollments):
        _fail(
            "duplicate_ssh_firmware_enrollment",
            "SSH firmware enrollment serials must be unique",
            2,
        )
    if len({item.host for item in ssh_enrollments}) != len(ssh_enrollments):
        _fail(
            "duplicate_ssh_firmware_enrollment",
            "SSH firmware enrollment hosts must be unique",
            2,
        )

    setup_manager = None
    setup_options = {
        "--setup-serial": setup_serial,
        "--setup-usb-sysfs-path": setup_usb_sysfs_path,
        "--setup-usb-interface": setup_usb_interface,
        "--setup-usb-host": setup_usb_host,
        "--setup-password-file": setup_password_file,
        "--setup-known-hosts-file": setup_known_hosts_file,
    }
    if not enable_canonical_setup and any(value is not None for value in setup_options.values()):
        _fail(
            "canonical_setup_not_enabled",
            "setup target options require explicit --enable-canonical-setup",
            2,
        )
    if enable_canonical_setup:
        missing = [name for name, value in setup_options.items() if value is None]
        if missing:
            _fail(
                "incomplete_canonical_setup",
                f"canonical setup is missing required options: {', '.join(missing)}",
                2,
            )
        if admin_policy is None:
            _fail(
                "admin_authentication_unavailable",
                "canonical setup requires --admin-token-file",
                2,
            )
        from pluto_plus.doctor import CANONICAL_POLICY
        from pluto_plus.setup import CanonicalSetupManager, SetupIdentity
        from pluto_plus.setup_helper import (
            BoundSshTransport,
            FixedSshSetupExecutor,
            SetupHelperError,
            remote_ssh_available,
            validate_bound_interface,
        )

        selected_serial = cast(str, setup_serial)
        selected_sysfs = cast(Path, setup_usb_sysfs_path)
        selected_interface = cast(str, setup_usb_interface)
        selected_host = _private_usb_host(cast(str, setup_usb_host))
        selected_password_file = cast(Path, setup_password_file)
        selected_known_hosts_file = cast(Path, setup_known_hosts_file)
        if not selected_sysfs.is_absolute() or selected_sysfs.parent != Path(
            "/sys/bus/usb/devices"
        ):
            _fail(
                "invalid_setup_usb_path",
                "--setup-usb-sysfs-path must name one direct USB sysfs device",
                2,
            )
        matches = [
            device.identity for device in devices if device.identity.serial == selected_serial
        ]
        if len(matches) != 1:
            _fail(
                "setup_identity_unavailable",
                "setup target serial must match exactly one configured managed radio",
                2,
            )
        try:
            validate_bound_interface(selected_interface, str(selected_sysfs))
        except ValueError as error:
            _fail("invalid_setup_usb_interface", str(error), 2)
        except SetupHelperError as error:
            _fail("setup_usb_interface_unavailable", str(error), 2)
        if not remote_ssh_available():
            _fail("setup_ssh_unavailable", "OpenSSH client is unavailable", 2)
        _read_private_file_bytes(
            selected_known_hosts_file,
            label="setup known-hosts",
            maximum_bytes=1024 * 1024,
        )
        try:
            identity = SetupIdentity(
                serial=selected_serial,
                usb_sysfs_path=str(selected_sysfs),
                observed_firmware=CANONICAL_POLICY.device_firmware,
            )
            executor = FixedSshSetupExecutor(
                identity=identity,
                transport=BoundSshTransport(
                    host=selected_host,
                    interface=selected_interface,
                    password=_read_private_text_file(
                        selected_password_file, label="setup password"
                    ),
                    known_hosts_file=selected_known_hosts_file,
                ),
                state_root=state_root.absolute(),
            )
        except ValueError as error:
            _fail("invalid_canonical_setup", str(error), 2)
        setup_manager = CanonicalSetupManager(
            receipt_directory=(state_root / "setup" / "receipts").absolute(),
            inspector=executor.inspect,
            executor=executor,
        )

    firmware_manager = None
    if firmware_helper_socket is not None:
        if not firmware_helper_socket.is_absolute():
            _fail(
                "invalid_firmware_helper_socket",
                "--firmware-helper-socket must be an absolute path",
                2,
            )
        try:
            socket_mode = firmware_helper_socket.stat().st_mode
        except OSError as error:
            _fail("firmware_helper_unavailable", str(error), 2)
        if not stat.S_ISSOCK(socket_mode):
            _fail(
                "invalid_firmware_helper_socket",
                "--firmware-helper-socket must name an existing Unix socket",
                2,
            )

        from pluto_plus.firmware import FirmwareManager, SysfsRadioFirmwareIdentityProbe
        from pluto_plus.firmware_helper import UnixFirmwareHelperClient

        staging_root = (state_root / "firmware" / "staging").absolute()

        def observed_firmware(serial: str, sysfs_path: str) -> str:
            matches = [
                device.identity
                for device in devices
                if device.identity.serial == serial and device.identity.usb_path == sysfs_path
            ]
            if len(matches) != 1 or matches[0].firmware_version is None:
                raise RuntimeError(
                    f"managed radio {serial!r} does not have one fresh matching firmware identity"
                )
            return cast(str, matches[0].firmware_version)

        firmware_manager = FirmwareManager(
            staging_directory=staging_root,
            receipt_directory=(state_root / "firmware" / "receipts").absolute(),
            identity_probe=SysfsRadioFirmwareIdentityProbe(
                observed_firmware_reader=observed_firmware
            ),
            executor=UnixFirmwareHelperClient(
                socket_path=firmware_helper_socket,
                staging_root=staging_root,
            ),
        )

    service = PlutoService(
        state_root=state_root,
        devices=tuple(devices),
        discovered_radios=discovered_radios,
        firmware_manager=firmware_manager,
        setup_manager=setup_manager,
    )
    if ssh_enrollments:
        from pluto_plus.doctor import CANONICAL_POLICY
        from pluto_plus.firmware import (
            FirmwareManager,
            FirmwareTransport,
            RadioFirmwareIdentity,
        )
        from pluto_plus.hardware.iio import IioRadioDevice
        from pluto_plus.ip_firmware import (
            IpFirmwareEnrollment,
            IpFirmwareError,
            IpFirmwareExecutor,
            PinnedSshFirmwareTransport,
        )
        from pluto_plus.models import Transport
        from pluto_plus.network_config import (
            NetworkConfigIdentity,
            NetworkConfigManager,
        )

        snapshots = {snapshot.identity.serial: snapshot for snapshot in service.list_radios()}
        try:
            for enrollment in ssh_enrollments:
                snapshot = snapshots.get(enrollment.serial)
                if snapshot is None or not snapshot.managed:
                    raise ValueError(
                        f"serial {enrollment.serial!r} is not exactly one managed radio"
                    )
                radio_identity = snapshot.identity
                if radio_identity.transport is not Transport.IIO_IP:
                    raise ValueError(
                        f"serial {enrollment.serial!r} is not a managed network-IIO radio"
                    )
                if radio_identity.uri != f"ip:{enrollment.host}":
                    raise ValueError(
                        f"serial {enrollment.serial!r} URI does not match enrolled host"
                    )
                if radio_identity.firmware_version is None:
                    raise ValueError(
                        f"serial {enrollment.serial!r} has no observed firmware version"
                    )
                transport = PinnedSshFirmwareTransport(
                    endpoint=enrollment.host,
                    known_hosts_file=enrollment.known_hosts_file,
                    private_key_file=enrollment.private_key_file,
                )
                initial_attestation = transport.attest()
                if (
                    initial_attestation.serial != enrollment.serial
                    or initial_attestation.active_firmware != radio_identity.firmware_version
                ):
                    raise ValueError(
                        "initial pinned-SSH identity does not match managed network-IIO state"
                    )

                def post_reset_probe(
                    requested_serial: str,
                    *,
                    enrolled_serial: str = enrollment.serial,
                    enrolled_host: str = enrollment.host,
                    enrolled_fingerprint: str = transport.host_key_fingerprint,
                ) -> Any:
                    if requested_serial != enrolled_serial:
                        raise RuntimeError("post-reset probe requested another serial")
                    probe = IioRadioDevice(
                        f"ip:{enrolled_host}",
                        serial=enrolled_serial,
                        radio_id=enrolled_serial,
                    )
                    probe.open()
                    try:
                        observed = probe.identity
                        if (
                            observed.serial != enrolled_serial
                            or observed.transport is not Transport.IIO_IP
                            or observed.uri != f"ip:{enrolled_host}"
                            or observed.firmware_version is None
                        ):
                            raise RuntimeError(
                                "post-reset network-IIO identity did not match enrollment"
                            )
                        return RadioFirmwareIdentity(
                            serial=observed.serial,
                            usb_sysfs_path=None,
                            observed_firmware=observed.firmware_version,
                            endpoint=enrolled_host,
                            host_key_fingerprint=enrolled_fingerprint,
                        )
                    finally:
                        probe.close()

                def post_reset_tx_guard(
                    requested_serial: str,
                    *,
                    enrolled_serial: str = enrollment.serial,
                    enrolled_host: str = enrollment.host,
                ) -> bool:
                    if requested_serial != enrolled_serial:
                        return False
                    guard = IioRadioDevice(
                        f"ip:{enrolled_host}",
                        serial=enrolled_serial,
                        radio_id=enrolled_serial,
                    )
                    try:
                        # open() performs strict TX mute/readback before exposing identity.
                        guard.open()
                        observed = guard.identity
                        return (
                            observed.serial == enrolled_serial
                            and observed.transport is Transport.IIO_IP
                            and observed.uri == f"ip:{enrolled_host}"
                            and observed.firmware_version == CANONICAL_POLICY.device_firmware
                        )
                    except Exception:
                        return False
                    finally:
                        with suppress(Exception):
                            guard.close()

                ip_executor = IpFirmwareExecutor(
                    enrollment=IpFirmwareEnrollment(
                        endpoint=enrollment.host,
                        serial=enrollment.serial,
                        board_model=initial_attestation.board_model,
                        observed_firmware=radio_identity.firmware_version,
                        host_key_fingerprint=transport.host_key_fingerprint,
                    ),
                    transport=transport,
                    expected_firmware=CANONICAL_POLICY.device_firmware,
                    post_reset_probe=post_reset_probe,
                    post_reset_tx_guard=post_reset_tx_guard,
                    evidence_directory=(
                        state_root / "firmware" / "ssh-evidence" / enrollment.serial
                    ).absolute(),
                )
                service.enroll_ip_firmware_manager(
                    enrollment.serial,
                    FirmwareManager(
                        staging_directory=(state_root / "firmware" / "staging").absolute(),
                        receipt_directory=(
                            state_root / "firmware" / "receipts" / "ssh_frm" / enrollment.serial
                        ).absolute(),
                        identity_probe=ip_executor.identity_probe,
                        executor=ip_executor,
                        transport=FirmwareTransport.SSH_FRM,
                    ),
                )
                service.enroll_network_config_manager(
                    enrollment.serial,
                    NetworkConfigManager(
                        identity=NetworkConfigIdentity(
                            serial=enrollment.serial,
                            endpoint=enrollment.host,
                            host_key_fingerprint=transport.host_key_fingerprint,
                        ),
                        backend=transport,
                        receipt_directory=(
                            state_root / "network-config" / "receipts" / enrollment.serial
                        ).absolute(),
                    ),
                )
        except (ValueError, IpFirmwareError) as error:
            service.close()
            _fail("invalid_ssh_firmware_enrollment", str(error), 2)
    api = create_app(service, admin_policy=admin_policy)
    try:
        if uds is not None:
            if not uds.is_absolute():
                _fail("invalid_uds", "--uds must be an absolute path", 2)
            uds.parent.mkdir(parents=True, exist_ok=True)
            uvicorn.run(api, uds=str(uds), log_level=log_level)
        else:
            uvicorn.run(api, host=host, port=port, log_level=log_level)
    finally:
        service.close()


def serve_entrypoint() -> None:
    """Entry point for ``plutod``, exposing the options of ``pluto serve`` directly."""
    app(args=["serve", *sys.argv[1:]], prog_name="plutod")


if __name__ == "__main__":
    app()
