"""Command-line client and daemon launcher for Pluto+ control."""

from __future__ import annotations

import json
import os
import stat
import sys
from dataclasses import dataclass
from importlib import import_module
from ipaddress import ip_address
from pathlib import Path
from typing import Any, NoReturn, cast
from urllib.parse import urlsplit

import httpx
import typer

DEFAULT_ENDPOINT = "http://127.0.0.1:8765"
DEFAULT_STATE_ROOT = Path(os.environ.get("PLUTO_STATE_ROOT", "./pluto-state"))
API_PREFIX = "api/v1"

app = typer.Typer(no_args_is_help=True, help="Control Pluto+ radios through plutod.")
radio_app = typer.Typer(no_args_is_help=True, help="Inspect and configure radios.")
settings_app = typer.Typer(no_args_is_help=True, help="Read or update radio settings.")
stream_app = typer.Typer(no_args_is_help=True, help="Manage live radio streams.")
capture_app = typer.Typer(no_args_is_help=True, help="Create persistent IQ captures.")
job_app = typer.Typer(no_args_is_help=True, help="Inspect stream and capture jobs.")
artifact_app = typer.Typer(no_args_is_help=True, help="Inspect captured artifacts.")
scan_app = typer.Typer(no_args_is_help=True, help="Run exclusive frequency scans.")
firmware_app = typer.Typer(no_args_is_help=True, help="Plan and execute guarded firmware updates.")
setup_app = typer.Typer(
    no_args_is_help=True, help="Plan and execute guarded canonical AD9361/2R2T setup."
)

app.add_typer(radio_app, name="radio")
radio_app.add_typer(settings_app, name="settings")
app.add_typer(stream_app, name="stream")
app.add_typer(capture_app, name="capture")
app.add_typer(job_app, name="job")
app.add_typer(artifact_app, name="artifact")
app.add_typer(scan_app, name="scan")
app.add_typer(firmware_app, name="firmware")
app.add_typer(setup_app, name="setup")


@dataclass
class _Context:
    endpoint: str
    admin_token: str | None = None
    client: ApiClient | None = None


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


@radio_app.command("list")
def radio_list(ctx: typer.Context) -> None:
    """List radios known to plutod."""
    _emit(_api(ctx).request("GET", "radios"))


@radio_app.command("status")
def radio_status(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Show identity, state, capabilities, and current settings."""
    _emit(_api(ctx).request("GET", f"radios/{radio_id}"))


@radio_app.command("recover")
def radio_recover(ctx: typer.Context, radio_id: str = typer.Argument(...)) -> None:
    """Reopen an errored/offline radio and re-attest its stable serial."""
    _emit(_api(ctx).request("POST", f"radios/{radio_id}/recover"))


@app.command("doctor")
def doctor(
    ctx: typer.Context,
    radio_id: str | None = typer.Argument(None),
) -> None:
    """Check one or all radios against the selected canonical setup profile."""

    path = "doctor" if radio_id is None else f"radios/{radio_id}/doctor"
    _emit(_api(ctx).request("GET", path))


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
    expected_version: str | None = typer.Option(None, "--expected-version"),
) -> None:
    """Create an expiring identity/hash-bound plan and one-time token."""
    body = {"image_id": image_id, "mode": mode}
    if expected_version is not None:
        body["expected_firmware_version"] = expected_version
    _emit(
        _api(ctx).request(
            "POST",
            f"radios/{radio_id}/firmware/plans",
            json_body=body,
        )
    )


@firmware_app.command("execute")
def firmware_execute(
    ctx: typer.Context,
    plan_id: str = typer.Argument(...),
    confirmation_token: str = typer.Option(..., "--token", prompt=True, hide_input=True),
) -> None:
    """Consume a plan's one-time token and perform its exact operation."""
    _emit(
        _api(ctx).request(
            "POST",
            "firmware/executions",
            json_body={"plan_id": plan_id, "confirmation_token": confirmation_token},
        )
    )


@firmware_app.command("receipt-list")
def firmware_receipt_list(ctx: typer.Context) -> None:
    """List receipts for authorized firmware attempts in this daemon lifetime."""
    _emit(_api(ctx).request("GET", "firmware/receipts"))


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
        devices.extend(_discover_production_devices())
    if not devices and not discovered_radios:
        _fail("no_radios", "no fake radios requested and no hardware radios discovered", 2)

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
            device.identity
            for device in devices
            if device.identity.serial == selected_serial
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
