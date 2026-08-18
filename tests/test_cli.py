from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import httpx
import pytest
from typer.testing import CliRunner

from pluto_plus.cli import (
    ApiClient,
    _direct_ip_devices,
    _direct_usb_devices,
    _iio_ip_devices,
    _network_iio_inventory,
    _read_ssh_firmware_enrollment,
    app,
)
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import Transport

runner = CliRunner()


@pytest.fixture
def api_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[list[httpx.Request], Callable[[httpx.Request], httpx.Response]]:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        path = request.url.path
        if request.method == "GET" and path.endswith("/inventory"):
            return httpx.Response(
                200,
                json={
                    "generated_at": "2026-08-16T12:00:00Z",
                    "records": [
                        {
                            "inventory_id": "SERIAL_A",
                            "serial": "SERIAL_A",
                            "classification": "confirmed_pluto_plus",
                            "sources": ["usb", "daemon_managed", "network"],
                            "managed": True,
                            "state": "ready",
                            "model": "PlutoSDR Rev.C",
                            "firmware_version": "v5",
                            "transport": "iio_ip",
                            "iio_uri": "ip:192.168.1.15",
                            "radio_ip": "192.168.1.15",
                            "usb_path": "/sys/bus/usb/devices/3-8",
                            "usb_bus_device": "003:011",
                            "usb_speed_mbps": 480,
                            "usb_interface_count": 7,
                            "host_network_interfaces": [
                                {"name": "enx001", "ipv4_addresses": ["192.168.2.10"]}
                            ],
                            "terminal_devices": ["/dev/ttyACM0"],
                            "storage_devices": ["/dev/sdb1"],
                            "notes": [],
                        }
                    ],
                },
            )
        if request.method == "GET" and path.endswith("/radios"):
            return httpx.Response(200, json=[{"identity": {"radio_id": "fake-001"}}])
        if request.method == "GET" and path.endswith("/firmware"):
            return httpx.Response(200, json={"available": True})
        if request.method == "GET" and path.endswith("/firmware/images"):
            return httpx.Response(200, json=[{"image_id": "image-1"}])
        if request.method == "GET" and path.endswith("/firmware/receipts"):
            return httpx.Response(200, json=[{"receipt_id": "receipt-1"}])
        if request.method == "GET" and path.endswith("/setup"):
            return httpx.Response(200, json={"available": True})
        if request.method == "GET" and path.endswith("/setup/receipts"):
            return httpx.Response(200, json=[{"receipt_id": "setup-receipt-1"}])
        if request.method == "GET" and path.endswith("/network-config"):
            return httpx.Response(200, json={"available": True})
        if request.method == "GET" and path.endswith("/network-config/receipts"):
            return httpx.Response(200, json=[{"receipt_id": "network-receipt-1"}])
        if request.method == "GET" and path.endswith("/doctor"):
            return httpx.Response(200, json={"radio_id": "fake-001", "healthy": False})
        if request.method == "GET" and "/radios/" in path:
            return httpx.Response(200, json={"identity": {"radio_id": "fake-001"}, "revision": 7})
        if request.method == "PATCH":
            return httpx.Response(200, json={"revision": 8, "state": "ready"})
        if request.method == "POST" and path.endswith("/streams"):
            return httpx.Response(200, json={"job_id": "job-1", "state": "running"})
        if request.method == "POST" and path.endswith("/recover"):
            return httpx.Response(200, json={"state": "ready", "revision": 8})
        if request.method == "DELETE":
            return httpx.Response(200, json={"job_id": "job-1", "state": "canceled"})
        if request.method == "GET" and path.endswith("/jobs"):
            return httpx.Response(200, json=[{"job_id": "job-1"}])
        if request.method == "GET" and "/jobs/" in path:
            return httpx.Response(200, json={"job_id": "job-1", "state": "complete"})
        if request.method == "GET" and path.endswith("/artifacts"):
            return httpx.Response(200, json=[{"artifact_id": "artifact-1"}])
        if request.method == "POST" and path.endswith("/analyses"):
            return httpx.Response(200, json={"analysis_id": "analysis-1"})
        if request.method == "POST" and path.endswith("/firmware/images"):
            return httpx.Response(201, json={"image_id": "image-1"})
        if request.method == "POST" and (
            path.endswith("/firmware/plans") or path.endswith("/doctor/firmware-plans")
        ):
            return httpx.Response(201, json={"plan": {"plan_id": "plan-1"}})
        if request.method == "POST" and path.endswith("/firmware/executions"):
            return httpx.Response(201, json={"receipt_id": "receipt-1"})
        if request.method == "POST" and path.endswith("/reconcile"):
            return httpx.Response(200, json={"receipt_id": "receipt-2"})
        if request.method == "POST" and path.endswith("/doctor/setup-plans"):
            return httpx.Response(201, json={"plan": {"plan_id": "setup-plan-1"}})
        if request.method == "POST" and path.endswith("/setup/executions"):
            return httpx.Response(201, json={"receipt_id": "setup-receipt-1"})
        if request.method == "POST" and path.endswith("/config/plans"):
            return httpx.Response(201, json={"plan": {"plan_id": "network-plan-1"}})
        if request.method == "POST" and path.endswith("/network-config/executions"):
            return httpx.Response(201, json={"receipt_id": "network-receipt-1"})
        return httpx.Response(404, json={"error": {"code": "not_found", "message": path}})

    monkeypatch.setattr(
        ApiClient,
        "_new_client",
        staticmethod(
            lambda endpoint: httpx.Client(
                base_url="http://test/api/v1/", transport=httpx.MockTransport(handler)
            )
        ),
    )
    return requests, handler


def _body(request: httpx.Request) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(request.content))


def test_radio_list_emits_json_and_uses_versioned_route(api_transport: Any) -> None:
    requests, _ = api_transport
    result = runner.invoke(app, ["radio", "list"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)[0]["identity"]["radio_id"] == "fake-001"
    assert requests[0].url.path == "/api/v1/radios"


def test_radio_inventory_defaults_to_full_table_and_supports_json(
    api_transport: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests, _ = api_transport
    monkeypatch.setattr(
        "pluto_plus.cli.scan_local_usb_plutos",
        lambda: (
            LocalUsbPluto(
                usb_path="/sys/bus/usb/devices/3-8",
                bus_number=3,
                device_number=11,
                product="PlutoSDR+ with timestamp support",
                serial="SERIAL_LOCAL",
                speed_mbps=480,
                interface_count=7,
                terminal_devices=("/dev/ttyACM0",),
                storage_devices=("/dev/sdb1",),
            ),
        ),
    )
    result = runner.invoke(app, ["radio", "inventory"])

    assert result.exit_code == 0, result.output
    assert "SERIAL_LOCAL" in result.stdout
    assert "attached/unmanaged" in result.stdout
    assert requests == []

    result = runner.invoke(app, ["radio", "inventory", "--daemon"])
    assert result.exit_code == 0, result.output
    for value in (
        "SERIAL_A",
        "192.168.1.15",
        "v5",
        "003:011 /sys/bus/usb/devices/3-8",
        "/dev/ttyACM0",
        "enx001=192.168.2.10",
        "/dev/sdb1",
    ):
        assert value in result.stdout
    assert requests[-1].url.path == "/api/v1/inventory"

    result = runner.invoke(app, ["radio", "inventory", "--daemon", "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["records"][0]["serial"] == "SERIAL_A"


def test_radio_inventory_network_discovery_is_explicit_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pluto_plus.models import (
        RadioCapabilities,
        RadioIdentity,
        RadioSettings,
        RadioSnapshot,
        RadioState,
    )

    requested: list[list[str]] = []
    network_snapshot = RadioSnapshot(
        identity=RadioIdentity(
            radio_id="SERIAL_NETWORK",
            serial="SERIAL_NETWORK",
            uri="ip:192.168.1.165",
            transport=Transport.IIO_IP,
            model="Analog Devices PlutoSDR Rev.C",
            firmware_version="v5",
        ),
        capabilities=RadioCapabilities(receiver_channels=(0, 1)),
        managed=False,
        state=RadioState.OFFLINE,
        revision=0,
        requested_settings=RadioSettings(),
        actual_settings=RadioSettings(),
    )

    def discover(
        networks: list[str], managed: list[str]
    ) -> tuple[tuple[Any, ...], tuple[Any, ...]]:
        requested.append(networks)
        assert managed == []
        return (), (network_snapshot,)

    monkeypatch.setattr("pluto_plus.cli.scan_local_usb_plutos", lambda: ())
    monkeypatch.setattr(
        "pluto_plus.cli.local_ipv4_discovery_networks",
        lambda *, exclude_interfaces: ("192.168.1.0/24",),
    )
    monkeypatch.setattr("pluto_plus.cli._network_iio_inventory", discover)

    result = runner.invoke(
        app,
        [
            "radio",
            "inventory",
            "--network",
            "--network-cidr",
            "192.168.50.0/24",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert requested == [["192.168.50.0/24", "192.168.1.0/24"]]
    record = json.loads(result.stdout)["records"][0]
    assert record["serial"] == "SERIAL_NETWORK"
    assert record["state"] == "discovered"
    assert record["sources"] == ["standalone_discovered", "network"]


def test_radio_inventory_rejects_daemon_with_standalone_network_options() -> None:
    result = runner.invoke(app, ["radio", "inventory", "--daemon", "--network"])

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "incompatible_inventory_options"


def test_radio_inventory_rejects_unknown_output_format(api_transport: Any) -> None:
    result = runner.invoke(app, ["radio", "inventory", "--format", "yaml"])

    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "invalid_inventory_format"


def test_endpoint_option_and_environment_are_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    endpoints: list[str] = []

    def make_client(endpoint: str) -> httpx.Client:
        endpoints.append(endpoint)
        return httpx.Client(
            base_url="http://test/api/v1/",
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json=[])),
        )

    monkeypatch.setattr(ApiClient, "_new_client", staticmethod(make_client))
    result = runner.invoke(app, ["--endpoint", "http://radio-host:9000", "radio", "list"])
    assert result.exit_code == 0, result.output
    assert endpoints == ["http://radio-host:9000"]

    monkeypatch.setenv("PLUTO_ENDPOINT", "http://environment-host:9001")
    result = runner.invoke(app, ["radio", "list"])
    assert result.exit_code == 0, result.output
    assert endpoints[-1] == "http://environment-host:9001"


def test_admin_token_file_is_forwarded_only_as_bearer_header(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "cli-admin-token-with-at-least-32-characters"
    token_file = tmp_path / "admin.token"
    token_file.write_text(token + "\n")
    token_file.chmod(0o600)
    requests: list[httpx.Request] = []

    def make_client(endpoint: str, *, admin_token: str | None = None) -> httpx.Client:
        assert endpoint == "http://127.0.0.1:8765"
        headers = {} if admin_token is None else {"Authorization": f"Bearer {admin_token}"}

        def handle(request: httpx.Request) -> httpx.Response:
            requests.append(request)
            return httpx.Response(200, json={"available": False})

        return httpx.Client(
            base_url="http://test/api/v1/",
            headers=headers,
            transport=httpx.MockTransport(handle),
        )

    monkeypatch.setattr(ApiClient, "_new_client", staticmethod(make_client))
    result = runner.invoke(
        app,
        ["--admin-token-file", str(token_file), "setup", "status"],
    )

    assert result.exit_code == 0, result.output
    assert requests[0].headers["authorization"] == f"Bearer {token}"
    assert token not in result.output


def test_normal_and_unix_endpoint_construction(monkeypatch: pytest.MonkeyPatch) -> None:
    client = ApiClient._new_client("https://example.test")
    assert str(client.base_url) == "https://example.test/api/v1/"
    client.close()

    captured: dict[str, Any] = {}

    def make_transport(*, uds: str) -> str:
        captured["uds"] = uds
        return uds

    monkeypatch.setattr(httpx, "HTTPTransport", make_transport)

    class DummyClient:
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)

    monkeypatch.setattr(httpx, "Client", DummyClient)
    ApiClient._new_client("unix:///run/plutod.sock")
    assert captured["uds"] == "/run/plutod.sock"
    assert captured["base_url"] == "http://plutod/api/v1/"
    assert captured["transport"] == "/run/plutod.sock"


def test_settings_set_fetches_revision_and_sends_only_requested_fields(api_transport: Any) -> None:
    requests, _ = api_transport
    result = runner.invoke(
        app,
        [
            "radio",
            "settings",
            "set",
            "fake-001",
            "--frequency",
            "1000000000",
            "--gain-mode",
            "slow_attack",
            "--channels",
            "0,1",
        ],
    )

    assert result.exit_code == 0, result.output
    assert [request.method for request in requests] == ["GET", "PATCH"]
    assert _body(requests[1]) == {
        "expected_revision": 7,
        "center_frequency_hz": 1_000_000_000.0,
        "gain_mode": "slow_attack",
        "channels": [0, 1],
    }


@pytest.mark.parametrize(
    ("arguments", "method", "path", "expected_body"),
    [
        (
            ["stream", "start", "fake-001", "--fft-size", "1024"],
            "POST",
            "/api/v1/radios/fake-001/streams",
            {"block_size": 65_536, "fft_size": 1024, "persist": False},
        ),
        (
            ["radio", "settings", "get", "fake-001"],
            "GET",
            "/api/v1/radios/fake-001/settings",
            None,
        ),
        (["radio", "recover", "fake-001"], "POST", "/api/v1/radios/fake-001/recover", None),
        (
            ["stream", "stop", "fake-001"],
            "DELETE",
            "/api/v1/radios/fake-001/streams/current",
            None,
        ),
        (
            ["capture", "start", "fake-001", "--samples", "8192", "--label", "demo"],
            "POST",
            "/api/v1/radios/fake-001/streams",
            {
                "sample_count": 8192,
                "block_size": 65_536,
                "fft_size": 4096,
                "persist": True,
                "label": "demo",
            },
        ),
        (["job", "status", "job-1"], "GET", "/api/v1/jobs/job-1", None),
        (["job", "list", "--radio", "fake-001"], "GET", "/api/v1/jobs", None),
        (["artifact", "list"], "GET", "/api/v1/artifacts", None),
        (
            ["analyze", "artifact-1", "--analyzer", "spectrum", "--parameters", '{"nfft":512}'],
            "POST",
            "/api/v1/analyses",
            {"artifact_id": "artifact-1", "analyzer": "spectrum", "parameters": {"nfft": 512}},
        ),
        (["firmware", "status"], "GET", "/api/v1/firmware", None),
        (["firmware", "image-list"], "GET", "/api/v1/firmware/images", None),
        (
            ["firmware", "plan", "fake-001", "image-1", "--mode", "persistent_qspi"],
            "POST",
            "/api/v1/radios/fake-001/firmware/plans",
            {"image_id": "image-1", "mode": "persistent_qspi"},
        ),
        (
            ["firmware", "execute", "plan-1", "--token", "secret"],
            "POST",
            "/api/v1/firmware/executions",
            {"plan_id": "plan-1", "confirmation_token": "secret"},
        ),
        (["firmware", "receipt-list"], "GET", "/api/v1/firmware/receipts", None),
        (["doctor", "fake-001"], "GET", "/api/v1/radios/fake-001/doctor", None),
        (["setup", "status"], "GET", "/api/v1/setup", None),
        (
            ["setup", "plan", "fake-001"],
            "POST",
            "/api/v1/radios/fake-001/doctor/setup-plans",
            {},
        ),
        (
            ["setup", "execute", "setup-plan-1", "--token", "secret"],
            "POST",
            "/api/v1/setup/executions",
            {"plan_id": "setup-plan-1", "confirmation_token": "secret"},
        ),
        (["setup", "receipt-list"], "GET", "/api/v1/setup/receipts", None),
        (["config", "status"], "GET", "/api/v1/network-config", None),
        (
            ["config", "show", "fake-001"],
            "GET",
            "/api/v1/radios/fake-001/config",
            None,
        ),
        (
            [
                "config",
                "plan",
                "fake-001",
                "--interface",
                "ethernet",
                "--mode",
                "static",
                "--address",
                "192.168.1.165",
                "--netmask",
                "255.255.255.0",
            ],
            "POST",
            "/api/v1/radios/fake-001/config/plans",
            {
                "interface": "ethernet",
                "mode": "static",
                "address": "192.168.1.165",
                "netmask": "255.255.255.0",
                "host_address": None,
            },
        ),
        (
            [
                "config",
                "execute",
                "network-plan-1",
                "--token",
                "secret",
                "--operator-confirmation",
                "SET STATIC IP fake-001 192.168.1.165",
            ],
            "POST",
            "/api/v1/network-config/executions",
            {
                "plan_id": "network-plan-1",
                "confirmation_token": "secret",
                "operator_confirmation": "SET STATIC IP fake-001 192.168.1.165",
            },
        ),
        (
            ["config", "receipt-list"],
            "GET",
            "/api/v1/network-config/receipts",
            None,
        ),
    ],
)
def test_command_routes(
    api_transport: Any,
    arguments: list[str],
    method: str,
    path: str,
    expected_body: dict[str, Any] | None,
) -> None:
    requests, _ = api_transport
    result = runner.invoke(app, arguments)

    assert result.exit_code == 0, result.output
    request = requests[-1]
    assert request.method == method
    assert request.url.path == path
    if "--radio" in arguments:
        assert request.url.params["radio_id"] == "fake-001"
    if expected_body is not None:
        assert _body(request) == expected_body


@pytest.mark.parametrize(
    "arguments",
    [
        ["capture", "start", "fake-001"],
        ["capture", "start", "fake-001", "--samples", "4", "--duration", "1"],
        ["stream", "start", "fake-001", "--samples", "4", "--duration", "1"],
        ["radio", "settings", "set", "fake-001", "--channels", "zero"],
        ["analyze", "artifact-1", "--parameters", "[]"],
    ],
)
def test_invalid_command_inputs_are_structured_errors(
    api_transport: Any, arguments: list[str]
) -> None:
    result = runner.invoke(app, arguments)

    assert result.exit_code == 2
    assert "error" in json.loads(result.stderr)


def test_firmware_upload_sends_raw_image_and_safe_filename(
    api_transport: Any, tmp_path: Path
) -> None:
    requests, _ = api_transport
    image = tmp_path / "candidate image.dfu"
    image.write_bytes(b"firmware bytes")

    result = runner.invoke(app, ["firmware", "upload", str(image)])

    assert result.exit_code == 0, result.output
    request = requests[-1]
    assert request.url.path == "/api/v1/firmware/images"
    assert request.url.params["filename"] == "candidate image.dfu"
    assert request.content == b"firmware bytes"


def test_remote_error_is_structured_and_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        ApiClient,
        "_new_client",
        staticmethod(
            lambda endpoint: httpx.Client(
                base_url="http://test/api/v1/",
                transport=httpx.MockTransport(
                    lambda request: httpx.Response(
                        409,
                        json={
                            "error": {
                                "code": "revision_conflict",
                                "message": "expected revision 2, current revision is 3",
                            }
                        },
                    )
                ),
            )
        ),
    )
    result = runner.invoke(app, ["radio", "status", "fake-001"])

    assert result.exit_code == 4
    assert json.loads(result.stderr)["error"]["code"] == "revision_conflict"


def test_connection_failure_is_structured_and_nonzero(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    monkeypatch.setattr(
        ApiClient,
        "_new_client",
        staticmethod(
            lambda endpoint: httpx.Client(
                base_url="http://test/api/v1/", transport=httpx.MockTransport(unavailable)
            )
        ),
    )
    result = runner.invoke(app, ["radio", "list"])

    assert result.exit_code == 3
    assert json.loads(result.stderr)["error"]["code"] == "daemon_unavailable"


def test_serve_composes_fake_service(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    pytest.importorskip("pluto_plus.api")
    observed: dict[str, Any] = {}

    def fake_run(api: Any, **kwargs: Any) -> None:
        from fastapi.testclient import TestClient

        with TestClient(api) as client:
            observed["radios"] = client.get("/api/v1/radios").json()
        observed.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    result = runner.invoke(
        app,
        [
            "serve",
            "--state-root",
            str(tmp_path),
            "--fake-radio",
            "sim-a",
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed["host"] == "0.0.0.0"
    assert observed["port"] == 9000
    assert observed["radios"][0]["identity"]["radio_id"] == "sim-a"


def test_serve_can_bind_unix_socket(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    observed: dict[str, Any] = {}

    def fake_run(_api: Any, **kwargs: Any) -> None:
        observed.update(kwargs)

    monkeypatch.setattr("uvicorn.run", fake_run)
    socket_path = tmp_path / "run" / "plutod.sock"
    result = runner.invoke(
        app,
        [
            "serve",
            "--state-root",
            str(tmp_path / "state"),
            "--fake-radio",
            "sim-a",
            "--uds",
            str(socket_path),
        ],
    )

    assert result.exit_code == 0, result.output
    assert observed["uds"] == str(socket_path)
    assert "host" not in observed and "port" not in observed


def test_serve_refuses_partial_or_unauthenticated_setup_configuration(
    tmp_path: Path,
) -> None:
    partial = runner.invoke(
        app,
        [
            "serve",
            "--state-root",
            str(tmp_path / "partial"),
            "--fake-radio",
            "sim-a",
            "--setup-serial",
            "sim-a",
        ],
    )
    assert partial.exit_code == 2
    assert json.loads(partial.stderr)["error"]["code"] == "canonical_setup_not_enabled"

    incomplete = runner.invoke(
        app,
        [
            "serve",
            "--state-root",
            str(tmp_path / "incomplete"),
            "--fake-radio",
            "sim-a",
            "--enable-canonical-setup",
        ],
    )
    assert incomplete.exit_code == 2
    assert json.loads(incomplete.stderr)["error"]["code"] == "incomplete_canonical_setup"

    password_file = tmp_path / "password"
    known_hosts_file = tmp_path / "known_hosts"
    password_file.write_text("analog\n")
    known_hosts_file.write_text("192.168.2.1 ssh-ed25519 AAAATEST\n")
    password_file.chmod(0o600)
    known_hosts_file.chmod(0o600)
    unauthenticated = runner.invoke(
        app,
        [
            "serve",
            "--state-root",
            str(tmp_path / "unauthenticated"),
            "--fake-radio",
            "sim-a",
            "--enable-canonical-setup",
            "--setup-serial",
            "sim-a",
            "--setup-usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--setup-usb-interface",
            "usb0",
            "--setup-usb-host",
            "192.168.2.1",
            "--setup-password-file",
            str(password_file),
            "--setup-known-hosts-file",
            str(known_hosts_file),
        ],
    )
    assert unauthenticated.exit_code == 2
    assert json.loads(unauthenticated.stderr)["error"]["code"] == "admin_authentication_unavailable"


def test_direct_ip_targets_are_explicitly_host_and_serial_bound() -> None:
    devices = _direct_ip_devices(["192.0.2.10,SERIAL_A"])

    assert len(devices) == 1
    assert devices[0].identity.serial == "SERIAL_A"
    assert devices[0].identity.transport is Transport.DIRECT_IP
    assert devices[0].identity.uri == "direct-ip://192.0.2.10:30432"

    result = runner.invoke(app, ["serve", "--direct-ip", "missing-serial"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "invalid_direct_ip"


def test_direct_usb_targets_are_exactly_serial_bound() -> None:
    devices = _direct_usb_devices(["SERIAL_A"])

    assert len(devices) == 1
    assert devices[0].identity.serial == "SERIAL_A"
    assert devices[0].identity.transport is Transport.DIRECT_USB
    assert devices[0].identity.uri == "direct-usb://SERIAL_A"

    result = runner.invoke(app, ["serve", "--direct-usb", " SERIAL_A"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "invalid_direct_usb"


def test_standard_iio_ip_targets_support_observed_or_pinned_serials() -> None:
    devices = _iio_ip_devices(["192.168.1.15", "192.168.1.20,1040005e0b100007100010000bf33a5d4d"])

    assert [device.identity.radio_id for device in devices] == [
        "192.168.1.15",
        "1040005e0b100007100010000bf33a5d4d",
    ]
    assert all(device.identity.transport is Transport.IIO_IP for device in devices)

    result = runner.invoke(app, ["serve", "--iio-ip", "192.168.1.15, serial"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "invalid_iio_ip"


def test_network_iio_inventory_promotes_only_selected_serial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pluto_plus.hardware.discovery import NetworkIioObservation

    observations = (
        NetworkIioObservation("192.0.2.10", "SERIAL_A", "Pluto A", "v1"),
        NetworkIioObservation("192.0.2.11", "SERIAL_B", "Pluto B", "v2"),
    )
    monkeypatch.setattr(
        "pluto_plus.hardware.discovery.discover_network_iio",
        lambda _networks: observations,
    )

    managed, passive = _network_iio_inventory(["192.0.2.0/24"], ["SERIAL_B"])

    assert [device.identity.serial for device in managed] == ["SERIAL_B"]
    assert [snapshot.identity.serial for snapshot in passive] == ["SERIAL_A"]
    assert passive[0].managed is False
    assert passive[0].capabilities.supports_live_tuning is False


def test_network_iio_management_requires_discovery() -> None:
    result = runner.invoke(app, ["serve", "--manage-discovered-iio", "SERIAL_A"])
    assert result.exit_code == 2
    assert json.loads(result.stderr)["error"]["code"] == "iio_network_discovery_unavailable"


def test_ssh_firmware_cli_sends_transport_confirmation_and_reconcile(
    api_transport: Any,
) -> None:
    requests, _ = api_transport

    plan = runner.invoke(
        app,
        [
            "firmware",
            "plan",
            "SERIAL_A",
            "image-1",
            "--mode",
            "persistent_qspi",
            "--transport",
            "ssh",
        ],
    )
    assert plan.exit_code == 0, plan.output
    assert _body(requests[-1])["transport"] == "ssh_frm"
    assert requests[-1].url.path.endswith("/radios/SERIAL_A/doctor/firmware-plans")

    rejected = runner.invoke(
        app,
        [
            "firmware",
            "plan",
            "SERIAL_A",
            "image-1",
            "--transport",
            "ssh",
        ],
    )
    assert rejected.exit_code == 2
    assert json.loads(rejected.stderr)["error"]["code"] == "invalid_firmware_mode"

    execute = runner.invoke(
        app,
        [
            "firmware",
            "execute",
            "plan-1",
            "--token",
            "secret",
            "--operator-confirmation",
            "FLASH SERIAL_A",
        ],
    )
    assert execute.exit_code == 0, execute.output
    assert _body(requests[-1])["operator_confirmation"] == "FLASH SERIAL_A"

    reconcile = runner.invoke(app, ["firmware", "reconcile", "receipt-1"])
    assert reconcile.exit_code == 0, reconcile.output
    assert requests[-1].url.path.endswith("/firmware/receipts/receipt-1/reconcile")


def test_ssh_firmware_enrollment_file_is_private_and_strict(tmp_path: Path) -> None:
    known_hosts = tmp_path / "known_hosts"
    private_key = tmp_path / "id_ed25519"
    enrollment = tmp_path / "enrollment.json"
    known_hosts.write_text("placeholder\n")
    private_key.write_text("placeholder\n")
    for path in (known_hosts, private_key):
        path.chmod(0o600)
    enrollment.write_text(
        json.dumps(
            {
                "serial": "SERIAL_A",
                "host": "192.168.2.15",
                "username": "root",
                "known_hosts_file": str(known_hosts),
                "private_key_file": str(private_key),
            }
        )
    )
    enrollment.chmod(0o600)

    parsed = _read_ssh_firmware_enrollment(enrollment)
    assert parsed.serial == "SERIAL_A"
    assert parsed.host == "192.168.2.15"

    enrollment.chmod(0o644)
    rejected = runner.invoke(
        app,
        [
            "serve",
            "--fake-radio",
            "SERIAL_A",
            "--ssh-firmware-enrollment",
            str(enrollment),
        ],
    )
    assert rejected.exit_code == 2
    assert json.loads(rejected.stderr)["error"]["code"] == "invalid_private_file"

    enrollment.chmod(0o600)
    token_file = tmp_path / "admin-token"
    token_file.write_text("a-valid-admin-token-with-at-least-32-characters")
    token_file.chmod(0o600)
    wrong_transport = runner.invoke(
        app,
        [
            "serve",
            "--fake-radio",
            "SERIAL_A",
            "--admin-token-file",
            str(token_file),
            "--ssh-firmware-enrollment",
            str(enrollment),
        ],
    )
    assert wrong_transport.exit_code == 2
    assert json.loads(wrong_transport.stderr)["error"]["code"] == "invalid_ssh_firmware_enrollment"


def test_usb_bootstrap_cli_is_dry_run_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pluto_plus.bootstrap_firmware import BootstrapPlan

    image = tmp_path / "canonical.dfu"
    image.write_bytes(b"qualified")
    plan = BootstrapPlan(
        plan_id="plan-1",
        usb_sysfs_path="/sys/bus/usb/devices/3-11",
        usb_port="3-11",
        usb_interface="enx001",
        block_device="/dev/sdb",
        partition="/dev/sdb1",
        before_firmware="v0.32",
        before_model="PlutoSDR Rev.C",
        before_phy="ad9363a",
        image_path=str(image),
        image_sha256="1" * 64,
        fit_sha256="2" * 64,
        fit_size=100,
        frm_sha256="3" * 64,
        expected_firmware="v5",
        confirmation_phrase="BOOTSTRAP 3-11",
    )
    execute_calls: list[object] = []
    force_modes: list[bool] = []

    def prepare(
        image: Path,
        usb_sysfs_path: Path,
        force_blank_serial: bool,
        **kwargs: object,
    ) -> tuple[object, bytes]:
        del image, usb_sysfs_path
        force_modes.append(force_blank_serial)
        return plan, b"frm"

    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.prepare_usb_flash_plan",
        prepare,
    )
    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.execute_usb_flash_plan",
        lambda *args, **kwargs: execute_calls.append((args, kwargs)),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "force-flash-usb",
            str(image),
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-11",
        ],
    )

    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    assert payload["mode"] == "dry_run"
    assert payload["will_write"] is False
    assert payload["plan"]["confirmation_phrase"] == "BOOTSTRAP 3-11"
    assert execute_calls == []
    assert force_modes == [True]

    normal = runner.invoke(
        app,
        [
            "firmware",
            "flash",
            str(image),
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-11",
        ],
    )
    assert normal.exit_code == 0, normal.output
    assert force_modes == [True, False]


def test_usb_bootstrap_cli_requires_and_passes_exact_confirmation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pluto_plus.bootstrap_firmware import BootstrapPlan, BootstrapResult

    image = tmp_path / "canonical.dfu"
    image.write_bytes(b"qualified")
    plan = BootstrapPlan(
        plan_id="plan-1",
        usb_sysfs_path="/sys/bus/usb/devices/3-11",
        usb_port="3-11",
        usb_interface="enx001",
        block_device="/dev/sdb",
        partition="/dev/sdb1",
        before_firmware="v0.32",
        before_model="PlutoSDR Rev.C",
        before_phy="ad9363a",
        image_path=str(image),
        image_sha256="1" * 64,
        fit_sha256="2" * 64,
        fit_size=100,
        frm_sha256="3" * 64,
        expected_firmware="v5",
        confirmation_phrase="BOOTSTRAP 3-11",
    )
    confirmations: list[str] = []
    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.prepare_usb_flash_plan",
        lambda image, usb_sysfs_path, force_blank_serial, **kwargs: (plan, b"frm"),
    )

    def execute(plan: object, frm: bytes, **kwargs: Any) -> BootstrapResult:
        del plan, frm
        confirmations.append(cast(str, kwargs["confirmation"]))
        return BootstrapResult(
            receipt_id="receipt-1",
            outcome="success",
            phases=("return_attested",),
            receipt_path=str(tmp_path / "receipt.json"),
            returned_serial="SERIAL_NEW",
            returned_firmware="v5",
            returned_phy="ad9363a",
        )

    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.execute_usb_flash_plan",
        execute,
    )

    missing = runner.invoke(
        app,
        [
            "firmware",
            "bootstrap-usb",
            str(image),
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-11",
            "--execute",
        ],
    )
    assert missing.exit_code == 2
    assert json.loads(missing.stderr)["error"]["code"] == "bootstrap_confirmation_required"

    result = runner.invoke(
        app,
        [
            "firmware",
            "bootstrap-usb",
            str(image),
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-11",
            "--execute",
            "--confirm",
            "BOOTSTRAP 3-11",
        ],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["returned_serial"] == "SERIAL_NEW"
    assert confirmations == ["BOOTSTRAP 3-11"]


def test_usb_flash_cli_routes_explicit_lan_host_without_usb_bind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pluto_plus.bootstrap_firmware import BootstrapPlan, BootstrapResult

    image = tmp_path / "canonical.dfu"
    image.write_bytes(b"qualified")
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("placeholder\n")
    known_hosts.chmod(0o600)
    password = tmp_path / "password"
    password.write_text("analog\n")
    password.chmod(0o600)
    plan = BootstrapPlan(
        plan_id="plan-lan",
        usb_sysfs_path="/sys/bus/usb/devices/3-8",
        usb_port="3-8",
        usb_interface="enx001",
        block_device="/dev/sdb",
        partition="/dev/sdb1",
        before_firmware="v0.32",
        before_model="PlutoSDR Rev.C",
        before_phy="ad9363a",
        image_path=str(image),
        image_sha256="1" * 64,
        fit_sha256="2" * 64,
        fit_size=100,
        frm_sha256="3" * 64,
        expected_firmware="v6",
        confirmation_phrase="FLASH SERIAL_A",
        target_serial="SERIAL_A",
    )
    transports: list[object] = []

    class RecordingSshTransport:
        def __init__(self, **kwargs: object) -> None:
            transports.append(kwargs)

    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.prepare_usb_flash_plan",
        lambda *args, **kwargs: (plan, b"frm"),
    )
    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.BoundSshBootstrapTransport",
        RecordingSshTransport,
    )
    monkeypatch.setattr(
        "pluto_plus.bootstrap_firmware.execute_usb_flash_plan_ssh",
        lambda *args, **kwargs: BootstrapResult(
            receipt_id="receipt-lan",
            outcome="success",
            phases=("return_attested",),
            receipt_path=str(tmp_path / "receipt.json"),
            returned_serial="SERIAL_A",
            returned_firmware="v6",
            returned_phy="ad9361",
        ),
    )

    result = runner.invoke(
        app,
        [
            "firmware",
            "flash",
            str(image),
            "--usb-sysfs-path",
            "/sys/bus/usb/devices/3-8",
            "--transport",
            "ssh",
            "--ssh-host",
            "192.168.1.14",
            "--ssh-known-hosts-file",
            str(known_hosts),
            "--ssh-password-file",
            str(password),
            "--execute",
            "--confirm",
            "FLASH SERIAL_A",
        ],
    )

    assert result.exit_code == 0, result.output
    assert transports == [
        {
            "interface": None,
            "password": "analog",
            "known_hosts_file": known_hosts.resolve(),
            "host": "192.168.1.14",
        }
    ]


def test_doctor_defaults_to_standalone_local_usb_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pluto_plus.local_doctor import LocalDoctorReport

    monkeypatch.setattr(
        "pluto_plus.local_doctor.diagnose_local_usb_radios",
        lambda path: LocalDoctorReport(
            generated_at="2026-08-16T12:00:00+00:00",
            canonical_firmware="v5",
            canonical_image_sha256="a" * 64,
            radios=(),
        ),
    )

    result = runner.invoke(app, ["doctor", "--format", "json"])

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["canonical_firmware"] == "v5"
