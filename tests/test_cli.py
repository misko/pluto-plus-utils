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
    app,
)
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
        if request.method == "POST" and path.endswith("/firmware/plans"):
            return httpx.Response(201, json={"plan": {"plan_id": "plan-1"}})
        if request.method == "POST" and path.endswith("/firmware/executions"):
            return httpx.Response(201, json={"receipt_id": "receipt-1"})
        if request.method == "POST" and path.endswith("/doctor/setup-plans"):
            return httpx.Response(201, json={"plan": {"plan_id": "setup-plan-1"}})
        if request.method == "POST" and path.endswith("/setup/executions"):
            return httpx.Response(201, json={"receipt_id": "setup-receipt-1"})
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
