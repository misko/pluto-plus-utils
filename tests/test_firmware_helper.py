from __future__ import annotations

import binascii
import hashlib
import json
import socket
import struct
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from pluto_plus.firmware import (
    DFU_PRODUCT_ID,
    DFU_SPECIFICATION,
    DFU_VENDOR_ID,
    FIT_MAGIC,
    PLUTO_FRM_MAGIC,
    FirmwareAuthorizationError,
    FirmwareIdentityError,
    FirmwareImageError,
    FirmwareManager,
    FirmwareMode,
    RadioFirmwareIdentity,
    generate_frm,
)
from pluto_plus.firmware_helper import (
    MAX_FRAME_BYTES,
    FirmwareHelperProtocolError,
    FirmwareHelperUnavailableError,
    PeerCredentials,
    UnixFirmwareHelperClient,
    UnixFirmwareHelperServer,
)

_HEADER = struct.Struct("!I")


def _fit() -> bytes:
    body = bytearray(96)
    body[:4] = FIT_MAGIC
    body[4:8] = len(body).to_bytes(4, "big")
    body[40 : 40 + len(PLUTO_FRM_MAGIC)] = PLUTO_FRM_MAGIC
    return bytes(body)


def _dfu() -> bytes:
    suffix = b"".join(
        (
            (0xFFFF).to_bytes(2, "little"),
            DFU_PRODUCT_ID.to_bytes(2, "little"),
            DFU_VENDOR_ID.to_bytes(2, "little"),
            DFU_SPECIFICATION.to_bytes(2, "little"),
            b"UFD\x10",
        )
    )
    partial = _fit() + suffix
    crc = binascii.crc32(partial) ^ 0xFFFFFFFF
    return partial + crc.to_bytes(4, "little")


@pytest.fixture
def radio() -> RadioFirmwareIdentity:
    return RadioFirmwareIdentity(
        serial="SERIAL_A",
        usb_sysfs_path="/sys/bus/usb/devices/1-2.3",
        observed_firmware="v0.37",
    )


class RecordingExecutor:
    def __init__(self, *, failure: Exception | None = None, uid: int = 0) -> None:
        self.failure = failure
        self.uid = uid
        self.calls: list[tuple[str, RadioFirmwareIdentity, str, bytes]] = []

    def effective_uid(self) -> int:
        return self.uid

    def load_volatile_dfu(self, radio: RadioFirmwareIdentity, image: Path) -> None:
        self.calls.append(("load_volatile_dfu", radio, image.name, image.read_bytes()))
        if self.failure is not None:
            raise self.failure

    def flash_persistent_qspi(
        self, radio: RadioFirmwareIdentity, image: Path, *, target_name: str
    ) -> None:
        self.calls.append(("flash_persistent_qspi", radio, target_name, image.read_bytes()))
        if self.failure is not None:
            raise self.failure


def _server(
    tmp_path: Path,
    radio: RadioFirmwareIdentity,
    executor: RecordingExecutor,
    *,
    authorize: bool = True,
) -> UnixFirmwareHelperServer:
    staging = tmp_path / "stage"
    execution = tmp_path / "execution"
    staging.mkdir(exist_ok=True)
    execution.mkdir(exist_ok=True)
    return UnixFirmwareHelperServer(
        socket_path=tmp_path / "firmware.sock",
        staging_root=staging,
        execution_root=execution,
        executor=executor,
        identity_probe=lambda _serial: radio,
        authorize_peer=lambda credentials: authorize and credentials.uid == 1000,
        peer_credentials=lambda _connection: PeerCredentials(pid=42, uid=1000, gid=1000),
        uid_provider=lambda: 0,
        request_timeout_s=0.5,
        maximum_image_bytes=1024 * 1024,
    )


@contextmanager
def _running(server: UnixFirmwareHelperServer, socket_path: Path) -> Iterator[None]:
    stop = threading.Event()
    failures: list[BaseException] = []

    def serve() -> None:
        try:
            server.serve_forever(stop.is_set)
        except BaseException as caught:
            failures.append(caught)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    deadline = time.monotonic() + 2
    ready = False
    while not ready and not failures and time.monotonic() < deadline:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.connect(str(socket_path))
            ready = True
        except (FileNotFoundError, ConnectionRefusedError):
            time.sleep(0.005)
    if failures:
        raise failures[0]
    assert ready
    try:
        yield
    finally:
        stop.set()
        thread.join(timeout=2)
        assert not thread.is_alive()
        if failures:
            raise failures[0]


def _client(tmp_path: Path, *, timeout: float = 0.5) -> UnixFirmwareHelperClient:
    return UnixFirmwareHelperClient(
        socket_path=tmp_path / "firmware.sock",
        staging_root=tmp_path / "stage",
        timeout_s=timeout,
        maximum_image_bytes=1024 * 1024,
        uid_provider=lambda: 1000,
    )


def _send_raw(socket_path: Path, body: bytes) -> dict[str, object]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(1)
        connection.connect(str(socket_path))
        connection.sendall(_HEADER.pack(len(body)) + body)
        header = _recv_exact(connection, _HEADER.size)
        (length,) = _HEADER.unpack(header)
        return json.loads(_recv_exact(connection, length))  # type: ignore[no-any-return]


def _recv_exact(connection: socket.socket, length: int) -> bytes:
    result = bytearray()
    while len(result) < length:
        chunk = connection.recv(length - len(result))
        assert chunk
        result.extend(chunk)
    return bytes(result)


def _request(
    radio: RadioFirmwareIdentity,
    *,
    path: str,
    digest: str,
    size: int,
    action: str = "load_volatile_dfu",
    extra: dict[str, object] | None = None,
) -> bytes:
    value: dict[str, object] = {
        "version": 1,
        "request_id": "a" * 32,
        "action": action,
        "radio": {
            "serial": radio.serial,
            "usb_sysfs_path": radio.usb_sysfs_path,
            "observed_firmware": radio.observed_firmware,
        },
        "image": {"path": path, "sha256": digest, "size": size},
    }
    if extra:
        value.update(extra)
    return json.dumps(value, separators=(",", ":")).encode()


@pytest.mark.parametrize("body", [b"{", b'{"x":1,"x":2}'])
def test_malformed_json_is_rejected_without_execution(
    tmp_path: Path, radio: RadioFirmwareIdentity, body: bytes
) -> None:
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    with _running(server, tmp_path / "firmware.sock"):
        response = _send_raw(tmp_path / "firmware.sock", body)
    assert response["ok"] is False
    assert response["error"]["code"] == "invalid_request"  # type: ignore[index]
    assert executor.calls == []


def test_oversized_frame_is_rejected_without_reading_a_body(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    with (
        _running(server, tmp_path / "firmware.sock"),
        socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection,
    ):
        connection.connect(str(tmp_path / "firmware.sock"))
        connection.sendall(_HEADER.pack(MAX_FRAME_BYTES + 1))
        response_length = _HEADER.unpack(_recv_exact(connection, _HEADER.size))[0]
        response = json.loads(_recv_exact(connection, response_length))
    assert response["error"]["code"] == "invalid_request"
    assert executor.calls == []


def test_unauthorized_peer_is_refused_before_request_is_read(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(_dfu())
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor, authorize=False)
    with (
        _running(server, tmp_path / "firmware.sock"),
        pytest.raises(FirmwareAuthorizationError, match="peer UID"),
    ):
        _client(tmp_path).load_volatile_dfu(radio, image)
    assert executor.calls == []


@pytest.mark.parametrize("path", ["../outside.dfu", "/tmp/outside.dfu", "x/../../y"])
def test_traversal_and_absolute_paths_are_refused(
    tmp_path: Path, radio: RadioFirmwareIdentity, path: str
) -> None:
    data = _dfu()
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    body = _request(radio, path=path, digest=hashlib.sha256(data).hexdigest(), size=len(data))
    with _running(server, tmp_path / "firmware.sock"):
        response = _send_raw(tmp_path / "firmware.sock", body)
    assert response["error"]["code"] == "invalid_request"  # type: ignore[index]
    assert executor.calls == []


def test_symlinked_staging_file_is_refused_server_side(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    data = _dfu()
    outside = tmp_path / "outside.dfu"
    outside.write_bytes(data)
    directory = tmp_path / "stage" / "digest"
    directory.mkdir(parents=True)
    (directory / "firmware.dfu").symlink_to(outside)
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    body = _request(
        radio,
        path="digest/firmware.dfu",
        digest=hashlib.sha256(data).hexdigest(),
        size=len(data),
    )
    with _running(server, tmp_path / "firmware.sock"):
        response = _send_raw(tmp_path / "firmware.sock", body)
    assert response["error"]["code"] == "invalid_image"  # type: ignore[index]
    assert executor.calls == []


def test_digest_drift_is_refused_server_side(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    original = _dfu()
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    body = _request(
        radio,
        path="digest/firmware.dfu",
        digest=hashlib.sha256(original).hexdigest(),
        size=len(original),
    )
    with _running(server, tmp_path / "firmware.sock"):
        response = _send_raw(tmp_path / "firmware.sock", body)
    assert response["error"]["code"] == "invalid_image"  # type: ignore[index]
    assert "digest or size changed" in response["error"]["message"]  # type: ignore[index]
    assert executor.calls == []


def test_live_identity_is_rechecked_by_privileged_server(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    data = _dfu()
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(data)
    executor = RecordingExecutor()
    other = RadioFirmwareIdentity(
        radio.serial, radio.usb_sysfs_path, "different-firmware"
    )
    server = UnixFirmwareHelperServer(
        socket_path=tmp_path / "firmware.sock",
        staging_root=tmp_path / "stage",
        execution_root=tmp_path / "execution",
        executor=executor,
        identity_probe=lambda _serial: other,
        authorize_peer=lambda _peer: True,
        peer_credentials=lambda _connection: PeerCredentials(1, 1000, 1000),
        uid_provider=lambda: 0,
    )
    (tmp_path / "execution").mkdir()
    with (
        _running(server, tmp_path / "firmware.sock"),
        pytest.raises(FirmwareIdentityError, match="identity"),
    ):
        _client(tmp_path).load_volatile_dfu(radio, image)
    assert executor.calls == []


def test_helper_process_and_executor_must_both_be_root(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    data = _dfu()
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(data)
    (tmp_path / "execution").mkdir()
    executor = RecordingExecutor(uid=0)
    server = UnixFirmwareHelperServer(
        socket_path=tmp_path / "firmware.sock",
        staging_root=tmp_path / "stage",
        execution_root=tmp_path / "execution",
        executor=executor,
        identity_probe=lambda _serial: radio,
        authorize_peer=lambda _peer: True,
        peer_credentials=lambda _connection: PeerCredentials(1, 1000, 1000),
        uid_provider=lambda: 1000,
    )
    with (
        _running(server, tmp_path / "firmware.sock"),
        pytest.raises(FirmwareAuthorizationError, match="not running as root"),
    ):
        _client(tmp_path).load_volatile_dfu(radio, image)
    assert executor.calls == []


@pytest.mark.parametrize("mode", [FirmwareMode.VOLATILE_DFU, FirmwareMode.PERSISTENT_QSPI])
def test_success_uses_only_the_two_domain_operations_and_private_copy(
    tmp_path: Path, radio: RadioFirmwareIdentity, mode: FirmwareMode
) -> None:
    data = _dfu() if mode is FirmwareMode.VOLATILE_DFU else generate_frm(_dfu())
    name = "firmware.dfu" if mode is FirmwareMode.VOLATILE_DFU else "pluto.frm"
    image = tmp_path / "stage" / hashlib.sha256(data).hexdigest() / name
    image.parent.mkdir(parents=True)
    image.write_bytes(data)
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    client = _client(tmp_path)
    assert client.effective_uid() == 1000  # the client never claims local root
    with _running(server, tmp_path / "firmware.sock"):
        if mode is FirmwareMode.VOLATILE_DFU:
            client.load_volatile_dfu(radio, image)
        else:
            client.flash_persistent_qspi(radio, image, target_name="pluto.frm")
    assert executor.calls == [
        (
            "load_volatile_dfu" if mode is FirmwareMode.VOLATILE_DFU else "flash_persistent_qspi",
            radio,
            name,
            data,
        )
    ]
    assert list((tmp_path / "execution").iterdir()) == []


def test_firmware_manager_accepts_boundary_without_local_root_claim(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    client = _client(tmp_path)
    manager = FirmwareManager(
        staging_directory=tmp_path / "stage",
        receipt_directory=tmp_path / "receipts",
        identity_probe=lambda _serial: radio,
        executor=client,
    )
    source = tmp_path / "release.dfu"
    source.write_bytes(_dfu())
    planned = manager.create_plan(radio, source, FirmwareMode.VOLATILE_DFU)
    with _running(server, tmp_path / "firmware.sock"):
        receipt = manager.execute(planned.plan, planned.confirmation_token)
    assert receipt.success
    assert client.effective_uid() == 1000
    assert len(executor.calls) == 1


def test_executor_timeout_is_mapped_without_retry(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(_dfu())
    executor = RecordingExecutor(
        failure=subprocess.TimeoutExpired(cmd=("dfu-util",), timeout=120)
    )
    server = _server(tmp_path, radio, executor)
    with (
        _running(server, tmp_path / "firmware.sock"),
        pytest.raises(FirmwareHelperUnavailableError, match="timed out"),
    ):
        _client(tmp_path).load_volatile_dfu(radio, image)
    assert len(executor.calls) == 1


def test_disconnect_and_client_deadline_map_to_unavailable(tmp_path: Path) -> None:
    image = tmp_path / "stage" / "digest" / "firmware.dfu"
    image.parent.mkdir(parents=True)
    image.write_bytes(_dfu())
    radio = RadioFirmwareIdentity("SERIAL_A", "/sys/bus/usb/devices/1-2", "v0.37")

    def run_listener(*, delay: float, ready: threading.Event) -> None:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(tmp_path / "firmware.sock"))
        listener.listen(1)
        ready.set()
        connection, _ = listener.accept()
        with connection:
            if delay:
                time.sleep(delay)
        listener.close()
        (tmp_path / "firmware.sock").unlink(missing_ok=True)

    disconnect_ready = threading.Event()
    disconnect = threading.Thread(
        target=run_listener,
        kwargs={"delay": 0, "ready": disconnect_ready},
        daemon=True,
    )
    disconnect.start()
    assert disconnect_ready.wait(timeout=1)
    with pytest.raises(FirmwareHelperUnavailableError, match="disconnected|read failed"):
        _client(tmp_path).load_volatile_dfu(radio, image)
    disconnect.join(timeout=1)
    assert not disconnect.is_alive()

    deadline_ready = threading.Event()
    deadline = threading.Thread(
        target=run_listener,
        kwargs={"delay": 0.2, "ready": deadline_ready},
        daemon=True,
    )
    deadline.start()
    assert deadline_ready.wait(timeout=1)
    with pytest.raises(FirmwareHelperUnavailableError, match="timed out"):
        _client(tmp_path, timeout=0.03).load_volatile_dfu(radio, image)
    deadline.join(timeout=1)
    assert not deadline.is_alive()


def test_arbitrary_command_fields_and_actions_are_not_protocol_surface(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    data = _dfu()
    executor = RecordingExecutor()
    server = _server(tmp_path, radio, executor)
    body = _request(
        radio,
        path="digest/firmware.dfu",
        digest=hashlib.sha256(data).hexdigest(),
        size=len(data),
        action="run_command",
        extra={"command": ["sh", "-c", "anything"]},
    )
    with _running(server, tmp_path / "firmware.sock"):
        response = _send_raw(tmp_path / "firmware.sock", body)
    assert response["error"]["code"] == "invalid_request"  # type: ignore[index]
    assert executor.calls == []


def test_client_rejects_out_of_root_and_wrong_persistent_target(
    tmp_path: Path, radio: RadioFirmwareIdentity
) -> None:
    (tmp_path / "stage").mkdir()
    outside = tmp_path / "outside.dfu"
    outside.write_bytes(_dfu())
    client = _client(tmp_path)
    with pytest.raises(FirmwareImageError, match="outside"):
        client.load_volatile_dfu(radio, outside)
    with pytest.raises(FirmwareImageError, match="exactly pluto.frm"):
        client.flash_persistent_qspi(radio, outside, target_name="boot.frm")


def test_response_request_id_mismatch_is_rejected() -> None:
    with pytest.raises(FirmwareHelperProtocolError, match="did not match"):
        UnixFirmwareHelperClient._handle_response(
            {"version": 1, "request_id": "b" * 32, "ok": True, "error": None},
            "a" * 32,
        )
