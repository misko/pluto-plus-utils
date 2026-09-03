from __future__ import annotations

import hashlib
import subprocess
from collections.abc import Sequence
from dataclasses import FrozenInstanceError, replace
from pathlib import Path

import pytest

import pluto_plus.userspace_iiod as lifecycle_module
import pluto_plus.userspace_iiod_probe as probe_module
from pluto_plus.persistent_hop import PERSISTENT_HOP_CAPABILITIES
from pluto_plus.userspace_iiod import (
    STOCK_IIOD_PORT,
    USERSPACE_IIOD_PORT,
    PinnedPasswordSshIiodTransport,
    RemoteIiodBinaryIdentity,
    RemoteIiodPaths,
    SshCommandResult,
    UserspaceIiodDeployment,
    UserspaceIiodLifecycle,
    UserspaceIiodLifecycleError,
    UserspaceIiodProcessIdentity,
    persistent_hop_endpoint_probe,
)

HOST = "192.168.1.20"
SERIAL = "104000bac4950008230026001b440a00ff"
SESSION = "0123456789abcdef0123456789abcdef"
PAYLOAD = b"\x7fELF\x02\x01synthetic-iiod"


def _credentials(tmp_path: Path, *, mode: int = 0o600) -> tuple[Path, Path]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    known_hosts = tmp_path / "known_hosts"
    password = tmp_path / "password"
    known_hosts.write_text(f"{HOST} ssh-ed25519 AAAATEST\n")
    password.write_text("not-a-real-password\n")
    known_hosts.chmod(mode)
    password.chmod(mode)
    return known_hosts, password


class _FakeTransport:
    def __init__(self) -> None:
        self.events: list[str] = []
        self.process: UserspaceIiodProcessIdentity | None = None
        self.binary: RemoteIiodBinaryIdentity | None = None
        self.alive = False
        self.fail_at: str | None = None
        self.terminate_result = True
        self.cleanup_result: tuple[str, ...] | None = None
        self.inspect_replacement: UserspaceIiodProcessIdentity | None = None
        self.inspect_calls = 0

    def attest_radio_serial(self) -> str:
        self.events.append("attest")
        if self.fail_at == "attest":
            raise RuntimeError("synthetic attest failure")
        return "WRONG" if self.fail_at == "wrong_serial" else SERIAL

    def stage(
        self,
        paths: RemoteIiodPaths,
        payload: bytes,
        *,
        expected_sha256: str,
    ) -> RemoteIiodBinaryIdentity:
        self.events.append("stage")
        assert payload == PAYLOAD
        assert hashlib.sha256(payload).hexdigest() == expected_sha256
        self.binary = RemoteIiodBinaryIdentity(paths.binary, len(payload), expected_sha256)
        if self.fail_at == "stage_after_write":
            raise RuntimeError("synthetic stage failure")
        if self.fail_at == "stage_identity":
            return replace(self.binary, bytes=self.binary.bytes + 1)
        return self.binary

    def start(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> UserspaceIiodProcessIdentity:
        self.events.append("start")
        self.process = UserspaceIiodProcessIdentity(
            pid=731,
            start_ticks=991,
            exe_path=paths.binary,
            binary_bytes=binary.bytes,
            binary_sha256=binary.sha256,
            radio_serial=SERIAL,
        )
        self.alive = True
        if self.fail_at == "start_after_spawn":
            raise RuntimeError("synthetic start failure")
        if self.fail_at == "start_identity":
            return replace(self.process, radio_serial="OTHER")
        return self.process

    def inspect(self, paths: RemoteIiodPaths) -> UserspaceIiodProcessIdentity | None:
        del paths
        self.events.append("inspect")
        self.inspect_calls += 1
        if self.fail_at == "inspect_error":
            raise RuntimeError("synthetic inspect failure")
        if not self.alive:
            return None
        if self.inspect_replacement is not None:
            return self.inspect_replacement
        return self.process

    def terminate(
        self,
        paths: RemoteIiodPaths,
        process: UserspaceIiodProcessIdentity,
        *,
        timeout_s: float,
    ) -> bool:
        del paths
        self.events.append("terminate")
        assert process == self.process
        assert timeout_s == 15
        if self.fail_at == "terminate_error":
            raise RuntimeError("synthetic terminate failure")
        if self.terminate_result:
            self.alive = False
        return self.terminate_result

    def cleanup(
        self,
        paths: RemoteIiodPaths,
        binary: RemoteIiodBinaryIdentity,
    ) -> tuple[str, ...]:
        self.events.append("cleanup")
        assert binary.path == paths.binary
        if self.fail_at == "cleanup_error":
            raise RuntimeError("synthetic cleanup failure")
        return self.cleanup_result or (paths.binary, paths.pid, paths.log)


def _lifecycle(
    tmp_path: Path,
    transport: _FakeTransport,
    *,
    alternate_ready: bool = True,
    stock_ready: bool = True,
    occupied_before_start: bool = False,
) -> UserspaceIiodLifecycle:
    known_hosts, password = _credentials(tmp_path)
    port_calls = 0

    def port_probe(host: str, port: int, timeout_s: float) -> bool:
        nonlocal port_calls
        assert (host, port) == (HOST, USERSPACE_IIOD_PORT)
        assert 0 < timeout_s <= 10
        port_calls += 1
        if occupied_before_start and port_calls == 1:
            return True
        return transport.alive

    def endpoint_probe(host: str, port: int, serial: str, timeout_s: float) -> bool:
        assert host == HOST and serial == SERIAL and timeout_s == 10
        if port == STOCK_IIOD_PORT:
            return stock_ready
        assert port == USERSPACE_IIOD_PORT
        return alternate_ready and transport.alive

    return UserspaceIiodLifecycle(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        port_probe=port_probe,
        serial_probe=endpoint_probe,
        transport=transport,
        session_id_factory=lambda: SESSION,
    )


def test_lifecycle_stages_attests_stops_and_returns_immutable_receipts(tmp_path: Path) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport)

    started = lifecycle.start(PAYLOAD)

    assert started.session_id == SESSION
    assert started.host == HOST
    assert started.expected_serial == SERIAL
    assert started.paths == RemoteIiodPaths(
        f"/tmp/ppu-iiod-{SESSION}.bin",
        f"/tmp/ppu-iiod-{SESSION}.pid",
        f"/tmp/ppu-iiod-{SESSION}.log",
    )
    assert started.binary.bytes == len(PAYLOAD)
    assert started.binary.sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    assert started.process.pid == 731
    assert started.process.start_ticks == 991
    assert started.process.port == USERSPACE_IIOD_PORT
    assert lifecycle.active is started
    with pytest.raises(FrozenInstanceError):
        started.process.pid = 5  # type: ignore[misc]

    stopped = lifecycle.stop()

    assert stopped.outcome == "stopped"
    assert stopped.observed_process == started.process
    assert stopped.identity_verified
    assert stopped.term_sent and stopped.exit_confirmed
    assert stopped.removed_paths == (
        started.paths.binary,
        started.paths.pid,
        started.paths.log,
    )
    assert stopped.alternate_port_closed and stopped.stock_endpoint_healthy
    assert lifecycle.active is None
    assert transport.events == [
        "attest",
        "stage",
        "start",
        "inspect",
        "inspect",
        "terminate",
        "cleanup",
    ]


@pytest.mark.parametrize(
    ("failure", "expected_tail"),
    [
        ("stage_after_write", ["inspect", "cleanup"]),
        ("stage_identity", ["inspect", "cleanup"]),
        ("start_after_spawn", ["inspect", "terminate", "cleanup"]),
        ("start_identity", ["inspect"]),
    ],
)
def test_failed_start_runs_bounded_owned_cleanup(
    tmp_path: Path,
    failure: str,
    expected_tail: list[str],
) -> None:
    transport = _FakeTransport()
    transport.fail_at = failure
    lifecycle = _lifecycle(tmp_path, transport)

    with pytest.raises((RuntimeError, UserspaceIiodLifecycleError)):
        lifecycle.start(PAYLOAD)

    assert lifecycle.active is None
    assert transport.events[-len(expected_tail) :] == expected_tail
    if failure != "start_identity":
        assert not transport.alive


def test_failed_readiness_terminates_before_removing_exact_artifacts(tmp_path: Path) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport, alternate_ready=False)

    with pytest.raises(UserspaceIiodLifecycleError, match="readiness"):
        lifecycle.start(PAYLOAD)

    assert transport.events[-3:] == ["inspect", "terminate", "cleanup"]
    assert not transport.alive


def test_start_waits_for_listener_before_capability_probe(tmp_path: Path) -> None:
    transport = _FakeTransport()
    known_hosts, password = _credentials(tmp_path)
    port_calls = 0
    endpoint_calls: list[int] = []

    def delayed_port(_host: str, _port: int, _timeout_s: float) -> bool:
        nonlocal port_calls
        port_calls += 1
        # First call is the pre-stage vacancy check. The process then exists,
        # but its listener accepts only on the third observation.
        return transport.alive and port_calls >= 3

    def endpoint(_host: str, port: int, _serial: str, _timeout_s: float) -> bool:
        endpoint_calls.append(port)
        return port == STOCK_IIOD_PORT or port_calls >= 3

    lifecycle = UserspaceIiodLifecycle(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        port_probe=delayed_port,
        serial_probe=endpoint,
        transport=transport,
        session_id_factory=lambda: SESSION,
    )

    started = lifecycle.start(PAYLOAD)

    assert started.alternate_endpoint_ready
    assert port_calls == 3
    assert endpoint_calls == [STOCK_IIOD_PORT, USERSPACE_IIOD_PORT]
    lifecycle.stop()


def test_failed_start_exposes_immutable_cleanup_receipt_on_lifecycle_error(
    tmp_path: Path,
) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport, alternate_ready=False)

    with pytest.raises(UserspaceIiodLifecycleError) as raised:
        lifecycle.start(PAYLOAD)

    receipt = raised.value.stop_receipt
    assert receipt is not None
    assert receipt.outcome == "stopped"
    assert receipt.expected_process == receipt.observed_process
    assert receipt.term_sent and receipt.exit_confirmed
    assert receipt.alternate_port_closed and receipt.stock_endpoint_healthy


@pytest.mark.parametrize("failure", ["wrong_serial", "attest"])
def test_pre_stage_ssh_identity_failure_never_mutates_remote(tmp_path: Path, failure: str) -> None:
    transport = _FakeTransport()
    transport.fail_at = failure

    with pytest.raises((RuntimeError, UserspaceIiodLifecycleError)):
        _lifecycle(tmp_path, transport).start(PAYLOAD)

    assert "stage" not in transport.events


def test_unhealthy_stock_or_occupied_alternate_never_stages(tmp_path: Path) -> None:
    first = _FakeTransport()
    with pytest.raises(UserspaceIiodLifecycleError, match="stock"):
        _lifecycle(tmp_path / "stock", first, stock_ready=False).start(PAYLOAD)
    assert first.events == []

    second = _FakeTransport()
    with pytest.raises(UserspaceIiodLifecycleError, match="already open"):
        _lifecycle(tmp_path / "occupied", second, occupied_before_start=True).start(PAYLOAD)
    assert second.events == ["attest"]


def test_stop_identity_change_is_fail_closed_and_retains_active_receipt(tmp_path: Path) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport)
    started = lifecycle.start(PAYLOAD)
    transport.inspect_replacement = replace(started.process, start_ticks=1_000)

    with pytest.raises(UserspaceIiodLifecycleError) as raised:
        lifecycle.stop()

    assert raised.value.start_receipt is started
    assert raised.value.stop_receipt is not None
    assert raised.value.stop_receipt.outcome == "cleanup_failed"
    assert not raised.value.stop_receipt.identity_verified
    assert transport.alive
    assert "terminate" not in transport.events
    assert "cleanup" not in transport.events
    assert lifecycle.active is started


@pytest.mark.parametrize("failure", ["terminate_error", "cleanup_error"])
def test_stop_propagates_cleanup_evidence_and_keeps_active_for_recovery(
    tmp_path: Path, failure: str
) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport)
    started = lifecycle.start(PAYLOAD)
    transport.fail_at = failure

    with pytest.raises(UserspaceIiodLifecycleError) as raised:
        lifecycle.stop()

    assert raised.value.start_receipt is started
    assert raised.value.stop_receipt is not None
    assert raised.value.stop_receipt.errors
    assert lifecycle.active is started
    if failure == "terminate_error":
        assert "cleanup" not in transport.events


def test_stop_requires_term_exit_and_exact_cleanup_paths(tmp_path: Path) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport)
    started = lifecycle.start(PAYLOAD)
    transport.terminate_result = False

    with pytest.raises(UserspaceIiodLifecycleError) as raised:
        lifecycle.stop()

    assert raised.value.stop_receipt is not None
    # The semantic transport did not attest TERM delivery, so the receipt must
    # conservatively leave both delivery and exit false.
    assert not raised.value.stop_receipt.term_sent
    assert not raised.value.stop_receipt.exit_confirmed
    assert "cleanup" not in transport.events
    transport.terminate_result = True
    transport.fail_at = None
    transport.cleanup_result = (started.paths.binary,)
    with pytest.raises(UserspaceIiodLifecycleError, match="not fully attested"):
        lifecycle.stop()


def test_stop_reports_stock_health_failure_after_safe_removal(tmp_path: Path) -> None:
    transport = _FakeTransport()
    known_hosts, password = _credentials(tmp_path)
    stock = {"healthy": True}

    lifecycle = UserspaceIiodLifecycle(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        port_probe=lambda _host, _port, _timeout: transport.alive,
        serial_probe=lambda _host, port, _serial, _timeout: (
            stock["healthy"] if port == STOCK_IIOD_PORT else transport.alive
        ),
        transport=transport,
        session_id_factory=lambda: SESSION,
    )
    lifecycle.start(PAYLOAD)
    stock["healthy"] = False

    with pytest.raises(UserspaceIiodLifecycleError) as raised:
        lifecycle.stop()

    assert raised.value.stop_receipt is not None
    assert raised.value.stop_receipt.removed_paths
    assert raised.value.stop_receipt.alternate_port_closed
    assert not raised.value.stop_receipt.stock_endpoint_healthy


def test_context_preserves_primary_error_and_attests_cleanup(tmp_path: Path) -> None:
    transport = _FakeTransport()
    lifecycle = _lifecycle(tmp_path, transport)

    with pytest.raises(LookupError, match="body failure"), lifecycle.session(PAYLOAD):
        raise LookupError("body failure")

    assert lifecycle.active is None
    assert transport.events[-2:] == ["terminate", "cleanup"]


def test_credentials_accept_0400_and_0600_but_reject_public_or_symlink(tmp_path: Path) -> None:
    for index, mode in enumerate((0o400, 0o600)):
        root = tmp_path / str(index)
        known_hosts, password = _credentials(root, mode=mode)
        PinnedPasswordSshIiodTransport(
            host=HOST,
            expected_serial=SERIAL,
            known_hosts_file=known_hosts,
            password_file=password,
            runner=_NeverRunner(),
        )

    known_hosts, password = _credentials(tmp_path / "public", mode=0o644)
    with pytest.raises(ValueError, match="0400/0600"):
        PinnedPasswordSshIiodTransport(
            host=HOST,
            expected_serial=SERIAL,
            known_hosts_file=known_hosts,
            password_file=password,
            runner=_NeverRunner(),
        )

    target_known, target_password = _credentials(tmp_path / "target")
    link = tmp_path / "known-link"
    link.symlink_to(target_known)
    with pytest.raises(ValueError, match="opened safely"):
        PinnedPasswordSshIiodTransport(
            host=HOST,
            expected_serial=SERIAL,
            known_hosts_file=link,
            password_file=target_password,
            runner=_NeverRunner(),
        )


class _NeverRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None,
        timeout_s: float,
    ) -> SshCommandResult:
        del argv, stdin, timeout_s
        raise AssertionError("runner must not be called")


class _RecordingRunner:
    def __init__(self, paths: RemoteIiodPaths) -> None:
        self.paths = paths
        self.calls: list[tuple[tuple[str, ...], bytes | None, float]] = []
        digest = hashlib.sha256(PAYLOAD).hexdigest()
        self.process_report = (
            "PPU\tpid\t731\n"
            "PPU\tstart_ticks\t991\n"
            f"PPU\texe_path\t{paths.binary}\n"
            f"PPU\tbinary_bytes\t{len(PAYLOAD)}\n"
            f"PPU\tbinary_sha256\t{digest}\n"
            f"PPU\tradio_serial\t{SERIAL}\n"
            "PPU\tport\t30432\n"
        ).encode()

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None,
        timeout_s: float,
    ) -> SshCommandResult:
        call = (tuple(argv), stdin, timeout_s)
        self.calls.append(call)
        if stdin == lifecycle_module._ATTEST_SERIAL_SCRIPT:
            output = f"PPU\tserial\t{SERIAL}\n".encode()
        elif stdin is PAYLOAD:
            digest = hashlib.sha256(PAYLOAD).hexdigest()
            output = (
                f"PPU\tpath\t{self.paths.binary}\n"
                f"PPU\tbytes\t{len(PAYLOAD)}\n"
                f"PPU\tsha256\t{digest}\n"
            ).encode()
        elif stdin == lifecycle_module._START_SCRIPT:
            output = self.process_report
        elif stdin == lifecycle_module._INSPECT_SCRIPT:
            output = b"PPU\tstate\trunning\n" + self.process_report
        elif stdin == lifecycle_module._TERMINATE_SCRIPT:
            output = b"PPU\texit_confirmed\t1\n"
        elif stdin == lifecycle_module._CLEANUP_SCRIPT:
            output = (
                f"PPU\tremoved_binary\t{self.paths.binary}\n"
                f"PPU\tremoved_pid\t{self.paths.pid}\n"
                f"PPU\tremoved_log\t{self.paths.log}\n"
            ).encode()
        else:  # pragma: no cover - test helper exhaustiveness
            raise AssertionError(f"unexpected operation: {call!r}")
        return SshCommandResult(0, output, b"")


def test_pinned_ssh_transport_has_only_fixed_semantic_commands(tmp_path: Path) -> None:
    known_hosts, password = _credentials(tmp_path)
    paths = RemoteIiodPaths(
        f"/tmp/ppu-iiod-{SESSION}.bin",
        f"/tmp/ppu-iiod-{SESSION}.pid",
        f"/tmp/ppu-iiod-{SESSION}.log",
    )
    runner = _RecordingRunner(paths)
    transport = PinnedPasswordSshIiodTransport(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        runner=runner,
    )
    digest = hashlib.sha256(PAYLOAD).hexdigest()

    assert transport.attest_radio_serial() == SERIAL
    binary = transport.stage(paths, PAYLOAD, expected_sha256=digest)
    process = transport.start(paths, binary)
    assert transport.inspect(paths) == process
    assert transport.terminate(paths, process, timeout_s=2)
    assert transport.cleanup(paths, binary) == (paths.binary, paths.pid, paths.log)

    assert runner.calls[1][1] is PAYLOAD
    assert b'nohup "$binary" -u local: -p 30432' in lifecycle_module._START_SCRIPT
    assert b'nohup "$binary" -i' not in lifecycle_module._START_SCRIPT
    assert b"umask 077" in lifecycle_module._START_SCRIPT
    for argv, _stdin, timeout in runner.calls:
        assert argv[0:2] == ("sshpass", "-f")
        assert str(password) in argv
        assert "StrictHostKeyChecking=yes" in argv
        assert f"UserKnownHostsFile={known_hosts}" in argv
        assert argv[-2] == f"root@{HOST}"
        assert 0 < timeout <= 120
    all_remote_source = b"\n".join(
        (
            lifecycle_module._ATTEST_SERIAL_SCRIPT,
            lifecycle_module._START_SCRIPT,
            lifecycle_module._INSPECT_SCRIPT,
            lifecycle_module._TERMINATE_SCRIPT,
            lifecycle_module._CLEANUP_SCRIPT,
        )
    ).lower()
    for forbidden in (b"qspi", b"flash_erase", b"mtd", b"fw_setenv", b"mount", b"reboot"):
        assert forbidden not in all_remote_source


def test_credential_change_is_detected_before_next_remote_operation(tmp_path: Path) -> None:
    known_hosts, password = _credentials(tmp_path)
    transport = PinnedPasswordSshIiodTransport(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        runner=_NeverRunner(),
    )
    password.write_text("changed\n")
    password.chmod(0o600)

    with pytest.raises(UserspaceIiodLifecycleError, match="changed"):
        transport.attest_radio_serial()


def test_transport_rejects_nonexact_remote_reports(tmp_path: Path) -> None:
    known_hosts, password = _credentials(tmp_path)

    class ExtraFieldRunner:
        def run(
            self,
            argv: Sequence[str],
            *,
            stdin: bytes | None,
            timeout_s: float,
        ) -> SshCommandResult:
            del argv, stdin, timeout_s
            return SshCommandResult(
                0,
                f"PPU\tserial\t{SERIAL}\nPPU\textra\tunexpected\n".encode(),
                b"",
            )

    transport = PinnedPasswordSshIiodTransport(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        runner=ExtraFieldRunner(),
    )
    with pytest.raises(UserspaceIiodLifecycleError, match="fields are not exact"):
        transport.attest_radio_serial()


def test_invalid_session_id_and_double_entry_never_create_a_second_process(
    tmp_path: Path,
) -> None:
    first = _FakeTransport()
    known_hosts, password = _credentials(tmp_path / "invalid")
    invalid = UserspaceIiodLifecycle(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known_hosts,
        password_file=password,
        port_probe=lambda *_args: False,
        serial_probe=lambda *_args: True,
        transport=first,
        session_id_factory=lambda: "../not-random",
    )
    with pytest.raises(UserspaceIiodLifecycleError, match="session ID"):
        invalid.start(PAYLOAD)
    assert "stage" not in first.events

    second = _FakeTransport()
    active = _lifecycle(tmp_path / "double", second)
    active.start(PAYLOAD)
    with pytest.raises(UserspaceIiodLifecycleError, match="already active"):
        active.start(PAYLOAD)
    assert second.events.count("start") == 1
    active.stop()
    with pytest.raises(UserspaceIiodLifecycleError, match="not active"):
        active.stop()


@pytest.mark.parametrize(
    "host",
    ["pluto.local", "192.168.2.20", "192.168.1.0", "192.168.1.255", "192.168.1.020"],
)
def test_host_gate_allows_only_canonical_usable_192_168_1_literals(
    tmp_path: Path, host: str
) -> None:
    known_hosts, password = _credentials(tmp_path)
    with pytest.raises(ValueError, match=r"192[.]168[.]1"):
        PinnedPasswordSshIiodTransport(
            host=host,
            expected_serial=SERIAL,
            known_hosts_file=known_hosts,
            password_file=password,
            runner=_NeverRunner(),
        )


def _probe_output(*, capabilities: tuple[str, ...] = ()) -> bytes:
    values = [f"PPU\tserial\t{SERIAL}", "PPU\tmetadata_abi\t3"]
    values.extend(
        f"PPU\tcapability_{index}\t{capability}" for index, capability in enumerate(capabilities)
    )
    return ("\n".join(values) + "\n").encode()


def test_default_endpoint_probe_branches_stock_health_and_alternate_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outputs = iter(
        (
            _probe_output(),
            _probe_output(capabilities=PERSISTENT_HOP_CAPABILITIES),
            _probe_output(capabilities=PERSISTENT_HOP_CAPABILITIES[:-1]),
        )
    )
    calls: list[tuple[str, ...]] = []

    def run(argv: Sequence[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        calls.append(tuple(argv))
        assert kwargs["timeout"] == 4
        return subprocess.CompletedProcess(argv, 0, next(outputs), b"")

    monkeypatch.setattr(lifecycle_module.subprocess, "run", run)

    assert persistent_hop_endpoint_probe(HOST, STOCK_IIOD_PORT, SERIAL, 4)
    assert persistent_hop_endpoint_probe(HOST, USERSPACE_IIOD_PORT, SERIAL, 4)
    assert not persistent_hop_endpoint_probe(HOST, USERSPACE_IIOD_PORT, SERIAL, 4)
    assert calls[0][-3:] == (HOST, "30431", SERIAL)
    assert calls[1][-3:] == (HOST, "30432", SERIAL)


def test_default_endpoint_probe_is_fail_closed_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timeout(*args: object, **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        del args, kwargs
        raise subprocess.TimeoutExpired("probe", 1)

    monkeypatch.setattr(lifecycle_module.subprocess, "run", timeout)
    assert not persistent_hop_endpoint_probe(HOST, USERSPACE_IIOD_PORT, SERIAL, 1)


class _ProbeBackend:
    attributes: dict[str, str] = {}
    closed = False

    def __init__(self, uri: str, *, expected_serial: str) -> None:
        assert uri in {f"ip:{HOST}:30431", f"ip:{HOST}:30432"}
        assert expected_serial == SERIAL

    def open(self) -> None:
        pass

    def context_attributes(self) -> dict[str, str]:
        return dict(self.attributes)

    def close(self) -> None:
        type(self).closed = True


def test_child_probe_uses_real_context_contract_without_requiring_stock_hop_attrs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(probe_module, "IioPersistentHopBackend", _ProbeBackend)
    _ProbeBackend.attributes = {"hw_serial": SERIAL, "iio,buffer-metadata": "3"}
    _ProbeBackend.closed = False

    stock = probe_module.probe_report(HOST, STOCK_IIOD_PORT, SERIAL)

    assert stock == _probe_output()
    assert _ProbeBackend.closed
    with pytest.raises(RuntimeError, match="capabilities"):
        probe_module.probe_report(HOST, USERSPACE_IIOD_PORT, SERIAL)

    _ProbeBackend.attributes.update({capability: "1" for capability in PERSISTENT_HOP_CAPABILITIES})
    assert probe_module.probe_report(HOST, USERSPACE_IIOD_PORT, SERIAL) == _probe_output(
        capabilities=PERSISTENT_HOP_CAPABILITIES
    )


@pytest.mark.parametrize(
    "attributes",
    [
        {"hw_serial": "OTHER", "iio,buffer-metadata": "3"},
        {"hw_serial": SERIAL, "iio,buffer-metadata": "2"},
    ],
)
def test_child_probe_fails_closed_on_serial_or_abi_and_always_closes(
    monkeypatch: pytest.MonkeyPatch,
    attributes: dict[str, str],
) -> None:
    monkeypatch.setattr(probe_module, "IioPersistentHopBackend", _ProbeBackend)
    _ProbeBackend.attributes = attributes
    _ProbeBackend.closed = False

    with pytest.raises(RuntimeError):
        probe_module.probe_report(HOST, STOCK_IIOD_PORT, SERIAL)

    assert _ProbeBackend.closed


def test_deployment_reads_one_stable_binary_and_exposes_leo_contract(tmp_path: Path) -> None:
    binary_path = tmp_path / "iiod"
    binary_path.write_bytes(PAYLOAD)
    transport = _FakeTransport()
    known_hosts, password = _credentials(tmp_path / "credentials")

    deployment = UserspaceIiodDeployment(
        host=HOST,
        expected_serial=SERIAL,
        binary_path=binary_path,
        known_hosts_path=known_hosts,
        password_path=password,
        port_probe=lambda _host, _port, _timeout: transport.alive,
        serial_probe=lambda _host, port, _serial, _timeout: (
            port == STOCK_IIOD_PORT or transport.alive
        ),
        transport=transport,
        session_id_factory=lambda: SESSION,
    )

    started = deployment.enter_and_attest()
    assert deployment.active is started
    stopped = deployment.exit_and_verify()
    assert stopped.outcome == "stopped"
    assert deployment.active is None


def test_deployment_rejects_symlink_binary_and_runner_transport_ambiguity(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "iiod"
    binary.write_bytes(PAYLOAD)
    binary_link = tmp_path / "iiod-link"
    binary_link.symlink_to(binary)
    known_hosts, password = _credentials(tmp_path / "credentials")
    transport = _FakeTransport()

    deployment = UserspaceIiodDeployment(
        host=HOST,
        expected_serial=SERIAL,
        binary_path=binary_link,
        known_hosts_path=known_hosts,
        password_path=password,
        port_probe=lambda *_args: False,
        serial_probe=lambda *_args: True,
        transport=transport,
    )
    with pytest.raises(UserspaceIiodLifecycleError, match="opened safely"):
        deployment.enter_and_attest()

    with pytest.raises(ValueError, match="either"):
        UserspaceIiodDeployment(
            host=HOST,
            expected_serial=SERIAL,
            binary_path=binary,
            known_hosts_path=known_hosts,
            password_path=password,
            port_probe=lambda *_args: False,
            serial_probe=lambda *_args: True,
            transport=transport,
            runner=_NeverRunner(),
        )


def test_receipt_models_reject_incomplete_success_and_noncanonical_paths(tmp_path: Path) -> None:
    transport = _FakeTransport()
    started = _lifecycle(tmp_path, transport).start(PAYLOAD)
    with pytest.raises(ValueError, match="healthy"):
        replace(started, alternate_endpoint_ready=False)
    with pytest.raises(ValueError, match="canonical"):
        RemoteIiodPaths("/tmp/iiod", "/tmp/iiod.pid", "/tmp/iiod.log")
