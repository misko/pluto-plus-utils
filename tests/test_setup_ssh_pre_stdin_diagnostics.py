from pathlib import Path

import pexpect
import pytest

from pluto_plus.setup_helper import (
    BoundSshTransport,
    SetupHelperError,
    SetupSshHostKeyChangedError,
)


@pytest.mark.parametrize(
    ("transcript", "exception", "message"),
    [
        (
            b"No ED25519 host key is known for 192.168.1.17\r\n"
            b"Host key verification failed.\r\nPRIVATE_SENTINEL",
            SetupHelperError,
            "host-key verification failed before accepting stdin",
        ),
        (
            b"REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n"
            b"Host key verification failed.\r\nPRIVATE_SENTINEL",
            SetupSshHostKeyChangedError,
            "host key changed",
        ),
        (
            b"unclassified EOF\r\nPRIVATE_SENTINEL",
            SetupHelperError,
            "closed before accepting stdin",
        ),
    ],
)
def test_pre_stdin_trust_failure_is_actionable_without_transcript_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    transcript: bytes,
    exception: type[Exception],
    message: str,
) -> None:
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fixture\n")
    known_hosts.chmod(0o600)
    arguments: list[str] = []

    class FailedChild:
        before = transcript
        exitstatus = 255
        signalstatus = None

        def expect(self, patterns: object, timeout: float | None = None) -> int:
            del patterns, timeout
            return 2

        def sendline(self, value: bytes) -> None:
            pytest.fail(
                f"credentials must not be sent before trust validation ({len(value)} bytes)"
            )

        def close(self, force: bool = False) -> None:
            del force

    def spawn(_binary: str, args: list[str], **_kwargs: object) -> FailedChild:
        arguments.extend(args)
        return FailedChild()

    monkeypatch.setattr(pexpect, "spawn", spawn)
    transport = BoundSshTransport(
        host="192.168.1.17",
        interface=None,
        password="PRIVATE_SENTINEL",
        known_hosts_file=known_hosts,
    )
    with pytest.raises(exception, match=message) as caught:
        transport.run("true", stdin=b"bounded fixture")
    assert "PRIVATE_SENTINEL" not in str(caught.value)
    assert "StrictHostKeyChecking=yes" in arguments
    assert f"UserKnownHostsFile={known_hosts}" in arguments
    assert known_hosts.read_text() == "fixture\n"


def test_stdin_result_excludes_authentication_and_client_diagnostics(tmp_path, monkeypatch):
    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fixture\n")
    known_hosts.chmod(0o600)

    class Child:
        before = b""
        exitstatus = 0
        signalstatus = None
        child_fd = 42
        calls = 0

        def expect(self, patterns, timeout=None):
            self.calls += 1
            if self.calls == 1:
                self.before = b"SSH client diagnostic\nroot@host's "
                return 0
            if self.calls == 2:
                self.before = b" \r\n"
                return 1
            self.before = b"tail\r\n"
            return 2

        def sendline(self, value):
            assert value == b"fixture"

        def close(self, force=False):
            pass

    monkeypatch.setattr(pexpect, "spawn", lambda *a, **kw: Child())
    monkeypatch.setattr(
        "pluto_plus.setup_helper._stream_pexpect_stdin", lambda *a, **kw: b"serial=fixture\r\n"
    )
    transport = BoundSshTransport(
        host="192.168.1.14", interface=None, password="fixture", known_hosts_file=known_hosts
    )
    assert transport.run("true", stdin=b"fixture") == "serial=fixture\ntail\n"


def test_large_flash_read_keeps_all_bytes_with_bounded_prompt_search(tmp_path):
    import sys

    known_hosts = tmp_path / "known_hosts"
    known_hosts.write_text("fixture\n")
    known_hosts.chmod(0o600)
    executable = tmp_path / "ssh-fixture"
    executable.write_text(
        f"#!{sys.executable}\n"
        "import os, tty\n"
        "tty.setraw(0)\n"
        "os.write(1, b'client warning\\nPPU\\tstdin_ready\\t1\\n')\n"
        "assert os.read(0, 1) == b'x'\n"
        "data = b'abcdef0123456789' * 131072\n"
        "while data:\n"
        "    data = data[os.write(1, data):]\n"
    )
    executable.chmod(0o755)
    transport = BoundSshTransport(
        host="192.168.1.14", interface=None, password="fixture",
        known_hosts_file=known_hosts, ssh_binary=str(executable),
    )
    assert transport.run("true", stdin=b"x", timeout_s=15) == "abcdef0123456789" * 131072
