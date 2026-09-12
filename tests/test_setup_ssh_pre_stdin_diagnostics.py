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
        (b"unclassified EOF\r\nPRIVATE_SENTINEL", SetupHelperError, "closed before accepting stdin"),
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
            pytest.fail(f"credentials must not be sent before trust validation ({len(value)} bytes)")

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
