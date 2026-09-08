"""Portable release/lifecycle checks. No radio, SSH, IIO, or RF is opened."""

import hashlib
import json
import os
import shutil
import subprocess
from dataclasses import replace

import pytest
from test_userspace_iiod import (
    HOST,
    PAYLOAD,
    SERIAL,
    SESSION,
    _credentials,
    _FakeTransport,
    _lifecycle,
)

from pluto_plus.userspace_iiod import (
    PinnedPasswordSshIiodTransport,
    RemoteIiodBinaryIdentity,
    RemoteIiodPaths,
    SshCommandResult,
    UserspaceIiodDeployment,
    UserspaceIiodLifecycleError,
)
from pluto_plus.userspace_iiod_bundle import (
    BundledIiodTransport,
    load_iiod_companion_bundle,
)

ROOT = "/tmp/ppu-iiod-bundle-abcdefabcdefabcdefabcdefabcdefab"


@pytest.fixture
def release(tmp_path):
    root = tmp_path / "release"
    root.mkdir(mode=0o700)
    files = []
    for name, payload, executable in (
        ("worker", b"worker fixture", True),
        ("templates-2500000.bin", b"templates2 fixture", False),
        ("templates-5000000.bin", b"templates5 fixture", False),
        ("libleo-scanner-glrt.so", b"sdk fixture", False),
        ("libfftw3.so.3", b"fftw fixture", False),
    ):
        (root / name).write_bytes(payload)
        (root / name).chmod(0o600)
        files.append(
            dict(
                name=name,
                bytes=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
                executable=executable,
            )
        )
    (root / "iiod").write_bytes(PAYLOAD)
    (root / "iiod").chmod(0o700)
    manifest = dict(
        schema_version=1,
        remote_directory=ROOT,
        daemon_sha256=hashlib.sha256(PAYLOAD).hexdigest(),
        daemon_bytes=len(PAYLOAD),
        files=files,
    )
    path = root / "bundle.json"
    path.write_text(json.dumps(manifest))
    path.chmod(0o600)
    return path


def rewrite(path, mutate):
    data = json.loads(path.read_bytes())
    mutate(data)
    path.write_text(json.dumps(data))


def test_snapshot_is_frozen_and_contains_exact_bytes(release):
    bundle = load_iiod_companion_bundle(release)
    assert bundle.remote_directory == ROOT
    assert len(bundle.files) == 5
    assert bundle.manifest_sha256 == hashlib.sha256(release.read_bytes()).hexdigest()
    assert bundle.daemon_sha256 == hashlib.sha256(PAYLOAD).hexdigest()
    before = bundle.files[0].payload
    (release.parent / "worker").write_bytes(b"changed")
    assert bundle.files[0].payload == before
    with pytest.raises(ValueError):
        replace(bundle, remote_directory="/mnt/qnap01")
    with pytest.raises(ValueError):
        replace(bundle.files[0], name="../bad")


@pytest.mark.parametrize(
    "key,value",
    [
        ("schema_version", 2),
        ("schema_version", True),
        ("schema_version", 1.0),
        ("remote_directory", "/tmp"),
        ("remote_directory", "/mnt/qnap01/x"),
        ("remote_directory", ROOT + "/../outside"),
        ("remote_directory", ROOT + "\n"),
        ("daemon_sha256", "bad"),
        ("daemon_sha256", "A" * 64),
        ("daemon_bytes", 0),
        ("daemon_bytes", True),
        ("daemon_bytes", 65 * 1024**2),
        ("files", []),
        ("files", {}),
    ],
)
def test_bad_top_level_manifest_rejected(release, key, value):
    rewrite(release, lambda data: data.update({key: value}))
    with pytest.raises(ValueError):
        load_iiod_companion_bundle(release)


@pytest.mark.parametrize(
    "key,value",
    [
        ("name", "../worker"),
        ("name", "/tmp/worker"),
        ("name", "a;touch-b"),
        ("name", "worker\n"),
        ("name", "owner"),
        ("name", "iiod"),
        ("name", "bundle.json"),
        ("name", "templates-2500000.bin"),
        ("sha256", "0" * 64),
        ("bytes", 1),
        ("bytes", True),
        ("bytes", 0),
        ("executable", "false"),
        ("executable", 1),
    ],
)
def test_bad_file_manifest_rejected(release, key, value):
    rewrite(release, lambda data: data["files"][0].update({key: value}))
    with pytest.raises(ValueError):
        load_iiod_companion_bundle(release)


@pytest.mark.parametrize("mutation", ["duplicate-key", "extra-key", "duplicate-file"])
def test_ambiguous_manifest_rejected(release, mutation):
    if mutation == "duplicate-key":
        release.write_text(
            release.read_text().replace(
                '"schema_version": 1', '"schema_version": 1, "schema_version": 1'
            )
        )
    elif mutation == "extra-key":
        rewrite(release, lambda data: data.update(command="anything"))
    else:
        rewrite(release, lambda data: data["files"].append(data["files"][0]))
    with pytest.raises(ValueError):
        load_iiod_companion_bundle(release)


@pytest.mark.parametrize(
    "mutation",
    [
        "symlink",
        "fifo",
        "hardlink",
        "writable",
        "missing",
        "directory-writable",
        "directory-symlink",
    ],
)
def test_unsafe_local_files_rejected_without_blocking(release, mutation, tmp_path):
    worker = release.parent / "worker"
    if mutation == "symlink":
        worker.unlink()
        worker.symlink_to(release.parent / "templates-2500000.bin")
    elif mutation == "fifo":
        worker.unlink()
        os.mkfifo(worker)
    elif mutation == "hardlink":
        os.link(worker, tmp_path / "other")
    elif mutation == "writable":
        worker.chmod(0o660)
    elif mutation == "missing":
        worker.unlink()
    elif mutation == "directory-writable":
        release.parent.chmod(0o770)
    else:
        (tmp_path / "link").symlink_to(release.parent, target_is_directory=True)
        release = tmp_path / "link" / release.name
    with pytest.raises((ValueError, OSError)):
        load_iiod_companion_bundle(release)


class CompanionTransport(_FakeTransport):
    def __init__(self):
        super().__init__()
        self.companions = False
        self.bundle_failure = None

    def stage_companions(self, bundle, owner):
        assert owner == SESSION and bundle.daemon_sha256 == hashlib.sha256(PAYLOAD).hexdigest()
        self.events.append("bundle-stage")
        self.companions = True
        if self.bundle_failure == "stage":
            raise RuntimeError("bundle stage interrupted")

    def verify_companions(self, bundle, owner):
        self.events.append("bundle-verify")
        assert self.companions and owner == SESSION
        if self.bundle_failure == "verify":
            raise RuntimeError("bundle changed")

    def cleanup_companions(self, bundle, owner):
        self.events.append("bundle-cleanup")
        assert not self.alive and owner == SESSION
        if self.bundle_failure == "cleanup":
            raise RuntimeError("bundle changed during cleanup")
        self.companions = False


def test_existing_lifecycle_cleans_companions_only_after_owned_daemon_exit(release, tmp_path):
    transport = CompanionTransport()
    lifecycle = _lifecycle(tmp_path / "credentials", BundledIiodTransport(transport, release))
    # Probes in this existing test helper inspect the injected transport's alive state.
    lifecycle._port_probe = lambda *_: transport.alive
    lifecycle._serial_probe = lambda *args: args[1] == 30431 or transport.alive
    first = lifecycle.start(PAYLOAD)
    assert transport.events.index("bundle-verify") < transport.events.index("start")
    stopped = lifecycle.stop()
    assert not transport.companions
    assert transport.events.index("terminate") < transport.events.index("bundle-cleanup")
    assert len(stopped.removed_paths) == 3  # Published V1 daemon receipt is unchanged.
    assert stopped.outcome == "stopped" and first.schema_version == stopped.schema_version == 1
    lifecycle.start(PAYLOAD)
    lifecycle.stop()  # One release can be reused only after verified cleanup.


@pytest.mark.parametrize(
    "failure", ["stage", "verify", "start_after_spawn", "terminate_error", "cleanup"]
)
def test_failures_preserve_primary_error_and_never_clean_live_dependencies(
    release, tmp_path, failure
):
    transport = CompanionTransport()
    wrapped = BundledIiodTransport(transport, release)
    lifecycle = _lifecycle(tmp_path / "credentials", wrapped)
    lifecycle._port_probe = lambda *_: transport.alive
    lifecycle._serial_probe = lambda *args: args[1] == 30431 or transport.alive
    if failure in {"stage", "verify", "cleanup"}:
        transport.bundle_failure = failure
    else:
        transport.fail_at = failure
    if failure in {"stage", "verify", "start_after_spawn"}:
        with pytest.raises(RuntimeError):
            lifecycle.start(PAYLOAD)
        assert not transport.companions and not transport.alive
    else:
        lifecycle.start(PAYLOAD)
        with pytest.raises(UserspaceIiodLifecycleError) as error:
            lifecycle.stop()
        assert error.value.stop_receipt.outcome == "cleanup_failed"
        assert transport.companions
        if failure == "terminate_error":
            assert "bundle-cleanup" not in transport.events and transport.alive


def test_local_digest_rejection_performs_no_stage(release, tmp_path):
    rewrite(release, lambda data: data.update(daemon_sha256="0" * 64))
    transport = CompanionTransport()
    lifecycle = _lifecycle(tmp_path / "credentials", BundledIiodTransport(transport, release))
    lifecycle._port_probe = lambda *_: transport.alive
    lifecycle._serial_probe = lambda *_: True
    with pytest.raises(UserspaceIiodLifecycleError, match="daemon digest"):
        lifecycle.start(PAYLOAD)
    assert "stage" not in transport.events and "bundle-stage" not in transport.events


def test_new_session_cannot_remove_dependencies_of_failed_previous_start(release):
    transport = CompanionTransport()
    wrapped = BundledIiodTransport(transport, release)
    paths = RemoteIiodPaths(
        *(f"/tmp/ppu-iiod-{SESSION}.{suffix}" for suffix in ("bin", "pid", "log"))
    )
    digest = hashlib.sha256(PAYLOAD).hexdigest()
    binary = wrapped.stage(paths, PAYLOAD, expected_sha256=digest)
    wrapped.start(paths, binary)
    other = RemoteIiodPaths(
        *(f"/tmp/ppu-iiod-{'f' * 32}.{suffix}" for suffix in ("bin", "pid", "log"))
    )
    with pytest.raises(UserspaceIiodLifecycleError, match="earlier stage"):
        wrapped.stage(other, PAYLOAD, expected_sha256=digest)
    before = list(transport.events)
    with pytest.raises(UserspaceIiodLifecycleError, match="different session"):
        wrapped.cleanup(other, RemoteIiodBinaryIdentity(other.binary, len(PAYLOAD), digest))
    assert transport.events == before and transport.companions and transport.alive
    wrapped.terminate(paths, transport.process, timeout_s=15)
    wrapped.cleanup(paths, binary)
    assert not transport.companions


def test_deployment_explicit_opt_in_uses_existing_lifecycle(release, tmp_path):
    transport = CompanionTransport()
    known, password = _credentials(tmp_path / "creds")
    deployment = UserspaceIiodDeployment(
        host=HOST,
        expected_serial=SERIAL,
        binary_path=release.parent / "iiod",
        known_hosts_path=known,
        password_path=password,
        bundle_manifest_path=release,
        transport=transport,
        session_id_factory=lambda: SESSION,
        port_probe=lambda *_: transport.alive,
        serial_probe=lambda *args: args[1] == 30431 or transport.alive,
    )
    assert not transport.events
    with deployment.session():
        assert transport.companions
    assert not transport.companions and not transport.alive


class LocalScriptRunner:
    """Execute the actual fixed shell operations in a test-owned namespace.

    Rewrite only the root path and expected uid, so root is not required. Never
    invoke SSH or a real daemon. This is not target BusyBox/ARM qualification.
    """

    def __init__(self, root):
        self.root = root
        self.calls = []
        self.environment = None

    def run(self, argv, *, stdin, timeout_s):
        self.calls.append((argv, stdin))
        command = argv[-1].replace(ROOT, str(self.root))
        if stdin is not None and stdin.startswith(b"set -eu\n"):
            stdin = stdin.replace(b"'drwx------:0'", f"'drwx------:{os.geteuid()}'".encode())
            stdin = stdin.replace(b"'-rw-------:1:0'", f"'-rw-------:1:{os.geteuid()}'".encode())
            stdin = stdin.replace(
                b'"$permissions:1:0"', f'"$permissions:1:{os.geteuid()}"'.encode()
            )
        result = subprocess.run(
            ["/bin/sh", "-c", command],
            input=stdin,
            capture_output=True,
            timeout=timeout_s,
            check=False,
            env=self.environment,
        )
        return SshCommandResult(result.returncode, result.stdout, result.stderr)


@pytest.fixture
def scripts(release, tmp_path):
    known, password = _credentials(tmp_path / "credentials")
    runner = LocalScriptRunner(tmp_path / "remote-bundle")
    transport = PinnedPasswordSshIiodTransport(
        host=HOST,
        expected_serial=SERIAL,
        known_hosts_file=known,
        password_file=password,
        runner=runner,
    )
    return transport, runner, load_iiod_companion_bundle(release)


def test_real_scripts_stage_verify_and_remove_only_enumerated_files(scripts, tmp_path):
    transport, runner, bundle = scripts
    sentinel = tmp_path / "unrelated"
    sentinel.write_text("preserve")
    transport.stage_companions(bundle, SESSION)
    for file in bundle.files:
        path = runner.root / file.name
        assert path.read_bytes() == file.payload
        assert path.stat().st_mode & 0o777 == (0o700 if file.executable else 0o600)
    transport.verify_companions(bundle, SESSION)
    transport.cleanup_companions(bundle, SESSION)
    assert not runner.root.exists() and sentinel.read_text() == "preserve"
    transport.cleanup_companions(bundle, SESSION)  # Verified absent is idempotent.
    assert all(
        argv[0] == "sshpass" and "StrictHostKeyChecking=yes" in argv for argv, _ in runner.calls
    )


@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-owner",
        "changed",
        "truncated",
        "symlink",
        "extra",
        "writable",
        "hardlink",
        "directory-writable",
    ],
)
def test_real_scripts_reject_changed_inventory_before_removing_anything(
    scripts, mutation, tmp_path
):
    transport, runner, bundle = scripts
    transport.stage_companions(bundle, SESSION)
    worker = runner.root / "worker"
    if mutation == "wrong-owner":
        (runner.root / "owner").write_text("another-session\n")
    elif mutation == "changed":
        worker.write_bytes(b"X" * len(bundle.files[0].payload))
    elif mutation == "truncated":
        worker.write_bytes(b"partial")
    elif mutation == "symlink":
        worker.unlink()
        worker.symlink_to(tmp_path / "outside")
    elif mutation == "extra":
        (runner.root / "other-owner-file").write_text("retain")
    elif mutation == "writable":
        worker.chmod(0o777)
    elif mutation == "hardlink":
        os.link(worker, tmp_path / "linked")
    else:
        runner.root.chmod(0o777)
    before = set(runner.root.iterdir())
    with pytest.raises(UserspaceIiodLifecycleError):
        transport.verify_companions(bundle, SESSION)
    with pytest.raises(UserspaceIiodLifecycleError):
        transport.cleanup_companions(bundle, SESSION)
    assert set(runner.root.iterdir()) == before


def test_real_scripts_refuse_preexisting_root_and_can_clean_missing_uploads(scripts):
    transport, runner, bundle = scripts
    transport.stage_companions(bundle, SESSION)
    with pytest.raises(UserspaceIiodLifecycleError):
        transport.stage_companions(bundle, "f" * 32)
    assert (runner.root / "owner").read_text().strip() == SESSION
    (runner.root / "worker").unlink()
    with pytest.raises(UserspaceIiodLifecycleError):
        transport.verify_companions(bundle, SESSION)
    transport.cleanup_companions(bundle, SESSION)
    assert not runner.root.exists()


def test_real_scripts_work_without_optional_stat_applet(scripts, tmp_path):
    transport, runner, bundle = scripts
    commands = tmp_path / "minimal-bin"
    commands.mkdir()
    for name in (
        "ls",
        "awk",
        "find",
        "wc",
        "tr",
        "cat",
        "sha256sum",
        "mkdir",
        "chmod",
        "rm",
        "rmdir",
    ):
        executable = shutil.which(name)
        assert executable is not None
        (commands / name).symlink_to(executable)
    assert not (commands / "stat").exists()
    runner.environment = {**os.environ, "PATH": str(commands)}
    transport.stage_companions(bundle, SESSION)
    transport.verify_companions(bundle, SESSION)
    transport.cleanup_companions(bundle, SESSION)
    assert not runner.root.exists()
