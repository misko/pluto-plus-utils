from __future__ import annotations

import importlib.metadata
import importlib.resources
import subprocess
import sys

import pluto_plus


def test_distribution_metadata_and_console_scripts_are_consistent() -> None:
    distribution = importlib.metadata.distribution("pluto-plus-utils")

    assert distribution.version == pluto_plus.__version__
    scripts = {
        entry_point.name: entry_point.value
        for entry_point in distribution.entry_points
        if entry_point.group == "console_scripts"
    }
    assert scripts == {
        "pluto": "pluto_plus.cli:app",
        "pluto-install-metadata-runtime": "pluto_plus.metadata_runtime_install:main",
        "plutod": "pluto_plus.cli:serve_entrypoint",
    }


def test_embedded_web_application_is_a_package_resource() -> None:
    static_root = importlib.resources.files("pluto_plus").joinpath("static")

    for filename in ("index.html", "app.js", "styles.css"):
        asset = static_root.joinpath(filename)
        assert asset.is_file(), filename
        assert asset.read_bytes(), filename


def test_base_cli_import_does_not_load_optional_hardware_drivers() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; import pluto_plus.cli; "
                "assert 'adi' not in sys.modules; assert 'iio' not in sys.modules; "
                "assert 'usb1' not in sys.modules"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr
