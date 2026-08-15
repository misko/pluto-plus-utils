# Release checklist

This checklist records the standalone distribution audit performed on
2026-08-15. It distinguishes offline package evidence from decisions and
hardware validation that cannot be inferred from a successful Python build.

## Current release gates

| Gate | Status | Evidence or action required |
|---|---|---|
| Wheel and sdist build | Pass | `uv build` produced both 0.1.0 artifacts. Hatch builds the wheel from the generated sdist. |
| Wheel package contents | Pass | Python modules, `py.typed`, direct-radio documentation, and all three web assets are present. Tests and repository documentation are not placed in the wheel. |
| Source distribution contents | Pass with review | Source, tests, documentation, lockfile, and static assets are present. Decide whether shipping `uv.lock` and the test suite in the sdist is intentional. |
| Console entry points | Pass | Wheel metadata declares `pluto = pluto_plus.cli:app` and `plutod = pluto_plus.cli:serve_entrypoint`. Both `--help` commands pass in a clean environment. |
| Clean wheel install | Pass | Installed the wheel and its base dependencies into a fresh Python 3.11 virtual environment outside the checkout. Import, packaged-resource, CLI-to-daemon, health, index, JavaScript, and CSS smoke checks passed with one fake radio. |
| Optional hardware isolation | Pass offline | Importing the base CLI does not import `adi`, `iio`, or `usb1`; native integrations remain in the `hardware` extra and are loaded lazily. Attached-radio validation remains separate. |
| Python compatibility | Partial | Python 3.11 is proven. `requires-python = ">=3.11"` also advertises every later Python version; add a supported-version CI matrix before publishing that open-ended claim. |
| Automated tests and static checks | Pass offline | Final local tree: 169 passed, 3 explicit opt-in skips; Ruff and strict mypy pass. The genuine Chromium lane also passes separately. Hardware and firmware mutation lanes remain explicit. |
| License and notices | Blocked on owner decision | No `LICENSE`, SPDX expression, copyright notice, or third-party notices file is present. Select and review a license; do not publish until package metadata and the sdist include it. |
| Project metadata | Needs decision | Add maintainers/authors, project URLs, license metadata after selection, and useful classifiers. Keep the version in `pyproject.toml` and `pluto_plus.__version__` synchronized or adopt one version source. |
| CI/release automation | Present; hosted run pending | `.github/workflows/ci.yml` defines offline tests on Python 3.11–3.13, lint, strict types, build, and a dedicated Playwright/Chromium job. Require a green hosted run, tagged immutable source, clean-install job, and protected publication credentials before publishing. |
| SBOM and provenance | Missing | Generate a CycloneDX or SPDX SBOM for the resolved release environment and retain artifact hashes, build logs, source revision, and build attestations. Do not treat `uv.lock` as an SBOM. |
| Dependency policy | Needs decision | Base dependencies are correctly separated from `dev` and `hardware`, and the lockfile has hashes. Define update cadence, vulnerability scanning, supported platforms, and whether release installs are constrained/locked. |
| Deployment security | Partial | Loopback/Unix-socket defaults and the peer-credential-authenticated firmware helper boundary are implemented. Remote HTTP authentication is not. Define service ownership/mode and system hardening before multi-user deployment. |
| Hardware/firmware acceptance | Not proven offline | Complete `docs/HARDWARE_ACCEPTANCE.md` on explicitly selected radios. Firmware helpers and persistent flash must remain fail-closed until site-specific privilege and exact-device gates pass. |

## Artifact verification

Run from a clean, tagged worktree with the intended Python versions:

```bash
uv sync --all-extras --locked
uv run pytest -q
uv run ruff check src tests
uv run mypy src/pluto_plus
uv build
sha256sum dist/*
```

Inspect the artifacts rather than assuming package discovery is correct:

```bash
tar -tzf dist/pluto_plus_utils-*.tar.gz | sort
unzip -l dist/pluto_plus_utils-*.whl
```

The wheel must contain at least:

- `pluto_plus/py.typed`
- `pluto_plus/static/index.html`
- `pluto_plus/static/app.js`
- `pluto_plus/static/styles.css`
- both console scripts in `*.dist-info/entry_points.txt`

It must not contain captures, firmware images, state databases, sockets,
credentials, build caches, or tests.

## Clean-install smoke

For every supported Python and operating-system lane:

1. Create a new virtual environment outside the repository.
2. Install only the built wheel and its declared dependencies.
3. Import `pluto_plus` and confirm `adi`, `iio`, and `usb1` were not imported.
4. Run `pluto --help` and `plutod --help`.
5. Start `plutod` with one fake radio and a temporary state directory.
6. Check `/api/v1/health`, `/`, and each `/static/*` asset.
7. Run `pluto radio list` against that daemon and stop it cleanly.
8. In the hardware lane, install `pluto-plus-utils[hardware]` and verify the
   host libiio/USB prerequisites before running marked acceptance tests.

## Publication checkpoint

Do not publish 0.1.0 until all of the following are recorded in the release:

- the license choice and matching package metadata;
- green final test, lint, type, build, and clean-install jobs;
- a supported Python/OS matrix;
- SHA-256 hashes for the exact wheel and sdist;
- an SBOM and dependency/security scan result;
- the source revision and release notes, including known hardware limitations;
- explicit confirmation that no production credentials, captured RF data, or
  firmware payloads are included.

Hardware qualification may remain a documented pre-release limitation, but it
must not be represented as passed based solely on fake-radio or parser tests.
