# Developer guide

This guide is for working on the source, not deploying a production PAM service.
For a first run use [Installation](INSTALLATION.md); for components and trust
boundaries use [Architecture](ARCHITECTURE.md).

## Toolchain and workspace

Python 3.12 is the tested baseline (`.python-version` and CI). Install `uv`, then
from the repository root:

```bash
uv sync --locked --python 3.12
uv run --no-sync pytest -q
uv run --no-sync ruff check packages tests/unit
uv run --no-sync ruff format --check packages tests/unit
uv run --no-sync mypy
```

These are the checks used by `.github/workflows/ci.yml` on pushes and pull
requests. `uv sync --locked` must not silently update `uv.lock`. If intentionally
changing dependencies, update the appropriate `pyproject.toml`, regenerate the
lockfile with `uv lock`, review its diff, and rerun checks. Commit both manifest
and lockfile changes.

The workspace contains two installable packages:

| Location | Responsibility |
| --- | --- |
| `packages/vg_core/src/vg_core/domain.py` | Actors, policies, requests, grants and audit-chain logic |
| `packages/vg_core/src/vg_core/rotation.py` | Rotation state machine and synthetic provider contracts |
| `packages/vg_api/src/vg_api/main.py` | FastAPI application and `vg-api` CLI |
| `packages/vg_api/src/vg_api/demo_auth.py` | Local demo identities and sessions |
| `packages/vg_api/src/vg_api/directory*.py` | Directory authentication, mappings and opt-in provisioning |
| `packages/vg_api/src/vg_api/*ssh*.py` | SSH session and managed-account access paths |
| `packages/vg_api/src/vg_api/rotation*.py` | Optional rotation integrations, persistence and worker |
| `packages/vg_api/src/vg_api/static/` | Browser application and bundled vendor assets |
| `tests/unit/` | Default pytest suite, including fake directory/provider tests |
| `tests/integration/` | Explicit smoke-test scripts, not the default pytest suite |
| `lab/` and `terraform/` | Optional lab/reference scaffolding, not production deployment |

## Run and inspect the application

```bash
./run-demo.sh
```

Use the generated credentials printed at launch with fictional data only. The
launcher creates/selects `.venv-host` or `.venv-container` and synchronizes the
locked environment before executing `vg-api --demo`. Plain `uv` commands normally
use `.venv`; do not assume they use the launcher's environment. To deliberately
reuse a launcher environment, set `UV_PROJECT_ENVIRONMENT` to its path before
running `uv` commands.

The default local endpoint is `http://127.0.0.1:8792`. FastAPI exposes `/docs` and
`/openapi.json` for the running app's HTTP schema. Optional routes depend on the
configured app; WebSocket behavior and side effects require source/runbook review,
not just OpenAPI. `/health` is a process-health check, not proof of directory,
credential, device or rotation health.

The UI is plain browser HTML/CSS/JavaScript under `static/`; there is no JavaScript
build step in the checked-in Python CI. Preserve vendor assets and licenses.
Brand assets and usage guidance are in [Branding](branding/BRAND.md).

## Focused tests

```bash
uv run --no-sync pytest -q tests/unit/test_control_plane.py
uv run --no-sync pytest -q tests/unit/test_directory_provisioning.py
uv run --no-sync pytest -q tests/unit/test_rotation.py
```

`pyproject.toml` sets pytest's `testpaths` to `tests/unit`. Passing the default suite
does not demonstrate a live domain write, a real remote session or a successful
lab cutover. Integration files are standalone scripts with different prerequisites;
read a script and its associated runbook before executing it. Some require a
running demo, browser dependencies, private operator inventory or a real isolated
lab. Do not run all integration/lab scripts indiscriminately.

Use fakes for external providers and injectable clocks for deadline behavior.
Follow existing tests for tenant isolation, ownership, quorum, session revocation,
LDAP paging failures and ambiguous credential changes. Verify that rejected
operations make no external write and return no secret. Add regression tests for
negative paths rather than only the UI's happy path.

## Security-sensitive changes

Authorization, group mapping, account lifecycle, credential persistence and session
brokering deserve explicit review. Keep identity and scope in trusted server state;
never treat client role selection or hidden UI controls as authorization. Keep
application-role grants distinct from AD group membership and host privileges.
Uncertain external writes must be reconciled, not retried blindly.

Use one process for the prototype. In-memory control-plane state is not shared
across workers. An encrypted rotation file does not make the control plane durable
or safe for multiple writers. Do not add worker scaling as a documentation shortcut.

## Documentation changes

Link new guides from [the index](README.md), use relative links, and distinguish
implemented code, optional prototypes and future designs. Architecture decision
records in `adr/` include planned directions and are not a current feature list.
Use reserved example domains/documentation addresses and fictitious identities.
Never copy operator-private configuration or runtime secrets into examples.

Before publishing, inspect `git diff --check`, review the diff and use the
[release checklist](FIRST-RELEASE.md). `.gitignore` reduces accidental inclusion;
it does not remove already tracked secrets or replace manual review.
