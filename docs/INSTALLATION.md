# Installation and first run

OpenPrivileged Community 0.1 is a **local development/lab prototype**, not a production PAM deployment. Start with the synthetic demo. It needs no Active Directory, Docker, cloud account, domain, or device credentials. Purchasing or configuring a public domain does not make this application safe to expose.

## Requirements

- Git and a Bash-compatible shell for the launcher.
- Python 3.12 and [uv](https://docs.astral.sh/uv/getting-started/installation/). The project requires Python >=3.12; the tested launcher explicitly selects 3.12.
- Network access on the first dependency synchronization, or a complete pre-populated uv cache.
- An unused loopback TCP port (8792 by default).

Use official installation instructions for Git, Python and uv on your operating system. Linux is the reference environment for optional lab transports and the rotation container. Windows users can use an appropriately configured Linux development environment; native Windows support is not claimed by this guide.

## Get the code

```bash
git clone https://github.com/ccaiccie/openprivileged.git
cd openprivileged
./run-demo.sh
```

The launcher runs `uv sync --locked --python 3.12`, then `vg-api --demo`. It selects `.venv-host` on a host or `.venv-container` when it detects a container. These environments are disposable dependencies, not application backups. Do not commit them.

Open **http://127.0.0.1:8792/** on the machine running the application. The terminal prints a fresh, different password for each synthetic user. Keep that terminal available, do not post its output, and never enter real passwords in this mode.

| Username | Demo purpose |
| --- | --- |
| `tech` | Technician requesting device access |
| `reviewer` | Independent approver |
| `admin` | Operational administration |
| `auditor` | Read-only audit review |
| `multi` | Technician and approver, with assigned-role switching |
| `superadmin` | User/group administration, separate from operational admin |

A user cannot approve their own request by switching roles. All seeded demo identities are scoped to Customer A. See [the user guide](USER-GUIDE.md) for the complete workflow.

## Confirm the installation

1. Sign in as `tech`, using the password from this launch.
2. Create a request using fictional reason/ticket text.
3. Sign out, then sign in as `reviewer` to approve it.
4. Return as `tech` and view the grant. An active grant is a simulation unless you explicitly configured a real isolated-lab target.
5. Sign in as `auditor` to inspect and verify the audit chain.

The API schema is at `/docs`. In demo UI mode it uses session cookies and CSRF protection, not Swagger's bearer authorization field. Never copy an internal testing token into a public client.

## Alternate port and stopping

```bash
./run-demo.sh --port 8795
```

Use the matching URL and passwords from that specific process. An older open tab may still point to an independent server. Stop your demo with Ctrl+C in its terminal when finished. **Restart loses in-memory users, sessions, requests, grants and audit events**, and generates new passwords. There is no shared persistent database in this default mode.

The server binds `127.0.0.1`; there is no supported public `--host` option. Do not change it to `0.0.0.0`, add a tunnel, or use a public reverse proxy to make the demo accessible remotely.

## Optional next steps

- [Configuration](CONFIGURATION.md): exact launcher flags and inventory example.
- [AD integration](AD-INTEGRATION.md): opt-in verified LDAPS, roles and equipment entitlements.
- [Deployment boundaries](DEPLOYMENT.md): what the Docker/reference scaffolding actually does.
- [Troubleshooting](TROUBLESHOOTING.md): login, certificate and connectivity failures.
- [Architecture](ARCHITECTURE.md): state, authorization and broker boundaries.

Optional lab integration is not part of the first-run installation. The sanitized release deliberately excludes private inventories, directory secrets, private keys and existing vault state. Do not expect a fresh clone to connect to another operator's lab.
