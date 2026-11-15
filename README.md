# OpenPrivileged

Community privileged-access-management prototype for isolated development labs.
Project website: https://openprivileged.com (hosted offerings will be announced there).

**Pre-release, not production-ready.** This is a sanitized source snapshot, not a
copy of a running environment. No passwords, private keys, vault state, machine-specific
inventory or operational account bindings are included. Read [SECURITY.md](SECURITY.md)
and [the release checklist](docs/FIRST-RELEASE.md) before use or publication.

## First implementation: local control-plane prototype

Implemented in `packages/vg_core` and `packages/vg_api`:

- Organization/customer-scoped inventory and server-owned identity/role scopes.
- Policy-limited access requests with a reason and change ticket.
- Distinct-person approval (including configurable multi-reviewer quorum), denial,
  replay protection and serialized transitions.
- Time-boxed **simulated** grants, lazy expiry, early revocation, and ownership enforcement.
- Per-customer hash-chained audit events, JSON export and chain verification.
- FastAPI/OpenAPI API and a localhost-only demo launcher with generated per-user passwords and server-side sessions.
- Unit, API and isolation tests; uv workspace, lockfile, Ruff, strict mypy, CI skeleton.

### Run on your development machine

```bash
cd /path/to/openprivileged
./run-demo.sh
```

Open http://127.0.0.1:8792/ and sign in with a demo username and its generated
password printed in the terminal. A single-role user enters their assigned view;
multi-role users get only their assigned choices. Superadmin manages demo users/groups,
separately from operational Admin. Never enter real credentials.
See [the walkthrough](docs/runbooks/local-demo.md) for the request/approval flow.
For real isolated-lab SSH/VNC and optional RDP, see [interactive lab access](docs/runbooks/interactive-lab.md).

```bash
uv run --no-sync pytest -q
uv run --no-sync ruff check packages tests/unit
uv run --no-sync ruff format --check packages tests/unit
uv run --no-sync mypy
```

## Security and implementation boundary

**This is not production PAM. Do not expose it using Cloudflare Tunnel or load real
credentials.** Storage is in-memory and lost on restart; no database/RLS, OIDC/MFA,
credential vault, session recording, collector, device account creation
or withdrawal exists yet. An `active` grant remains a simulation unless the operator configures a lab target.
Explicit isolated-lab targets support browser SSH and VNC with server-side grant and identity checks.
These are local prototypes, not a general production broker. Active connections are rechecked every second
and close on expiry, revocation, logout or role changes. Remote background jobs and shared desktop state
can survive disconnection. Expiry for disconnected grants is evaluated on reads/revokes or explicit
`ControlPlane.expire()` calls; no background scheduler exists yet. No real customer
network, cloud or VM changes are made by this implementation.

The default app factory rejects all authenticated routes unless supplied trusted identity
mappings. Operational identity and tenant scope come from server state, never client headers. Requested role selection is checked against assigned groups.
Local demo sessions are not a substitute for production identity, OIDC and MFA.
Audit chains detect edits/reordering within supplied events, but cannot prove completeness
or resist full history replacement without external trusted anchors. No WORM storage or
external anchoring is implemented. Reasons/tickets may contain sensitive text; use fictional
values only. Multi-process operation is unsupported until transactional persistence exists.

## Next slices

1. Postgres/Alembic plus transaction-scoped RLS and database-backed concurrency tests.
2. Validated OIDC identity mapping with MFA requirements; replace demo-token adapter.
3. Durable expiry/outbox worker and policy administration with audit.
4. KMS-backed credential vault, then SSH broker and verified withdrawal against a lab.

Included lab/Terraform files are reference scaffolding, not deployed services or completed product features. Machine-specific network lab and FRR pilot automation is intentionally excluded.

### Development environments

Python 3.12 is required. The launcher uses separate `.venv-host` and
`.venv-container` environments and synchronizes locked dependencies before
starting. `.python-version` pins Python 3.12.

### Optional Active Directory test integration

OpenPrivileged now has an opt-in LDAPS authentication/import prototype with explicit group-to-role
and group-to-device mappings. See [Active Directory setup and limitations](docs/integrations/active-directory.md).
Existing local demo accounts remain unchanged unless `--directory-config` is supplied.

### Technician password-rotation reference

An isolated synthetic-only rotation engine now models a distinct privileged
account per technician, four-hour deadlines, broker-only secret injection,
failure reconciliation, optional encrypted local persistence and an opt-in worker. An optional managed RDP gateway and allowlisted AD-lab reset provider are also
implemented. None is **enabled in the live demo or against real credentials**. See
[implementation boundary and production prerequisites](docs/design/technician-password-rotation.md).

### Combined rotation container

The existing single-process AD-lab API/broker/rotation worker now has an opt-in
[container package and cutover runbook](docs/runbooks/rotation-container.md).
It keeps encrypted state on an external owner-only bind mount and secrets out of
the image/environment. Building/testing the image does **not** cut over the live
worker, enable host boot services, or make the prototype production-ready.

### AD group mapping and equipment accounts

See [AD managed-account configuration](docs/AD-MANAGED-ACCOUNTS.md) for the `a.username` convention, opt-in creation, and least-privilege delegation options. In **Setup AD**, load security groups, add a group, select its application roles and assigned devices, test, then save. Saving revokes existing sessions.

## License

OpenPrivileged Community original code is licensed under the
[Apache License 2.0](LICENSE). Third-party components retain their own licenses
and notices; see [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
# openprivileged
