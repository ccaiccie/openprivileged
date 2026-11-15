# Operator guide

[Documentation home](README.md) · [Deployment](DEPLOYMENT.md) · [Security policy](../SECURITY.md)

This guide describes operation of the optional isolated-lab runtime. It is not a
production service runbook or permission to change a domain. Keep the service local,
use synthetic accounts and explicitly authorize any AD write or live cutover.

## Ownership and state

Run one combined API/rotation process with one ASGI worker. It owns the encrypted
vault for its lifetime; a filesystem lock rejects another owner. Do not add a cron
rotation process, run CLI state inspection against the live locked vault, copy a
vault to run a second instance, or scale containers. This is not HA/distributed locking.

| State | Persistence and recovery implication |
| --- | --- |
| Requests, grants, browser sessions, identity cache and audit | In memory; restart loses them. Users sign in and request/connect again. |
| Rotation current/pending secrets, generation and due time | Encrypted vault; retain the latest data and original encryption key. |
| Editable directory settings and reader secret | Separate encrypted settings store when configured. |
| Staged account intent and initial secret | Separate encrypted provisioning journal when configured; never share its directory with another store. |
| Inventories, pins and runtime settings | Operator-controlled private files; version/review without putting secrets in Git. |

All sensitive stores and files belong outside the repository with restrictive
permissions. Follow the store's owner-only requirements; do not fix validation by
making files world-readable. Keep encryption keys recoverable under a separate
protected policy. Same-host key custody is a prototype limitation, not a KMS/HSM.

## Read-only health checks

For a running combined application, use the configured loopback URL:

```bash
curl --fail-with-body http://127.0.0.1:8766/healthz/rotation
```

The default combined app binds this port; use your actual approved address if different.
`/health` is an API liveness check and is not enough to establish rotation readiness.
`/healthz/rotation` returns HTTP 200 only when the worker is healthy and all account
states are ready; otherwise it returns 503. It exposes worker liveness/progress and
secret-free state, not passwords. Keep even these operational details private.

The top-level `generation` and `due_at` describe the **first** configured account.
The `accounts` list reports IDs/states for all configured accounts, not per-account
generation values. Do not claim every account rotated from a change in that single
number. To verify one scheduled rotation, record its generation and due timestamp,
wait past the due time/poll cycle, then verify advancement, ready state and a healthy
worker. Investigate rather than forcing a reset when the expected transition is absent.

For an already stopped runtime, the runner provides a check-only mode:

```bash
uv run --no-sync python -m vg_api.rotation_runner /absolute/private/runtime.json
```

Select the same installed environment used for the runtime (set
`UV_PROJECT_ENVIRONMENT` when using `.venv-host`, `.venv-container` or another
operator-selected environment; see [development](DEVELOPMENT.md)).
It opens/locks the vault and prints sanitized status. With no `--run` it does not
trigger rotation. Do not use it beside the combined service; lock failure then is
expected. `--run` starts password changes when due, and `--enroll-managed` writes
enrollment state. Neither is a read-only diagnostic.

Container health can also be inspected without dumping environment/configuration:

```bash
docker compose --env-file /absolute/private/rotation.env \
  -f lab/docker/compose.rotation.yml ps
```

A healthy container is not proof that every remote device login succeeds. Test
approved end-to-end sessions separately. An unhealthy running container is not
automatically restarted solely because its health check failed.

## Rotation lifecycle

The interval is four hours, with a 30-second worker poll. The persisted deadline
survives restart. An overdue account is not allowed to inject a credential into a
new session until safely ready again.

Before a reset, the service persists a generated pending credential and recovery
state. It then changes the password through the configured adapter and verifies it.
Only successful verification promotes the pending version, increments generation,
and schedules the next deadline. A timeout can mean the remote write succeeded;
never assume the previous password is still valid.

| State | Operator response |
| --- | --- |
| `ready` | Check worker freshness and expected deadline; no reset is needed merely to inspect health. |
| `overdue` | Check worker progress, connectivity and delegated rights. Do not start a second worker. |
| `recovery_required` | Quarantine; preserve both encrypted versions and reconcile with an authorized operator. |
| `storage_failed` | Stop new operational reliance; investigate storage/key/ownership safely. Never bypass persistence. |
| `suspended` | Usually settings-change suspension; reconcile configuration, then perform a controlled single-owner restart. |

Recovery is not simply “retry rotation.” The core `recover()` first verifies the
saved pending secret, then the previous secret; it can reset to the existing pending
secret if appropriate. It is a potentially mutating operation, not a health probe.
There is no general-purpose public recovery UI/CLI in this snapshot. Use a reviewed,
operator-controlled procedure for the exact adapter and account; do not hand-edit
ciphertext, erase pending state, print secrets, or generate a second password blindly.

## Change and restart checklist

1. Record secret-free health, generation/due time, expected identity GUIDs and scope.
2. Notify affected lab users and allow sessions/operations to finish. A restart
   destroys in-memory requests, grants and audit history.
3. Stop gracefully and verify the existing owner exited. Avoid killing during reset.
4. Make a consistent protected backup of the stopped encrypted stores and their
   corresponding settings; retain keys separately under approved recovery controls.
5. Review scope, account GUID/DN, CA/SSH/RDP pins and storage paths. Identity changes
   require explicit reconciliation/re-enrollment, not changing names to bypass checks.
6. Start exactly one process against the latest original state. Verify readiness,
   authorized sign-in, target connectivity, and subsequent scheduled rotation.

Rollback software using the **latest** vault. Never roll back to an old credential
snapshot after AD changed without reconciliation. Restoring an old snapshot can
restore a password that no longer works and lose evidence of an uncertain change.
A backup copy must never become a concurrent second owner.

## Security and release discipline

Keep logs and health snapshots secret-free, but review them before sharing: account
IDs, target names, reasons and tickets may identify internal infrastructure. Never
upload runtime JSON, password files, vaults, journal files, private keys, cookies,
raw LDAP errors or a broad support archive into a public issue.

Certificate/host-key mismatch is a stop condition. Verify a legitimate change via
an independent trusted channel before updating pins. Do not disable validation.
Do not grant Domain Admin to fix a delegated operation. See
[managed-account permissions](AD-MANAGED-ACCOUNTS.md#permission-options).

Monitor worker freshness and due times externally before relying on unattended lab
operation. This repository installs no complete alerting, backup, durable audit,
recording, high-availability or disaster-recovery system. Follow the
[security policy](../SECURITY.md) and [release checklist](FIRST-RELEASE.md).
