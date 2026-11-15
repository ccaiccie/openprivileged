# Combined API + password-rotation container

This packages the **single-process AD lab prototype**.
It does not make the application production PAM, change account scope, create an
AD principal, change AD permissions, or join equipment to a domain.

The API, RDP broker and 30-second rotation polling worker stay in one Python
process. The four-hour deadline is stored in the encrypted vault, not reset at
container startup. Do not create a separate cron/worker container, use multiple
ASGI workers, or scale this service. A Linux lifetime `flock` rejects a second
owner of the same vault. This is not distributed coordination or HA.

## Layout

- Image: `lab/docker/rotation/Dockerfile`, Python base digest pinned, uv version
  pinned and application dependencies installed from `uv.lock` (`--frozen`).
  Debian security-package versions follow the base distribution repositories at
  build time; this is not a bit-for-bit reproducible OS package snapshot.
- Compose: `lab/docker/compose.rotation.yml`, independent of the existing lab
  Compose project. No other service is started or stopped by this file.
- Vault: an existing host directory bind-mounted read/write at
  `/var/lib/vaultgate/vault`. Preserve the **original** vault directory/lock inode
  for cutover; do not use a copied vault concurrently with its original.
- Secrets: a dedicated owner-only directory, mounted read-only at
  `/run/vaultgate-secrets`. Passwords and keys are never image layers, Docker
  environment values, Compose values, or command arguments.
- Numeric build-time and runtime UID/GID must match the host owner of vault and secrets. Use a
  non-root UID. The image creates a matching passwd entry required by OpenSSH. Directory modes `0700`, private files `0600`, no symlinks/hardlinks.
- Root filesystem read-only, all Linux capabilities dropped, no new privileges,
  no Docker socket mount, core dumps disabled, bounded temporary storage/logs.

## Network and existing dependencies

This first package uses **Linux host networking**, because the existing code
connects to the approved host-local guacd endpoint at `127.0.0.1:4823` and the
current app binds `127.0.0.1:8766`. It publishes no Docker ports. Host networking
is *not* network isolation; it grants the process the host's network reachability.
Starting this service therefore requires explicit approval for the live cutover.

The existing guacd service and AD/Ubuntu lab remain external dependencies. The
container adds its own fixed hosts entry for DC1; it does not edit the host's DNS
or hosts file. TLS hostname/CA verification and SSH/RDP pins remain enforced.
No host firewall, routing, Docker daemon, boot settings or existing guacd settings
are modified by building this image. Do not expose port 8766 publicly.

## Prepare configuration without exposing credentials

Do not deploy from example paths. For an authorized cutover, retain all existing
account scope, immutable GUID/DN, directory group mappings and certificate pins.
Create a separate private **copy of the runtime JSON config** with only these
path references changed. Do not copy or reset the encrypted vault state:

| Runtime JSON key | Container path |
| --- | --- |
| `vault_directory` | `/var/lib/vaultgate/vault` |
| `key_file` | `/run/vaultgate-secrets/vault.key` |
| `reader_password_file` | `/run/vaultgate-secrets/reader-password` |
| `directory.ca_file` | `/run/vaultgate-secrets/dc-ca.pem` |
| `ssh.private_key` | `/run/vaultgate-secrets/dc-ssh-key` |
| `ssh.known_hosts` | `/run/vaultgate-secrets/known_hosts` |

The JSON itself belongs at `/run/vaultgate-secrets/config.json`. For this baseline synthetic layout, the dedicated
host secrets directory contains only those six dependency files plus `config.json`,
with the approved existing values. Optional editable settings and provisioning
require additional, separate writable store mounts and read-only key paths; the
example Compose file does not add those mounts automatically. Review any extension
against [configuration](../CONFIGURATION.md) and the store isolation requirements. Never include all lab-user password fixtures or unrelated SSH
keys. Preserve the same vault encryption key; regenerating it destroys access to
the existing ciphertext. Keep the directory outside this repository and outside
shared/cloud-synced folders. Key custody on the same host is still a lab limitation.

Copy `lab/docker/rotation/.env.example` to an operator-private file outside the repository and fill
in the two existing absolute directories and numeric owner IDs. This file contains
paths only, not secret values. Compose will refuse missing variables or missing
mount directories instead of silently creating them.

## Build and validate only

Run from the repository root:

```bash
docker build --build-arg VG_UID="$(id -u)" --build-arg VG_GID="$(id -g)" \
  -t vaultgate-rotation:local -f lab/docker/rotation/Dockerfile .
docker compose --env-file /absolute/private/rotation.env \
  -f lab/docker/compose.rotation.yml config --quiet
```

The Docker build-context allowlist excludes private fixtures, virtual environments,
logs, generated documents, tests and other repository content. The runtime image
contains installed application code and dependencies, not a writable checkout.

## Approved cutover procedure (not performed by the build)

1. Confirm no active sessions that would be interrupted. Stop the current combined
   host process gracefully, allow reset/verification to finish, and verify it
   exited and released the vault lock. Do **not** kill during a pending reset.
2. Take an encrypted backup under the approved protected storage policy, with
   separate key recovery. Use the original vault directory for the container.
3. Start exactly one combined service:
   `docker compose --env-file /absolute/private/rotation.env -f lab/docker/compose.rotation.yml up -d --no-build`.
4. Verify container health and `/healthz/rotation`, account generation and due
   timestamp without logging secrets, then an approved normal-login → RDP session.
5. Observe a scheduled rotation and a new login using the resulting credential.
   Test graceful container restart and persistence without adding a second owner.
6. Only with separate approval, test host reboot and Docker startup. The
   `unless-stopped` policy restarts the container when Docker starts unless it was
   explicitly stopped; it cannot start Docker itself or run while your development machine is off.

Rollback: gracefully stop the container first, verify lock release, and restart
its original combined process against the **same latest vault**. Never restore an
older vault backup after AD has changed without explicit reconciliation; that
could restore a stale password. Do not start the old process beside the container.

## Failure behavior and remaining service work

- Health checks mark unhealthy; Docker does not automatically restart a running
  process merely because it is unhealthy. Add external monitoring/alerting before
  relying on unattended operation. Do not blindly restart/retry uncertain resets.
- Startup checks the persisted deadline. Overdue accounts cannot open new sessions
  and the worker attempts due rotation. A pending/uncertain change remains
  quarantined for operator reconciliation; startup does not generate another reset.
- SIGTERM permits up to 120 seconds in Compose for worker shutdown. Abrupt loss can
  leave a recoverable pending version; exercise that recovery with synthetic data.
- The API's grants/sessions/audit are still in-memory. Container restart discards
  them even though the encrypted rotation state survives. This is not a durable
  production control plane.
- The original adapter retains its explicitly allowlisted synthetic account. The
  optional generalized managed-account runtime requires separate configuration and
  enrollment; see [managed accounts](../AD-MANAGED-ACCOUNTS.md). Delegate reset
  authority narrowly rather than using a domain administrator.
- No new autostart configuration, alerts, HA, central key custody or backup system
  is installed by this repository work. Containerization solves packaging and
  makes supervision available; it does not establish production readiness.

## Network-isolated synthetic image test

`lab/docker/rotation/smoke.py` exercises the actual installed app lifecycle with a
fake adapter, without credentials or connectivity to AD/equipment. Run it in two
successive containers using the same dedicated, marked fixture directory. Use
`--network none`, `--read-only`, non-root UID/GID, dropped capabilities, no new
privileges, and only the fixture plus the read-only smoke-script mounts. The
`first` phase rotates an overdue synthetic account, verifies health and exclusive
ownership, and sends SIGTERM. `restart` verifies the preserved generation/deadline
and confirms no duplicate rotation. Never point this script at real vault data.


For current health semantics, scheduled-rotation verification and backup/recovery
precautions, see the [operator guide](../OPERATIONS.md). Example packaging does not
prove that a service has been deployed or tested in your environment.
