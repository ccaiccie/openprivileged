# Deployment modes and boundaries

**There is no supported public production deployment in this release.** The safe starting point is a synthetic localhost demo. A public domain, Docker image or TLS reverse proxy does not supply missing production identity, durable authorization state, key custody or security review.

## Choose the correct mode

| Mode | Entry point | What it provides | What it does not provide |
| --- | --- | --- | --- |
| Synthetic local demo | `./run-demo.sh` | Generated demo identities, simulated request/approval/grant flow | AD, real device access, durable state |
| Explicit isolated-lab broker | Demo plus approved inventory/credential flags | Configured SSH/VNC and optional RDP transport | Generic network access, account withdrawal, production isolation |
| Combined rotation lab runtime | `vg_api.rotation_app` / rotation Compose | One API/broker/rotation worker with encrypted rotation state | HA, distributed workers, durable ordinary grants/audit |
| Platform reference scaffolding | Legacy Compose/Terraform | Development design/reference pieces | A working hosted OpenPrivileged platform |

## Local execution

Follow [installation](INSTALLATION.md). Use an unused loopback port and preserve any existing process until its state is no longer needed. Never start multiple processes and assume they share users or grants. Default storage is process-local.

Do not expose the app with a public tunnel, public reverse proxy, load balancer or forwarded port. The local authentication boundary includes loopback/Host checks and a localhost HTTP cookie without `Secure`. It is not a production deployment contract.

## Optional combined container

The relevant files are:

- `lab/docker/rotation/Dockerfile`
- `lab/docker/compose.rotation.yml`
- `.dockerignore` (the Docker build-context allowlist) and `lab/docker/rotation/.env.example`
- [Detailed container runbook](runbooks/rotation-container.md)

The Compose service uses **Linux host networking**, non-root UID/GID, a read-only root filesystem, dropped capabilities, `no-new-privileges`, bounded tmpfs/logs and external bind mounts. Host networking shares host reachability; it is not network isolation. It expects external approved directory/equipment services and loopback guacd at port **4823**. Sanitized `example.local`/documentation-address placeholders are not usable infrastructure.

Its configuration requires `VG_UID`, `VG_GID`, `VG_VAULT_DIR` and `VG_SECRETS_DIR`. Vault and secret directories must already exist. Keep them outside Git and cloud-shared folders, using owner-only permissions and the correct numeric owner. Preserve the vault's encryption key and original state. The image does not create a domain, grant permissions, initialize arbitrary AD users or safely infer the required runtime configuration.

### Build/validate is not deployment

After reviewing the Dockerfile and choosing a non-root runtime owner, the documented build interface is:

```bash
docker build --build-arg VG_UID="$(id -u)" --build-arg VG_GID="$(id -g)" \
  -t vaultgate-rotation:local -f lab/docker/rotation/Dockerfile .
docker compose --env-file /absolute/private/rotation.env \
  -f lab/docker/compose.rotation.yml config --quiet
```

These steps build and validate only. They do not start the application. Do not run as root or substitute an existing live vault into a synthetic image test. Use the dedicated network-disabled synthetic test procedure in the container runbook.

### Before any authorized cutover

- Verify the intended account, domain, OU, immutable identity bindings, devices and permissions.
- Confirm recovery material and protected backups, including encryption-key recovery.
- Gracefully stop the previous owner and verify lock release; never kill during an uncertain password reset.
- Start exactly one combined process, using the current original vault, not a simultaneously active copy.
- Verify worker health, generation/deadline and an authorized session without printing credentials.
- Observe a scheduled rotation and verify post-rotation access before relying on the service.

Do not create another cron job, worker container, ASGI worker or replica. A local file lock is not distributed coordination. Stopping a browser does not stop the worker. Docker's `unless-stopped` policy can restart a stopped process after a crash/daemon restart as applicable; an **unhealthy** status alone does not cause Docker to restart a still-running container. External monitoring is not installed here.

Rolling back code does not roll back AD passwords. Stop the newer owner first, and use the latest vault. Restoring stale state after AD changed can break credential reconciliation. Consult [operations](OPERATIONS.md) rather than retrying uncertain resets.

## Legacy Compose and infrastructure references

`lab/docker/compose.yml` is separate lab scaffolding. Its guacd publishes loopback **4822**, not the 4823 expected by the interactive/rotation path. Its optional profiles include PostgreSQL, Redis, MinIO and an RDP proxy spike. Starting those services does not migrate the application to durable storage or wire up a hosted service. Throwaway fixture credentials in that file are not production defaults.

Do not execute Terraform or launch cloud infrastructure to install the default demo. Reference infrastructure describes experiments and future design, not a supported production release procedure.

## Production readiness is a separate engineering effort

At minimum, a production design needs independently reviewed authentication/MFA and recovery, transactional persistent authorization and expiry, durable externally anchored audit, appropriate tenant isolation, key management, safe credential reconciliation, monitored backups/restores, restricted network exposure, transport/session controls, patching, capacity and failure testing. This list is a planning boundary, not a certification checklist or claim that completing it alone makes the product safe.

Read [SECURITY.md](../SECURITY.md) and [architecture](ARCHITECTURE.md) before planning any broader rollout.
