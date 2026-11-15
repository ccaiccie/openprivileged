# Configuration reference

Keep operator configuration outside the repository. The release contains synthetic examples, not usable secrets or another operator's environment. Do not weaken target allowlists, TLS validation or file-permission checks to make an example run.

## Standard launcher

`./run-demo.sh` supplies `--demo` automatically. The underlying `vg-api` command requires that flag and otherwise refuses startup because production authentication/persistence are not implemented.

| Flag | Default | Meaning |
| --- | --- | --- |
| `--demo` | Supplied by script | Seed fictional devices; enable the local prototype |
| `--port N` | `8792` | HTTP port; host remains `127.0.0.1` |
| `--lab-inventory PATH` | Unset | Append operator-owned isolated-lab devices and explicit direct entitlements |
| `--desktop-credentials PATH` | Unset | Owner-only approved VNC/desktop credential file |
| `--rdp-manifest PATH` | Unset | Explicit RDP certificate-pin manifest; requires desktop credentials |
| `--directory-config PATH` | Unset | Verified LDAPS configuration; disables generated demo-password authentication |

```bash
# Synthetic first run, with an alternate port
./run-demo.sh --port 8795

# Optional private lab, only after preparing the files and endpoints
./run-demo.sh --port 8797 --lab-inventory /absolute/private/inventory.json
```

There is no command-line cloud deployment, public hostname, multi-worker, production database or automatic domain-join switch. Existing processes are not hot-reloaded by editing a file.

## Inventory format

`lab_access.load_inventory` reads a JSON object containing a `devices` array. The standard demo loader scopes imported devices to `demo-msp` / `customer-a`, sets direct access mode and reads an explicit `entitled_users` list. Do not treat this loader as a production multi-tenant inventory service.

The following is a **format example**, not a provisioned target:

```json
{
  "devices": [
    {
      "id": "lab-router-1",
      "name": "Isolated test router",
      "platform": "linux",
      "protocol": "ssh",
      "entitled_users": ["tech"],
      "ssh": {
        "host": "127.0.0.1",
        "port": 2222,
        "username": "labuser",
        "private_key": "/absolute/private/ssh-key",
        "known_hosts": "/absolute/private/known_hosts"
      }
    }
  ]
}
```

Replace every field to match an authorized isolated target before use. The key and pinned host file must already exist. The fixed **Test SSH** probe executes an FRR `show version` command, so an arbitrary Linux SSH service is not a valid probe target merely because it accepts SSH.

Validation includes:

- Unique device IDs, with no collision against seeded demo IDs.
- `ssh` settings only on an SSH-protocol device.
- Numeric loopback or RFC1918 private IP addresses, not arbitrary hostnames/public addresses.
- Valid port and a restricted SSH username format.
- Absolute credential paths. The key must be owned by the current user with no group/other permission bits.
- Owner-controlled, nonempty `known_hosts`, not group/other writable, explicitly pinning the exact host and port.

Obtain host-key fingerprints through a trusted independent channel. Blindly accepting a scanned key defeats pinning. Never put private keys or passwords into the inventory or commit them.

## Directory configuration

The typed schema is `DirectoryConfig` in `packages/vg_api/src/vg_api/directory.py`; unknown fields are rejected.

| Field | Purpose / constraints |
| --- | --- |
| `host`, `port` | Verified directory DNS hostname; port defaults to 636 |
| `ca_file` | Trusted CA file for LDAPS verification |
| `bind_dn` | Reader identity DN |
| `bind_password_env` | Name of the environment variable containing the reader password, not the password itself |
| `user_base_dn`, `group_base_dn` | Explicit search bases |
| `org_id`, `tenant_ids` | Server-owned application organization/customer scopes; tenant list cannot be empty |
| `group_mappings` | Nonempty list of group DN, `roles`, and `device_ids`; duplicate DNs rejected case-insensitively |
| `nested_groups` | Whether transitive membership is enabled; default false |
| `timeout_seconds` | Per-operation timeout, default 5, range 1–30 |
| `max_users` | Import bound, default 1000, range 1–10000 |

The reader does not need Domain Admin. Read permission is different from account-creation/password-reset authority. Do not put a domain administrator password in a persistent application environment as a shortcut. See [AD integration](AD-INTEGRATION.md) for setup, examples and least-privilege options, and [managed accounts](AD-MANAGED-ACCOUNTS.md) for `a.username` provisioning.

The combined rotation runtime uses a separate private JSON configuration and secret-file references. Do not interchange its JSON with the standard directory JSON or assume `--directory-config` starts rotation.

## Optional desktop and managed rotation settings

Desktop loaders and managed-account adapters impose additional lab-specific target and identity restrictions. They are intentionally not generic arbitrary-host connectors. Follow [interactive lab access](runbooks/interactive-lab.md), [managed accounts](AD-MANAGED-ACCOUNTS.md) and [operations](OPERATIONS.md). Private inventories, credential files and pinned manifests are not supplied by this repository.

The combined process runs separately as:

```text
python -m vg_api.rotation_app /absolute/private/config.json --port 8766
```

This is a runtime interface reference, **not a first-run command**: startup can activate the worker against configured AD accounts. Prepare and review its full scope before running. Never run it alongside an existing owner of that vault/account.

**Current combined-runtime limitation:** `rotation_app.managed_application` still requires the legacy `binding` structure and a valid `rdp_fingerprint` (32 colon-separated hexadecimal bytes), and unconditionally constructs the legacy RDP device/target even when managed SSH inventory is configured. An SSH-only inventory does not remove this startup requirement. Use a genuine verified certificate fingerprint for the approved lab configuration; do not supply a dummy pin or claim a generic SSH-only deployment is supported. Removing that scaffold requires a code change, not merely omitting the JSON fields.

## Configuration change discipline

1. Record the intended scope and retain a protected configuration backup.
2. Validate paths, ownership, certificates, target identity and group mappings.
3. Use synthetic checks before a real isolated-lab integration.
4. Plan state loss/session interruption before restarting a process.
5. After a supported settings save, reauthenticate and verify authorization; settings changes revoke sessions. In managed mode, follow the controlled restart/revalidation workflow rather than assuming rotation resumed.
6. Keep private files and keys out of Git, images, screenshots, command history and support reports.
