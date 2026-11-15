# Active Directory / LDAPS prototype

Opt-in, local-only integration. Existing demo mode is unchanged. This is not production
SSO: no MFA, persistence, HA or internet-facing HTTPS endpoint is provided. Use a test
AD directory and test accounts only. No directory has been contacted by the implementation
tests, and existing running demos are not restarted automatically.

## Behavior

* AD authenticates passwords by binding as the uniquely found user over verified LDAPS.
  OpenPrivileged does not retain the user's password. A separate read-only service account
  reads users, account status and memberships. LDAP filters are escaped, referrals disabled.
* `sAMAccountName` is the login name (not UPN). `objectGUID` becomes the immutable local
  identity `ad:<guid>`, so renames do not create a second identity. Display name and mail
  populate the user list. Scope the user search base to the intended organizational unit.
* Only explicitly mapped AD groups grant roles and device IDs. Memberships union together.
  One role is selected automatically; multiple assigned roles use the existing dropdown.
  Operational `admin` and user-management `superadmin` remain separate roles. Domain Admins
  are **not** automatically OpenPrivileged superadmins. Map a dedicated group deliberately.
* Device mappings govern inventory visibility, requests, approvals, grants and connections,
  in addition to organization/tenant boundaries. A mapped device marked `direct` can be
  launched without approval. A device marked `approval` still requires the normal approval.
  An empty device list grants no devices, not all devices. Auditor audit visibility remains
  tenant-wide, so only assign auditor/admin/approver to people allowed to read tenant audit.
* First successful login imports the mapped user. Superadmins can use **Sync Active
  Directory** on Users & groups (`POST /v1/directory/sync`, CSRF required) to import all
  eligible users in the configured search base. AD users are read-only in OpenPrivileged:
  create users and change their group memberships in AD, not in this prototype.
* Every protected request and active tunnel authorization check rereads directory status
  and membership. There is no offline authorization fallback. A directory failure, removed
  or disabled account, or changed memberships invalidates the affected local sessions.
  Role/device changes require login again, even when access increased. Sync invalidates
  users omitted from a complete snapshot. Old grant records remain in audit/history but
  cannot bypass current role/device authorization. Active bridges close on their next
  existing authorization check; this does not kill remote background processes.
* Direct groups are the default. `nested_groups: true` uses AD's matching-rule-in-chain
  search inside `group_base_dn`. Primary-group membership (`primaryGroupID`, commonly
  Domain Users) is deliberately unsupported. Use dedicated ordinary security groups.
* Imports are bounded by `max_users` (default 1000). No LDAP paging yet; limit/time/referral
  results reject the whole import instead of silently accepting a partial snapshot.
  Large directories should use a narrower OU for this prototype. Repeated LDAP checks
  are deliberately conservative, not production-scale caching or synchronization.

## Configuration

Create an operator-owned JSON file outside the repository using this example (no password
in JSON). Device IDs must already exist in the configured inventory, and tenant IDs must
match the policies/inventory. Dedicated groups should be controlled by trusted AD admins.

```json
{
  "host": "dc01.lab.example",
  "port": 636,
  "ca_file": "/absolute/path/to/lab-ad-ca.pem",
  "bind_dn": "CN=OpenPrivileged Reader,OU=Service Accounts,DC=lab,DC=example",
  "bind_password_env": "VAULTGATE_AD_BIND_PASSWORD",
  "user_base_dn": "OU=OpenPrivileged Test Users,DC=lab,DC=example",
  "group_base_dn": "OU=OpenPrivileged Groups,DC=lab,DC=example",
  "org_id": "demo-msp",
  "tenant_ids": ["customer-a"],
  "nested_groups": false,
  "max_users": 1000,
  "group_mappings": [
    {
      "group_dn": "CN=VG-Technicians,OU=OpenPrivileged Groups,DC=lab,DC=example",
      "roles": ["technician"],
      "device_ids": ["vg-frr1", "vg-ubuntu-rdp", "vg-ubuntu-vnc"]
    },
    {
      "group_dn": "CN=VG-Admins,OU=OpenPrivileged Groups,DC=lab,DC=example",
      "roles": ["admin"],
      "device_ids": ["vg-frr1"]
    },
    {
      "group_dn": "CN=VG-Identity-Admins,OU=OpenPrivileged Groups,DC=lab,DC=example",
      "roles": ["superadmin"],
      "device_ids": []
    }
  ]
}
```

Before an explicitly authorized test-directory connection, configure:

1. DC hostname and reachable LDAPS port with matching server certificate SAN.
2. Trusted CA PEM bundle. Certificate chain and hostname validation cannot be disabled.
3. Dedicated least-privilege read-only bind account. Supply its password using the named
   environment variable via approved local secret injection, not command arguments, Git,
   shell history or chat. No AD write privileges are needed.
4. Search bases, tenant scope, dedicated group DNs, roles and exact inventory device IDs.
5. A fresh localhost test instance; do not restart an existing in-memory demo unintentionally.

After dependency synchronization, append `--directory-config /path/ad.json` to the normal
`vg-api --demo` invocation along with the existing lab inventory options. Use a free port.
All local generated demo passwords and bearer authentication are disabled in directory mode.
The process still listens only on `127.0.0.1`; do not expose it via a tunnel or public proxy.

## Verification

Unit tests mock directory records and LDAP transport. They exercise credential rejection,
TLS-required options, escaping, account status, incomplete searches, mappings, role changes,
read-only membership, sync permission, outage/session invalidation and device isolation.
A real AD integration test, real CA failure test and production threat review remain required.

If computed AD lockout flags are not readable by the service account, a nonzero
`lockoutTime` is conservatively rejected. An automatically unlocked account may therefore
remain denied until its lockout state is cleared or computed flags are made readable.
Directory tunnel checks run in bounded worker dispatch so LDAP I/O does not block the
browser-session event loop. Directory reads are still serialized with identity updates.

## Superadmin integration editor (single directory)

Choose **Setup AD** in the left sidebar to open the **Active Directory integration**
panel as superadmin. It stays separate from Users & groups and is hidden until selected.
The button appears when the app is running in directory mode. It displays the configured LDAPS
host, CA file, reader DN, search bases and explicit role/device mappings. It does not
return reader passwords. Test validates the candidate settings and confirms the
current immutable AD identity would remain a superadmin. Saving repeats verification,
persists the settings, then activates them and signs out all users. Invalid settings,
loss of superadmin authority, scope changes, unknown devices and stale revisions are
rejected. Changing the server/port/reader DN requires entering the password explicitly;
the stored reader credential is never silently sent to a new destination.

The editor supports **one existing AD integration**, not multiple simultaneous forests
or first-time setup from demo authentication. For an unrelated new domain, use a
separate operator-reviewed bootstrap so existing identities cannot accidentally inherit
cross-domain privileges. AD memberships still remain read-only. Configuring login does
not alter the separate password-rotation adapter, its target accounts or its AD authority.

For the combined container, enable durable editing with two optional runtime JSON keys:

- `directory_settings_directory`: an existing, owner-only directory, separate from
  `vault_directory`, mounted read/write outside the container's writable layer.
- `directory_settings_key_file`: an existing, owner-only 32-byte binary encryption key,
  mounted read-only. Keep it outside Git and the image and protect/back up it separately.

These are operator deployment inputs, not browser-supplied paths. The separate store
uses the existing AES-GCM, atomic-write and exclusive-lock implementation. Its internal
filenames are `rotation.enc` and `rotation.lock` in **that separate directory**; do not
point it at the credential-rotation vault. Saved settings are loaded on restart and
must retain the bootstrap org/customer scope. Loss/corruption of the encrypted settings
fails startup closed rather than silently reverting. Without storage, the panel remains
viewable/testable and clearly says saving is disabled. The password input is cleared after saving or signing out, and no password is ever
prepopulated from saved state.

CA paths entered in the editor refer to files already mounted inside the service.
There is no trust-bypass switch or automatic file upload. Provision a verified CA bundle
before using a new directory. This editor is still local-lab functionality, not a
production credential manager or multi-tenant identity administration service.
