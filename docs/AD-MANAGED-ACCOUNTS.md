# Superadmin: AD groups and technician equipment accounts

## Two identities, two purposes

A technician signs into OpenPrivileged with the normal AD account, for example `joe.bloe`.
Equipment sessions must use the separate AD account `a.joe.bloe`. The `a.` prefix is
literal, not an AD role or automatic administrator privilege. That second account
must exist in AD. Its group memberships and target-machine rights determine what
it can do; its name alone grants nothing. The password is generated and held by
the service, not shown to technicians or returned by the provisioning API.

Choose existing AD security groups in **Setup AD** and map them to OpenPrivileged roles
(superadmin, admin, technician, approver, auditor as supported by the application).
These mappings authorize application behavior. They do not add users to AD groups
or make an equipment account an administrator. Keep normal-user role groups
separate from equipment-access groups. Retain a tested recovery superadmin mapping.

AD sAMAccountName is limited to 20 characters and must be unique among security
principals in the domain, including groups ([Microsoft naming rules](https://learn.microsoft.com/en-us/windows/win32/ad/naming-properties)).
The naming helper uses `a.` plus the current `sAMAccountName`. It rejects names
longer than 18 characters, existing `a.` prefixes, and unsupported characters rather
than silently truncating or mapping two people to the same account. Renaming the
normal account needs an explicit migration of the managed binding. Never infer
ownership of an existing `a.*` account solely from its name; verify immutable GUIDs.

## Permission options

**1. Manual creation, read-only discovery (smallest application authority).**
An AD administrator creates the `a.*` users in a dedicated OU and assigns approved
equipment rights. OpenPrivileged's reader needs only directory read access for users,
groups and memberships in its configured scope. A separately delegated rotation
identity needs Reset Password for the managed accounts. Creation is not required
for discovery or group mapping.

**2. Dedicated OU delegation (recommended for opt-in creation).**
Create a dedicated OU containing only OpenPrivileged-managed equipment users. Delegate
the provisioning identity **Create User objects** on that OU, directory read access,
and **Reset Password** on descendant user objects for initial password setting.
Permit only the attributes the creation operation needs (`sAMAccountName`,
`displayName`, `userAccountControl` for a disabled normal user), testing the effective
rights in an isolated OU. Exact inherited/default rights depend on your ACL design.
Do not delegate Full Control, Write DACL, ownership, user deletion, domain-wide
write, group creation, or membership changes. In particular, do not grant Domain
Admins or Enterprise Admins. Restrict the OU to these identities because delegation
inherits to objects beneath it.

Keep creation and rotation identities separate if practical. The recurring rotation
identity needs Reset Password only on the approved managed users/OU, not Create
User or rights to reset technicians' normal accounts. Enabling an account needs
write access to `userAccountControl` and is a separate privileged activation step.
Changing an equipment-access group's members needs write access to that group's
`member` attribute; do not bundle that into account creation.

**3. Windows provisioning broker (larger deployment).**
Keep AD write authority on a narrowly scoped Windows service/JEA endpoint, ideally
with managed service-account credential custody. The web service sends constrained
requests rather than retaining broad AD credentials. This is an architecture option,
not an implemented connector. gMSA is a service identity option, not a replacement
for each technician's separate equipment identity.

The UI asks for a delegated writer only after explicit creation consent. It does
not grant permissions to itself. An authorized AD administrator must set the OU
ACLs separately. Credentials are used against the configured, certificate-verified
LDAPS host for one operation and are not saved as integration reader credentials.
Do not paste Domain Admin passwords into the form.

## What this version implements, and what it deliberately does not

The new staged provisioning API is **disabled by default**. An operator must supply
`ProvisioningConfig(domain_base_dn=..., target_ou_dn=...)` and a separate encrypted
`SettingsStore` to `DirectoryProvisioning` / `create_app`. The journal must not reuse
the directory-settings or rotation-state file. Use the existing owner-only,
AES-GCM `EncryptedRotationStore` with a dedicated directory and approved key custody.
Do not substitute a plaintext file store. No command here changes production ACLs.

1. Superadmin previews the current technician GUID. The service derives `a.username`
   itself and checks collisions across the domain, not just the target OU.
2. Superadmin explicitly confirms the exact name, target OU and **disabled** creation,
   then supplies a delegated writer identity. Reader credentials are not promoted.
3. The service durably saves an encrypted pending journal with the generated initial
   secret before any AD write. It creates the user disabled, sets the password over
   LDAPS, checks its GUID/disabled status, and records the result. No group is changed.
4. On timeout or partial failure, the account can already exist. A pending journal
   blocks automatic retries. Reconcile the actual object, GUID and saved operation
   with an AD administrator. Never blindly delete/recreate or reset an existing user.

**A staged account is not yet usable for SSH.** This version does not enable it,
assign equipment groups, or automatically enroll it into the existing lab rotation
worker. An explicit operator-only generalized enrollment path is now available below. The current live lab worker still has an explicit synthetic `vg-*` allowlist
and a pre-enrolled `vg-tech-admin` binding. Merely creating `a.joe.bloe` must not
silently replace that account or break existing sessions.

Activation must be an explicitly approved maintenance action: verify the object's
GUID and intended owner, delegate rotation only for it, assign approved equipment
rights, enable during the approved maintenance window and verify initial authentication,
enroll the exact technician-GUID-to-account-GUID/device binding into durable rotation
state, then test hidden-credential
SSH and the four-hour rotation/recovery path. If enrollment/storage cannot be
confirmed, keep broker access closed and disable/reconcile the account. No
activation, live AD writes, deployments, or permission changes were performed as
part of implementing this feature.

## Security checks and limitations

Use LDAPS with trusted CA and hostname verification; never enable insecure password
writes. Only the configured domain/OU is accepted, with no referrals. The app does
not return generated passwords, writer passwords, LDAP exceptions or raw server
errors. Provisioning is superadmin-only and uses the existing session/CSRF checks.
The writer password is never persisted. Python cannot guarantee erasure of strings
from process memory; protect the host, logs, traces and backups accordingly.

This is a single-process lab staging workflow, not a transaction across AD and the
vault. Encrypted journal intent prevents unsafe automatic retries but cannot undo
a remote write after a timeout. Multi-instance provisioning, live effective-rights
analysis, existing-account adoption, unattended activation and live validation of generalized enrollment are not included. Do not interpret a successful reader test as proof of
write rights. Test with synthetic identities in the delegated OU before rollout.

## Microsoft references

- [OU delegation model](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/delegating-administration-by-using-ou-objects)
- [Delegation of Control Wizard](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/delegation-control-wizard)
- [LDAP password operations and transport requirements](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/change-windows-active-directory-user-password)
- [Creating a user and account flags](https://learn.microsoft.com/en-us/windows/win32/ad/creating-a-user)

References checked November 14, 2026. Scope choices and staged activation above are
OpenPrivileged design decisions, not a claim that Microsoft prescribes this exact workflow.

### Optional combined-process configuration

The combined process accepts the following additional private runtime configuration.
This is an example, not an instruction to grant permissions or enable the feature:

```json
{
  "account_provisioning": {
    "scope": {
      "domain_base_dn": "DC=example,DC=invalid",
      "target_ou_dn": "OU=OpenPrivileged Managed,DC=example,DC=invalid"
    },
    "journal_directory": "/approved/private/provisioning-journal",
    "journal_key_file": "/approved/private/provisioning-key"
  }
}
```

The directory must already exist with owner-only permissions; the key file must
contain exactly 32 bytes, be owner-only, and follow approved key-storage procedures.
These values are not added to the live configuration automatically. Leave the entire
`account_provisioning` section absent to retain disabled provisioning. The process
holds an exclusive journal lock and closes it on shutdown. Sharing a state directory
with integration or rotation storage fails closed instead of overwriting that state.


## Picking domain groups in Setup AD

1. Sign in with a mapped superadmin identity and open **Setup AD** in the left navigation.
2. Set the LDAPS reader and user/group search bases. The server must trust the DC certificate.
3. Click **Load domain groups**. This discovers security groups under the chosen group base through read-only, paged queries. No AD memberships are changed.
4. Choose a group, click **Add selected group**, and select one or more application roles: superadmin, admin, technician, approver, auditor. Multiple group memberships combine their roles and device assignments. A OpenPrivileged role does not confer domain-admin rights.
5. Select assigned devices for technician access. Device IDs are checked against the integration's organization/customer inventory.
6. **Test connection & permissions**, then **Save & activate**. The current immutable AD identity must retain superadmin access; otherwise saving is rejected. A successful save revokes sessions and requires sign-in again. **Discard changes** restores the saved configuration.

Nested group resolution is opt-in and uses AD's transitive-membership matching rule under the configured group base. Primary-group membership is not used; assign explicit security-group memberships. Authorization refreshes the AD identity on requests and does not fall back to cached permissions when the directory is unavailable. Group discovery rejects partial/error/referral responses, repeated page cookies, and catalogs larger than 10,000 groups; narrow the base if needed.


## Explicit generalized enrollment and runtime (not activated)

The separate `ManagedAdRotationAdapter` supports multiple approved `a.username`
accounts without widening the original hard-coded synthetic lab adapter. A private
runtime file must supply `managed_accounts`, with each entry containing:

```json
{
  "binding": {
    "id": "managed-joe",
    "org_id": "YOUR_ORGANIZATION_ID",
    "tenant_id": "YOUR_TENANT_ID",
    "technician_id": "ad:REGULAR_ACCOUNT_GUID",
    "privileged_username": "a.joe.bloe",
    "authority_id": "dc.example.invalid",
    "device_ids": ["vg-frr-1"]
  },
  "object_guid": "PRIVILEGED_ACCOUNT_GUID",
  "regular_username": "joe.bloe",
  "distinguished_name": "CN=a.joe.bloe,OU=OpenPrivileged Managed,DC=example,DC=invalid"
}
```

`managed_scope` contains the same `domain_base_dn` and `target_ou_dn` fields as the
provisioning scope. The existing `directory`, `reader_password_file`, `ssh`,
`vault_directory` and `key_file` fields remain required. `ssh` identifies the
preconfigured delegated Windows rotation authority with pinned known-hosts and
approved private-key custody. Its account needs Reset Password only for the
approved managed OU/users, plus directory reads. It does not need Domain Admin.
The application does not provision that identity or grant its permissions.

Use a **new encrypted vault directory** when switching from synthetic lab accounts;
the runtime rejects vault bindings not exactly present in the configured allowlist.
The combined app currently still supports one organization/tenant and its configured
lab equipment inventory. Preserve its existing `binding` organization/tenant fields
for inventory compatibility; session credentials are chosen from the exact managed
technician/device bindings, never from the union of inventory devices.

After the domain owner has approved and performed activation and equipment-access
permissions, an operator may explicitly enroll an already-enabled staged account:

```text
python -m vg_api.rotation_runner /approved/private/runtime.json --enroll-managed managed-joe
```

This command verifies the staged source GUID, privileged GUID, name and OU against
the operator allowlist, authenticates the initial hidden credential, confirms that
the account is enabled, and persists the binding in encrypted rotation state. It
never enables users, resets a password, grants access, starts a worker, or installs
a service. The initial secret is removed from the current journal snapshot after
successful enrollment, but older backups must remain protected. If vault persistence
succeeds but journal cleanup fails, do not retry blindly: inspect enrollment state
and reconcile the journal without changing the password.

A normal start refuses to serve until every configured account is enrolled. The
combined process then uses the same `RotationService` for SSH credential injection
and four-hour rotation. The adapter checks the current regular identity, technician
role and device entitlement before verification/reset; resets target the privileged
GUID, not a name that could have been deleted and recreated. LDAP credential
verification additionally checks target GUID, name and enabled state. Directory
configuration saves suspend managed sessions and rotation **before** persistence/activation.
A failed save also remains suspended. The UI reports that a controlled runtime restart
is required; the runtime reloads saved settings on that restart. Existing in-flight
operations may finish, but no further rotation or credential injection starts under
the old configuration. Browser authorization rechecks current mappings. Never restart
into stale operator configuration. Each credential injection revalidates both regular
identity/entitlement and target GUID/name/enabled state over LDAPS.

Synthetic tests cover GUID/name/OU/authority rejection, enabled-state checks, secret
transport through stdin instead of arguments, hidden SSH username selection,
four-hour rotation, staged enrollment and exact persisted allowlists. These are
**not live domain tests**. Live activation, delegated rights, reset execution,
restart/recovery, and target login must be verified during an approved rollout.


### Immutable managed-vault identity binding

The generalized encrypted vault now wraps core rotation records with the privileged
GUID, exact DN, regular username and configured domain/OU scope. Opening it against
a changed privileged GUID/DN/name fails closed even when the application binding ID
is unchanged. Older generalized snapshots without this identity envelope are not
automatically adopted; explicitly reconcile and reenroll with verified GUIDs. The
original synthetic lab vault format is unchanged. Never edit encrypted records or
remove identity metadata to bypass this check.


### Large AD group catalogs

Group discovery uses the same LDAPS connection and RFC 2696 cookies across 500-object pages. AD's default `MaxPageSize` is 1,000 objects per search; paging retrieves more than that without raising the domain policy. Microsoft recommends leaving default page settings unless there is a demonstrated need to change them.

A catalog is returned only after a successful final page with an explicit empty server cookie. Missing/malformed paging controls, non-success LDAP results (including size/time/admin limits), referrals, repeated cookies, more than 100 pages, or more than 10,000 distinct groups fail the whole discovery rather than displaying a partial catalog. Existing saved mappings are not modified by discovery failures. Narrow the group search base if a configured service bound is exceeded. Tests use synthetic catalogs of 1,501 and 10,000 groups; they do not prove performance against a particular live domain.

References: [Microsoft paging search results](https://learn.microsoft.com/en-us/previous-versions/windows/desktop/ldap/paging-search-results), [AD LDAP policies](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/3f0137a1-63df-400c-bf97-e1040f055a99), [LDAP performance considerations](https://learn.microsoft.com/en-us/windows-server/administration/performance-tuning/role/active-directory-server/ldap-considerations).
