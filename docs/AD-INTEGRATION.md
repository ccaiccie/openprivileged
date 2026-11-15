# Active Directory integration

[Documentation home](README.md) · [Managed accounts](AD-MANAGED-ACCOUNTS.md) · [User guide](USER-GUIDE.md)

This is an opt-in isolated-lab integration, not a domain-joining wizard or a
production identity platform. The default local demo does not contact AD. One
configured directory supplies identities and security-group mappings; the combined
rotation application currently supports one organization/customer scope.

## Before configuring

Have an AD administrator supply the DC hostname, trusted issuing CA, user and group
search-base distinguished names (DNs), and a dedicated reader identity. The service
host must resolve/reach the DC and read the configured CA file. LDAPS defaults to
TCP 636, with certificate and hostname validation mandatory. Do not replace this
with plaintext LDAP or disable TLS validation to solve a connection failure.

The reader needs to read the relevant users, immutable GUIDs, account attributes,
security groups and memberships. It does not need account-creation, password-reset,
group-write or Domain Admin privileges. Test the actual effective permissions in
an isolated scope rather than assuming a successful bind proves every search works.

Configure the initial superadmin security-group mapping in the operator's private
runtime settings. Users with no mapped roles are denied. Directory mode deliberately
disables the local-demo user/password and bearer-token fallback. Keep a separately
controlled recovery procedure and a second tested superadmin identity; the app does
not create a break-glass domain administrator for you.

See [configuration](CONFIGURATION.md) for runtime files. Editable Setup AD additionally
requires a separate encrypted directory-settings store; without it, saving is unavailable.
The CA path is a path **inside the running service/container**, not the browser computer.

## Configure and validate in Setup AD

1. Sign in using a mapped superadmin account and select the **superadmin** role.
2. Open **Setup AD**. Enter the DC hostname, port, CA path, reader DN, and search bases.
   Supply a reader password when changing server/account; leaving it blank retains
   an existing secret only when the integration permits reuse for the same identity.
3. Choose **Load domain groups**. This reads AD security groups under the group base.
   It neither creates a group nor changes membership. Choose a group and **Add selected
   group**, then select roles and assigned devices.
4. Keep at least one mapping that gives the current immutable AD identity superadmin.
   The save validation rejects a configuration that locks the current editor out.
5. Choose **Test connection & permissions**. This tests the proposed read configuration
   and current superadmin access; it does not test account-creation or reset rights.
6. Review device scope and role combinations, then **Save & activate**. Successful
   saving signs everybody out. Sign in again and test each intended role using a
   separate synthetic user. **Discard changes** restores the saved form values.

In the combined managed-rotation runtime, a settings save suspends new managed
credential injection and rotation **before persistence**. Even a persistence failure
leaves that runtime suspended. Plan a controlled restart after reconciling the saved
settings and operator configuration. An in-flight operation may finish; do not assume
suspension reverses an already-started AD operation.

## Role and device semantics

Supported roles are `superadmin`, `admin`, `technician`, `approver`, and `auditor`.
Matching mappings combine available roles and device assignments, but a browser
session operates as one selected role at a time. Superadmin is configuration
administration, not an implicit grant of every operational role. See the
[role matrix](USER-GUIDE.md#roles).

Device IDs must exist in the configured organization/customer inventory. Selecting
a role does not create equipment or grant rights on an operating system. A device
assignment and application grant authorize the broker; the target AD account still
needs its independently configured equipment privileges. A visible device or an AD
group name alone is not evidence that a working SSH/RDP/VNC transport is configured.

Nested membership is opt-in (`nested_groups`). When enabled, AD's transitive matching
rule resolves memberships under the configured group base. Primary-group membership
is excluded: use explicit security-group membership. The application refreshes AD
identity/entitlements on requests. Unavailable/incomplete directory results fail
closed instead of reusing cached authorization. Membership changes can invalidate
sessions and require a fresh sign-in.

**Sync** imports mapped directory identities into the in-memory application view;
it does not create AD users or edit AD memberships. Directory-managed memberships
cannot be changed through the demo user-management workflow.

## Large directories and safe failure

Group discovery uses one LDAPS connection with 500-result RFC 2696 pages. The catalog
must finish with an explicit empty paging cookie. Referrals, failed/partial searches,
missing or malformed controls, repeated cookies, more than 100 pages, or more than
10,000 distinct groups reject the complete discovery. Saved mappings remain intact.
Narrow the group base rather than raising domain-wide LDAP policy for this prototype.

The per-operation directory timeout is configurable from 1 to 30 seconds (default 5).
There is no end-to-end discovery deadline; discovery currently holds the auth lock.
Large catalogs or a slow DC may delay other authentication operations. Test realistic
catalog sizes before relying on this lab workflow.

## Privileged equipment accounts

Normal sign-in `joe.bloe` and equipment identity `a.joe.bloe` are separate principals.
The prefix grants no special AD privilege. Account creation, activation, equipment
membership, enrollment and recurring reset authority are distinct operations.
[Managed-account documentation](AD-MANAGED-ACCOUNTS.md) explains the manual option,
OU-scoped delegation, staged creation, immutable GUID binding and optional runtime.

## Source of truth

- `packages/vg_api/src/vg_api/directory.py`: schema, LDAPS searches and mappings.
- `directory_auth.py`: live authorization refresh and import behavior.
- `directory_management.py`: discovery, validation, encrypted save and session invalidation.
- `tests/unit/test_directory*.py`: synthetic positive and fail-closed cases.

These tests are not certification of your domain ACLs, network or production readiness.
