# Local demo walkthrough

Run ./run-demo.sh (or add --port 8795 if another demo already uses 8792).
Open the localhost URL printed in that terminal. Use fictional data only.

## One sign-in, assigned roles
The launcher generates a different temporary password for each demo user:
- tech: Technician
- reviewer: Approver
- admin: operational Admin, not user management
- auditor: read-only Auditor
- multi: Technician and Approver
- superadmin: user and group management only

Enter the username and its printed demo password. Single-role users enter their
view directly. Multi-role users get a dropdown containing only their assigned roles.
Selecting a role is checked and audited by the server. Changing the URL cannot
change identity; old portal paths display the same sign-in/application.

Technician: Devices -> Request access -> reason, ticket and duration.
Sign out and sign in as reviewer or admin to approve/deny independently.
A multi-role user cannot approve their own technician request after switching roles.
Grants are simulated and can be revoked; expiry is evaluated on refresh.
Auditor: Audit trail -> Verify chain. No mutations are permitted.

Superadmin: Users & groups -> create a demo username with one or more operational
groups. The generated password is displayed once. Existing user memberships can
be changed; all affected sessions are revoked immediately. The seeded superadmin
account cannot change its own groups or create another superadmin. Operational
Admin cannot manage users. Groups have fixed role mappings for this prototype.
All seeded users and new users are restricted to Customer A.

## Session and security boundary
The demo uses salted scrypt password hashes, opaque server-side one-hour sessions,
HttpOnly/SameSite=Strict cookies, CSRF tokens for mutations, local Host/client checks,
foreign-origin rejection, basic failed-login throttling and a bounded session/user
store. Sign out invalidates the server-side session. No session token is kept in
localStorage and no endpoint discloses every user's credentials. The previous
/demo/identities token endpoint has been removed.

This is NOT production authentication. The HTTP localhost cookie intentionally
does not use Secure. Do not expose it through a proxy/tunnel or use real passwords.
Production requires TLS, hardened persistent identities/sessions, OIDC/MFA, recovery,
secure provisioning, durable audit and independent review. In-memory users, groups,
sessions, requests and grants vanish on restart. Earlier demo instances may still
run old code; stop them yourself once their state is no longer needed.

The /docs schema remains available, but Swagger's bearer Authorize is not used by
the running demo. Authenticated API mutations need its cookie and X-CSRF-Token.
The internal non-UI app factory retains a trusted bearer adapter for unit testing.

## Tests
Run pytest -q, Ruff and mypy from the uv environment.
tests/integration/http_demo_smoke.py launches its own isolated server, signs in with
generated passwords, validates roles/expiry and independently verifies audit hashes.
It takes about a minute for real wall-clock expiry.
tests/integration/browser_demo_smoke.py checks actual login, role views, self-review
prevention, superadmin user creation and desktop/mobile workflows.
Set CHROMIUM_PATH for an installed Chromium if needed.
Neither script touches existing demo processes.

## "Not Found" during login
An older demo process can serve the newly edited static login page without having
the newer authentication API loaded. The UI now detects this and disables sign-in
with an explicit stale-server warning. Open the URL printed by the newest launcher,
not an older demo tab. Use that launch's generated password; restarting changes it.
Do not restart a process merely to fix the URL: in-memory state would be lost.

## Explicit direct lab entitlement and SSH test
Run with --lab-inventory /path/to/private-lab/inventory.json once that inventory and its verified
lab endpoints have been provisioned. Existing processes are not hot-reloaded; starting
a separate port preserves their state. Inventory is operator-controlled, not editable
through an unauthenticated browser request. Each device lists exact entitled usernames.
Being an Admin or in the same tenant alone does not grant direct entitlement.

For an entitled technician/admin, Devices -> Connect establishes or reuses an
active standing grant without an approval request or duration dialog. API clients
may also request time-bounded direct grants. Grants -> Test SSH
runs only a fixed read-only FRR "show version" over SSH, with strict pinned host-key
checking and a server-held key. No private key or arbitrary target/command is sent to
the browser. Wrong owner, tenant, role, expired/revoked grant or removed entitlement is
denied server-side. A configured target is not a health guarantee. Unconfigured targets
are labelled, not represented as connected.

The fixed probe above is only a connectivity/authorization test. Separate opt-in
interactive SSH, browser RDP and browser VNC transports are implemented for approved
isolated labs; see [interactive lab](interactive-lab.md) and [browser VNC](browser-vnc.md).
They require configured targets and dependencies and are not enabled by a plain
local-demo launch. This is not full session recording or a production broker.

Opt-in real lab verification (performs only the configured read-only FRR SSH probe):

    uv run --no-sync python tests/integration/lab_ssh_smoke.py --inventory /path/to/private-lab/inventory.json

This launches a separate local app, uses generated test identities, creates direct
one-minute grants for the three explicitly entitled FRR devices, checks pinned-key
SSH, revokes each grant and confirms reconnect is denied. It leaves running user
apps and lab configuration untouched.
