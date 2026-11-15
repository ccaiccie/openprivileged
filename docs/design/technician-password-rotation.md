# Technician privileged credentials: reference prototype

## User requirement
Each technician signs into OpenPrivileged with their ordinary identity. A different,
individually assigned privileged identity authenticates to authorized equipment.
Its password rotates every four hours. The technician must not be shown that
password, receive it through an API, or copy it into a terminal.

## Implemented, isolated foundation
`vg_core.rotation` is a **single-process, synthetic-credential-only reference**,
now with optional durable AES-256-GCM state and an opt-in polling worker.
It is not enabled in the demo, does not register API routes, and does not contact
AD or equipment by default. Existing live SSH/VNC/RDP configuration is unchanged.
An optional managed RDP route integration and explicitly allowlisted AD-lab reset
adapter are now implemented, but neither has been enabled against real targets.

- Explicit organization/tenant/technician/device mapping to a privileged account
  and password authority. Sharing a privileged account across bindings and
  overlapping technician/device mappings are rejected.
- Four-hour deadline from initial verified enrollment or successful rotation.
  `RotationWorker` polls every 30 seconds when explicitly started, and requires
  a durable store. No worker is started by the app and no OS task is installed.
  Late scheduling blocks new connections rather than extending password validity.
- Generated 256-bit random URL-safe pending passwords. Adapter-specific password
  constraints must be validated before deploying a real adapter.
- Pending version retained before mutation, promoted only after verification.
  Adapter failure or timeout quarantines the account. No blind automatic retry.
  Explicit recovery verifies pending first, then current; retries the SAME pending
  value only when current still verifies. Neither matching leaves it quarantined.
- Process-local locking serializes rotation and connection establishment. Trusted
  adapters must have bounded timeouts. This lock deliberately trades availability
  for simple safety and is not a distributed lock.
- Broker-only callback passes the password to the backend, never returns it.
  The callback must revalidate the live grant and inject credentials into a
  trusted transport, not into browser JavaScript, shell arguments, environment
  variables or terminal input. Only the assigned technician can select a mapping.
- Status contains only account ID, state, generation and deadline. Adapter error
  messages are suppressed because exceptions can embed credentials. No logging
  of passwords is implemented. Python memory is not securely zeroized.

Run tests with `uv run --no-sync pytest -q tests/unit/test_rotation.py`.
Tests use a fake target and clock, including the exact four-hour boundary,
concurrent worker calls, target failure before/after change, unavailable target,
recovery, identity isolation, grant denial and secret-safe status/errors.

## Mandatory work before real use
1. Production key custody, restricted broker identity, tenant-specific encryption
   keys and durable HA persistence. The optional local encrypted snapshot survives
   restart and retains pending/current versions, but lacks KMS, rollback protection
   and high availability. The default store-less mode still loses all state on
   restart. **Neither mode is approved for real credentials.** Python private
   attributes are not a security boundary.
2. Durable worker/outbox with distributed leases, clock discipline, bounded
   retries, operator alerting, secret-free audit events and recovery runbook.
   A four-hour policy is not a guarantee of completion during target outage.
3. Integrate authenticated session/grant revalidation and backend injection into
   each transport. Test every API, WebSocket, trace, crash report and recording
   for canary leakage. The reference service alone does not secure the broker.
4. Explicit approved account/target scope and least-privileged rotation service;
   exclude domain Administrator, break-glass, service and ordinary login accounts.
   Test provisioning and privileged group assignment separately. No Domain Admin
   rights are implied by a technician's equipment access.
5. Decide authority model: AD-backed accounts rotate at AD once; device-local
   accounts need separate authority bindings. Equipment must actually authenticate
   against the selected authority. Do not copy one password independently to
   unrelated equipment and claim atomic rotation.
6. AD-specific tests for password policy, replication, selected DCs, old-password
   acceptance and cached authentication. Verification at one DC is not proof all
   equipment rejects the old password. Recovery verification must account for
   replication and lockout policy before performing further password changes.
7. Rotation does **not** revoke existing SSH/RDP sessions, Kerberos tickets,
   background jobs or device tokens. Session lifetime/revocation is separate.
   Privileged operators may still be able to alter accounts or install alternate
   credentials on equipment; least privilege and command/session controls remain
   required even when the broker never reveals its injected password.

No live accounts were enabled, no real passwords rotated, and no running demo,
AD configuration, device configuration or system scheduling was changed.


## Local durable mode and worker
`vg_api.rotation_store.EncryptedRotationStore` uses the already-installed
PyCryptodome AES-256-GCM implementation with a fresh random nonce per snapshot and
authenticated format marker. It accepts an externally supplied 32-byte key; it
never generates or saves that key. Keep production keys out of code, arguments,
environment dumps and the same directory as ciphertext. A test key is not a
usable deployment key.

The supplied absolute, non-symlink directory must already be owner-only. State
and lock files are owner-only. The store rejects unsafe file types/permissions,
locks out a second writer using Linux flock, and writes ciphertext to a temporary
file followed by fsync, atomic replace and directory fsync. Pending is committed
before remote mutation. Promotion is committed only after successful verification.
Any storage failure poisons the service instance: connections and further changes
fail closed until reopening from durable state and reconciling. Corrupt ciphertext,
wrong keys and unsupported data fail closed rather than resetting state.

Construct the store, then `RotationService(adapter, store=store)`, then optionally
`RotationWorker(service)`. Explicitly call `worker.start()`. Its public `failed`
flag indicates any non-ready account or worker error; it is not an alert delivery
system. Stop the worker and all broker callers before closing the store. If stop
times out, do not close the store or start a competing worker. The containing
process must remain running for scheduling; no service manager is configured.

Crash tests simulate interruption after the target accepts a password and after
promotion persistence fails. Restart retains the same pending value and reconciles
without another target change. Tests also check wrong key/tamper/truncation,
exclusive ownership, encrypted bytes, permissions, and opt-in worker execution.

Limitations: local Linux filesystem only, no network/shared-volume locking claim;
no rollback-resistant trusted generation counter or defense against a same-user
attacker replacing/deleting the whole vault. No production backup/key recovery,
key rotation or per-tenant key separation. Encryption does not protect secrets
from a compromised running broker or memory/core dumps. No configured live rotation, credential reveal UI/API, or installed scheduled
task exists. The optional managed RDP integration below is covered by synthetic
route tests, not a real equipment login.


## Optional AD lab adapter and managed RDP route
`AdLabRotationAdapter` accepts only operator-configured `AccountBinding` values
paired with immutable AD object GUIDs and exact DNs under the OpenPrivileged Lab Users
OU. Its reset script checks GUID, DN, username and OU before changing a password.
The script runs through a separately approved, pinned DC1 SSH authority. Passwords
travel through SSH stdin JSON, never command arguments, terminal input or printed
output. It changes no users, group memberships, login permissions or policies.
Use only validated operator-owned SSH key and pinned known-hosts paths. The
Administrator SSH authority is a lab-only compatibility mechanism, not an
acceptable production least-privilege service design.

Verification uses certificate-validated LDAPS to the configured DC1 DNS identity,
binds as the selected user, and checks the account's object GUID to detect a
recreated DN. This needs the existing optional `ldap3` dependency in the selected
runtime. No unavailable dependency is bypassed. AD reset failure is uncertain and
requires normal pending-state recovery. Generated managed passwords now always
include uppercase, lowercase, digits and punctuation in addition to 256 random
bits; this still does not guarantee compliance with every custom password policy.

Pass `rotation_service=service` to `create_app` to use managed credentials on the
configured RDP route. When supplied, missing/overdue/recovery-required bindings
fail closed: there is no static-password fallback. The immutable target remains
the existing isolated Ubuntu address and certificate pin; only the username and
password come from the trusted mapping. The gateway holds the rotation lock
through backend authentication, rechecks session/grant permission immediately
before and after setup, and closes late connections after cancellation. Browser
messages contain only session display/control traffic, not the injected password.
The existing RDP heartbeat continues checking authorization after connection.

A synthetic WebSocket integration test signs in as the ordinary technician,
requests a grant, opens the managed route, advances a fake clock by four hours,
rotates, then opens it again with the new privileged password. Only the fake
backend sees either secret. Separate tests cover cancellation and revoked access.
This verifies application plumbing, not real RDP/AD interoperability.

**Live test prerequisite:** an ordinary AD technician and a different dedicated
privileged account must be explicitly approved along with its equipment scope.
The Ubuntu lab target currently uses device-local authentication; it does not
accept AD accounts merely because an AD account exists. Provisioning equipment
accounts, granting admin/logon rights, or changing authentication/domain membership
requires a separately approved plan. None was performed for this implementation.
